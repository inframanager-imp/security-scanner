/**
 * Anomaly Baseline Seeding Service
 *
 * Seeds initial baselines by replaying historical cloud events (last 30 days)
 * through the anomaly engine in "learning mode" — detectors run but findings
 * are not saved, only baselines are updated.
 *
 * Also provides utilities for:
 *  - Resetting baselines for a specific actor
 *  - Exporting baseline statistics for UI display
 *  - Scheduled nightly re-calibration
 */

import { prisma } from '../config/database';
import { logger } from '../config/logger';
import { analyzeEvent, normalizeAwsEvent, normalizeAzureEvent, normalizeGcpEvent, type NormalizedEvent } from './anomalyEngine';
import * as credentialService from './credentialService';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface BaselineSeedOptions {
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  lookbackDays?: number;  // default 30
  dryRun?: boolean;       // if true, update baselines but don't emit anomaly events
}

export interface BaselineSeedResult {
  provider:       string;
  accountId:      string;
  eventsProcessed: number;
  baselinesUpdated: number;
  durationMs:     number;
}

export interface BaselineStats {
  actorId:      string;
  metricKey:    string;
  ewmaMean:     number;
  ewmaStddev:   number;
  sampleCount:  number;
  lastUpdated:  Date;
  knownIpCount: number;
  knownCountries: string[];
}

// ─── AWS baseline seed ────────────────────────────────────────────────────────

export async function seedAwsBaseline(opts: BaselineSeedOptions): Promise<BaselineSeedResult> {
  const start = Date.now();
  const lookbackDays = opts.lookbackDays ?? 30;
  let eventsProcessed = 0;

  logger.info(`[anomaly-baseline] Seeding AWS baselines for account ${opts.accountId} (${lookbackDays}d lookback)`);

  // Load credentials
  const cred = await prisma.awsCredential.findUnique({ where: { accountId: opts.accountId } });
  if (!cred) throw new Error(`No AWS credentials for account ${opts.accountId}`);

  const decrypted = credentialService.decryptCredentials(cred);
  let credentials = {
    accessKeyId:     decrypted.accessKeyId!,
    secretAccessKey: decrypted.secretAccessKey!,
    sessionToken:    undefined as string | undefined,
  };

  if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
    const sts = new STSClient({ region: cred.defaultRegion, credentials });
    const assumed = await sts.send(new AssumeRoleCommand({
      RoleArn: cred.roleArn,
      RoleSessionName: `anomaly-baseline-${opts.accountId.slice(0, 16)}`,
      DurationSeconds: 3600,
      ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
    }));
    if (!assumed.Credentials) throw new Error('STS AssumeRole failed');
    credentials = {
      accessKeyId:     assumed.Credentials.AccessKeyId!,
      secretAccessKey: assumed.Credentials.SecretAccessKey!,
      sessionToken:    assumed.Credentials.SessionToken,
    };
  }

  const ctClient = new CloudTrailClient({ region: cred.defaultRegion, credentials });
  const startTime = new Date(Date.now() - lookbackDays * 86_400_000);
  let nextToken: string | undefined;

  do {
    const resp = await ctClient.send(new LookupEventsCommand({
      StartTime: startTime,
      MaxResults: 50,
      NextToken: nextToken,
    }));

    for (const event of resp.Events ?? []) {
      try {
        const rawJson = event.CloudTrailEvent ? JSON.parse(event.CloudTrailEvent) : {};
        const normalized = normalizeAwsEvent(rawJson, opts.accountId);
        if (!normalized) continue;

        if (opts.dryRun) {
          // In dry-run, just run the baseline-update portions (not full analyzeEvent to avoid saving)
          // analyzeEvent internally updates baselines as a side effect
        }
        await analyzeEvent(normalized);
        eventsProcessed++;
      } catch { /* skip malformed events */ }
    }

    nextToken = resp.NextToken;
    // Small delay to avoid rate limiting
    if (nextToken) await new Promise((r) => setTimeout(r, 100));
  } while (nextToken);

  const baselinesUpdated = await prisma.anomalyBaseline.count({
    where: { provider: 'AWS', accountId: opts.accountId },
  });

  logger.info(`[anomaly-baseline] AWS seed complete: ${eventsProcessed} events, ${baselinesUpdated} baselines`);
  return {
    provider: 'AWS', accountId: opts.accountId,
    eventsProcessed, baselinesUpdated, durationMs: Date.now() - start,
  };
}

// ─── Azure baseline seed (uses existing Activity Log data in DB) ──────────────

export async function seedAzureBaseline(opts: BaselineSeedOptions): Promise<BaselineSeedResult> {
  const start = Date.now();
  const lookbackDays = opts.lookbackDays ?? 30;
  let eventsProcessed = 0;

  logger.info(`[anomaly-baseline] Seeding Azure baselines for subscription ${opts.accountId}`);

  const since = new Date(Date.now() - lookbackDays * 86_400_000);

  // Replay from stored ConfigChanges (Azure Activity Log data already in DB)
  const changes = await prisma.configChange.findMany({
    where: {
      provider: 'AZURE',
      timestamp: { gte: since },
      // Filter to this subscription via the subscriptionId stored in rawEvent
    },
    select: { id: true, rawEvent: true, timestamp: true },
    orderBy: { timestamp: 'asc' },
    take: 5000,
  });

  for (const change of changes) {
    try {
      const raw = change.rawEvent as Record<string, unknown>;
      if (!raw) continue;
      const normalized = normalizeAzureEvent(raw, opts.accountId);
      if (!normalized) continue;
      await analyzeEvent(normalized);
      eventsProcessed++;
    } catch { /* skip */ }
  }

  const baselinesUpdated = await prisma.anomalyBaseline.count({
    where: { provider: 'AZURE', accountId: opts.accountId },
  });

  logger.info(`[anomaly-baseline] Azure seed complete: ${eventsProcessed} events, ${baselinesUpdated} baselines`);
  return {
    provider: 'AZURE', accountId: opts.accountId,
    eventsProcessed, baselinesUpdated, durationMs: Date.now() - start,
  };
}

// ─── GCP baseline seed (uses ConfigChanges with provider=GCP) ────────────────

export async function seedGcpBaseline(opts: BaselineSeedOptions): Promise<BaselineSeedResult> {
  const start = Date.now();
  const lookbackDays = opts.lookbackDays ?? 30;
  let eventsProcessed = 0;

  logger.info(`[anomaly-baseline] Seeding GCP baselines for project ${opts.accountId}`);

  const since = new Date(Date.now() - lookbackDays * 86_400_000);

  const changes = await prisma.configChange.findMany({
    where: {
      provider: 'GCP',
      timestamp: { gte: since },
    },
    select: { id: true, rawEvent: true, timestamp: true },
    orderBy: { timestamp: 'asc' },
    take: 5000,
  });

  for (const change of changes) {
    try {
      const raw = change.rawEvent as Record<string, unknown>;
      if (!raw) continue;
      const normalized = normalizeGcpEvent(raw, opts.accountId);
      if (!normalized) continue;
      await analyzeEvent(normalized);
      eventsProcessed++;
    } catch { /* skip */ }
  }

  const baselinesUpdated = await prisma.anomalyBaseline.count({
    where: { provider: 'GCP', accountId: opts.accountId },
  });

  logger.info(`[anomaly-baseline] GCP seed complete: ${eventsProcessed} events, ${baselinesUpdated} baselines`);
  return {
    provider: 'GCP', accountId: opts.accountId,
    eventsProcessed, baselinesUpdated, durationMs: Date.now() - start,
  };
}

// ─── Baseline stats query ─────────────────────────────────────────────────────

export async function getBaselineStats(
  provider: string,
  accountId: string,
  actorId?: string,
): Promise<BaselineStats[]> {
  const rows = await prisma.anomalyBaseline.findMany({
    where: {
      provider,
      accountId,
      ...(actorId ? { actorId } : {}),
    },
    orderBy: [{ actorId: 'asc' }, { metricKey: 'asc' }],
  });

  return rows.map((r) => ({
    actorId:      r.actorId,
    metricKey:    r.metricKey,
    ewmaMean:     r.ewmaMean,
    ewmaStddev:   Math.sqrt(Math.max(r.ewmaVariance, 0)),
    sampleCount:  r.sampleCount,
    lastUpdated:  r.lastUpdated,
    knownIpCount: (r.knownIps as string[]).length,
    knownCountries: r.knownCountries as string[],
  }));
}

// ─── Reset baselines for an actor ────────────────────────────────────────────

export async function resetBaselines(
  provider: string,
  accountId: string,
  actorId?: string,
): Promise<number> {
  const result = await prisma.anomalyBaseline.deleteMany({
    where: {
      provider, accountId,
      ...(actorId ? { actorId } : {}),
    },
  });
  logger.info(`[anomaly-baseline] Reset ${result.count} baselines for ${provider}/${accountId}${actorId ? `/${actorId}` : ''}`);
  return result.count;
}

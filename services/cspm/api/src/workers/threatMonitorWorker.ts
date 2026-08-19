/**
 * Threat Monitor Worker
 *
 * BullMQ worker that processes repeatable 'monitor-account' jobs.
 * Each job polls CloudTrail for new threat indicators since the last check,
 * saves new findings to the DB, and emits real-time Socket.IO events.
 *
 * Job interval: every 2 minutes per account (configured in threatMonitorService)
 */

import { Worker, Job } from 'bullmq';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { redis } from '../config/redis';
import { prisma } from '../config/database';
import { logger } from '../config/logger';
import * as credentialService from '../services/credentialService';
import {
  THREAT_QUEUE,
  getLastCheck,
  setLastCheck,
  markEventSeen,
} from '../services/threatMonitorService';
import { getIO } from '../socket/index';
import { analyzeEvent, normalizeAwsEvent } from '../services/anomalyEngine';
import AWSClient from '../../../src/aws/client';
import { ThreatDetectionScanner } from '../../../src/scanners/threatdetection';

interface MonitorJobData {
  accountId: string;
}

function resourceFingerprint(evidence: unknown): string {
  const e = (evidence ?? {}) as Record<string, unknown>;
  if (e.resourceId != null) return String(e.resourceId);
  for (const key of ['functionName', 'trailName', 'bucket', 'username', 'accessKeyId', 'keyId', 'dbId', 'clusterId', 'secretName', 'sgId', 'instanceId', 'resourceName', 'arn', 'name', 'id']) {
    if (e[key] != null) return String(e[key]);
  }
  return 'account-level';
}

async function processMonitorJob(job: Job<MonitorJobData>): Promise<void> {
  const { accountId } = job.data;

  try {
    // ── 1. Load credentials ─────────────────────────────────────────────────
    const cred = await prisma.awsCredential.findUnique({ where: { accountId } });
    if (!cred) {
      logger.warn(`Threat monitor: no credentials for account ${accountId}`);
      return;
    }

    const decrypted = credentialService.decryptCredentials(cred);
    let explicitCredentials = {
      accessKeyId:     decrypted.accessKeyId!,
      secretAccessKey: decrypted.secretAccessKey!,
      sessionToken:    undefined as string | undefined,
      region:          cred.defaultRegion,
    };

    if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
      const stsClient = new STSClient({
        region: cred.defaultRegion,
        credentials: {
          accessKeyId:     decrypted.accessKeyId!,
          secretAccessKey: decrypted.secretAccessKey!,
        },
      });
      const assumed = await stsClient.send(new AssumeRoleCommand({
        RoleArn: cred.roleArn,
        RoleSessionName: `threat-monitor-${accountId.slice(0, 16)}`,
        DurationSeconds: 900,
        ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
      }));
      if (!assumed.Credentials) throw new Error('STS AssumeRole returned no credentials');
      explicitCredentials = {
        accessKeyId:     assumed.Credentials.AccessKeyId!,
        secretAccessKey: assumed.Credentials.SecretAccessKey!,
        sessionToken:    assumed.Credentials.SessionToken,
        region:          cred.defaultRegion,
      };
    }

    // ── 2. Get time window ──────────────────────────────────────────────────
    const since    = await getLastCheck(accountId);
    const checkEnd = new Date();

    logger.debug(`Threat monitor [${accountId}]: checking ${since.toISOString()} → ${checkEnd.toISOString()}`);

    // ── 3. Run incremental threat scan ──────────────────────────────────────
    const awsClient = new AWSClient(cred.defaultRegion, undefined, explicitCredentials);
    let findings: Array<any> = [];

    try {
      const scanner = new ThreatDetectionScanner(awsClient);
      findings = await scanner.scanSince(since);
    } finally {
      await awsClient.cleanup();
    }

    // ── 3b. Run ML anomaly detection on all raw events ──────────────────────
    try {
      const scanner = new ThreatDetectionScanner(awsClient);
      const rawEvents = await (scanner as any).getRawEvents?.(since) ?? [];
      for (const rawEvent of rawEvents) {
        const normalized = normalizeAwsEvent(rawEvent, accountId);
        if (normalized) await analyzeEvent(normalized);
      }
    } catch (anomalyErr) {
      logger.debug(`Anomaly scan skipped: ${(anomalyErr as Error).message}`);
    }

    // ── 4. Deduplicate & save new findings ──────────────────────────────────
    const newFindings: typeof findings = [];

    for (const finding of findings) {
      const eventId = finding._eventId;

      // Use eventId-based dedup first (exact CloudTrail event)
      if (eventId) {
        const isNew = await markEventSeen(accountId, eventId);
        if (!isNew) continue;
      }

      // Also check DB-level fingerprint dedup (same pattern as scanWorker)
      const fingerprint = `${finding.service}:${finding.title}:${resourceFingerprint(finding.evidence)}`;
      const existing = await prisma.finding.findFirst({
        where: {
          scan: { accountId },
          findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
          service: finding.service,
          title:   finding.title,
        },
        select: { id: true, evidence: true },
      });

      if (existing) {
        const existingFp = `${finding.service}:${finding.title}:${resourceFingerprint(existing.evidence)}`;
        if (existingFp === fingerprint) continue;
      }

      newFindings.push(finding);
    }

    if (newFindings.length === 0) {
      emitHeartbeat(accountId, checkEnd, 0);
      await setLastCheck(accountId, checkEnd);
      return;
    }

    // ── 5. Get or create a "monitoring scan" record for this account ─────────
    let monitorScan = await prisma.scan.findFirst({
      where: { accountId, status: 'MONITORING' },
      orderBy: { createdAt: 'desc' },
    });

    if (!monitorScan) {
      monitorScan = await prisma.scan.create({
        data: {
          accountId,
          status:    'MONITORING',
          triggeredBy: 'system',
          services:  ['threatdetection'],
          regions:   [cred.defaultRegion],
        },
      });
    }

    // ── 6. Persist findings ──────────────────────────────────────────────────
    const created = await prisma.finding.createMany({
      data: newFindings.map(f => ({
        scanId:        monitorScan!.id,
        service:       f.service,
        severity:      f.severity,
        title:         f.title,
        description:   f.description,
        evidence:      f.evidence ?? {},
        remediation:   f.remediation,
        findingStatus: 'OPEN' as const,
        tags:          f.tags ?? [],
        discoveredAt:  f.timestamp ?? new Date(),
      })),
    });

    logger.info(`Threat monitor [${accountId}]: ${created.count} new threat(s) detected`);

    // ── 7. Emit real-time Socket.IO events ───────────────────────────────────
    try {
      const io = getIO();

      for (const f of newFindings) {
        io.to(`threats:${accountId}`).emit('threat:detected', {
          accountId,
          finding: {
            title:          f.title,
            severity:       f.severity,
            description:    f.description,
            threatCategory: f.evidence?.threatCategory,
            actor:          f.evidence?.actor,
            sourceIP:       f.evidence?.sourceIP,
            eventTime:      f.evidence?.eventTime,
            affectedResource: f.evidence?.affectedResource,
          },
          detectedAt: new Date().toISOString(),
        });
      }

      io.to('threats:all').emit('threat:detected', {
        accountId,
        count: newFindings.length,
        highestSeverity: newFindings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
          : newFindings.some(f => f.severity === 'HIGH') ? 'HIGH' : 'MEDIUM',
        detectedAt: new Date().toISOString(),
      });

      emitHeartbeat(accountId, checkEnd, created.count);
    } catch (socketErr) {
      logger.warn('Could not emit threat Socket.IO events', { error: (socketErr as Error).message });
    }

    // ── 8. Update lastCheck ──────────────────────────────────────────────────
    await setLastCheck(accountId, checkEnd);

  } catch (err) {
    logger.error(`Threat monitor job failed for account ${accountId}`, { error: (err as Error).message });
    // Don't throw — repeatable jobs should keep running even if one check fails
  }
}

function emitHeartbeat(accountId: string, checkedAt: Date, newThreats: number): void {
  try {
    const io = getIO();
    io.to(`threats:${accountId}`).emit('threat:heartbeat', {
      accountId,
      checkedAt: checkedAt.toISOString(),
      newThreats,
    });
    io.to('threats:all').emit('threat:heartbeat', {
      accountId,
      checkedAt: checkedAt.toISOString(),
      newThreats,
    });
  } catch { /* socket not ready */ }
}

export function createThreatMonitorWorker(): Worker {
  const worker = new Worker<MonitorJobData>(
    THREAT_QUEUE,
    processMonitorJob,
    {
      connection: redis,
      concurrency: 3, // run up to 3 account checks simultaneously
    },
  );

  worker.on('completed', (job) => {
    logger.debug(`Threat monitor job completed: ${job.data.accountId}`);
  });

  worker.on('failed', (job, err) => {
    logger.error(`Threat monitor job failed: ${job?.data.accountId}`, { error: err.message });
  });

  return worker;
}

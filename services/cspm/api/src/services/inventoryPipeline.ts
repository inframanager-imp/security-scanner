/**
 * Inventory Pipeline
 *
 * Manages the full lifecycle from "account added" → "real-time monitoring active".
 *
 * Pipeline phases (run sequentially in background):
 *   Phase 1 — INITIALIZING: Full resource discovery (captures all current configs)
 *   Phase 2 — Sync config changes (last 7 days on first run to backfill history)
 *   Phase 3 — Reconcile (apply any deletion events to inventory)
 *   Phase 4 — READY: Real-time monitoring begins
 *
 * After READY, periodic sync runs every 30 minutes automatically.
 *
 * Enrichment: during every config sync, each change event is enriched with
 * the REAL previousValue from inventory.configState, so before/after diffs
 * are accurate even when CloudTrail/Activity Logs don't include old state.
 */

import { prisma } from '../config/database';
import { logger } from '../config/logger';
import {
  discoverAwsResources,
  discoverAzureResources,
  discoverGcpResources,
} from './resourceDiscoveryService';
import { syncInventoryFromChange } from './inventorySync';
import { runDriftForTarget }       from './baselineService';
import {
  classifyAwsEvent,
  classifyAzureEvent,
  classifyGcpEvent,
  isAzureNoiseEvent,
} from './configChangeClassifier';
import { fetchAwsResourceState, type AwsFetchContext } from './awsResourceFetch';
import { fetchGcpResourceState }   from './gcpResourceFetch';
import { decryptAzureCredentials } from './azureCredentialService';
import { decryptGcpCredentials }   from './gcpCredentialService';
import * as credentialService        from './credentialService';
import { isInFreezeWindow }          from './freezeWindowService';
import { dispatchAlerts }            from './alertService';
import { dispatchIntegrations }      from './integrationService';
import { analyzeForEscalation }      from './iamEscalationService';
import { fetchAzureResourceState }   from './azureArmFetch';
import { startMonitoring }           from './threatMonitorService';
import { startAzureMonitoring }      from './azureThreatMonitorService';
import { startConfigSync }           from './configSyncMonitorService';
import { Severity, ChangeCategory, Prisma } from '@prisma/client';
import {
  CloudTrailClient,
  LookupEventsCommand,
  LookupAttributeKey,
} from '@aws-sdk/client-cloudtrail';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import AzureClient from '../../../src/azure/client';
import GcpClient   from '../../../src/gcp/client';

// ─── Internal CloudTrail client (same as configChanges route) ─────────────────

type RawAwsCredentials = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

async function getAwsCredentials(accountId: string, region: string): Promise<RawAwsCredentials> {
  const cred = await prisma.awsCredential.findUnique({ where: { accountId } });
  if (!cred) throw new Error('No credentials for account');
  const dec = credentialService.decryptCredentials(cred);
  if (!dec.accessKeyId || !dec.secretAccessKey) throw new Error('Missing credentials');

  let credentials: RawAwsCredentials = {
    accessKeyId:     dec.accessKeyId,
    secretAccessKey: dec.secretAccessKey,
  };

  if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
    const sts = new STSClient({ region, credentials });
    const assumed = await sts.send(new AssumeRoleCommand({
      RoleArn: cred.roleArn, RoleSessionName: 'pipeline-sync',
      DurationSeconds: 900,
      ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
    }));
    if (!assumed.Credentials) throw new Error('STS AssumeRole failed');
    credentials = {
      accessKeyId:     assumed.Credentials.AccessKeyId!,
      secretAccessKey: assumed.Credentials.SecretAccessKey!,
      sessionToken:    assumed.Credentials.SessionToken,
    };
  }
  return credentials;
}

async function getCtClient(accountId: string, region: string): Promise<CloudTrailClient> {
  const credentials = await getAwsCredentials(accountId, region);
  return new CloudTrailClient({ region, credentials });
}

// ─── Inventory enrichment ─────────────────────────────────────────────────────

async function fetchInventoryConfig(
  provider: string,
  targetId:  string,
  resourceId: string | null,
  resourceName: string | null,
): Promise<Record<string, unknown> | null> {
  if (!resourceId && !resourceName) return null;

  const orConditions: Prisma.ResourceInventoryWhereInput[] = [];
  if (resourceId) {
    orConditions.push({ nativeId: { contains: resourceId, mode: 'insensitive' } });
  }
  if (resourceName) {
    orConditions.push({ resourceName: { equals: resourceName, mode: 'insensitive' } });
  }

  const where: Prisma.ResourceInventoryWhereInput = {
    provider,
    OR: orConditions,
  };
  if (provider === 'AWS')   where.awsAccountId  = targetId;
  if (provider === 'AZURE') where.azureSubId    = targetId;
  if (provider === 'GCP')   where.gcpProjectId  = targetId;

  const resource = await prisma.resourceInventory.findFirst({ where, select: { configState: true } });
  return resource ? resource.configState as Record<string, unknown> : null;
}

// ─── Config sync (shared logic, called both on-demand and from pipeline) ───────

export async function syncConfigChanges(
  provider: string,
  targetId: string,
  windowHours = 24,
): Promise<{ eventsFound: number; changesStored: number }> {
  const windowEnd   = new Date();
  const windowStart = new Date(windowEnd.getTime() - Math.min(windowHours, 720) * 60 * 60 * 1000);

  let eventsFound = 0;
  let changesStored = 0;

  // Cache freeze window once per sync run — not per event (avoids N DB queries)
  const frozenCache = new Map<string, boolean>();
  async function isFrozen(prov: string, tgt: string): Promise<boolean> {
    const key = `${prov}:${tgt}`;
    if (!frozenCache.has(key)) frozenCache.set(key, await isInFreezeWindow(prov, tgt));
    return frozenCache.get(key)!;
  }

  if (provider === 'AWS') {
    const account = await prisma.account.findUnique({ where: { id: targetId } });
    if (!account) throw new Error('Account not found');

    const cred      = await prisma.awsCredential.findUnique({ where: { accountId: targetId } });
    const region    = cred?.defaultRegion ?? 'us-east-1';
    const rawCreds  = await getAwsCredentials(targetId, region);
    const fetchCtx: AwsFetchContext = { credentials: rawCreds, region };
    const client    = new CloudTrailClient({ region, credentials: rawCreds });

    let nextToken: string | undefined;
    let page = 0;
    do {
      const resp = await client.send(new LookupEventsCommand({
        StartTime: windowStart,
        EndTime:   windowEnd,
        MaxResults: 50,
        NextToken:  nextToken,
        LookupAttributes: [{ AttributeKey: LookupAttributeKey.READ_ONLY, AttributeValue: 'false' }],
      }));
      nextToken = resp.NextToken;

      for (const e of resp.Events ?? []) {
        eventsFound++;
        const eventId = e.EventId ?? `${e.EventName}-${e.EventTime?.toISOString()}`;
        const parsed  = JSON.parse(e.CloudTrailEvent ?? '{}') as Record<string, unknown>;

        const classified = classifyAwsEvent({
          eventName:         e.EventName ?? null,
          requestParameters: (parsed.requestParameters as Record<string, unknown>) ?? null,
          responseElements:  (parsed.responseElements  as Record<string, unknown>) ?? null,
          userIdentity:      (parsed.userIdentity      as Record<string, unknown>) ?? null,
          sourceIPAddress:   (parsed.sourceIPAddress   as string) ?? null,
          awsRegion:         (parsed.awsRegion         as string) ?? region,
          resources:         (e.Resources ?? []).map(r => ({ type: r.ResourceType, name: r.ResourceName })),
        });

        // ── previousValue: real config from inventory snapshot before this event ──
        const inventoryPrev = await fetchInventoryConfig('AWS', targetId, classified.resourceId, classified.resourceName);
        const previousValue = inventoryPrev ?? classified.previousValue ?? undefined;

        // ── newValue: fetch actual resource state from AWS API (post-change snapshot) ──
        const liveNewValue = await fetchAwsResourceState(
          fetchCtx,
          classified.resourceType,
          classified.resourceId,
          e.EventName ?? '',
          parsed.requestParameters as Record<string, unknown> ?? {},
        ).catch(() => null);
        const newValue = liveNewValue ?? classified.newValue ?? undefined;

        // ── Freeze window check (cached) ──
        const frozen = await isFrozen('AWS', targetId);

        const saved = await prisma.configChange.upsert({
          where:  { sourceEventId_provider: { sourceEventId: eventId, provider: 'AWS' } },
          update: {},
          create: {
            provider:        'AWS',
            awsAccountId:    targetId,
            sourceEventId:   eventId,
            eventName:       e.EventName ?? 'Unknown',
            eventTime:       e.EventTime ?? new Date(),
            changeAction:    classified.changeAction,
            category:        classified.category as ChangeCategory,
            riskScore:       classified.riskScore,
            severity:        classified.severity as Severity,
            summary:         classified.summary,
            actor:           classified.actor,
            actorType:       classified.actorType,
            sourceIp:        classified.sourceIp,
            resourceType:    classified.resourceType,
            resourceId:      classified.resourceId,
            resourceName:    classified.resourceName,
            previousValue:   previousValue as Prisma.InputJsonValue | undefined,
            newValue:        newValue as Prisma.InputJsonValue | undefined,
            freezeViolation: frozen,
          },
        });

        // Only count + alert if this was a newly created record
        const isNew = Date.now() - saved.createdAt.getTime() < 10_000;
        if (isNew) {
          changesStored++;
          void dispatchAlerts(saved);        // fire-and-forget
          void dispatchIntegrations(saved);  // webhook / ServiceNow / Jira
          void analyzeForEscalation(saved);  // IAM privilege escalation

          // ── Sync change to inventory (deletion or modification) ──
          await syncInventoryFromChange({
            provider:     'AWS', targetId,
            eventName:    e.EventName ?? '',
            resourceId:   classified.resourceId,
            resourceName: classified.resourceName,
            resourceType: classified.resourceType,
            newValue:     classified.newValue as Record<string, unknown> | null ?? null,
            eventTime:    e.EventTime ?? new Date(),
          });
        }
      }
      page++;
    } while (nextToken && page < 20);

    await client.destroy();

  } else if (provider === 'AZURE') {
    const sub  = await prisma.azureSubscription.findUnique({ where: { id: targetId } });
    if (!sub) throw new Error('Azure subscription not found');
    const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId: targetId } });
    if (!cred) throw new Error('No Azure credentials');

    const dec   = decryptAzureCredentials(cred);
    const azure = new AzureClient({
      subscriptionId: sub.subscriptionId,
      tenantId:       dec.tenantId,
      clientId:       dec.clientId,
      clientSecret:   dec.clientSecret,
      authMethod:     cred.authMethod as 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY',
    });

    const monitor = azure.monitor();
    const filter  = [
      `eventTimestamp ge '${windowStart.toISOString()}'`,
      `eventTimestamp le '${windowEnd.toISOString()}'`,
    ].join(' and ');

    for await (const event of monitor.activityLogs.list(filter)) {
      eventsFound++;
      const op = (event.operationName?.value ?? '').toLowerCase();
      if (!op.endsWith('/write') && !op.endsWith('/delete') && !op.endsWith('/action')) continue;
      if (isAzureNoiseEvent(event.operationName?.value ?? '')) continue;

      const eventId    = event.eventDataId ?? `${op}-${event.eventTimestamp?.toISOString()}`;
      const classified = classifyAzureEvent({
        eventDataId:       eventId,
        operationName:     event.operationName?.value ?? null,
        caller:            event.caller ?? null,
        resourceGroupName: event.resourceGroupName ?? null,
        resourceId:        event.resourceId ?? null,
        level:             event.level ?? null,
        status:            event.status?.value ?? null,
        properties:        (event.properties as Record<string, unknown>) ?? null,
        description:       event.description ?? null,
      });

      // ── previousValue: inventory snapshot before this event ──
      const eventResourceId = event.resourceId ?? classified.resourceId;
      const inventoryPrev   = await fetchInventoryConfig('AZURE', targetId, eventResourceId, classified.resourceName);
      const previousValue   = inventoryPrev ?? classified.previousValue ?? undefined;

      // ── newValue: fetch real ARM resource state (full post-change config) ──
      const opLower = (event.operationName?.value ?? '').toLowerCase();
      const isWrite = opLower.endsWith('/write') || opLower.endsWith('/action');
      const isDelete = opLower.endsWith('/delete');

      let armState: Record<string, unknown> | null = null;
      if ((isWrite || isDelete) && eventResourceId) {
        armState = await fetchAzureResourceState(azure.credential, eventResourceId).catch(() => null);
      }
      const azureNewValue = armState ?? (classified.newValue as Record<string, unknown> | null) ?? undefined;

      // ── Freeze window check (cached) ──
      const frozen = await isFrozen('AZURE', targetId);

      const saved = await prisma.configChange.upsert({
        where:  { sourceEventId_provider: { sourceEventId: eventId, provider: 'AZURE' } },
        // Update newValue if the record exists but was stored without ARM state
        update: {
          newValue: azureNewValue as Prisma.InputJsonValue | undefined ?? Prisma.JsonNull,
        },
        create: {
          provider:       'AZURE',
          azureSubId:     targetId,
          sourceEventId:  eventId,
          eventName:      event.operationName?.value ?? 'Unknown',
          eventTime:      event.eventTimestamp ?? new Date(),
          changeAction:   classified.changeAction,
          category:       classified.category as ChangeCategory,
          riskScore:      classified.riskScore,
          severity:       classified.severity as Severity,
          summary:        classified.summary,
          actor:          classified.actor,
          actorType:      classified.actorType,
          sourceIp:       classified.sourceIp,
          resourceType:   classified.resourceType,
          resourceId:     classified.resourceId,
          resourceName:   classified.resourceName,
          previousValue:  previousValue as Prisma.InputJsonValue | undefined,
          newValue:       azureNewValue as Prisma.InputJsonValue | undefined,
          freezeViolation: frozen,
        },
      });

      // Only count + alert if this was a newly created record
      const isNew = Date.now() - saved.createdAt.getTime() < 10_000;
      if (isNew) {
        changesStored++;
        void dispatchAlerts(saved);        // fire-and-forget
        void dispatchIntegrations(saved);  // webhook / ServiceNow / Jira
        void analyzeForEscalation(saved);  // IAM privilege escalation

        // Sync inventory with ARM state (already fetched above — no extra network call)
        await syncInventoryFromChange({
          provider:     'AZURE', targetId,
          eventName:    event.operationName?.value ?? '',
          resourceId:   eventResourceId,
          resourceName: classified.resourceName,
          resourceType: classified.resourceType,
          newValue:     armState ?? (classified.newValue as Record<string, unknown> | null) ?? null,
          eventTime:    event.eventTimestamp ?? new Date(),
        });
      }

      if (eventsFound >= 2000) break;
    }

  } else if (provider === 'GCP') {
    const project = await prisma.gcpProject.findUnique({ where: { id: targetId } });
    if (!project) throw new Error('GCP project not found');
    const cred = await prisma.gcpCredential.findUnique({ where: { projectId: targetId } });
    if (!cred) throw new Error('No GCP credentials');

    const dec = decryptGcpCredentials(cred);
    const gcpClient = new GcpClient({
      projectId:   project.projectId,
      credentials: dec.serviceAccountKey ? JSON.parse(dec.serviceAccountKey) as Record<string, unknown> : undefined,
      authMethod:  cred.authMethod as 'SERVICE_ACCOUNT_KEY' | 'WORKLOAD_IDENTITY',
    });

    const logging = gcpClient.logging();
    const filter  = [
      `logName="projects/${project.projectId}/logs/cloudaudit.googleapis.com%2Factivity"`,
      `timestamp>="${windowStart.toISOString()}"`,
      `timestamp<="${windowEnd.toISOString()}"`,
    ].join('\n');

    const logResp = await logging.entries.list({
      requestBody: { filter, pageSize: 500, resourceNames: [`projects/${project.projectId}`] },
    });
    const entries = logResp.data.entries ?? [];
    for (const entry of entries) {
      eventsFound++;
      const payload   = ((entry.protoPayload as Record<string, unknown>) ?? (entry.jsonPayload as Record<string, unknown>) ?? {}) as Record<string, unknown>;
      const insertId  = entry.insertId ?? `gcp-${Date.now()}-${eventsFound}`;
      const ts        = entry.timestamp;
      const eventTime = ts ? new Date(ts as string) : new Date();

      const classified    = classifyGcpEvent(payload);
      const inventoryPrev = await fetchInventoryConfig('GCP', targetId, classified.resourceId, classified.resourceName);
      const previousValue = inventoryPrev ?? classified.previousValue ?? undefined;

      // ── newValue: fetch actual resource state from GCP API (post-change snapshot) ──
      const liveGcpState = await fetchGcpResourceState(
        gcpClient,
        (payload.methodName as string) ?? '',
        classified.resourceId,
        project.projectId,
      ).catch(() => null);
      const gcpNewValue = liveGcpState ?? classified.newValue ?? undefined;

      // ── Freeze window check ──
      const frozen = await isFrozen('GCP', targetId);

      const saved = await prisma.configChange.upsert({
        where:  { sourceEventId_provider: { sourceEventId: insertId, provider: 'GCP' } },
        update: {},
        create: {
          provider:       'GCP',
          gcpProjectId:   targetId,
          sourceEventId:  insertId,
          eventName:      (payload.methodName as string) ?? 'Unknown',
          eventTime,
          changeAction:   classified.changeAction,
          category:       classified.category as ChangeCategory,
          riskScore:      classified.riskScore,
          severity:       classified.severity as Severity,
          summary:        classified.summary,
          actor:          classified.actor,
          actorType:      classified.actorType,
          sourceIp:       classified.sourceIp,
          resourceType:   classified.resourceType,
          resourceId:     classified.resourceId,
          resourceName:   classified.resourceName,
          previousValue:  previousValue as Prisma.InputJsonValue | undefined,
          newValue:       gcpNewValue as Prisma.InputJsonValue | undefined,
          freezeViolation: frozen,
        },
      });

      // Only count + alert if this was a newly created record
      const isNew = Date.now() - saved.createdAt.getTime() < 10_000;
      if (isNew) {
        changesStored++;
        void dispatchAlerts(saved);        // fire-and-forget
        void dispatchIntegrations(saved);  // webhook / ServiceNow / Jira
        void analyzeForEscalation(saved);  // IAM privilege escalation

        await syncInventoryFromChange({
          provider:     'GCP', targetId,
          eventName:    (payload.methodName as string) ?? '',
          resourceId:   classified.resourceId,
          resourceName: classified.resourceName,
          resourceType: classified.resourceType,
          newValue:     classified.newValue as Record<string, unknown> | null ?? null,
          eventTime,
        });
      }
    }
  }

  return { eventsFound, changesStored };
}

// ─── Update pipeline timestamps ───────────────────────────────────────────────

export async function markSyncedReady(provider: string, targetId: string): Promise<void> {
  const now = new Date();
  let wasNotReady = false;

  if (provider === 'AWS') {
    const acct = await prisma.account.findUnique({ where: { id: targetId }, select: { inventoryStatus: true } });
    if (acct && acct.inventoryStatus !== 'READY') {
      await prisma.account.update({ where: { id: targetId }, data: { inventoryStatus: 'READY', lastConfigSyncAt: now } });
      wasNotReady = true;
    }
  } else if (provider === 'AZURE') {
    const sub = await prisma.azureSubscription.findUnique({ where: { id: targetId }, select: { inventoryStatus: true } });
    if (sub && sub.inventoryStatus !== 'READY') {
      await prisma.azureSubscription.update({ where: { id: targetId }, data: { inventoryStatus: 'READY', lastConfigSyncAt: now } });
      wasNotReady = true;
    }
  } else if (provider === 'GCP') {
    const proj = await prisma.gcpProject.findUnique({ where: { id: targetId }, select: { inventoryStatus: true } });
    if (proj && proj.inventoryStatus !== 'READY') {
      await prisma.gcpProject.update({ where: { id: targetId }, data: { inventoryStatus: 'READY', lastConfigSyncAt: now } });
      wasNotReady = true;
    }
  }

  // Register BullMQ sync job if account was just promoted to READY
  if (wasNotReady) {
    await startConfigSync(provider, targetId).catch((e) =>
      logger.warn(`[config-sync] Failed to start job after markSyncedReady: ${(e as Error).message}`)
    );
  }
}

async function setStatus(
  provider: string,
  targetId: string,
  status: 'PENDING' | 'INITIALIZING' | 'READY' | 'FAILED',
  extra?: { pipelineError?: string; lastDiscoveryAt?: Date; lastConfigSyncAt?: Date; inventoryInitAt?: Date },
) {
  const data = { inventoryStatus: status, ...extra };

  if (provider === 'AWS') {
    await prisma.account.update({ where: { id: targetId }, data });
  } else if (provider === 'AZURE') {
    await prisma.azureSubscription.update({ where: { id: targetId }, data });
  } else if (provider === 'GCP') {
    await prisma.gcpProject.update({ where: { id: targetId }, data });
  }
}

// ─── Main pipeline orchestrator ───────────────────────────────────────────────

/**
 * Called when credentials are verified for a new account/subscription/project.
 * Runs fully in background — responds immediately.
 */
export function triggerInitialPipeline(provider: string, targetId: string): void {
  void (async () => {
    const tag = `[pipeline:${provider}:${targetId.slice(0, 8)}]`;
    logger.info(`${tag} Starting initial inventory pipeline`);

    try {
      // Phase 1: Mark as INITIALIZING
      await setStatus(provider, targetId, 'INITIALIZING', { pipelineError: undefined });

      // Phase 2: Full resource discovery
      logger.info(`${tag} Phase 1/3 — Resource discovery`);
      const now = new Date();

      if (provider === 'AWS') {
        await discoverAwsResources(targetId);
      } else if (provider === 'AZURE') {
        await discoverAzureResources(targetId);
      } else if (provider === 'GCP') {
        await discoverGcpResources(targetId);
      }

      await setStatus(provider, targetId, 'INITIALIZING', { lastDiscoveryAt: new Date() });
      logger.info(`${tag} Phase 1/3 — Discovery complete`);

      // Phase 3: Pull last 7 days of config changes (backfill)
      logger.info(`${tag} Phase 2/3 — Config change backfill (7 days)`);
      const { changesStored } = await syncConfigChanges(provider, targetId, 168);
      await setStatus(provider, targetId, 'INITIALIZING', { lastConfigSyncAt: new Date() });
      logger.info(`${tag} Phase 2/3 — Stored ${changesStored} config changes`);

      // Run drift detection against any existing baselines (non-fatal)
      void runDriftForTarget(provider, targetId);

      // Phase 4: READY
      logger.info(`${tag} Phase 3/3 — Pipeline READY`);
      await setStatus(provider, targetId, 'READY', {
        inventoryInitAt:  now,
        lastDiscoveryAt:  new Date(),
        lastConfigSyncAt: new Date(),
        pipelineError:    undefined,
      });

      // Auto-start near-real-time threat monitoring for this account (non-fatal)
      if (provider === 'AWS') {
        void startMonitoring(targetId).catch((e) =>
          logger.warn(`${tag} Failed to auto-start threat monitoring: ${(e as Error).message}`)
        );
      } else if (provider === 'AZURE') {
        void startAzureMonitoring(targetId).catch((e) =>
          logger.warn(`${tag} Failed to auto-start Azure threat monitoring: ${(e as Error).message}`)
        );
      }

      // Auto-start config change sync BullMQ job — survives restarts, no event gaps
      void startConfigSync(provider, targetId).catch((e) =>
        logger.warn(`${tag} Failed to auto-start config sync job: ${(e as Error).message}`)
      );

      logger.info(`${tag} Pipeline initialization complete`);

    } catch (err) {
      const msg = (err as Error).message;
      logger.error(`${tag} Pipeline failed: ${msg}`);
      await setStatus(provider, targetId, 'FAILED', { pipelineError: msg }).catch(() => {});
    }
  })();
}

// ─── Periodic sync for all READY accounts ────────────────────────────────────

/**
 * Called every 30 seconds by app.ts.
 * Runs an incremental config change sync (last 15 min) for every READY account.
 * Uses an overlap guard so a slow run is skipped rather than stacked.
 */
// Per-target sync guard — prevents concurrent syncs for the same account/sub/project
const _syncingTargets = new Set<string>();

export async function runPeriodicSync(): Promise<void> {
  const [awsAccounts, azureSubs, gcpProjects] = await Promise.all([
    prisma.account.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
    prisma.azureSubscription.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
    prisma.gcpProject.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
  ]);

  const targets = [
    ...awsAccounts.map(a => ({ provider: 'AWS',   targetId: a.id })),
    ...azureSubs.map(s  => ({ provider: 'AZURE',  targetId: s.id })),
    ...gcpProjects.map(p => ({ provider: 'GCP',   targetId: p.id })),
  ];

  if (targets.length === 0) return;

  // Run all accounts in parallel — each is independently guarded
  const results = await Promise.allSettled(
    targets.map(async ({ provider, targetId }) => {
      const lockKey = `${provider}:${targetId}`;

      // Skip this target if its previous sync is still running
      if (_syncingTargets.has(lockKey)) {
        logger.debug(`[realtime-sync] ${lockKey} — previous sync still running, skipping tick`);
        return;
      }
      _syncingTargets.add(lockKey);

      try {
        const now = new Date();
        const windowStart = new Date(now.getTime() - 15 * 60 * 1000); // last 15 min

        // Create a sync run record so the UI "Last synced" timestamp always stays current
        const run = await prisma.configSyncRun.create({
          data: { provider, targetId, windowStart, windowEnd: now, status: 'RUNNING', startedAt: now },
        });

        try {
          const { eventsFound, changesStored } = await syncConfigChanges(provider, targetId, 0.25);

          await prisma.configSyncRun.update({
            where: { id: run.id },
            data:  { status: 'COMPLETED', completedAt: new Date(), eventsFound, changesStored },
          });

          // Always update lastConfigSyncAt regardless of whether new changes were found
          await setStatus(provider, targetId, 'READY', { lastConfigSyncAt: new Date() });

          if (changesStored > 0) {
            logger.info(`[realtime-sync] ${provider}:${targetId.slice(0, 8)} — ${changesStored} new changes, triggering drift scan`);
          }
          void runDriftForTarget(provider, targetId);
        } catch (err) {
          await prisma.configSyncRun.update({
            where: { id: run.id },
            data:  { status: 'FAILED', completedAt: new Date(), errorMessage: (err as Error).message },
          }).catch(() => {});
          throw err;
        }
      } finally {
        _syncingTargets.delete(lockKey);
      }
    }),
  );

  const failed = results.filter((r) => r.status === 'rejected');
  if (failed.length > 0) {
    for (const r of failed) {
      logger.warn(`[realtime-sync] A target failed: ${(r as PromiseRejectedResult).reason}`);
    }
  }
}

// ─── Periodic full resource re-discovery ──────────────────────────────────────

/**
 * Runs a full resource discovery for every READY account/subscription/project
 * once per day — completely in background, no manual trigger needed.
 *
 * Why daily:
 *   - Config change sync (30s) tracks WHAT changed via API events
 *   - But resources created/deleted outside our monitored event window
 *     (e.g. during downtime, via console without CloudTrail, or by AWS internally)
 *     only get reconciled via a full re-discovery.
 *   - Daily discovery ensures ResourceInventory is always accurate and
 *     Baseline & Drift always compares against real current state.
 *
 * Per-target guard prevents concurrent discoveries for the same target.
 */
const _discoveringTargets = new Set<string>();

export async function runPeriodicDiscovery(): Promise<void> {
  const [awsAccounts, azureSubs, gcpProjects] = await Promise.all([
    prisma.account.findMany({
      where:  { inventoryStatus: 'READY' },
      select: { id: true, lastDiscoveryAt: true },
    }),
    prisma.azureSubscription.findMany({
      where:  { inventoryStatus: 'READY' },
      select: { id: true, lastDiscoveryAt: true },
    }),
    prisma.gcpProject.findMany({
      where:  { inventoryStatus: 'READY' },
      select: { id: true, lastDiscoveryAt: true },
    }),
  ]);

  const targets = [
    ...awsAccounts.map(a  => ({ provider: 'AWS',   targetId: a.id, lastDiscoveryAt: a.lastDiscoveryAt })),
    ...azureSubs.map(s    => ({ provider: 'AZURE',  targetId: s.id, lastDiscoveryAt: s.lastDiscoveryAt })),
    ...gcpProjects.map(p  => ({ provider: 'GCP',    targetId: p.id, lastDiscoveryAt: p.lastDiscoveryAt })),
  ];

  if (targets.length === 0) return;

  const DISCOVERY_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
  const now = new Date();

  await Promise.allSettled(
    targets.map(async ({ provider, targetId, lastDiscoveryAt }) => {
      // Skip if discovered less than 24 hours ago
      if (lastDiscoveryAt && now.getTime() - lastDiscoveryAt.getTime() < DISCOVERY_INTERVAL_MS) {
        return;
      }

      const lockKey = `discover:${provider}:${targetId}`;
      if (_discoveringTargets.has(lockKey)) {
        logger.debug(`[discovery] ${lockKey} — already running, skipping`);
        return;
      }
      _discoveringTargets.add(lockKey);

      try {
        logger.info(`[discovery] Starting periodic re-discovery for ${provider}:${targetId.slice(0, 8)}`);

        if (provider === 'AWS') {
          await discoverAwsResources(targetId);
        } else if (provider === 'AZURE') {
          await discoverAzureResources(targetId);
        } else if (provider === 'GCP') {
          await discoverGcpResources(targetId);
        }

        await setStatus(provider, targetId, 'READY', { lastDiscoveryAt: new Date() });

        // Immediately run drift after re-discovery so baselines reflect fresh state
        void runDriftForTarget(provider, targetId);

        logger.info(`[discovery] Completed re-discovery for ${provider}:${targetId.slice(0, 8)}`);
      } catch (err) {
        logger.error(`[discovery] Failed for ${provider}:${targetId.slice(0, 8)}: ${(err as Error).message}`);
      } finally {
        _discoveringTargets.delete(lockKey);
      }
    })
  );
}

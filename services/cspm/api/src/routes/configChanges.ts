/**
 * Config Changes API
 *
 * POST /api/config-changes/sync   — pull events from CloudTrail / Activity Logs / GCP Audit into DB
 * GET  /api/config-changes        — paginated list (filterable)
 * GET  /api/config-changes/stats  — summary stats for dashboard cards
 * GET  /api/config-changes/:id    — single change detail with rawEvent
 * PATCH /api/config-changes/:id/status   — acknowledge / resolve
 * POST  /api/config-changes/bulk-status  — bulk acknowledge
 * GET   /api/config-changes/export/csv   — CSV download
 * GET   /api/config-changes/runs         — list ingest runs for a target
 */
import { Router, Request, Response } from 'express';
import {
  CloudTrailClient,
  LookupEventsCommand,
  LookupAttributeKey,
} from '@aws-sdk/client-cloudtrail';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { prisma }     from '../config/database';
import { authenticate } from '../middleware/authenticate';
import * as credentialService from '../services/credentialService';
import { decryptAzureCredentials } from '../services/azureCredentialService';
import { fetchAzureResourceState } from '../services/azureArmFetch';
import { decryptGcpCredentials }   from '../services/gcpCredentialService';
import AzureClient from '../../../src/azure/client';
import GcpClient   from '../../../src/gcp/client';
import {
  classifyAwsEvent,
  classifyAzureEvent,
  classifyGcpEvent,
  isAzureNoiseEvent,
} from '../services/configChangeClassifier';
import { fetchAwsResourceState, type AwsFetchContext } from '../services/awsResourceFetch';
import { fetchGcpResourceState }   from '../services/gcpResourceFetch';
import { syncInventoryFromChange } from '../services/inventorySync';
import { markSyncedReady }         from '../services/inventoryPipeline';
import { Severity, ChangeCategory, Prisma } from '@prisma/client';

const router = Router();
router.use(authenticate);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreToSeverity(score: number): Severity {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

type RawCreds = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

async function getAwsCredentials(accountId: string, region: string): Promise<RawCreds> {
  const cred = await prisma.awsCredential.findUnique({ where: { accountId } });
  if (!cred) throw new Error('No credentials configured for this account');
  const dec = credentialService.decryptCredentials(cred);
  if (!dec.accessKeyId || !dec.secretAccessKey) throw new Error('Missing access key credentials');

  let credentials: RawCreds = { accessKeyId: dec.accessKeyId, secretAccessKey: dec.secretAccessKey };

  if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
    const sts    = new STSClient({ region, credentials });
    const assumed = await sts.send(new AssumeRoleCommand({
      RoleArn: cred.roleArn, RoleSessionName: 'config-changes',
      DurationSeconds: 900,
      ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
    }));
    if (!assumed.Credentials) throw new Error('STS AssumeRole returned no credentials');
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

// ─── Sync endpoint ────────────────────────────────────────────────────────────

/**
 * POST /api/config-changes/sync
 * Body: { provider: 'AWS'|'AZURE'|'GCP', targetId: string, windowHours?: number }
 * Pulls write events from the cloud provider and stores them as ConfigChange rows.
 */

/**
 * POST /api/config-changes/reconcile-inventory
 * Replays all stored deletion ConfigChanges for a target and marks matching
 * ResourceInventory records as DELETED. Useful to backfill existing data.
 */
router.post('/reconcile-inventory', async (req: Request, res: Response) => {
  const { provider, targetId } = req.body as { provider: string; targetId: string };
  if (!provider || !targetId) {
    res.status(400).json({ error: 'provider and targetId are required' });
    return;
  }

  // Find all stored changes that look like deletions
  const where: Record<string, unknown> = {};
  if (provider === 'AWS')   where.awsAccountId  = targetId;
  if (provider === 'AZURE') where.azureSubId    = targetId;
  if (provider === 'GCP')   where.gcpProjectId  = targetId;

  const changes = await prisma.configChange.findMany({
    where,
    select: { eventName: true, resourceId: true, resourceName: true, resourceType: true, newValue: true, eventTime: true },
    orderBy: { eventTime: 'asc' },
  });

  let reconciled = 0;
  for (const c of changes) {
    const before = await prisma.resourceInventory.count({
      where: {
        provider,
        state: 'DELETED',
        ...(provider === 'AWS'   ? { awsAccountId:  targetId } :
            provider === 'AZURE' ? { azureSubId:    targetId } :
                                   { gcpProjectId:  targetId }),
      },
    });

    await syncInventoryFromChange({
      provider,
      targetId,
      eventName:    c.eventName,
      resourceId:   c.resourceId,
      resourceName: c.resourceName,
      resourceType: c.resourceType,
      newValue:     c.newValue as Record<string, unknown> | null ?? null,
      eventTime:    c.eventTime,
    });

    const after = await prisma.resourceInventory.count({
      where: {
        provider,
        state: 'DELETED',
        ...(provider === 'AWS'   ? { awsAccountId:  targetId } :
            provider === 'AZURE' ? { azureSubId:    targetId } :
                                   { gcpProjectId:  targetId }),
      },
    });
    if (after > before) reconciled++;
  }

  res.json({ data: { message: `Reconciled ${reconciled} inventory records from ${changes.length} stored changes.`, reconciled } });
});

router.post('/sync', async (req: Request, res: Response) => {
  const { provider, targetId, windowHours = 24 } = req.body as {
    provider: string; targetId: string; windowHours?: number;
  };

  if (!provider || !targetId) {
    res.status(400).json({ error: 'provider and targetId are required' });
    return;
  }

  const windowEnd   = new Date();
  const windowStart = new Date(windowEnd.getTime() - Math.min(windowHours, 168) * 60 * 60 * 1000);

  // Create or find existing run for this window
  const run = await prisma.configSyncRun.create({
    data: { provider, targetId, windowStart, windowEnd, status: 'RUNNING', startedAt: new Date() },
  });

  // Kick off async ingest — respond immediately
  res.json({ data: { runId: run.id, status: 'RUNNING', windowStart, windowEnd } });

  // Background ingest
  void (async () => {
    let eventsFound = 0;
    let changesStored = 0;
    try {
      if (provider === 'AWS') {
        const account = await prisma.account.findUnique({ where: { id: targetId } });
        if (!account) throw new Error('AWS account not found');

        const cred     = await prisma.awsCredential.findUnique({ where: { accountId: targetId } });
        const region   = cred?.defaultRegion ?? 'us-east-1';
        const rawCreds = await getAwsCredentials(targetId, region);
        const fetchCtx: AwsFetchContext = { credentials: rawCreds, region };
        const client   = new CloudTrailClient({ region, credentials: rawCreds });

        let nextToken: string | undefined;
        let page = 0;
        do {
          const cmd = new LookupEventsCommand({
            StartTime: windowStart,
            EndTime:   windowEnd,
            MaxResults: 50,
            NextToken:  nextToken,
            LookupAttributes: [{ AttributeKey: LookupAttributeKey.READ_ONLY, AttributeValue: 'false' }],
          });
          const resp = await client.send(cmd);
          nextToken  = resp.NextToken;

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

            // Live post-change resource state (full config snapshot after the event)
            const liveState = await fetchAwsResourceState(
              fetchCtx,
              classified.resourceType,
              classified.resourceId,
              e.EventName ?? '',
              (parsed.requestParameters as Record<string, unknown>) ?? {},
            ).catch(() => null);
            const awsNewValue = liveState ?? classified.newValue ?? undefined;

            await prisma.configChange.upsert({
              where:  { sourceEventId_provider: { sourceEventId: eventId, provider: 'AWS' } },
              update: {},
              create: {
                provider:      'AWS',
                awsAccountId:  targetId,
                sourceEventId: eventId,
                eventName:     e.EventName ?? 'Unknown',
                eventTime:     e.EventTime ?? new Date(),
                changeAction:  classified.changeAction,
                category:      classified.category as ChangeCategory,
                riskScore:     classified.riskScore,
                severity:      classified.severity as Severity,
                summary:       classified.summary,
                actor:         classified.actor,
                actorType:     classified.actorType,
                sourceIp:      classified.sourceIp,
                resourceType:  classified.resourceType,
                resourceId:    classified.resourceId,
                resourceName:  classified.resourceName,
                previousValue: classified.previousValue as unknown as Prisma.InputJsonValue | undefined ?? undefined,
                newValue:      awsNewValue as unknown as Prisma.InputJsonValue | undefined,
              },
            });
            changesStored++;

            // Keep ResourceInventory in sync
            await syncInventoryFromChange({
              provider:     'AWS',
              targetId,
              eventName:    e.EventName ?? '',
              resourceId:   classified.resourceId,
              resourceName: classified.resourceName,
              resourceType: classified.resourceType,
              newValue:     classified.newValue as Record<string, unknown> | null ?? null,
              eventTime:    e.EventTime ?? new Date(),
            });
          }
          page++;
        } while (nextToken && page < 20);

        await client.destroy();

      } else if (provider === 'AZURE') {
        const sub  = await prisma.azureSubscription.findUnique({ where: { id: targetId } });
        if (!sub) throw new Error('Azure subscription not found');
        const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId: targetId } });
        if (!cred) throw new Error('No Azure credentials configured');

        const dec    = decryptAzureCredentials(cred);
        const azure  = new AzureClient({
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
          // Only care about write/delete operations — skip noise namespaces
          const op = (event.operationName?.value ?? '').toLowerCase();
          if (!op.endsWith('/write') && !op.endsWith('/delete') && !op.endsWith('/action')) continue;
          if (isAzureNoiseEvent(event.operationName?.value ?? '')) continue;

          const eventId = event.eventDataId ?? `${op}-${event.eventTimestamp?.toISOString()}`;

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

          // ── newValue: fetch real ARM state (full post-change resource config) ──
          // ARM GET covers ALL Azure resource types via a single generic REST call.
          // This is what enables exact parameter diffs for any Azure resource.
          const eventResourceId = event.resourceId ?? classified.resourceId;
          const isWrite  = op.endsWith('/write') || op.endsWith('/action');
          const isDelete = op.endsWith('/delete');
          let armState: Record<string, unknown> | null = null;
          if ((isWrite || isDelete) && eventResourceId) {
            armState = await fetchAzureResourceState(azure.credential, eventResourceId).catch(() => null);
          }
          const azureNewValue = armState ?? (classified.newValue as Record<string, unknown> | null) ?? undefined;

          await prisma.configChange.upsert({
            where:  { sourceEventId_provider: { sourceEventId: eventId, provider: 'AZURE' } },
            update: { newValue: azureNewValue as unknown as Prisma.InputJsonValue ?? Prisma.JsonNull },
            create: {
              provider:      'AZURE',
              azureSubId:    targetId,
              sourceEventId: eventId,
              eventName:     event.operationName?.value ?? 'Unknown',
              eventTime:     event.eventTimestamp ?? new Date(),
              changeAction:  classified.changeAction,
              category:      classified.category as ChangeCategory,
              riskScore:     classified.riskScore,
              severity:      classified.severity as Severity,
              summary:       classified.summary,
              actor:         classified.actor,
              actorType:     classified.actorType,
              sourceIp:      classified.sourceIp,
              resourceType:  classified.resourceType,
              resourceId:    classified.resourceId,
              resourceName:  classified.resourceName,
              previousValue: classified.previousValue as unknown as Prisma.InputJsonValue | undefined ?? undefined,
              newValue:      azureNewValue as unknown as Prisma.InputJsonValue | undefined,
            },
          });
          changesStored++;

          // Keep ResourceInventory in sync (ARM state already fetched — no extra call)
          await syncInventoryFromChange({
            provider:     'AZURE',
            targetId,
            eventName:    event.operationName?.value ?? '',
            resourceId:   eventResourceId,
            resourceName: classified.resourceName,
            resourceType: classified.resourceType,
            newValue:     armState ?? (classified.newValue as Record<string, unknown> | null) ?? null,
            eventTime:    event.eventTimestamp ?? new Date(),
          });

          if (eventsFound >= 1000) break;
        }

      } else if (provider === 'GCP') {
        const project = await prisma.gcpProject.findUnique({ where: { id: targetId } });
        if (!project) throw new Error('GCP project not found');
        const cred = await prisma.gcpCredential.findUnique({ where: { projectId: targetId } });
        if (!cred) throw new Error('No GCP credentials configured');

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
          const payload = ((entry.protoPayload as Record<string, unknown>) ?? (entry.jsonPayload as Record<string, unknown>) ?? {}) as Record<string, unknown>;
          const insertId = entry.insertId ?? `gcp-${Date.now()}-${eventsFound}`;
          const ts = entry.timestamp;
          const eventTime = ts ? new Date(ts as string) : new Date();

          const classified = classifyGcpEvent(payload);

          // Live post-change resource state from GCP API
          const liveGcpState = await fetchGcpResourceState(
            gcpClient,
            (payload.methodName as string) ?? '',
            classified.resourceId,
            project.projectId,
          ).catch(() => null);
          const gcpNewValue = liveGcpState ?? classified.newValue ?? undefined;

          await prisma.configChange.upsert({
            where:  { sourceEventId_provider: { sourceEventId: insertId, provider: 'GCP' } },
            update: {},
            create: {
              provider:      'GCP',
              gcpProjectId:  targetId,
              sourceEventId: insertId,
              eventName:     (payload.methodName as string) ?? 'Unknown',
              eventTime,
              changeAction:  classified.changeAction,
              category:      classified.category as ChangeCategory,
              riskScore:     classified.riskScore,
              severity:      classified.severity as Severity,
              summary:       classified.summary,
              actor:         classified.actor,
              actorType:     classified.actorType,
              sourceIp:      classified.sourceIp,
              resourceType:  classified.resourceType,
              resourceId:    classified.resourceId,
              resourceName:  classified.resourceName,
              previousValue: classified.previousValue as unknown as Prisma.InputJsonValue | undefined ?? undefined,
              newValue:      gcpNewValue as unknown as Prisma.InputJsonValue | undefined,
            },
          });
          changesStored++;

          // Keep ResourceInventory in sync
          await syncInventoryFromChange({
            provider:     'GCP',
            targetId,
            eventName:    (payload.methodName as string) ?? '',
            resourceId:   classified.resourceId,
            resourceName: classified.resourceName,
            resourceType: classified.resourceType,
            newValue:     classified.newValue as Record<string, unknown> | null ?? null,
            eventTime,
          });
        }
      }

      await prisma.configSyncRun.update({
        where: { id: run.id },
        data: { status: 'COMPLETED', completedAt: new Date(), eventsFound, changesStored },
      });

      // Promote account to READY if it was PENDING/FAILED — ensures periodic sync picks it up
      await markSyncedReady(provider, targetId).catch(() => {});

    } catch (err) {
      await prisma.configSyncRun.update({
        where: { id: run.id },
        data: { status: 'FAILED', completedAt: new Date(), errorMessage: (err as Error).message },
      });
    }
  })();
});

// ─── Stats ────────────────────────────────────────────────────────────────────

router.get('/stats', async (req: Request, res: Response) => {
  try {
    const { provider, targetId, startTime, endTime } = req.query as Record<string, string>;
    if (!provider || !targetId) {
      res.status(400).json({ error: 'provider and targetId are required' });
      return;
    }

    const where: Record<string, unknown> = buildWhere(provider, targetId);
    if (startTime || endTime) {
      const eventTimeFilter: Record<string, Date> = {};
      if (startTime) eventTimeFilter.gte = new Date(startTime);
      if (endTime)   eventTimeFilter.lte = new Date(endTime);
      (where as Record<string, unknown>).eventTime = eventTimeFilter;
    }

    const [bySeverity, byCategory, byActor, timeline] = await Promise.all([
      prisma.configChange.groupBy({ by: ['severity'], where, _count: { id: true } }),
      prisma.configChange.groupBy({ by: ['category'], where, _count: { id: true } }),
      prisma.configChange.groupBy({
        by: ['actor'], where: { ...where as object, actor: { not: null } },
        _count: { id: true }, orderBy: { _count: { id: 'desc' } }, take: 10,
      }),
      // 30-day daily timeline
      (() => {
        const col = provider === 'AWS' ? Prisma.sql`"awsAccountId"` : provider === 'AZURE' ? Prisma.sql`"azureSubId"` : Prisma.sql`"gcpProjectId"`;
        return prisma.$queryRaw<{ date: string; severity: string; count: bigint }[]>`
          SELECT DATE("eventTime") as date, severity, COUNT(*) as count
          FROM "ConfigChange"
          WHERE ${col} = ${targetId}
            AND "eventTime" >= NOW() - INTERVAL '30 days'
          GROUP BY DATE("eventTime"), severity
          ORDER BY date ASC
        `;
      })(),
    ]);

    const severityMap = Object.fromEntries(bySeverity.map((r) => [r.severity, r._count.id]));
    const categoryMap = Object.fromEntries(byCategory.map((r) => [r.category, r._count.id]));

    // Build timeline buckets
    const tMap = new Map<string, Record<string, number>>();
    for (const row of timeline) {
      const d = String(row.date).split('T')[0];
      if (!tMap.has(d)) tMap.set(d, { critical: 0, high: 0, medium: 0, low: 0 });
      tMap.get(d)![row.severity.toLowerCase()] = Number(row.count);
    }

    res.json({
      data: {
        bySeverity: {
          CRITICAL: severityMap['CRITICAL'] ?? 0,
          HIGH:     severityMap['HIGH']     ?? 0,
          MEDIUM:   severityMap['MEDIUM']   ?? 0,
          LOW:      severityMap['LOW']      ?? 0,
        },
        byCategory: categoryMap,
        topActors:  byActor.map((r) => ({ actor: r.actor, count: r._count.id })),
        timeline:   Array.from(tMap.entries()).map(([date, counts]) => ({ date, ...counts })),
        total: Object.values(severityMap).reduce((a, b) => a + b, 0),
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── List ─────────────────────────────────────────────────────────────────────

function buildWhere(provider: string, targetId: string): Record<string, unknown> {
  if (provider === 'AWS')   return { awsAccountId: targetId };
  if (provider === 'AZURE') return { azureSubId:   targetId };
  if (provider === 'GCP')   return { gcpProjectId: targetId };
  return {};
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const {
      provider, targetId, changeAction, severity, category, changeStatus, actor,
      search, startTime, endTime, sortBy = 'eventTime', sortOrder = 'desc',
    } = req.query as Record<string, string>;

    const page     = parseInt(req.query.page     as string) || 1;
    const pageSize = Math.min(parseInt(req.query.pageSize as string) || 50, 200);
    const skip     = (page - 1) * pageSize;

    if (!provider || !targetId) {
      res.status(400).json({ error: 'provider and targetId are required' });
      return;
    }

    const where: Record<string, unknown> = buildWhere(provider, targetId);
    if (changeAction) where.changeAction = changeAction;
    if (severity)     where.severity     = severity;
    if (category)     where.category     = category;
    if (changeStatus) where.changeStatus = changeStatus;
    if (actor)        where.actor        = { contains: actor, mode: 'insensitive' };
    if (startTime || endTime) {
      where.eventTime = {
        ...(startTime ? { gte: new Date(startTime) } : {}),
        ...(endTime   ? { lte: new Date(endTime)   } : {}),
      };
    }
    if (search) {
      where.OR = [
        { summary:      { contains: search, mode: 'insensitive' } },
        { actor:        { contains: search, mode: 'insensitive' } },
        { eventName:    { contains: search, mode: 'insensitive' } },
        { resourceId:   { contains: search, mode: 'insensitive' } },
        { resourceName: { contains: search, mode: 'insensitive' } },
      ];
    }

    const validSort: Record<string, string> = { eventTime: 'eventTime', riskScore: 'riskScore', severity: 'severity' };
    const orderField = validSort[sortBy] ?? 'eventTime';

    const [rows, total] = await Promise.all([
      prisma.configChange.findMany({
        where,
        skip,
        take: pageSize,
        orderBy: { [orderField]: sortOrder === 'asc' ? 'asc' : 'desc' },
        select: {
          id: true, provider: true, changeAction: true, category: true, riskScore: true, severity: true,
          eventName: true, eventTime: true, region: true,
          actor: true, actorType: true, sourceIp: true,
          resourceType: true, resourceId: true, resourceName: true,
          summary: true, changeStatus: true, acknowledgedBy: true, acknowledgedAt: true,
          notes: true, createdAt: true,
          // omit rawEvent from list — too large
        },
      }),
      prisma.configChange.count({ where }),
    ]);

    res.json({
      data: rows,
      meta: {
        total, page, pageSize,
        totalPages: Math.ceil(total / pageSize),
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Single change detail (includes previousValue, newValue) ─────────────────

router.get('/export/csv', async (req: Request, res: Response) => {
  try {
    const { provider, targetId, severity, category, changeStatus } = req.query as Record<string, string>;
    if (!provider || !targetId) {
      res.status(400).json({ error: 'provider and targetId are required' });
      return;
    }

    const where: Record<string, unknown> = buildWhere(provider, targetId);
    if (severity)     where.severity     = severity;
    if (category)     where.category     = category;
    if (changeStatus) where.changeStatus = changeStatus;

    const rows = await prisma.configChange.findMany({
      where,
      orderBy: { eventTime: 'desc' },
      take: 5000,
      select: {
        eventTime: true, changeAction: true, severity: true, category: true, riskScore: true,
        eventName: true, actor: true, resourceType: true, resourceName: true,
        summary: true, changeStatus: true, sourceIp: true,
      },
    });

    const header = 'Event Time,Action,Severity,Category,Risk Score,Event,Actor,Resource Type,Resource,Summary,Status,Source IP\n';
    const csv = rows.map((r) =>
      [
        r.eventTime.toISOString(),
        r.changeAction,
        r.severity,
        r.category,
        r.riskScore,
        r.eventName,
        r.actor ?? '',
        r.resourceType ?? '',
        r.resourceName ?? '',
        `"${(r.summary ?? '').replace(/"/g, '""')}"`,
        r.changeStatus,
        r.sourceIp ?? '',
      ].join(',')
    ).join('\n');

    const filename = `config-changes-${targetId}-${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(header + csv);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/runs', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.query as Record<string, string>;
    if (!provider || !targetId) {
      res.status(400).json({ error: 'provider and targetId are required' });
      return;
    }
    const [runs, lastCompleted] = await Promise.all([
      prisma.configSyncRun.findMany({
        where:   { provider, targetId },
        orderBy: { createdAt: 'desc' },
        take:    10,
      }),
      // Separately fetch the most recent COMPLETED run so the UI always has a
      // reliable "last successful sync" time regardless of current run status.
      prisma.configSyncRun.findFirst({
        where:   { provider, targetId, status: 'COMPLETED' },
        orderBy: { completedAt: 'desc' },
        select:  { completedAt: true, changesStored: true },
      }),
    ]);
    res.json({ runs, lastSuccessfulSyncAt: lastCompleted?.completedAt ?? null, lastChangesStored: lastCompleted?.changesStored ?? null });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const change = await prisma.configChange.findUnique({ where: { id: req.params.id } });
    if (!change) { res.status(404).json({ error: 'Change not found' }); return; }
    res.json({ data: change });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Acknowledge / status update ──────────────────────────────────────────────

router.patch('/:id/status', async (req: Request, res: Response) => {
  try {
    const { status, notes } = req.body as { status: string; notes?: string };
    const allowed = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'];
    if (!allowed.includes(status)) {
      res.status(400).json({ error: 'Invalid status' });
      return;
    }
    const change = await prisma.configChange.update({
      where: { id: req.params.id },
      data: {
        changeStatus:  status as 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE',
        notes:         notes ?? undefined,
        acknowledgedBy: status === 'ACKNOWLEDGED' ? req.user!.id : undefined,
        acknowledgedAt: status === 'ACKNOWLEDGED' ? new Date() : undefined,
      },
    });
    res.json({ data: change });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.post('/bulk-status', async (req: Request, res: Response) => {
  try {
    const { ids, status, notes } = req.body as { ids: string[]; status: string; notes?: string };
    if (!Array.isArray(ids) || ids.length === 0) {
      res.status(400).json({ error: 'ids array is required' });
      return;
    }
    if (ids.length > 200) {
      res.status(422).json({ error: 'Maximum 200 IDs per bulk request' });
      return;
    }
    const allowed = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'];
    if (!allowed.includes(status)) {
      res.status(400).json({ error: 'Invalid status' });
      return;
    }
    const result = await prisma.configChange.updateMany({
      where: { id: { in: ids } },
      data: {
        changeStatus:  status as 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE',
        notes:         notes ?? undefined,
        acknowledgedBy: status === 'ACKNOWLEDGED' ? req.user!.id : undefined,
        acknowledgedAt: status === 'ACKNOWLEDGED' ? new Date() : undefined,
      },
    });
    res.json({ data: { updated: result.count } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

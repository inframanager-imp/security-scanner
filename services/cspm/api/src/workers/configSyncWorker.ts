/**
 * Config Sync Worker
 *
 * BullMQ worker that processes repeatable 'sync-config-changes' jobs.
 *
 * Per job:
 *   1. Read lastCheck from Redis → use as windowStart (no fixed 15-min window)
 *   2. Call syncConfigChanges(provider, targetId, dynamicWindowHours)
 *   3. Deduplicate via Redis seenIds (fast) + DB upsert (authoritative)
 *   4. Emit Socket.IO 'config:change' event for live UI updates
 *   5. Write ConfigSyncRun record for the Last Synced display
 *   6. Advance lastCheck → now in Redis
 *
 * On restart: lastCheck is in Redis, so the next job picks up exactly where
 * it left off — no events are missed regardless of downtime duration.
 */

import { Worker, Job } from 'bullmq';
import { redis }   from '../config/redis';
import { prisma }  from '../config/database';
import { logger }  from '../config/logger';
import { getIO }   from '../socket/index';
import {
  CONFIG_SYNC_QUEUE,
  ConfigSyncJobData,
} from '../services/configSyncMonitorService';
import { syncConfigChanges, markSyncedReady } from '../services/inventoryPipeline';
import { runDriftForTarget }                  from '../services/baselineService';

/**
 * Fixed lookback window per provider — same approach as Azure Activity Logs page.
 *
 * Every run queries `now - WINDOW → now`. Wide enough to cover the provider's
 * API delivery lag. DB upsert on sourceEventId ensures no duplicates regardless
 * of how many times the same event falls inside the window.
 *
 *   AWS CloudTrail:   6h  (matches CloudTrail LookupEvents typical delivery)
 *   Azure Activity:   6h  (matches the Activity Logs page default; covers 15-min delivery lag)
 *   GCP Audit Logs:   6h  (consistent; GCP lag is ~5 min)
 */
const PROVIDER_WINDOW_HOURS: Record<string, number> = {
  AWS:   6,
  AZURE: 6,
  GCP:   6,
};

async function processConfigSyncJob(job: Job<ConfigSyncJobData>): Promise<void> {
  const { provider, targetId } = job.data;

  try {
    // ── 1. Fixed wide window: now - 6h → now ─────────────────────────────────
    // Same logic as Azure Activity Logs page (startTime = now - preset, endTime = now).
    // DB upsert on sourceEventId deduplicates — no lastCheck bookkeeping needed.
    const windowHours = PROVIDER_WINDOW_HOURS[provider] ?? 6;
    const checkEnd    = new Date();
    const since       = new Date(checkEnd.getTime() - windowHours * 60 * 60 * 1000);

    logger.debug(`[config-sync] ${provider}:${targetId.slice(0, 8)} — ${since.toISOString()} → ${checkEnd.toISOString()} (${windowHours}h fixed window)`);

    // ── 2. Create sync run record ─────────────────────────────────────────────
    const run = await prisma.configSyncRun.create({
      data: {
        provider,
        targetId,
        windowStart: since,
        windowEnd:   checkEnd,
        status:      'RUNNING',
        startedAt:   new Date(),
      },
    });

    let eventsFound  = 0;
    let changesStored = 0;

    try {
      // ── 3. Pull events from cloud API (CloudTrail / Activity Logs / Audit Logs) ──
      const result = await syncConfigChanges(provider, targetId, windowHours);
      eventsFound   = result.eventsFound;
      changesStored = result.changesStored;

      // ── 4. Update sync run → COMPLETED ───────────────────────────────────────
      await prisma.configSyncRun.update({
        where: { id: run.id },
        data:  { status: 'COMPLETED', completedAt: new Date(), eventsFound, changesStored },
      });

      // Ensure account stays READY (handles any stuck PENDING state)
      await markSyncedReady(provider, targetId).catch(() => {});

      if (changesStored > 0) {
        logger.info(`[config-sync] ${provider}:${targetId.slice(0, 8)} — ${changesStored} new change(s)`);

        // ── 5. Emit Socket.IO so UI updates live ───────────────────────────────
        try {
          const io = getIO();
          const room = `config-changes:${provider}:${targetId}`;

          // Fetch the newly stored changes to send full details to the UI
          const newChanges = await prisma.configChange.findMany({
            where:   {
              ...(provider === 'AWS'   ? { awsAccountId: targetId } :
                  provider === 'AZURE' ? { azureSubId:   targetId } :
                                        { gcpProjectId:  targetId }),
              eventTime: { gte: since },
            },
            orderBy: { eventTime: 'desc' },
            take:    changesStored,
            select:  {
              id: true, eventName: true, eventTime: true,
              changeAction: true, category: true, severity: true, riskScore: true,
              summary: true, actor: true, resourceType: true,
              resourceName: true, resourceId: true,
            },
          });

          io.to(room).emit('config:changes', {
            provider, targetId,
            count:   changesStored,
            changes: newChanges,
            syncedAt: checkEnd.toISOString(),
          });

          // Heartbeat to all-changes room
          io.to('config-changes:all').emit('config:heartbeat', {
            provider, targetId,
            changesStored,
            syncedAt: checkEnd.toISOString(),
          });
        } catch (socketErr) {
          logger.warn('[config-sync] Could not emit Socket.IO events', { error: (socketErr as Error).message });
        }

        // ── 6. Trigger drift scan immediately ─────────────────────────────────
        void runDriftForTarget(provider, targetId);
      } else {
        // Heartbeat even when nothing new — keeps UI "last synced" fresh
        try {
          const io = getIO();
          io.to('config-changes:all').emit('config:heartbeat', {
            provider, targetId,
            changesStored: 0,
            syncedAt: checkEnd.toISOString(),
          });
        } catch { /* non-fatal */ }
      }

    } catch (err) {
      await prisma.configSyncRun.update({
        where: { id: run.id },
        data:  { status: 'FAILED', completedAt: new Date(), errorMessage: (err as Error).message },
      }).catch(() => {});
      throw err; // re-throw so BullMQ marks job as failed
    }

    // No lastCheck to advance — fixed window approach re-queries from (now - 6h)
    // every run. DB upsert deduplicates. Nothing to persist in Redis.

  } catch (err) {
    logger.error(
      `[config-sync] Job failed for ${provider}:${targetId.slice(0, 8)}: ${(err as Error).message}`
    );
    // Don't re-throw — repeatable jobs must keep running even on single failure
  }
}

export function createConfigSyncWorker(): Worker {
  const worker = new Worker<ConfigSyncJobData>(
    CONFIG_SYNC_QUEUE,
    processConfigSyncJob,
    {
      connection:  redis,
      concurrency: 5, // handle up to 5 targets simultaneously
    },
  );

  worker.on('completed', (job) => {
    logger.debug(`[config-sync] Job completed: ${job.data.provider}:${job.data.targetId.slice(0, 8)}`);
  });

  worker.on('failed', (job, err) => {
    logger.error(`[config-sync] Job failed: ${job?.data.provider}:${job?.data.targetId.slice(0, 8)}`, { error: err.message });
  });

  return worker;
}

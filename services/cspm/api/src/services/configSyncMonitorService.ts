/**
 * Config Sync Monitor Service
 *
 * Manages per-target BullMQ repeatable jobs for config change sync.
 *
 * Strategy: fixed wide window (now - 6h → now) every 30 seconds — same as
 * the Azure Activity Logs page. DB upsert on sourceEventId deduplicates.
 * No lastCheck bookkeeping needed — wide window always covers delivery lag.
 *
 * BullMQ jobs persist in Redis — survive API restarts automatically.
 * resumeAllConfigSyncJobs() re-registers all READY targets on startup.
 */

import { Queue } from 'bullmq';
import { redis }  from '../config/redis';
import { logger } from '../config/logger';
import { prisma } from '../config/database';

export const CONFIG_SYNC_QUEUE    = 'config-sync-monitor';
export const CONFIG_SYNC_INTERVAL = 30 * 1000; // 30 seconds — matches Azure Activity Logs page

export const configSyncQueue = new Queue(CONFIG_SYNC_QUEUE, { connection: redis });

export interface ConfigSyncJobData {
  provider: string;
  targetId: string;
}

export async function startConfigSync(provider: string, targetId: string): Promise<void> {
  const jobId = `config-sync-${provider}-${targetId}`;

  await configSyncQueue.add(
    'sync-config-changes',
    { provider, targetId } satisfies ConfigSyncJobData,
    {
      jobId,
      repeat:           { every: CONFIG_SYNC_INTERVAL },
      attempts:         1,
      removeOnComplete: 10,
      removeOnFail:     10,
    },
  );

  logger.info(`[config-sync] Started BullMQ job for ${provider}:${targetId.slice(0, 8)}`);
}

export async function stopConfigSync(provider: string, targetId: string): Promise<void> {
  const jobId = `config-sync-${provider}-${targetId}`;
  const repeatableJobs = await configSyncQueue.getRepeatableJobs();

  for (const job of repeatableJobs) {
    if (job.key.includes(jobId)) {
      await configSyncQueue.removeRepeatableByKey(job.key);
    }
  }

  logger.info(`[config-sync] Stopped BullMQ job for ${provider}:${targetId.slice(0, 8)}`);
}

/**
 * Called on API startup — re-registers BullMQ jobs for all READY accounts/subs/projects.
 * BullMQ deduplicates by jobId so calling this multiple times is safe.
 */
export async function resumeAllConfigSyncJobs(): Promise<void> {
  const [awsAccounts, azureSubs, gcpProjects] = await Promise.all([
    prisma.account.findMany({
      where:  { inventoryStatus: 'READY' },
      select: { id: true },
    }),
    prisma.azureSubscription.findMany({
      where:  { inventoryStatus: 'READY' },
      select: { id: true },
    }),
    prisma.gcpProject.findMany({
      where:  { inventoryStatus: 'READY' },
      select: { id: true },
    }),
  ]);

  const targets = [
    ...awsAccounts.map(a => ({ provider: 'AWS',   targetId: a.id })),
    ...azureSubs.map(s   => ({ provider: 'AZURE',  targetId: s.id })),
    ...gcpProjects.map(p => ({ provider: 'GCP',    targetId: p.id })),
  ];

  if (targets.length === 0) {
    logger.info('[config-sync] No READY targets to resume');
    return;
  }

  logger.info(`[config-sync] Resuming sync jobs for ${targets.length} target(s)...`);

  for (const { provider, targetId } of targets) {
    try {
      await startConfigSync(provider, targetId);
    } catch (err) {
      logger.warn(`[config-sync] Failed to resume job for ${provider}:${targetId.slice(0, 8)}: ${(err as Error).message}`);
    }
  }
}

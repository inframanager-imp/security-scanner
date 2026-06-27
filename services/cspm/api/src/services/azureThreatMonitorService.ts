/**
 * Azure Threat Monitor Service
 *
 * Manages per-subscription real-time threat monitoring using BullMQ repeatable jobs.
 *
 * Redis keys:
 *   azure:threat:monitoring:{subscriptionId}   — "1" if active
 *   azure:threat:lastCheck:{subscriptionId}    — ISO timestamp of last completed check
 *   azure:threat:seenIds:{subscriptionId}      — Set of Azure event correlation IDs already processed (24h TTL)
 */

import { Queue } from 'bullmq';
import { redis } from '../config/redis';
import { logger } from '../config/logger';

export const AZURE_THREAT_QUEUE   = 'azure-threat-monitoring';
export const AZURE_CHECK_INTERVAL = 60 * 1000; // 1 minute

export const azureThreatQueue = new Queue(AZURE_THREAT_QUEUE, { connection: redis });

const monitorKey   = (id: string) => `azure:threat:monitoring:${id}`;
const lastCheckKey = (id: string) => `azure:threat:lastCheck:${id}`;
const seenIdsKey   = (id: string) => `azure:threat:seenIds:${id}`;

export async function startAzureMonitoring(subscriptionId: string): Promise<void> {
  await redis.set(monitorKey(subscriptionId), '1');

  const existing = await redis.get(lastCheckKey(subscriptionId));
  if (!existing) {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    await redis.set(lastCheckKey(subscriptionId), fiveMinAgo);
  }

  await azureThreatQueue.add(
    'monitor-azure',
    { subscriptionId },
    {
      jobId:  `azure-threat-monitor-${subscriptionId}`,
      repeat: { every: AZURE_CHECK_INTERVAL },
      attempts: 1,
      removeOnComplete: 10,
      removeOnFail: 10,
    },
  );

  logger.info(`Azure threat monitoring STARTED for subscription ${subscriptionId}`);
}

export async function stopAzureMonitoring(subscriptionId: string): Promise<void> {
  await redis.del(monitorKey(subscriptionId));

  const repeatableJobs = await azureThreatQueue.getRepeatableJobs();
  for (const job of repeatableJobs) {
    if (job.key.includes(subscriptionId)) {
      await azureThreatQueue.removeRepeatableByKey(job.key);
    }
  }

  logger.info(`Azure threat monitoring STOPPED for subscription ${subscriptionId}`);
}

export async function isAzureMonitoring(subscriptionId: string): Promise<boolean> {
  return (await redis.get(monitorKey(subscriptionId))) === '1';
}

export async function getAzureMonitoredSubscriptions(): Promise<string[]> {
  const keys = await redis.keys('azure:threat:monitoring:*');
  return keys.map(k => k.replace('azure:threat:monitoring:', ''));
}

export async function getAzureLastCheck(subscriptionId: string): Promise<Date> {
  const val = await redis.get(lastCheckKey(subscriptionId));
  return val ? new Date(val) : new Date(Date.now() - 10 * 60 * 1000);
}

export async function setAzureLastCheck(subscriptionId: string, time: Date): Promise<void> {
  await redis.set(lastCheckKey(subscriptionId), time.toISOString());
}

export async function markAzureEventSeen(subscriptionId: string, eventId: string): Promise<boolean> {
  const key = seenIdsKey(subscriptionId);
  const added = await redis.sadd(key, eventId);
  if (added > 0) {
    await redis.expire(key, 24 * 60 * 60);
    return true;
  }
  return false;
}

export async function resumeAllAzureMonitors(): Promise<void> {
  const ids = await getAzureMonitoredSubscriptions();
  if (ids.length === 0) return;

  logger.info(`Resuming Azure threat monitoring for ${ids.length} subscription(s)...`);
  for (const id of ids) {
    try {
      await startAzureMonitoring(id);
    } catch (err) {
      logger.error(`Failed to resume Azure threat monitor for ${id}`, { error: (err as Error).message });
    }
  }
}

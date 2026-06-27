/**
 * Threat Monitor Service
 *
 * Manages per-account real-time threat monitoring using BullMQ repeatable jobs.
 * State is persisted in Redis so monitoring survives API restarts.
 *
 * Redis keys used:
 *   threat:monitoring:{accountId}   — "1" if active
 *   threat:lastCheck:{accountId}    — ISO timestamp of last completed check
 *   threat:seenIds:{accountId}      — Set of CloudTrail event IDs already processed (24h TTL)
 */

import { Queue } from 'bullmq';
import { redis } from '../config/redis';
import { logger } from '../config/logger';

export const THREAT_QUEUE = 'threat-monitoring';
export const CHECK_INTERVAL_MS = 60 * 1000; // 1 minute

// Shared queue instance — also used by the worker
export const threatQueue = new Queue(THREAT_QUEUE, { connection: redis });

// ─── Keys ────────────────────────────────────────────────────────────────────

const monitorKey  = (accountId: string) => `threat:monitoring:${accountId}`;
const lastCheckKey = (accountId: string) => `threat:lastCheck:${accountId}`;
const seenIdsKey  = (accountId: string) => `threat:seenIds:${accountId}`;

// ─── Public API ───────────────────────────────────────────────────────────────

/** Enable real-time monitoring for an account. Idempotent. */
export async function startMonitoring(accountId: string): Promise<void> {
  // Mark as active in Redis
  await redis.set(monitorKey(accountId), '1');

  // Seed lastCheck to 5 min ago so the first run catches recent events
  const existing = await redis.get(lastCheckKey(accountId));
  if (!existing) {
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    await redis.set(lastCheckKey(accountId), fiveMinAgo);
  }

  // Upsert repeatable job (BullMQ deduplicates by jobId)
  await threatQueue.add(
    'monitor-account',
    { accountId },
    {
      jobId:  `threat-monitor-${accountId}`,
      repeat: { every: CHECK_INTERVAL_MS },
      attempts: 1,
      removeOnComplete: 10,
      removeOnFail: 10,
    },
  );

  logger.info(`Threat monitoring STARTED for account ${accountId}`);
}

/** Disable real-time monitoring for an account. Idempotent. */
export async function stopMonitoring(accountId: string): Promise<void> {
  await redis.del(monitorKey(accountId));

  // Remove all repeatable jobs for this account
  const repeatableJobs = await threatQueue.getRepeatableJobs();
  for (const job of repeatableJobs) {
    if (job.id === `threat-monitor-${accountId}` || job.name === 'monitor-account') {
      // Match by key pattern since BullMQ appends repeat info to key
      if (job.key.includes(accountId)) {
        await threatQueue.removeRepeatableByKey(job.key);
      }
    }
  }

  logger.info(`Threat monitoring STOPPED for account ${accountId}`);
}

/** Check whether an account has monitoring active. */
export async function isMonitoring(accountId: string): Promise<boolean> {
  return (await redis.get(monitorKey(accountId))) === '1';
}

/** Return all account IDs currently being monitored. */
export async function getMonitoredAccounts(): Promise<string[]> {
  const keys = await redis.keys('threat:monitoring:*');
  return keys.map(k => k.replace('threat:monitoring:', ''));
}

/** Get/update the lastCheck timestamp for an account. */
export async function getLastCheck(accountId: string): Promise<Date> {
  const val = await redis.get(lastCheckKey(accountId));
  return val ? new Date(val) : new Date(Date.now() - 10 * 60 * 1000);
}

export async function setLastCheck(accountId: string, time: Date): Promise<void> {
  await redis.set(lastCheckKey(accountId), time.toISOString());
}

/**
 * Track seen CloudTrail event IDs to avoid duplicate alerts.
 * Returns true if the eventId is NEW (not yet seen).
 */
export async function markEventSeen(accountId: string, eventId: string): Promise<boolean> {
  const key = seenIdsKey(accountId);
  const added = await redis.sadd(key, eventId);
  if (added > 0) {
    // Expire the set after 24h to keep Redis clean
    await redis.expire(key, 24 * 60 * 60);
    return true;  // new event
  }
  return false;   // already seen
}

/**
 * On server startup: re-register repeatable jobs for all accounts
 * that had monitoring enabled before restart.
 */
export async function resumeAllMonitors(): Promise<void> {
  const accountIds = await getMonitoredAccounts();
  if (accountIds.length === 0) return;

  logger.info(`Resuming threat monitoring for ${accountIds.length} account(s)...`);
  for (const accountId of accountIds) {
    try {
      await startMonitoring(accountId);
    } catch (err) {
      logger.error(`Failed to resume threat monitor for ${accountId}`, { error: (err as Error).message });
    }
  }
}

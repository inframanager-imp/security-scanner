/**
 * DSPM Scan Worker
 *
 *   Queue: `dspm-scans`
 *   Job:   { provider, accountId }
 *
 * Long-running per-account; per-bucket sample size bounds total cost.
 */

import { Queue, Worker, Job } from 'bullmq';
import { redis } from '../config/redis';
import { logger } from '../config/logger';
import { runDspmScanForAccount } from '../services/dspmService';

export const DSPM_QUEUE = 'dspm-scans';

export interface DspmJob {
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  triggeredBy?: 'MANUAL' | 'SCHEDULED';
}

let queueSingleton: Queue<DspmJob> | null = null;

export function getDspmQueue(): Queue<DspmJob> {
  if (!queueSingleton) {
    queueSingleton = new Queue<DspmJob>(DSPM_QUEUE, { connection: redis });
  }
  return queueSingleton;
}

export async function enqueueDspmScan(data: DspmJob): Promise<string> {
  const queue = getDspmQueue();
  const jobId = `${data.provider}:${data.accountId}:${Math.floor(Date.now() / 60000)}`;
  const job = await queue.add('dspm-scan', data, {
    jobId,
    attempts: 1,
    removeOnComplete: 50,
    removeOnFail: 50,
  });
  return job.id ?? jobId;
}

async function processDspmJob(job: Job<DspmJob>): Promise<void> {
  const { provider, accountId, triggeredBy } = job.data;
  try {
    logger.info('dspmWorker.start', { provider, accountId, triggeredBy });
    const result = await runDspmScanForAccount(provider, accountId);
    logger.info('dspmWorker.done', { provider, accountId, ...result });
  } catch (err) {
    logger.error('dspmWorker.failed', { provider, accountId, error: (err as Error).message });
    throw err;
  }
}

export function createDspmWorker(): Worker {
  const worker = new Worker<DspmJob>(DSPM_QUEUE, processDspmJob, {
    connection: redis,
    concurrency: 1,
  });

  worker.on('completed', (job) => {
    logger.debug('dspmWorker.completed', { jobId: job.id, ...job.data });
  });

  worker.on('failed', (job, err) => {
    logger.error('dspmWorker.failed', {
      jobId: job?.id,
      data: job?.data,
      error: err.message,
    });
  });

  return worker;
}

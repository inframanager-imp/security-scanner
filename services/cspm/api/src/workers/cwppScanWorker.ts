/**
 * CWPP Scan Worker
 *
 * Runs the agentless workload-vulnerability pipeline for an account.
 *   Queue: `cwpp-scans`
 *   Job:   { provider, accountId }
 *
 * Triggered by:
 *   - POST /api/cwpp/scan (manual)
 *   - Daily repeatable per-account schedule (added by the routes / service code)
 */

import { Queue, Worker, Job } from 'bullmq';
import { redis } from '../config/redis';
import { logger } from '../config/logger';
import { runCwppScanForAccount } from '../services/cwppService';

export const CWPP_QUEUE = 'cwpp-scans';

export interface CwppJob {
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  triggeredBy?: 'MANUAL' | 'SCHEDULED';
}

let queueSingleton: Queue<CwppJob> | null = null;

export function getCwppQueue(): Queue<CwppJob> {
  if (!queueSingleton) {
    queueSingleton = new Queue<CwppJob>(CWPP_QUEUE, { connection: redis });
  }
  return queueSingleton;
}

export async function enqueueCwppScan(data: CwppJob): Promise<string> {
  const queue = getCwppQueue();
  const jobId = `${data.provider}:${data.accountId}:${Math.floor(Date.now() / 60000)}`;
  const job = await queue.add('cwpp-scan', data, {
    jobId,
    attempts: 1,
    removeOnComplete: 50,
    removeOnFail: 50,
  });
  return job.id ?? jobId;
}

async function processCwppJob(job: Job<CwppJob>): Promise<void> {
  const { provider, accountId, triggeredBy } = job.data;
  try {
    logger.info('cwppWorker.start', { provider, accountId, triggeredBy });
    const result = await runCwppScanForAccount(provider, accountId);
    logger.info('cwppWorker.done', { provider, accountId, ...result });
  } catch (err) {
    logger.error('cwppWorker.failed', { provider, accountId, error: (err as Error).message });
    throw err;
  }
}

export function createCwppWorker(): Worker {
  const worker = new Worker<CwppJob>(CWPP_QUEUE, processCwppJob, {
    connection: redis,
    concurrency: 1,
  });

  worker.on('completed', (job) => {
    logger.debug('cwppWorker.completed', { jobId: job.id, ...job.data });
  });

  worker.on('failed', (job, err) => {
    logger.error('cwppWorker.failed', {
      jobId: job?.id,
      data: job?.data,
      error: err.message,
    });
  });

  return worker;
}

/**
 * Evidence Worker
 *
 * Refreshes ComplianceEvidence rows for every account on a daily cadence and
 * also runs on-demand after a scan completes.
 *
 *   Queue: `evidence-refresh`
 *   Job:   { provider, accountId, frameworkId? }
 *
 * On each fire it calls collectEvidenceForAccount(), which re-evaluates every
 * control mapped to scanner findings and updates evidence rows with passing /
 * failing counts plus a snapshot of the offending configState.
 */

import { Queue, Worker, Job } from 'bullmq';
import { redis } from '../config/redis';
import { logger } from '../config/logger';
import { collectEvidenceForAccount } from '../services/evidenceService';

export const EVIDENCE_QUEUE = 'evidence-refresh';

export interface EvidenceJob {
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  frameworkId?: string;
  triggeredBy?: 'SCAN' | 'SCHEDULED' | 'MANUAL';
}

let queueSingleton: Queue<EvidenceJob> | null = null;

export function getEvidenceQueue(): Queue<EvidenceJob> {
  if (!queueSingleton) {
    queueSingleton = new Queue<EvidenceJob>(EVIDENCE_QUEUE, { connection: redis });
  }
  return queueSingleton;
}

export async function enqueueEvidenceRefresh(data: EvidenceJob): Promise<string> {
  const queue = getEvidenceQueue();
  // Coalesce same-account refreshes within a 1-minute window
  const jobId = `${data.provider}:${data.accountId}:${data.frameworkId ?? 'all'}:${Math.floor(Date.now() / 60000)}`;
  const job = await queue.add('refresh-evidence', data, {
    jobId,
    attempts: 2,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: 100,
    removeOnFail: 50,
  });
  return job.id ?? jobId;
}

async function processEvidenceJob(job: Job<EvidenceJob>): Promise<void> {
  const { provider, accountId, frameworkId, triggeredBy } = job.data;
  try {
    logger.info('evidenceWorker.start', { provider, accountId, frameworkId, triggeredBy });
    const result = await collectEvidenceForAccount(accountId, provider, frameworkId as any);
    logger.info('evidenceWorker.done', { provider, accountId, frameworkId, ...result });
  } catch (err) {
    logger.error('evidenceWorker.failed', { provider, accountId, error: (err as Error).message });
    throw err;
  }
}

export function createEvidenceWorker(): Worker {
  const worker = new Worker<EvidenceJob>(EVIDENCE_QUEUE, processEvidenceJob, {
    connection: redis,
    concurrency: 2,
  });

  worker.on('completed', (job) => {
    logger.debug('evidenceWorker.completed', { jobId: job.id, ...job.data });
  });

  worker.on('failed', (job, err) => {
    logger.error('evidenceWorker.failed', {
      jobId: job?.id,
      data: job?.data,
      error: err.message,
    });
  });

  return worker;
}

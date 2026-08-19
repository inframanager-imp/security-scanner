/**
 * Graph Build Worker
 *
 * Re-builds the unified asset graph (identity + encryption edges, exposure paths)
 * for an account. Triggered:
 *   - After every cloud scan completes (scanWorker / azureScanWorker / gcpScanWorker
 *     enqueue a graph-build job once findings are persisted)
 *   - Daily as a fallback via a repeatable job
 *
 * Also runs the CIEM pass (flattenPermissions + detectAttackPaths) when ciemService is
 * wired in by Phase 2 — kept as a callable extension point here.
 */

import { Queue, Worker, Job } from 'bullmq';
import { redis } from '../config/redis';
import { logger } from '../config/logger';
import { buildGraphForAccount } from '../services/graphEnrichmentService';

export const GRAPH_BUILD_QUEUE = 'graph-build';

export interface GraphBuildJob {
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string; // internal Account / AzureSubscription / GcpProject id
  triggeredBy?: 'SCAN' | 'SCHEDULED' | 'MANUAL';
}

let queueSingleton: Queue<GraphBuildJob> | null = null;

export function getGraphBuildQueue(): Queue<GraphBuildJob> {
  if (!queueSingleton) {
    queueSingleton = new Queue<GraphBuildJob>(GRAPH_BUILD_QUEUE, { connection: redis });
  }
  return queueSingleton;
}

export async function enqueueGraphBuild(data: GraphBuildJob): Promise<string> {
  const queue = getGraphBuildQueue();
  // Coalesce duplicate runs within 30s using a deterministic jobId
  const jobId = `${data.provider}:${data.accountId}:${Math.floor(Date.now() / 30000)}`;
  const job = await queue.add('build-graph', data, {
    jobId,
    attempts: 2,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: 100,
    removeOnFail: 50,
  });
  return job.id ?? jobId;
}

async function processGraphBuildJob(job: Job<GraphBuildJob>): Promise<void> {
  const { provider, accountId, triggeredBy } = job.data;
  try {
    logger.info('graphBuildWorker.start', { provider, accountId, triggeredBy });
    const result = await buildGraphForAccount(provider, accountId);

    // Phase 2 (CIEM): chain into ciemService once available
    try {
      // Lazy import so the worker doesn't fail to load if Phase 2 isn't wired yet
      const { runCiemPassForAccount } = await import('../services/ciemService');
      if (typeof runCiemPassForAccount === 'function') {
        await runCiemPassForAccount(provider, accountId);
      }
    } catch (err) {
      // ciemService not present yet, or it errored — log and continue
      logger.debug('graphBuildWorker.ciem-skipped', {
        provider,
        accountId,
        reason: (err as Error).message,
      });
    }

    logger.info('graphBuildWorker.done', { provider, accountId, ...result });
  } catch (err) {
    logger.error('graphBuildWorker.failed', {
      provider,
      accountId,
      error: (err as Error).message,
    });
    throw err;
  }
}

export function createGraphBuildWorker(): Worker {
  const worker = new Worker<GraphBuildJob>(
    GRAPH_BUILD_QUEUE,
    processGraphBuildJob,
    {
      connection: redis,
      concurrency: 2,
    },
  );

  worker.on('completed', (job) => {
    logger.debug('graphBuildWorker.completed', { jobId: job.id, ...job.data });
  });

  worker.on('failed', (job, err) => {
    logger.error('graphBuildWorker.failed', {
      jobId: job?.id,
      data: job?.data,
      error: err.message,
    });
  });

  return worker;
}

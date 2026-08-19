/**
 * Startup reconciliation for in-process, unpersisted work orphaned by a
 * server restart.
 *
 * Two independent failure modes were found and reproduced live (2026-08-18):
 *
 * 1. Scan jobs: a BullMQ job's actual execution lives in this process's
 *    memory. If the process restarts mid-scan, the job is left "active" in
 *    Redis with no worker holding it. BullMQ's own stalled-job detection
 *    eventually notices (after stalledInterval x maxStalledCount) and — with
 *    this app's `attempts: 2` config — automatically RETRIES it, silently
 *    re-running the scan minutes later. Observed directly: a scan job marked
 *    FAILED by hand in Postgres resurrected ~20 minutes after a restart and
 *    ran a full duplicate scan concurrently with a fresh, legitimate one
 *    against the same AWS account, causing API throttling for both.
 *
 * 2. Inventory pipelines (triggerInitialPipeline): fire-and-forget
 *    `void (async () => {...})()` with zero persistence. If the process
 *    restarts while one is mid-flight, the account/subscription/project is
 *    left in `INITIALIZING` forever — nothing ever calls setStatus('FAILED')
 *    for an orphaned run, and (before this fix) the only recovery path
 *    (re-verify credentials) explicitly excluded INITIALIZING from its
 *    retry condition.
 *
 * Call `reconcileOrphanedWork()` once at boot, after `prisma.$connect()` but
 * BEFORE creating any BullMQ workers or calling triggerInitialPipeline again
 * for anything — otherwise a freshly re-triggered pipeline could get swept
 * up by this same pass.
 */
import { prisma } from '../config/database';
import { logger } from '../config/logger';
import { scanQueue } from './scanJobService';
import { azureScanQueue } from '../workers/azureScanWorker';
import { gcpScanQueue } from '../workers/gcpScanWorker';
import { triggerInitialPipeline } from './inventoryPipeline';

const ORPHAN_MESSAGE = 'Orphaned by a server restart while this scan was in progress — no result was produced. Re-run the scan.';

async function reconcileScanTable(
  label: string,
  queue: { getJob(id: string): Promise<{ remove(): Promise<void> } | undefined> },
  findRunning: () => Promise<{ id: string; jobId: string | null }[]>,
  markFailed: (id: string) => Promise<unknown>,
): Promise<number> {
  const stuck = await findRunning();
  for (const scan of stuck) {
    if (scan.jobId) {
      try {
        const job = await queue.getJob(scan.jobId);
        if (job) await job.remove();
      } catch (err) {
        logger.debug(`${label}: could not remove orphaned job`, { scanId: scan.id, error: (err as Error).message });
      }
    }
    await markFailed(scan.id);
  }
  if (stuck.length > 0) {
    logger.info(`${label}: reconciled ${stuck.length} orphaned scan(s) from a previous process`);
  }
  return stuck.length;
}

async function reconcileStuckPipelines(): Promise<number> {
  const [accounts, subs, projects] = await Promise.all([
    prisma.account.findMany({ where: { inventoryStatus: 'INITIALIZING' }, select: { id: true } }),
    prisma.azureSubscription.findMany({ where: { inventoryStatus: 'INITIALIZING' }, select: { id: true } }),
    prisma.gcpProject.findMany({ where: { inventoryStatus: 'INITIALIZING' }, select: { id: true } }),
  ]);

  for (const a of accounts) triggerInitialPipeline('AWS', a.id);
  for (const s of subs) triggerInitialPipeline('AZURE', s.id);
  for (const p of projects) triggerInitialPipeline('GCP', p.id);

  const total = accounts.length + subs.length + projects.length;
  if (total > 0) {
    logger.info(`Inventory pipeline: re-triggered ${total} target(s) stuck INITIALIZING from a previous process`, {
      aws: accounts.length, azure: subs.length, gcp: projects.length,
    });
  }
  return total;
}

export async function reconcileOrphanedWork(): Promise<void> {
  const [awsCount, azureCount, gcpCount] = await Promise.all([
    reconcileScanTable(
      'AWS scan',
      scanQueue,
      () => prisma.scan.findMany({ where: { status: { in: ['QUEUED', 'RUNNING'] } }, select: { id: true, jobId: true } }),
      (id) => prisma.scan.update({ where: { id }, data: { status: 'FAILED', errorMessage: ORPHAN_MESSAGE, completedAt: new Date() } }),
    ),
    reconcileScanTable(
      'Azure scan',
      azureScanQueue,
      () => prisma.azureScan.findMany({ where: { status: { in: ['QUEUED', 'RUNNING'] } }, select: { id: true, jobId: true } }),
      (id) => prisma.azureScan.update({ where: { id }, data: { status: 'FAILED', errorMessage: ORPHAN_MESSAGE, completedAt: new Date() } }),
    ),
    reconcileScanTable(
      'GCP scan',
      gcpScanQueue,
      () => prisma.gcpScan.findMany({ where: { status: { in: ['QUEUED', 'RUNNING'] } }, select: { id: true, jobId: true } }),
      (id) => prisma.gcpScan.update({ where: { id }, data: { status: 'FAILED', errorMessage: ORPHAN_MESSAGE, completedAt: new Date() } }),
    ),
  ]);

  const pipelineCount = await reconcileStuckPipelines();

  const total = awsCount + azureCount + gcpCount + pipelineCount;
  if (total === 0) {
    logger.info('Startup reconciliation: nothing orphaned, clean start');
  }
}

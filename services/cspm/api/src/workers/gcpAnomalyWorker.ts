/**
 * GCP Anomaly Monitor Worker
 *
 * BullMQ repeatable worker that polls GCP Cloud Audit Logs for new events
 * and runs them through the ML anomaly engine.
 *
 * Polls every 2 minutes per project.
 * Uses GCP Cloud Logging API (entries.list) to fetch AuditLog entries.
 */

import { Worker, Queue, Job } from 'bullmq';
import { redis }   from '../config/redis';
import { prisma }  from '../config/database';
import { logger }  from '../config/logger';
import { analyzeEvent, normalizeGcpEvent } from '../services/anomalyEngine';
import GcpClient   from '../../../src/gcp/client';
import { decryptGcpCredentials } from '../services/gcpCredentialService';

export const GCP_ANOMALY_QUEUE   = 'gcp-anomaly-monitoring';
export const GCP_CHECK_INTERVAL  = 2 * 60 * 1000; // 2 minutes

export const gcpAnomalyQueue = new Queue(GCP_ANOMALY_QUEUE, { connection: redis });

// ─── Redis keys ───────────────────────────────────────────────────────────────

const monitorKey   = (projectId: string) => `gcp:anomaly:monitoring:${projectId}`;
const lastCheckKey = (projectId: string) => `gcp:anomaly:lastCheck:${projectId}`;

// ─── Public control functions ─────────────────────────────────────────────────

export async function startGcpAnomalyMonitor(projectId: string): Promise<void> {
  await redis.set(monitorKey(projectId), '1');
  const existing = await redis.get(lastCheckKey(projectId));
  if (!existing) {
    await redis.set(lastCheckKey(projectId), new Date(Date.now() - 5 * 60_000).toISOString());
  }
  await gcpAnomalyQueue.add('monitor-gcp-project', { projectId }, {
    jobId:  `gcp-anomaly-${projectId}`,
    repeat: { every: GCP_CHECK_INTERVAL },
    attempts: 1,
    removeOnComplete: 10,
    removeOnFail:     10,
  });
  logger.info(`GCP anomaly monitoring STARTED for project ${projectId}`);
}

export async function stopGcpAnomalyMonitor(projectId: string): Promise<void> {
  await redis.del(monitorKey(projectId));
  const jobs = await gcpAnomalyQueue.getRepeatableJobs();
  for (const job of jobs) {
    if (job.key.includes(projectId)) await gcpAnomalyQueue.removeRepeatableByKey(job.key);
  }
  logger.info(`GCP anomaly monitoring STOPPED for project ${projectId}`);
}

export async function isGcpMonitoring(projectId: string): Promise<boolean> {
  return (await redis.get(monitorKey(projectId))) === '1';
}

// ─── Worker ───────────────────────────────────────────────────────────────────

interface GcpJobData { projectId: string; }

async function processGcpAnomalyJob(job: Job<GcpJobData>): Promise<void> {
  const { projectId } = job.data;

  try {
    // Load GCP project + credentials
    const project = await prisma.gcpProject.findUnique({ where: { id: projectId } });
    if (!project) { logger.warn(`GCP anomaly: project ${projectId} not found`); return; }

    const cred = await prisma.gcpCredential.findUnique({ where: { projectId } });
    if (!cred) { logger.warn(`GCP anomaly: no credentials for project ${projectId}`); return; }

    // Decrypt credentials
    const decrypted = decryptGcpCredentials(cred);

    const gcpClient = new GcpClient({
      projectId:   project.projectId,
      credentials: decrypted.serviceAccountKey ? JSON.parse(decrypted.serviceAccountKey) : undefined,
    });

    // Time window
    const sinceRaw = await redis.get(lastCheckKey(projectId));
    const since    = sinceRaw ? new Date(sinceRaw) : new Date(Date.now() - 5 * 60_000);
    const checkEnd = new Date();

    logger.debug(`GCP anomaly [${projectId}]: ${since.toISOString()} → ${checkEnd.toISOString()}`);

    // Fetch Cloud Audit Log entries via Cloud Logging API
    const logging = gcpClient.logging();
    const filter = [
      `logName:"cloudaudit.googleapis.com"`,
      `timestamp>="${since.toISOString()}"`,
      `timestamp<="${checkEnd.toISOString()}"`,
    ].join(' AND ');

    let anomalyCount = 0;
    let pageToken: string | undefined;

    do {
      const resp = await logging.entries.list({
        requestBody: {
          resourceNames: [`projects/${project.projectId}`],
          filter,
          orderBy:   'timestamp asc',
          pageSize:  200,
          pageToken,
        },
      });

      for (const entry of resp.data.entries ?? []) {
        const normalized = normalizeGcpEvent(entry as Record<string, unknown>, projectId);
        if (!normalized) continue;
        const detections = await analyzeEvent(normalized);
        anomalyCount += detections.length;
      }

      pageToken = resp.data.nextPageToken ?? undefined;
      if (pageToken) await new Promise((r) => setTimeout(r, 100));
    } while (pageToken);

    if (anomalyCount > 0) {
      logger.info(`GCP anomaly [${projectId}]: ${anomalyCount} anomalie(s) detected`);
    }

    await redis.set(lastCheckKey(projectId), checkEnd.toISOString());

  } catch (err) {
    logger.error(`GCP anomaly job failed for project ${projectId}`, { error: (err as Error).message });
  }
}

export function createGcpAnomalyWorker(): Worker {
  const worker = new Worker<GcpJobData>(
    GCP_ANOMALY_QUEUE,
    processGcpAnomalyJob,
    { connection: redis, concurrency: 2 },
  );

  worker.on('completed', (job) => logger.debug(`GCP anomaly job completed: ${job.data.projectId}`));
  worker.on('failed',    (job, err) => logger.error(`GCP anomaly job failed: ${job?.data.projectId}`, { error: err.message }));

  return worker;
}

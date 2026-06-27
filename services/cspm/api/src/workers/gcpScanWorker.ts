import { Worker, Job, Queue } from 'bullmq';
import { Prisma }             from '@prisma/client';
import { redis }              from '../config/redis';
import { prisma }             from '../config/database';
import { logger }             from '../config/logger';
import { getIO }              from '../socket/index';
import { decryptGcpCredentials } from '../services/gcpCredentialService';
// GcpScanEngine is lazy-loaded inside the job to avoid loading googleapis at startup

interface GcpScanJobData {
  scanId:    string;
  projectId: string;  // GcpProject.id (UUID, not GCP project ID)
  services:  string[];
}

export const gcpScanQueue = new Queue<GcpScanJobData>('gcp-scans', {
  connection: redis,
});

async function processGcpScanJob(job: Job<GcpScanJobData>): Promise<void> {
  const { scanId, projectId, services } = job.data;
  logger.info(`Starting GCP scan job: ${scanId}`, { projectId, services });

  await prisma.gcpScan.update({
    where: { id: scanId },
    data:  { status: 'RUNNING', startedAt: new Date() },
  });

  try {
    const io = getIO();
    io.to(`gcp-scan:${scanId}`).emit('gcp-scan:started', { scanId, startedAt: new Date() });
  } catch { /* socket optional */ }

  const startTime = Date.now();

  try {
    const cred = await prisma.gcpCredential.findUnique({ where: { projectId } });
    if (!cred) throw new Error('No GCP credentials configured for this project');

    const decrypted = decryptGcpCredentials(cred);

    const project = await prisma.gcpProject.findUnique({
      where:  { id: projectId },
      select: { projectId: true },
    });
    if (!project) throw new Error('GCP project record not found');

    // Parse service account JSON key if provided
    let credentials: Record<string, unknown> | undefined;
    if (decrypted.serviceAccountKey) {
      try {
        credentials = JSON.parse(decrypted.serviceAccountKey);
      } catch {
        throw new Error('Invalid service account key JSON');
      }
    }

    const { GcpScanEngine } = await import('../../../src/gcp/engine');
    const engine = new GcpScanEngine();
    const report = await engine.executeScan({
      services,
      credentials: {
        projectId:           project.projectId,
        credentials,
        serviceAccountEmail: decrypted.serviceAccountEmail,
      },
    });

    // ── Deduplication ────────────────────────────────────────────────────────
    function resourceFingerprint(evidence: unknown): string {
      const e = (evidence ?? {}) as Record<string, unknown>;
      for (const key of [
        'resourceName', 'resource', 'instance', 'cluster', 'bucket',
        'secret', 'key', 'dataset', 'topic', 'subscription',
        'function', 'service', 'repository', 'name', 'id',
      ]) {
        if (e[key] != null) return String(e[key]);
      }
      return 'project-level';
    }

    const existing = await prisma.gcpFinding.findMany({
      where: {
        scan: { projectId },
        findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
      },
      select: { service: true, title: true, evidence: true },
    });

    const existingKeys = new Set(
      existing.map(f => `${f.service}:${f.title}:${resourceFingerprint(f.evidence)}`),
    );

    const toInsert = report.findings
      .map(f => ({
        scanId,
        service:       f.service,
        severity:      f.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
        title:         f.title,
        description:   f.description,
        evidence:      (f.evidence ?? {}) as Prisma.InputJsonValue,
        remediation:   f.remediation,
        findingStatus: 'OPEN' as const,
        tags:          f.tags ?? [],
        resourceName:  (f.evidence as any)?.resourceName ?? (f.evidence as any)?.resource ?? null,
        region:        (f.evidence as any)?.region ?? (f.evidence as any)?.location ?? null,
        discoveredAt:  f.timestamp ?? new Date(),
      }))
      .filter(f => {
        const key = `${f.service}:${f.title}:${resourceFingerprint(f.evidence)}`;
        if (existingKeys.has(key)) return false;
        existingKeys.add(key);
        return true;
      });

    if (toInsert.length > 0) {
      await prisma.gcpFinding.createMany({ data: toInsert });
      try {
        const { enrichRecentFindings } = await import('../services/riskScoringService');
        await enrichRecentFindings('GCP', scanId);
      } catch (err) {
        logger.warn('gcpScanWorker.risk-enrich-failed', { scanId, error: (err as Error).message });
      }
    }

    try {
      const { enqueueGraphBuild } = await import('./graphBuildWorker');
      await enqueueGraphBuild({ provider: 'GCP', accountId: projectId, triggeredBy: 'SCAN' });
    } catch (err) {
      logger.warn('gcpScanWorker.graph-enqueue-failed', { scanId, error: (err as Error).message });
    }

    try {
      const { enqueueEvidenceRefresh } = await import('./evidenceWorker');
      await enqueueEvidenceRefresh({ provider: 'GCP', accountId: projectId, triggeredBy: 'SCAN' });
    } catch (err) {
      logger.warn('gcpScanWorker.evidence-enqueue-failed', { scanId, error: (err as Error).message });
    }

    await prisma.gcpScanSummary.create({
      data: {
        scanId,
        critical: report.summary.critical,
        high:     report.summary.high,
        medium:   report.summary.medium,
        low:      report.summary.low,
        info:     report.summary.info,
        total:    report.totalFindings,
      },
    });

    const durationMs = Date.now() - startTime;
    await prisma.gcpScan.update({
      where: { id: scanId },
      data:  { status: 'COMPLETED', completedAt: new Date(), durationMs },
    });

    try {
      const io = getIO();
      io.to(`gcp-scan:${scanId}`).emit('gcp-scan:completed', {
        scanId, completedAt: new Date(), durationMs, summary: report.summary,
      });
    } catch { /* socket optional */ }

    logger.info(`GCP scan completed: ${scanId}`, { durationMs, totalFindings: report.totalFindings });
  } catch (err) {
    const errorMessage = (err as Error).message;
    logger.error(`GCP scan failed: ${scanId}`, { error: errorMessage });

    await prisma.gcpScan.update({
      where: { id: scanId },
      data:  { status: 'FAILED', completedAt: new Date(), durationMs: Date.now() - startTime, errorMessage },
    });

    try {
      const io = getIO();
      io.to(`gcp-scan:${scanId}`).emit('gcp-scan:failed', { scanId, error: errorMessage });
    } catch { /* socket optional */ }

    throw err;
  }
}

export function createGcpScanWorker(): Worker<GcpScanJobData> {
  const worker = new Worker<GcpScanJobData>('gcp-scans', processGcpScanJob, {
    connection: redis,
    concurrency: 2,
  });

  worker.on('completed', job => logger.info(`GCP scan job ${job.id} completed`));
  worker.on('failed',    (job, err) => logger.error(`GCP scan job ${job?.id} failed`, { error: err.message }));
  worker.on('error',     err => logger.error('GCP scan worker error', { error: err.message }));

  return worker;
}

export default createGcpScanWorker;

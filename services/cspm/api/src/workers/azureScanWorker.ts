import { Worker, Job, Queue } from 'bullmq';
import { Prisma }             from '@prisma/client';
import { redis }              from '../config/redis';
import { prisma }             from '../config/database';
import { logger }             from '../config/logger';
import { getIO }              from '../socket/index';
import { decryptAzureCredentials } from '../services/azureCredentialService';
// AzureScanEngine is lazy-loaded inside the job to avoid loading all ARM SDKs at startup

interface AzureScanJobData {
  scanId:         string;
  subscriptionId: string;
  services:       string[];
}

export const azureScanQueue = new Queue<AzureScanJobData>('azure-scans', {
  connection: redis,
});

async function processAzureScanJob(job: Job<AzureScanJobData>): Promise<void> {
  const { scanId, subscriptionId, services } = job.data;
  logger.info(`Starting Azure scan job: ${scanId}`, { subscriptionId, services });

  await prisma.azureScan.update({
    where: { id: scanId },
    data:  { status: 'RUNNING', startedAt: new Date() },
  });

  try {
    const io = getIO();
    io.to(`azure-scan:${scanId}`).emit('azure-scan:started', { scanId, startedAt: new Date() });
  } catch { /* socket optional */ }

  const startTime = Date.now();

  try {
    // Load credential
    const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId } });
    if (!cred) throw new Error('No Azure credentials configured for this subscription');

    const decrypted = decryptAzureCredentials(cred);

    // Load the subscription's Azure subscription ID (the actual Azure GUID)
    const subscription = await prisma.azureSubscription.findUnique({
      where: { id: subscriptionId },
      select: { subscriptionId: true },
    });
    if (!subscription) throw new Error('Azure subscription record not found');

    // Run the scan engine (lazy-loaded to avoid slow startup)
    const { AzureScanEngine } = await import('../../../src/azure/engine');
    const engine = new AzureScanEngine();
    const report = await engine.executeScan({
      services,
      credentials: {
        subscriptionId: subscription.subscriptionId,
        tenantId:       decrypted.tenantId,
        clientId:       decrypted.clientId,
        clientSecret:   decrypted.clientSecret,
        authMethod:     cred.authMethod as 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY',
      },
    });

    // ── Deduplication (same pattern as AWS worker) ────────────────────────
    function resourceFingerprint(evidence: unknown): string {
      const e = (evidence ?? {}) as Record<string, unknown>;
      for (const key of [
        'resourceId', 'vault', 'account', 'server', 'database',
        'cluster', 'nsg', 'rule', 'app', 'vm', 'name', 'id',
      ]) {
        if (e[key] != null) return String(e[key]);
      }
      return 'subscription-level';
    }

    const existing = await prisma.azureFinding.findMany({
      where: {
        scan: { subscriptionId },
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
        resourceGroup: (f.evidence as any)?.resourceGroup ?? null,
        resourceId:    (f.evidence as any)?.resourceId ?? null,
        discoveredAt:  f.timestamp ?? new Date(),
      }))
      .filter(f => {
        const key = `${f.service}:${f.title}:${resourceFingerprint(f.evidence)}`;
        if (existingKeys.has(key)) return false;
        existingKeys.add(key);
        return true;
      });

    if (toInsert.length > 0) {
      await prisma.azureFinding.createMany({ data: toInsert });
      try {
        const { enrichRecentFindings } = await import('../services/riskScoringService');
        await enrichRecentFindings('AZURE', scanId);
      } catch (err) {
        logger.warn('azureScanWorker.risk-enrich-failed', { scanId, error: (err as Error).message });
      }
    }

    try {
      const { enqueueGraphBuild } = await import('./graphBuildWorker');
      await enqueueGraphBuild({ provider: 'AZURE', accountId: subscriptionId, triggeredBy: 'SCAN' });
    } catch (err) {
      logger.warn('azureScanWorker.graph-enqueue-failed', { scanId, error: (err as Error).message });
    }

    try {
      const { enqueueEvidenceRefresh } = await import('./evidenceWorker');
      await enqueueEvidenceRefresh({ provider: 'AZURE', accountId: subscriptionId, triggeredBy: 'SCAN' });
    } catch (err) {
      logger.warn('azureScanWorker.evidence-enqueue-failed', { scanId, error: (err as Error).message });
    }

    await prisma.azureScanSummary.create({
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
    await prisma.azureScan.update({
      where: { id: scanId },
      data:  { status: 'COMPLETED', completedAt: new Date(), durationMs },
    });

    try {
      const io = getIO();
      io.to(`azure-scan:${scanId}`).emit('azure-scan:completed', {
        scanId, completedAt: new Date(), durationMs, summary: report.summary,
      });
    } catch { /* socket optional */ }

    logger.info(`Azure scan completed: ${scanId}`, { durationMs, totalFindings: report.totalFindings });
  } catch (err) {
    const errorMessage = (err as Error).message;
    logger.error(`Azure scan failed: ${scanId}`, { error: errorMessage });

    await prisma.azureScan.update({
      where: { id: scanId },
      data:  { status: 'FAILED', completedAt: new Date(), durationMs: Date.now() - startTime, errorMessage },
    });

    try {
      const io = getIO();
      io.to(`azure-scan:${scanId}`).emit('azure-scan:failed', { scanId, error: errorMessage });
    } catch { /* socket optional */ }

    throw err;
  }
}

export function createAzureScanWorker(): Worker<AzureScanJobData> {
  const worker = new Worker<AzureScanJobData>('azure-scans', processAzureScanJob, {
    connection: redis,
    concurrency: 2,
  });

  worker.on('completed', job => logger.info(`Azure scan job ${job.id} completed`));
  worker.on('failed',    (job, err) => logger.error(`Azure scan job ${job?.id} failed`, { error: err.message }));
  worker.on('error',     err => logger.error('Azure scan worker error', { error: err.message }));

  return worker;
}

export default createAzureScanWorker;

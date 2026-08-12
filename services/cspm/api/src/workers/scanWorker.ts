import { Worker, Job } from 'bullmq';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { redis } from '../config/redis';
import { prisma } from '../config/database';
import { logger } from '../config/logger';
import * as credentialService from '../services/credentialService';
import { dedupKey } from '../services/dedupService';
import { getIO } from '../socket/index';
import { ScanEngine } from '../../../src/scanners/engine';
import type { ScanOptions } from '../../../src/utils/types';

interface ScanJobData {
  scanId: string;
  accountId: string;
  services: string[];
  regions: string[];
}

async function processScanJob(job: Job<ScanJobData>): Promise<void> {
  const { scanId, accountId, services, regions } = job.data;

  logger.info(`Starting scan job: ${scanId}`, { accountId, services, regions });

  // Update scan to RUNNING
  await prisma.scan.update({
    where: { id: scanId },
    data: {
      status: 'RUNNING',
      startedAt: new Date(),
    },
  });

  // Emit scan:started event
  try {
    const io = getIO();
    io.to(`scan:${scanId}`).emit('scan:started', { scanId, startedAt: new Date() });
  } catch (socketErr) {
    logger.warn('Could not emit scan:started event', { error: (socketErr as Error).message });
  }

  const startTime = Date.now();

  try {
    // Get account + credentials
    const cred = await prisma.awsCredential.findUnique({ where: { accountId } });

    if (!cred) {
      throw new Error('No credentials configured for this account');
    }

    const decrypted = credentialService.decryptCredentials(cred);

    if (cred.authMethod === 'ACCESS_KEY' && (!decrypted.accessKeyId || !decrypted.secretAccessKey)) {
      throw new Error('Missing access key credentials');
    }
    if (cred.authMethod === 'ASSUME_ROLE' && (!decrypted.accessKeyId || !decrypted.secretAccessKey || !cred.roleArn)) {
      throw new Error('ASSUME_ROLE requires accessKeyId, secretAccessKey and roleArn');
    }

    let explicitCredentials: ScanOptions['_explicitCredentials'] = {
      accessKeyId: decrypted.accessKeyId!,
      secretAccessKey: decrypted.secretAccessKey!,
      region: cred.defaultRegion,
    };

    // Handle ASSUME_ROLE: call STS to get temporary credentials
    if (cred.authMethod === 'ASSUME_ROLE' && cred.roleArn) {
      const stsClient = new STSClient({
        region: cred.defaultRegion,
        credentials: {
          accessKeyId: decrypted.accessKeyId!,
          secretAccessKey: decrypted.secretAccessKey!,
        },
      });

      const assumed = await stsClient.send(new AssumeRoleCommand({
        RoleArn: cred.roleArn,
        RoleSessionName: `scanner-${scanId.slice(0, 16)}`,
        DurationSeconds: 3600,
        ...(cred.externalId ? { ExternalId: cred.externalId } : {}),
      }));

      if (!assumed.Credentials) {
        throw new Error('STS AssumeRole returned no credentials');
      }

      explicitCredentials = {
        accessKeyId: assumed.Credentials.AccessKeyId!,
        secretAccessKey: assumed.Credentials.SecretAccessKey!,
        sessionToken: assumed.Credentials.SessionToken,
        region: cred.defaultRegion,
      };
    }

    // Find the last successfully completed scan for this account (for ECR smart-skip)
    const lastCompletedScan = await prisma.scan.findFirst({
      where: { accountId, status: 'COMPLETED', id: { not: scanId } },
      orderBy: { completedAt: 'desc' },
      select: { completedAt: true },
    });

    // Run scan via ScanEngine
    const engine = new ScanEngine();
    const scanOptions: ScanOptions = {
      services,
      regions,
      _explicitCredentials: explicitCredentials,
      lastScanAt: lastCompletedScan?.completedAt ?? undefined,
    };

    const report = await engine.executeScan(scanOptions);

    // ── Deduplication ──────────────────────────────────────────────────────
    // See dedupService.ts for the fingerprint/key logic and why checkId is
    // preferred over service:title. Extracted there so it's unit-testable.

    // Fetch all existing active findings for this account in one query
    const existingFindings = await prisma.finding.findMany({
      where: {
        scan: { accountId },
        findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
      },
      select: { service: true, title: true, checkId: true, evidence: true },
    });

    const existingKeys = new Set(
      existingFindings.map(
        (f) => dedupKey(f.service, f.title, f.checkId, f.evidence),
      ),
    );

    // Partition: new findings vs already-known
    const findingData = report.findings.map((finding) => ({
      scanId,
      checkId: finding.checkId ?? null,
      service: finding.service,
      severity: finding.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
      title: finding.title,
      description: finding.description,
      evidence: finding.evidence ?? {},
      remediation: finding.remediation,
      findingStatus: 'OPEN' as const,
      tags: finding.tags || [],
      discoveredAt: finding.timestamp || new Date(),
    }));

    // Use accumulated set: prevents duplicates both against the DB (existingKeys)
    // AND within the current batch (two findings with the same key in one scan run).
    const seenKeys = new Set<string>(existingKeys);
    const toInsert = findingData.filter((f) => {
      const key = dedupKey(f.service, f.title, f.checkId, f.evidence);
      if (seenKeys.has(key)) return false;
      seenKeys.add(key);
      return true;
    });
    const skippedCount = findingData.length - toInsert.length;

    if (skippedCount > 0) {
      logger.info(
        `Dedup: skipped ${skippedCount} finding(s) already tracked as OPEN/ACKNOWLEDGED`,
        { scanId, skippedCount, newCount: toInsert.length },
      );
    }

    if (toInsert.length > 0) {
      await prisma.finding.createMany({ data: toInsert });
      try {
        const { enrichRecentFindings } = await import('../services/riskScoringService');
        await enrichRecentFindings('AWS', scanId);
      } catch (err) {
        logger.warn('scanWorker.risk-enrich-failed', { scanId, error: (err as Error).message });
      }
    }

    // Enqueue asset-graph rebuild + risk enrichment for this account.
    // Failures here must not block the scan finalization.
    try {
      const { enqueueGraphBuild } = await import('./graphBuildWorker');
      await enqueueGraphBuild({ provider: 'AWS', accountId, triggeredBy: 'SCAN' });
    } catch (err) {
      logger.warn('scanWorker.graph-enqueue-failed', { scanId, error: (err as Error).message });
    }

    try {
      const { enqueueEvidenceRefresh } = await import('./evidenceWorker');
      await enqueueEvidenceRefresh({ provider: 'AWS', accountId, triggeredBy: 'SCAN' });
    } catch (err) {
      logger.warn('scanWorker.evidence-enqueue-failed', { scanId, error: (err as Error).message });
    }

    // Create ScanSummary reflecting what this scan detected in total
    // (both new and already-known), so trend data stays accurate.
    await prisma.scanSummary.create({
      data: {
        scanId,
        critical: report.summary.critical,
        high: report.summary.high,
        medium: report.summary.medium,
        low: report.summary.low,
        info: report.summary.info,
        total: report.totalFindings,
      },
    });

    const durationMs = Date.now() - startTime;

    // Update scan to COMPLETED
    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'COMPLETED',
        completedAt: new Date(),
        durationMs,
      },
    });

    const summary = report.summary;

    // Emit scan:completed event
    try {
      const io = getIO();
      io.to(`scan:${scanId}`).emit('scan:completed', {
        scanId,
        completedAt: new Date(),
        durationMs,
        summary,
      });
    } catch (socketErr) {
      logger.warn('Could not emit scan:completed event', { error: (socketErr as Error).message });
    }

    logger.info(`Scan completed: ${scanId}`, { durationMs, totalFindings: report.totalFindings });
  } catch (err) {
    const errorMessage = (err as Error).message;
    logger.error(`Scan failed: ${scanId}`, { error: errorMessage });

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'FAILED',
        completedAt: new Date(),
        durationMs: Date.now() - startTime,
        errorMessage,
      },
    });

    // Emit scan:failed event
    try {
      const io = getIO();
      io.to(`scan:${scanId}`).emit('scan:failed', {
        scanId,
        error: errorMessage,
        failedAt: new Date(),
      });
    } catch (socketErr) {
      logger.warn('Could not emit scan:failed event', { error: (socketErr as Error).message });
    }

    throw err;
  }
}

export function createScanWorker(): Worker<ScanJobData> {
  const worker = new Worker<ScanJobData>('scans', processScanJob, {
    connection: redis,
    concurrency: 3,
    // Full AWS scans run for minutes; the default 30s lock expires mid-scan and
    // causes "could not renew lock" + duplicate stalled re-runs. Give the job a
    // long lock and match the stalled-check cadence to it.
    lockDuration: 600000,      // 10 min
    stalledInterval: 600000,   // 10 min
    maxStalledCount: 1,
  });

  worker.on('completed', (job) => {
    logger.info(`Job ${job.id} completed`);
  });

  worker.on('failed', (job, err) => {
    logger.error(`Job ${job?.id} failed`, { error: err.message });
  });

  worker.on('error', (err) => {
    logger.error('Worker error', { error: err.message });
  });

  return worker;
}

export default createScanWorker;

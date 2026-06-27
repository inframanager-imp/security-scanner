/**
 * Azure Threat Monitor Worker
 *
 * BullMQ worker processing repeatable 'monitor-azure' jobs.
 * Each job polls Azure Monitor Activity Logs and NSG changes for new threat
 * indicators since the last check, saves findings to DB, emits Socket.IO events.
 *
 * Job interval: every 2 minutes per subscription.
 */

import { Worker, Job } from 'bullmq';
import { Prisma }      from '@prisma/client';
import { redis }       from '../config/redis';
import { prisma }      from '../config/database';
import { logger }      from '../config/logger';
import { getIO }       from '../socket/index';
import { decryptAzureCredentials } from '../services/azureCredentialService';
import {
  AZURE_THREAT_QUEUE,
  getAzureLastCheck,
  setAzureLastCheck,
  markAzureEventSeen,
} from '../services/azureThreatMonitorService';
import AzureClient     from '../../../src/azure/client';
import { AzureThreatScanner } from '../../../src/azure/scanners/threatScanner';
import { analyzeEvent, normalizeAzureEvent } from '../services/anomalyEngine';

interface MonitorJobData {
  subscriptionId: string; // internal DB id
}

function evidenceFingerprint(evidence: unknown): string {
  const e = (evidence ?? {}) as Record<string, unknown>;
  for (const key of ['principal', 'nsg', 'caller', 'account', 'vaults', 'resourceGroup', 'id']) {
    if (e[key] != null) return String(e[key]);
  }
  return 'subscription-level';
}

async function processAzureMonitorJob(job: Job<MonitorJobData>): Promise<void> {
  const { subscriptionId } = job.data;

  try {
    // ── 1. Load credentials ────────────────────────────────────────────────
    const cred = await prisma.azureCredential.findUnique({ where: { subscriptionId } });
    if (!cred) {
      logger.warn(`Azure threat monitor: no credentials for subscription ${subscriptionId}`);
      return;
    }

    const sub = await prisma.azureSubscription.findUnique({
      where: { id: subscriptionId },
      select: { subscriptionId: true },
    });
    if (!sub) return;

    const decrypted = decryptAzureCredentials(cred);

    const client = new AzureClient({
      subscriptionId: sub.subscriptionId,
      tenantId:       decrypted.tenantId,
      clientId:       decrypted.clientId,
      clientSecret:   decrypted.clientSecret,
      authMethod:     cred.authMethod as 'SERVICE_PRINCIPAL' | 'MANAGED_IDENTITY',
    });

    // ── 2. Time window ─────────────────────────────────────────────────────
    const since    = await getAzureLastCheck(subscriptionId);
    const checkEnd = new Date();

    logger.debug(`Azure threat monitor [${subscriptionId}]: ${since.toISOString()} → ${checkEnd.toISOString()}`);

    // ── 3. Run incremental threat scan ─────────────────────────────────────
    const scanner = new AzureThreatScanner(client);
    const findings = await scanner.scanSince(since);

    // ── 3b. ML anomaly detection on raw Activity Log events ─────────────────
    try {
      const rawEvents = await (scanner as any).getRawEvents?.(since) ?? [];
      for (const rawEvent of rawEvents) {
        const normalized = normalizeAzureEvent(rawEvent as Record<string, unknown>, subscriptionId);
        if (normalized) await analyzeEvent(normalized);
      }
    } catch (anomalyErr) {
      logger.debug(`Azure anomaly scan skipped: ${(anomalyErr as Error).message}`);
    }

    // ── 4. Deduplicate ─────────────────────────────────────────────────────
    const newFindings: typeof findings = [];

    for (const finding of findings) {
      const correlationId = (finding.evidence as any)?.eventCorrelationId as string | undefined;
      if (correlationId) {
        const isNew = await markAzureEventSeen(subscriptionId, correlationId);
        if (!isNew) continue;
      }

      const fingerprint = `${finding.service}:${finding.title}:${evidenceFingerprint(finding.evidence)}`;
      const existing = await prisma.azureFinding.findFirst({
        where: {
          scan: { subscriptionId },
          findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
          service: finding.service,
          title:   finding.title,
        },
        select: { id: true, evidence: true },
      });

      if (existing) {
        const existingFp = `${finding.service}:${finding.title}:${evidenceFingerprint(existing.evidence)}`;
        if (existingFp === fingerprint) continue;
      }

      newFindings.push(finding);
    }

    if (newFindings.length === 0) {
      emitAzureHeartbeat(subscriptionId, checkEnd, 0);
      await setAzureLastCheck(subscriptionId, checkEnd);
      return;
    }

    // ── 5. Get or create MONITORING scan record ─────────────────────────────
    let monitorScan = await prisma.azureScan.findFirst({
      where: { subscriptionId, status: 'MONITORING' },
      orderBy: { createdAt: 'desc' },
    });

    if (!monitorScan) {
      monitorScan = await prisma.azureScan.create({
        data: {
          subscriptionId,
          status:   'MONITORING',
          services: ['threat'],
        },
      });
    }

    // ── 6. Persist findings ────────────────────────────────────────────────
    const created = await prisma.azureFinding.createMany({
      data: newFindings.map(f => ({
        scanId:        monitorScan!.id,
        service:       f.service,
        severity:      f.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
        title:         f.title,
        description:   f.description,
        evidence:      (f.evidence ?? {}) as Prisma.InputJsonValue,
        remediation:   f.remediation,
        findingStatus: 'OPEN' as const,
        tags:          f.tags ?? [],
        resourceGroup: (f.evidence as any)?.resourceGroup ?? null,
        resourceId:    (f.evidence as any)?.resourceId    ?? null,
        discoveredAt:  f.timestamp ?? new Date(),
      })),
    });

    logger.info(`Azure threat monitor [${subscriptionId}]: ${created.count} new threat(s)`);

    // ── 7. Socket.IO ───────────────────────────────────────────────────────
    try {
      const io = getIO();

      for (const f of newFindings) {
        io.to(`azure-threats:${subscriptionId}`).emit('azure-threat:detected', {
          subscriptionId,
          finding: {
            title:          f.title,
            severity:       f.severity,
            description:    f.description,
            threatCategory: (f.evidence as any)?.threatCategory,
            principal:      (f.evidence as any)?.principal ?? (f.evidence as any)?.caller,
            eventTime:      (f.evidence as any)?.firstEvent,
          },
          detectedAt: new Date().toISOString(),
        });
      }

      io.to('azure-threats:all').emit('azure-threat:detected', {
        subscriptionId,
        count: newFindings.length,
        highestSeverity: newFindings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
          : newFindings.some(f => f.severity === 'HIGH') ? 'HIGH' : 'MEDIUM',
        detectedAt: new Date().toISOString(),
      });

      emitAzureHeartbeat(subscriptionId, checkEnd, created.count);
    } catch (socketErr) {
      logger.warn('Azure threat: could not emit Socket.IO events', { error: (socketErr as Error).message });
    }

    await setAzureLastCheck(subscriptionId, checkEnd);

  } catch (err) {
    logger.error(`Azure threat monitor job failed for ${subscriptionId}`, { error: (err as Error).message });
    // Don't throw — keep the repeatable job running
  }
}

function emitAzureHeartbeat(subscriptionId: string, checkedAt: Date, newThreats: number): void {
  try {
    const io = getIO();
    const payload = { subscriptionId, checkedAt: checkedAt.toISOString(), newThreats };
    io.to(`azure-threats:${subscriptionId}`).emit('azure-threat:heartbeat', payload);
    io.to('azure-threats:all').emit('azure-threat:heartbeat', payload);
  } catch { /* socket not ready */ }
}

export function createAzureThreatMonitorWorker(): Worker {
  const worker = new Worker<MonitorJobData>(
    AZURE_THREAT_QUEUE,
    processAzureMonitorJob,
    {
      connection: redis,
      concurrency: 3,
    },
  );

  worker.on('completed', job => {
    logger.debug(`Azure threat monitor job completed: ${job.data.subscriptionId}`);
  });
  worker.on('failed', (job, err) => {
    logger.error(`Azure threat monitor job failed: ${job?.data.subscriptionId}`, { error: err.message });
  });

  return worker;
}

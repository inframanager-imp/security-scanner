// Polyfill globalThis.crypto for Node.js < 19 (required by @azure/core-util and ARM SDKs)
if (!globalThis.crypto) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { webcrypto } = require('crypto') as typeof import('crypto');
  (globalThis as Record<string, unknown>).crypto = webcrypto;
}

import './config/env'; // Load and validate env first
import http from 'http';
import app from './app';
import { env } from './config/env';
import { logger } from './config/logger';
import { prisma } from './config/database';
import { initSocket } from './socket/index';
import { createScanWorker } from './workers/scanWorker';
import { createThreatMonitorWorker } from './workers/threatMonitorWorker';
import { createAzureScanWorker } from './workers/azureScanWorker';
import { createAzureThreatMonitorWorker } from './workers/azureThreatMonitorWorker';
import { createGcpScanWorker } from './workers/gcpScanWorker';
import { createGcpAnomalyWorker } from './workers/gcpAnomalyWorker';
import { createGraphBuildWorker } from './workers/graphBuildWorker';
import { createEvidenceWorker } from './workers/evidenceWorker';
import { createCwppWorker } from './workers/cwppScanWorker';
import { createDspmWorker } from './workers/dspmScanWorker';
import { resumeAllMonitors, startMonitoring } from './services/threatMonitorService';
import { resumeAllAzureMonitors, startAzureMonitoring } from './services/azureThreatMonitorService';
import { seed } from './seed';

async function main(): Promise<void> {
  // Create HTTP server
  const server = http.createServer(app);

  // Initialize Socket.IO
  initSocket(server);
  logger.info('Socket.IO initialized');

  // Connect to database
  await prisma.$connect();
  logger.info('Database connected');

  // Run seed on first start
  await seed();

  // Start BullMQ scan worker
  const worker = createScanWorker();
  logger.info('Scan worker started');

  // Start real-time threat monitor worker and resume any active monitors
  const threatWorker = createThreatMonitorWorker();
  logger.info('Threat monitor worker started');

  // Start Azure scan worker
  const azureWorker = createAzureScanWorker();
  logger.info('Azure scan worker started');

  // Start Azure threat monitor worker and resume active monitors
  const azureThreatWorker = createAzureThreatMonitorWorker();
  logger.info('Azure threat monitor worker started');

  // Start GCP scan worker
  const gcpWorker = createGcpScanWorker();
  logger.info('GCP scan worker started');

  // Start GCP anomaly monitor worker
  const gcpAnomalyWorker = createGcpAnomalyWorker();
  logger.info('GCP anomaly monitor worker started');

  // Start asset graph build worker (powers CIEM, attack paths, risk prioritization)
  const graphWorker = createGraphBuildWorker();
  logger.info('Graph build worker started');

  // Start compliance evidence auto-refresh worker
  const evidenceWorker = createEvidenceWorker();
  logger.info('Evidence worker started');

  // Start CWPP agentless workload scan worker
  const cwppWorker = createCwppWorker();
  logger.info('CWPP worker started');

  // Start DSPM sensitive-data discovery worker
  const dspmWorker = createDspmWorker();
  logger.info('DSPM worker started');

  // Resume monitors that were previously manually started
  await resumeAllMonitors();
  await resumeAllAzureMonitors();

  // Auto-start threat monitoring for ALL READY accounts/subscriptions
  // so monitoring is active without requiring a manual UI click
  try {
    const [readyAccounts, readySubs] = await Promise.all([
      prisma.account.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
      prisma.azureSubscription.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
    ]);
    await Promise.allSettled([
      ...readyAccounts.map(a => startMonitoring(a.id)),
      ...readySubs.map(s => startAzureMonitoring(s.id)),
    ]);
    logger.info(`Auto-started threat monitoring for ${readyAccounts.length} AWS + ${readySubs.length} Azure targets`);
  } catch (err) {
    logger.warn('Auto-start threat monitoring failed (non-fatal)', { error: (err as Error).message });
  }

  // Start listening
  const port = env.PORT;
  server.listen(port, () => {
    logger.info(`AWS Scanner API running on port ${port}`, {
      env: env.NODE_ENV,
      port,
    });
  });

  // Graceful shutdown
  const shutdown = async (signal: string): Promise<void> => {
    logger.info(`Received ${signal}, starting graceful shutdown...`);

    server.close(async () => {
      logger.info('HTTP server closed');

      try {
        await Promise.all([worker.close(), threatWorker.close(), azureWorker.close(), azureThreatWorker.close(), gcpWorker.close(), gcpAnomalyWorker.close(), graphWorker.close(), evidenceWorker.close(), cwppWorker.close(), dspmWorker.close()]);
        logger.info('Workers closed');
      } catch (err) {
        logger.error('Error closing workers', { error: (err as Error).message });
      }

      try {
        await prisma.$disconnect();
        logger.info('Database disconnected');
      } catch (err) {
        logger.error('Error disconnecting database', { error: (err as Error).message });
      }

      process.exit(0);
    });

    // Force exit after 30 seconds
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled promise rejection', { reason });
  });

  process.on('uncaughtException', (err) => {
    logger.error('Uncaught exception', { error: err.message, stack: err.stack });
    process.exit(1);
  });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

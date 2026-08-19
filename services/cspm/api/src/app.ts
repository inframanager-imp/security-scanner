import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { env } from './config/env';
import { logger } from './config/logger';
import { prisma } from './config/database';
import { errorHandler } from './middleware/errorHandler';
import authRouter from './routes/auth';
import accountsRouter from './routes/accounts';
import scansRouter from './routes/scans';
import dashboardRouter from './routes/dashboard';
import findingsRouter from './routes/findings';
import cloudtrailRouter from './routes/cloudtrail';
import complianceRouter from './routes/compliance';
import threatsRouter from './routes/threats';
import azureSubscriptionsRouter from './routes/azureSubscriptions';
import azureScansRouter from './routes/azureScans';
import azureActivityLogsRouter from './routes/azureActivityLogs';
import azureComplianceRouter from './routes/azureCompliance';
import azureThreatsRouter from './routes/azureThreats';
import gcpProjectsRouter from './routes/gcpProjects';
import gcpScansRouter from './routes/gcpScans';
import configChangesRouter    from './routes/configChanges';
import resourceInventoryRouter from './routes/resourceInventory';
import graphRouter             from './routes/graph';
import ciemRouter              from './routes/ciem';
import cwppRouter              from './routes/cwpp';
import dspmRouter              from './routes/dspm';
import alertsRouter            from './routes/alerts';
import freezeWindowsRouter     from './routes/freezeWindows';
import postureScoreRouter      from './routes/postureScore';
import baselinesRouter         from './routes/baselines';
import approvalsRouter         from './routes/approvals';
import reportSchedulesRouter   from './routes/reportSchedules';
import vaptReportsRouter       from './routes/vaptReports';
import integrationsRouter      from './routes/integrations';
import iamEscalationRouter     from './routes/iamEscalation';
import iamUsersRouter          from './routes/iamUsers';
import riskRegisterRouter      from './routes/riskRegister';
import anomalyRouter           from './routes/anomaly';
import configSyncWebhookRouter from './routes/configSyncWebhook';
import { runPostureScoreUpdate }      from './services/postureScoreService';
import { processScheduledReports }    from './services/reportService';
import { runDriftForTarget }          from './services/baselineService';
import { expireStaleApprovals }       from './services/approvalService';
import { resumeAllConfigSyncJobs }    from './services/configSyncMonitorService';
import { createConfigSyncWorker }     from './workers/configSyncWorker';
import { runPeriodicDiscovery }       from './services/inventoryPipeline';

const app = express();

app.use(helmet());
app.use(
  cors({
    origin: env.CORS_ORIGIN,
    credentials: true,
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Skip rate limiting entirely in development
const isDev = env.NODE_ENV === 'development';

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1_000,
  skip: (req) => isDev || req.path.startsWith('/auth'),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip ?? 'unknown',
  message: { error: 'Too many requests, please try again later' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  skip: () => isDev,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip ?? 'unknown',
  message: { error: 'Too many auth requests, please try again later' },
});

app.use('/api', generalLimiter);
app.use('/api/auth/login',   authLimiter);
app.use('/api/auth/refresh', authLimiter);
// logout is never rate-limited — blocking it would trap users in a broken session

app.use((req, _res, next) => {
  logger.debug(`${req.method} ${req.path}`, { query: req.query });
  next();
});

app.get('/api/health', (_req, res) => {
  res.json({ data: { status: 'ok', timestamp: new Date().toISOString() } });
});

app.use('/api/auth', authRouter);
app.use('/api/accounts', accountsRouter);
app.use('/api/scans', scansRouter);
app.use('/api/dashboard', dashboardRouter);
app.use('/api/findings', findingsRouter);
app.use('/api/cloudtrail', cloudtrailRouter);
app.use('/api/compliance', complianceRouter);
app.use('/api/threats', threatsRouter);
app.use('/api/azure/subscriptions', azureSubscriptionsRouter);
app.use('/api/azure/scans', azureScansRouter);
app.use('/api/azure/activity-logs', azureActivityLogsRouter);
app.use('/api/azure/compliance', azureComplianceRouter);
app.use('/api/azure/threats', azureThreatsRouter);
app.use('/api/gcp/projects', gcpProjectsRouter);
app.use('/api/gcp/scans', gcpScansRouter);
app.use('/api/config-changes',    configChangesRouter);
app.use('/api/resource-inventory', resourceInventoryRouter);
app.use('/api/graph',             graphRouter);
app.use('/api/ciem',              ciemRouter);
app.use('/api/cwpp',              cwppRouter);
app.use('/api/dspm',              dspmRouter);
app.use('/api/alerts',            alertsRouter);
app.use('/api/freeze-windows',    freezeWindowsRouter);
app.use('/api/posture-score',     postureScoreRouter);
app.use('/api/baselines',         baselinesRouter);
app.use('/api/approvals',         approvalsRouter);
app.use('/api/report-schedules',  reportSchedulesRouter);
app.use('/api/reports',           vaptReportsRouter);
app.use('/api/integrations',      integrationsRouter);
app.use('/api/iam-escalation',    iamEscalationRouter);
app.use('/api/iam-users',         iamUsersRouter);
app.use('/api/risk-register',     riskRegisterRouter);
app.use('/api/anomaly',           anomalyRouter);
app.use('/api/config-sync/webhook', configSyncWebhookRouter);

app.use((_req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ─── Config sync: BullMQ worker + resume all READY targets ────────────────────
createConfigSyncWorker();
void resumeAllConfigSyncJobs().catch((e) =>
  logger.warn('[config-sync] Failed to resume jobs on startup', { error: (e as Error).message })
);

let _driftScanRunning = false;
setInterval(() => {
  if (_driftScanRunning) return;
  _driftScanRunning = true;
  void (async () => {
    try {
      const baselines = await prisma.configBaseline.findMany({
        where:  { isActive: true },
        select: { id: true, provider: true, targetId: true, name: true },
      });
      await Promise.allSettled(
        baselines.map(b => runDriftForTarget(b.provider, b.targetId))
      );
    } catch (err) {
      logger.warn('[drift-scan] Periodic drift scan failed', { error: (err as Error).message });
    } finally {
      _driftScanRunning = false;
    }
  })();
}, 5 * 60 * 1000);

setInterval(() => { void runPostureScoreUpdate(); }, 60 * 1000);

setInterval(() => { void processScheduledReports(); }, 60 * 1000);

setInterval(() => { void expireStaleApprovals(); }, 15 * 60 * 1000);

void runPeriodicDiscovery().catch((e) =>
  logger.warn('[discovery] Startup discovery check failed', { error: (e as Error).message })
);
setInterval(() => { void runPeriodicDiscovery(); }, 60 * 60 * 1000);

setInterval(() => {
  void (async () => {
    try {
      const targets = await prisma.configSyncRun.groupBy({ by: ['provider', 'targetId'] });
      for (const { provider, targetId } of targets) {
        const keep = await prisma.configSyncRun.findMany({
          where:   { provider, targetId },
          orderBy: { createdAt: 'desc' },
          take:    50,
          select:  { id: true, createdAt: true },
        });
        if (keep.length === 50) {
          const oldest = keep[keep.length - 1];
          await prisma.configSyncRun.deleteMany({
            where: { provider, targetId, createdAt: { lt: oldest.createdAt } },
          });
        }
      }
    } catch { /* non-fatal */ }
  })();
}, 60 * 60 * 1000);

app.use(errorHandler);

export default app;

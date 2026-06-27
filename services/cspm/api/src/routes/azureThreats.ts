import { Router, Request, Response } from 'express';
import { authenticate } from '../middleware/authenticate';
import { prisma }       from '../config/database';
import {
  startAzureMonitoring,
  stopAzureMonitoring,
  isAzureMonitoring,
  getAzureLastCheck,
  getAzureMonitoredSubscriptions,
} from '../services/azureThreatMonitorService';

const router = Router();
router.use(authenticate);

/**
 * POST /api/azure/threats/monitor/:subscriptionId/start
 */
router.post('/monitor/:subscriptionId/start', async (req: Request, res: Response) => {
  const { subscriptionId } = req.params;

  const sub = await prisma.azureSubscription.findUnique({
    where: { id: subscriptionId },
    select: { id: true, name: true },
  });
  if (!sub) {
    res.status(404).json({ error: 'Azure subscription not found' });
    return;
  }

  const cred = await prisma.azureCredential.findUnique({
    where: { subscriptionId },
    select: { id: true },
  });
  if (!cred) {
    res.status(422).json({ error: 'No Azure credentials configured for this subscription' });
    return;
  }

  await startAzureMonitoring(subscriptionId);
  res.json({
    data: {
      subscriptionId,
      monitoring: true,
      message: `Real-time threat monitoring started for ${sub.name}`,
    },
  });
});

/**
 * POST /api/azure/threats/monitor/:subscriptionId/stop
 */
router.post('/monitor/:subscriptionId/stop', async (req: Request, res: Response) => {
  const { subscriptionId } = req.params;

  const sub = await prisma.azureSubscription.findUnique({
    where: { id: subscriptionId },
    select: { id: true, name: true },
  });
  if (!sub) {
    res.status(404).json({ error: 'Azure subscription not found' });
    return;
  }

  await stopAzureMonitoring(subscriptionId);
  res.json({
    data: {
      subscriptionId,
      monitoring: false,
      message: `Real-time threat monitoring stopped for ${sub.name}`,
    },
  });
});

/**
 * GET /api/azure/threats/monitor/:subscriptionId/status
 */
router.get('/monitor/:subscriptionId/status', async (req: Request, res: Response) => {
  const { subscriptionId } = req.params;

  const [active, lastCheck] = await Promise.all([
    isAzureMonitoring(subscriptionId),
    getAzureLastCheck(subscriptionId).catch(() => null),
  ]);

  res.json({
    data: {
      subscriptionId,
      monitoring:  active,
      lastCheck:   lastCheck?.toISOString() ?? null,
    },
  });
});

/**
 * GET /api/azure/threats/monitor/all
 */
router.get('/monitor/all', async (_req: Request, res: Response) => {
  const subscriptions = await prisma.azureSubscription.findMany({
    select: { id: true, name: true, subscriptionId: true },
  });

  const statuses = await Promise.all(
    subscriptions.map(async sub => {
      const [active, lastCheck] = await Promise.all([
        isAzureMonitoring(sub.id),
        getAzureLastCheck(sub.id).catch(() => null),
      ]);
      return {
        subscriptionId:       sub.id,
        name:                 sub.name,
        azureSubscriptionId:  sub.subscriptionId,
        monitoring:           active,
        lastCheck:            lastCheck?.toISOString() ?? null,
      };
    }),
  );

  res.json({ data: statuses });
});

/**
 * GET /api/azure/threats/findings?subscriptionId=X&severity=HIGH&limit=50
 * Returns threat findings for a subscription.
 */
router.get('/findings', async (req: Request, res: Response) => {
  try {
    const { subscriptionId, severity } = req.query as Record<string, string>;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
    const page  = parseInt(req.query.page  as string) || 1;
    const skip  = (page - 1) * limit;

    if (!subscriptionId) {
      res.status(400).json({ error: 'subscriptionId is required' });
      return;
    }

    const where: Record<string, unknown> = {
      scan: { subscriptionId },
      service: 'Azure-Threat',
    };
    if (severity) where.severity = severity;

    const [findings, total] = await Promise.all([
      prisma.azureFinding.findMany({
        where,
        orderBy: { discoveredAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true, service: true, severity: true, title: true,
          description: true, evidence: true, remediation: true,
          findingStatus: true, tags: true, discoveredAt: true,
          scan: { select: { id: true, createdAt: true } },
        },
      }),
      prisma.azureFinding.count({ where }),
    ]);

    res.json({
      data: findings,
      meta: { total, page, limit, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * GET /api/azure/threats/summary
 * Returns threat counts by category across all monitored subscriptions.
 */
router.get('/summary', async (_req: Request, res: Response) => {
  try {
    const monitoredIds = await getAzureMonitoredSubscriptions();

    const counts = await prisma.azureFinding.groupBy({
      by: ['severity'],
      where: {
        service:       'Azure-Threat',
        findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
        scan: { subscriptionId: { in: monitoredIds } },
      },
      _count: { severity: true },
    });

    const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const row of counts) {
      summary[row.severity as keyof typeof summary] = row._count.severity;
    }

    res.json({
      data: {
        monitoredSubscriptions: monitoredIds.length,
        findings: summary,
        total: Object.values(summary).reduce((a, b) => a + b, 0),
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

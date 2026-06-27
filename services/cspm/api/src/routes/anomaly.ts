import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { getBaselineStats, resetBaselines, seedAwsBaseline, seedAzureBaseline, seedGcpBaseline } from '../services/anomalyBaselineService';

const router = Router();
router.use(authenticate);

// ─── Anomaly Events ───────────────────────────────────────────────────────────

// GET /api/anomaly/events?provider=&accountId=&type=&severity=&status=&limit=
router.get('/events', async (req: Request, res: Response) => {
  try {
    const { provider, accountId, type: anomalyType, severity, status, limit = '100', offset = '0' } = req.query as Record<string, string>;

    const where: Record<string, unknown> = {};
    if (provider)     where.provider    = provider;
    if (accountId)    where.accountId   = accountId;
    if (anomalyType)  where.anomalyType = anomalyType;
    if (severity)     where.severity    = severity;
    if (status)       where.status      = status;

    const [events, total] = await Promise.all([
      prisma.anomalyEvent.findMany({
        where,
        orderBy: { detectedAt: 'desc' },
        take:   Math.min(500, +limit),
        skip:   +offset,
      }),
      prisma.anomalyEvent.count({ where }),
    ]);

    res.json({ data: events, total });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/anomaly/events/:id
router.get('/events/:id', async (req: Request, res: Response) => {
  try {
    const event = await prisma.anomalyEvent.findUnique({ where: { id: req.params.id } });
    if (!event) { res.status(404).json({ error: 'Not found' }); return; }
    res.json({ data: event });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// PATCH /api/anomaly/events/:id — update status / add notes
router.patch('/events/:id', async (req: Request, res: Response) => {
  try {
    const { status, notes } = req.body as { status?: string; notes?: string };
    const update: Record<string, unknown> = {};
    if (status) {
      update.status = status;
      if (status === 'RESOLVED' || status === 'FALSE_POSITIVE') update.resolvedAt = new Date();
    }
    if (notes !== undefined) update.notes = notes;

    const event = await prisma.anomalyEvent.update({ where: { id: req.params.id }, data: update });
    res.json({ data: event });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/anomaly/summary?provider=&accountId=&days=7
// Returns counts by type + severity for dashboard widgets.
router.get('/summary', async (req: Request, res: Response) => {
  try {
    const { provider, accountId, days = '7' } = req.query as Record<string, string>;
    const since = new Date(Date.now() - +days * 86_400_000);
    const where: Record<string, unknown> = { detectedAt: { gte: since } };
    if (provider)  where.provider  = provider;
    if (accountId) where.accountId = accountId;

    const [byType, bySeverity, byStatus, trend] = await Promise.all([
      prisma.anomalyEvent.groupBy({ by: ['anomalyType'], where, _count: { id: true } }),
      prisma.anomalyEvent.groupBy({ by: ['severity'],    where, _count: { id: true } }),
      prisma.anomalyEvent.groupBy({ by: ['status'],      where, _count: { id: true } }),
      // Daily trend — last 7 days
      prisma.$queryRaw<Array<{ day: string; count: bigint }>>`
        SELECT DATE_TRUNC('day', "detectedAt")::text AS day, COUNT(*)::bigint AS count
        FROM "AnomalyEvent"
        WHERE "detectedAt" >= ${since}
          ${provider   ? prisma.$queryRaw`AND provider = ${provider}`   : prisma.$queryRaw``}
          ${accountId  ? prisma.$queryRaw`AND "accountId" = ${accountId}` : prisma.$queryRaw``}
        GROUP BY 1
        ORDER BY 1
      `.catch(() => [] as Array<{ day: string; count: bigint }>),
    ]);

    res.json({
      data: {
        byType:     Object.fromEntries(byType.map((r) => [r.anomalyType, r._count.id])),
        bySeverity: Object.fromEntries(bySeverity.map((r) => [r.severity,    r._count.id])),
        byStatus:   Object.fromEntries(byStatus.map((r) => [r.status,        r._count.id])),
        trend:      trend.map((r) => ({ day: r.day, count: Number(r.count) })),
        total:      byType.reduce((s, r) => s + r._count.id, 0),
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Baselines ────────────────────────────────────────────────────────────────

// GET /api/anomaly/baselines?provider=&accountId=&actorId=
router.get('/baselines', async (req: Request, res: Response) => {
  try {
    const { provider, accountId, actorId } = req.query as Record<string, string>;
    if (!provider || !accountId) { res.status(400).json({ error: 'provider and accountId required' }); return; }
    const stats = await getBaselineStats(provider, accountId, actorId);
    res.json({ data: stats });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// DELETE /api/anomaly/baselines — reset baselines
router.delete('/baselines', async (req: Request, res: Response) => {
  try {
    const { provider, accountId, actorId } = req.query as Record<string, string>;
    if (!provider || !accountId) { res.status(400).json({ error: 'provider and accountId required' }); return; }
    const count = await resetBaselines(provider, accountId, actorId);
    res.json({ data: { deleted: count } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// POST /api/anomaly/baselines/seed — trigger baseline seeding from historical data
router.post('/baselines/seed', async (req: Request, res: Response) => {
  try {
    const { provider, accountId, lookbackDays = 30 } = req.body as {
      provider: 'AWS' | 'AZURE' | 'GCP';
      accountId: string;
      lookbackDays?: number;
    };
    if (!provider || !accountId) { res.status(400).json({ error: 'provider and accountId required' }); return; }

    // Run seeding in background — return immediately
    res.json({ data: { message: 'Baseline seeding started', provider, accountId, lookbackDays } });

    setImmediate(async () => {
      try {
        if (provider === 'AWS')   await seedAwsBaseline({ provider, accountId, lookbackDays });
        if (provider === 'AZURE') await seedAzureBaseline({ provider, accountId, lookbackDays });
        if (provider === 'GCP')   await seedGcpBaseline({ provider, accountId, lookbackDays });
      } catch (err) {
        // Background — just log
        console.error('[anomaly] baseline seed error', (err as Error).message);
      }
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/anomaly/actors?provider=&accountId= — list unique actors with anomaly counts
router.get('/actors', async (req: Request, res: Response) => {
  try {
    const { provider, accountId } = req.query as Record<string, string>;
    const where: Record<string, unknown> = {};
    if (provider)  where.provider  = provider;
    if (accountId) where.accountId = accountId;

    const rows = await prisma.anomalyEvent.groupBy({
      by: ['actorId'],
      where,
      _count:  { id: true },
      _max:    { score: true, detectedAt: true },
      orderBy: { _count: { id: 'desc' } },
      take: 50,
    });

    res.json({
      data: rows.map((r) => ({
        actorId:      r.actorId,
        anomalyCount: r._count.id,
        maxScore:     r._max.score,
        lastSeen:     r._max.detectedAt,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

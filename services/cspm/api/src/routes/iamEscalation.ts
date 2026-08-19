/**
 * IAM Privilege Escalation Routes
 *
 * GET  /api/iam-escalation              — list events (filterable)
 * GET  /api/iam-escalation/stats        — counts by type, severity, provider
 * GET  /api/iam-escalation/:id          — single event detail
 * PATCH /api/iam-escalation/:id         — acknowledge / resolve
 * POST /api/iam-escalation/backfill     — retroactive scan of existing changes
 */

import { Router, Request, Response } from 'express';
import { prisma }           from '../config/database';
import { backfillEscalationScan } from '../services/iamEscalationService';
import { logger }           from '../config/logger';

const router = Router();

// ─── Stats ────────────────────────────────────────────────────────────────────

router.get('/stats', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.query as Record<string, string>;
    const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const where: Record<string, unknown> = { eventTime: { gte: since30d } };
    if (provider) where.provider = provider;
    if (targetId) where.targetId = targetId;

    const [byType, bySeverity, byStatus, total] = await Promise.all([
      prisma.iamEscalationEvent.groupBy({
        by:    ['escalationType'],
        where,
        _count: { id: true },
        orderBy: { _count: { id: 'desc' } },
      }),
      prisma.iamEscalationEvent.groupBy({
        by:    ['severity'],
        where,
        _count: { id: true },
      }),
      prisma.iamEscalationEvent.groupBy({
        by:    ['status'],
        where,
        _count: { id: true },
      }),
      prisma.iamEscalationEvent.count({ where }),
    ]);

    res.json({
      total,
      byType:     byType.map((r) => ({ type: r.escalationType, count: r._count.id })),
      bySeverity: Object.fromEntries(bySeverity.map((r) => [r.severity, r._count.id])),
      byStatus:   Object.fromEntries(byStatus.map((r) => [r.status, r._count.id])),
    });
  } catch (err) {
    logger.error('[iam-escalation] stats failed', err);
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

// ─── List events ──────────────────────────────────────────────────────────────

router.get('/', async (req: Request, res: Response) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page     as string) || 1);
    const pageSize = Math.min(100, parseInt(req.query.pageSize as string) || 25);
    const { provider, targetId, status, severity, escalationType } = req.query as Record<string, string>;
    const days = Math.min(365, parseInt(req.query.days as string) || 30);
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const where: Record<string, unknown> = { eventTime: { gte: since } };
    if (provider)       where.provider       = provider;
    if (targetId)       where.targetId       = targetId;
    if (status)         where.status         = status;
    if (severity)       where.severity       = severity;
    if (escalationType) where.escalationType = escalationType;

    const [total, events] = await Promise.all([
      prisma.iamEscalationEvent.count({ where }),
      prisma.iamEscalationEvent.findMany({
        where,
        orderBy: [{ severity: 'asc' }, { eventTime: 'desc' }],
        skip:    (page - 1) * pageSize,
        take:    pageSize,
        select: {
          id: true, provider: true, targetId: true, escalationType: true,
          severity: true, actor: true, actorType: true, targetPrincipal: true,
          resourceType: true, resourceId: true, eventName: true,
          eventTime: true, summary: true, status: true, createdAt: true,
        },
      }),
    ]);

    const mapped = events.map(({ resourceId, ...rest }) => ({ ...rest, resourceName: resourceId }));

    res.json({ total, page, pageSize, events: mapped });
  } catch (err) {
    logger.error('[iam-escalation] list failed', err);
    res.status(500).json({ error: 'Failed to list escalation events' });
  }
});

// ─── Get single event ─────────────────────────────────────────────────────────

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const event = await prisma.iamEscalationEvent.findUnique({
      where:   { id: req.params.id },
      include: {
        change: {
          select: {
            id: true, severity: true, category: true, eventName: true,
            eventTime: true, summary: true, previousValue: true, newValue: true, sourceIp: true,
          },
        },
      },
    });
    if (!event) return res.status(404).json({ error: 'Not found' });
    res.json(event);
  } catch (err) {
    logger.error('[iam-escalation] get failed', err);
    res.status(500).json({ error: 'Failed to get event' });
  }
});

// ─── Acknowledge / resolve ────────────────────────────────────────────────────

router.patch('/:id', async (req: Request, res: Response) => {
  try {
    const { status, notes } = req.body as { status: 'ACKNOWLEDGED' | 'RESOLVED' | 'OPEN'; notes?: string };

    if (!['OPEN', 'ACKNOWLEDGED', 'RESOLVED'].includes(status)) {
      return res.status(400).json({ error: 'status must be OPEN | ACKNOWLEDGED | RESOLVED' });
    }

    const updated = await prisma.iamEscalationEvent.update({
      where: { id: req.params.id },
      data:  {
        status,
        ...(notes !== undefined && { notes }),
        ...(status === 'ACKNOWLEDGED' && { acknowledgedAt: new Date() }),
        ...(status === 'RESOLVED'     && { resolvedAt:     new Date() }),
      },
      select: { id: true, status: true, acknowledgedAt: true, resolvedAt: true, notes: true },
    });

    res.json(updated);
  } catch (err) {
    logger.error('[iam-escalation] patch failed', err);
    res.status(500).json({ error: 'Failed to update event' });
  }
});

// ─── Retroactive backfill ─────────────────────────────────────────────────────

router.post('/backfill', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.body as { provider: string; targetId: string };
    if (!provider || !targetId) {
      return res.status(400).json({ error: 'provider and targetId are required' });
    }

    // Run async, respond immediately
    void backfillEscalationScan(provider, targetId).then((count) => {
      logger.info(`[iam-escalation] Backfill complete for ${provider}:${targetId.slice(0, 8)} — ${count} changes scanned`);
    });

    res.json({ message: 'Backfill scan started in background' });
  } catch (err) {
    logger.error('[iam-escalation] backfill failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

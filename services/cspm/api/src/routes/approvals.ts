/**
 * Approval Workflow Routes
 *
 * GET  /api/approvals            — list approval requests (with status/action filters)
 * GET  /api/approvals/pending    — quick count of pending approvals
 * GET  /api/approvals/:id        — get single approval request detail
 * POST /api/approvals/:id/approve — approve (executes the action)
 * POST /api/approvals/:id/reject  — reject
 * DELETE /api/approvals/:id       — cancel (only PENDING requests)
 */

import { Router, Request, Response } from 'express';
import { prisma }              from '../config/database';
import { approveRequest, rejectRequest, cancelRequest } from '../services/approvalService';
import { logger }              from '../config/logger';

const router = Router();

// ─── List ─────────────────────────────────────────────────────────────────────

router.get('/', async (req: Request, res: Response) => {
  try {
    const { status, action, baselineId, page: pageStr, pageSize: pageSizeStr } = req.query as Record<string, string>;
    const page     = Math.max(1, parseInt(pageStr) || 1);
    const pageSize = Math.min(100, parseInt(pageSizeStr) || 25);

    const where: Record<string, unknown> = {};
    if (status)     where.status     = status;
    if (action)     where.action     = action;
    if (baselineId) where.baselineId = baselineId;

    const [total, items] = await Promise.all([
      prisma.approvalRequest.count({ where }),
      prisma.approvalRequest.findMany({
        where,
        orderBy: { requestedAt: 'desc' },
        skip:    (page - 1) * pageSize,
        take:    pageSize,
      }),
    ]);

    // Enrich with baseline names
    const bIds = [...new Set(items.map((i) => i.baselineId).filter(Boolean) as string[])];
    const baselines = bIds.length > 0
      ? await prisma.configBaseline.findMany({ where: { id: { in: bIds } }, select: { id: true, name: true, provider: true } })
      : [];
    const bMap = new Map(baselines.map((b) => [b.id, b]));

    res.json({
      total, page, pageSize,
      items: items.map((item) => ({
        ...item,
        baseline: item.baselineId ? (bMap.get(item.baselineId) ?? null) : null,
      })),
    });
  } catch (err) {
    logger.error('[approvals] list failed', err);
    res.status(500).json({ error: 'Failed to list approvals' });
  }
});

// ─── Pending count ────────────────────────────────────────────────────────────

router.get('/pending', async (_req: Request, res: Response) => {
  try {
    const count = await prisma.approvalRequest.count({ where: { status: 'PENDING' } });
    res.json({ count });
  } catch (err) {
    logger.error('[approvals] pending count failed', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// ─── Get single ───────────────────────────────────────────────────────────────

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const approval = await prisma.approvalRequest.findUnique({ where: { id: req.params.id } });
    if (!approval) return res.status(404).json({ error: 'Not found' });

    const baseline = approval.baselineId
      ? await prisma.configBaseline.findUnique({
          where:  { id: approval.baselineId },
          select: { id: true, name: true, provider: true, targetId: true },
        })
      : null;

    const drift = approval.driftId
      ? await prisma.driftResult.findUnique({
          where:  { id: approval.driftId },
          select: { id: true, resourceType: true, resourceName: true, driftType: true, severity: true },
        })
      : null;

    res.json({ ...approval, baseline, drift });
  } catch (err) {
    logger.error('[approvals] get failed', err);
    res.status(500).json({ error: 'Failed to get approval' });
  }
});

// ─── Approve ──────────────────────────────────────────────────────────────────

router.post('/:id/approve', async (req: Request, res: Response) => {
  try {
    const { reviewedBy, reviewedByName, reviewNotes } = req.body as {
      reviewedBy: string; reviewedByName?: string; reviewNotes?: string;
    };
    if (!reviewedBy) return res.status(400).json({ error: 'reviewedBy (email) is required' });

    const result = await approveRequest({
      requestId: req.params.id,
      reviewedBy,
      reviewedByName,
      reviewNotes,
    });

    res.json(result);
  } catch (err) {
    const msg = (err as Error).message;
    logger.error('[approvals] approve failed', err);
    res.status(msg.includes('not found') ? 404 : 422).json({ error: msg });
  }
});

// ─── Reject ───────────────────────────────────────────────────────────────────

router.post('/:id/reject', async (req: Request, res: Response) => {
  try {
    const { reviewedBy, reviewedByName, reviewNotes } = req.body as {
      reviewedBy: string; reviewedByName?: string; reviewNotes?: string;
    };
    if (!reviewedBy) return res.status(400).json({ error: 'reviewedBy (email) is required' });

    const result = await rejectRequest({
      requestId: req.params.id,
      reviewedBy,
      reviewedByName,
      reviewNotes,
    });

    res.json(result);
  } catch (err) {
    const msg = (err as Error).message;
    logger.error('[approvals] reject failed', err);
    res.status(msg.includes('not found') ? 404 : 422).json({ error: msg });
  }
});

// ─── Cancel ───────────────────────────────────────────────────────────────────

router.post('/:id/cancel', async (req: Request, res: Response) => {
  try {
    const { cancelledBy } = req.body as { cancelledBy?: string };
    const result = await cancelRequest(req.params.id, cancelledBy ?? 'unknown');
    res.json(result);
  } catch (err) {
    const msg = (err as Error).message;
    logger.error('[approvals] cancel failed', err);
    res.status(msg.includes('not found') ? 404 : 422).json({ error: msg });
  }
});

router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const result = await cancelRequest(req.params.id, 'unknown');
    res.json(result);
  } catch (err) {
    const msg = (err as Error).message;
    res.status(msg.includes('not found') ? 404 : 422).json({ error: msg });
  }
});

export default router;

/**
 * Posture Score Routes
 *
 * GET current score and historical trend for a provider+targetId.
 * POST /compute triggers an immediate on-demand recalculation.
 */

import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { computePostureScore } from '../services/postureScoreService';
import { logger } from '../config/logger';

const router = Router();

// ─── Get current (most recent) score for a target ────────────────────────────

router.get('/current', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.query as { provider: string; targetId: string };
    if (!provider || !targetId) {
      return res.status(400).json({ error: 'provider and targetId are required' });
    }

    const latest = await prisma.postureScore.findFirst({
      where:   { provider, targetId },
      orderBy: { calculatedAt: 'desc' },
    });

    if (!latest) return res.status(404).json({ error: 'No posture score yet — run compute first' });

    res.json(latest);
  } catch (err) {
    logger.error('[posture] current failed', err);
    res.status(500).json({ error: 'Failed to get posture score' });
  }
});

// ─── Get score history (trend) ────────────────────────────────────────────────

router.get('/history', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.query as { provider: string; targetId: string };
    const days    = Math.min(90, parseInt(req.query.days as string) || 30);
    const since   = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    if (!provider || !targetId) {
      return res.status(400).json({ error: 'provider and targetId are required' });
    }

    const history = await prisma.postureScore.findMany({
      where:   { provider, targetId, calculatedAt: { gte: since } },
      orderBy: { calculatedAt: 'asc' },
      select: {
        score: true, grade: true,
        criticalOpen: true, highOpen: true, mediumOpen: true, lowOpen: true,
        freezeViolations: true, calculatedAt: true,
      },
    });

    res.json({ provider, targetId, days, history });
  } catch (err) {
    logger.error('[posture] history failed', err);
    res.status(500).json({ error: 'Failed to get posture history' });
  }
});

// ─── Get summary across all READY accounts ────────────────────────────────────

router.get('/summary', async (_req: Request, res: Response) => {
  try {
    // Latest score per provider+targetId via subquery
    const scores = await prisma.$queryRaw<Array<{
      provider: string; targetId: string; score: number; grade: string; calculatedAt: Date;
    }>>`
      SELECT DISTINCT ON ("provider", "targetId")
        "provider", "targetId", "score", "grade", "calculatedAt"
      FROM "PostureScore"
      ORDER BY "provider", "targetId", "calculatedAt" DESC
    `;

    const gradeCount = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    for (const s of scores) {
      gradeCount[s.grade as keyof typeof gradeCount]++;
    }

    const avgScore = scores.length
      ? Math.round(scores.reduce((sum, s) => sum + s.score, 0) / scores.length)
      : null;

    res.json({ total: scores.length, avgScore, gradeCount, scores });
  } catch (err) {
    logger.error('[posture] summary failed', err);
    res.status(500).json({ error: 'Failed to get posture summary' });
  }
});

// ─── On-demand compute ────────────────────────────────────────────────────────

router.post('/compute', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.body as { provider: string; targetId: string };
    if (!provider || !targetId) {
      return res.status(400).json({ error: 'provider and targetId are required' });
    }

    const result = await computePostureScore(provider, targetId);
    res.json(result);
  } catch (err) {
    logger.error('[posture] compute failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

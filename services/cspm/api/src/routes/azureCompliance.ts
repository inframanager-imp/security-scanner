import { Router, Request, Response } from 'express';
import { prisma }       from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { scoreAzureFrameworks, AZURE_FRAMEWORKS } from '../services/azureComplianceService';

const router = Router();
router.use(authenticate);

/**
 * Build active Azure finding title sets for a subscription.
 * Only OPEN and ACKNOWLEDGED findings count as non-compliant.
 */
async function getActiveFindingData(subscriptionId: string): Promise<{
  titles: Set<string>;
  counts: Map<string, number>;
}> {
  const scans = await prisma.azureScan.findMany({
    where: { subscriptionId },
    select: { id: true },
  });

  const rows = await prisma.azureFinding.groupBy({
    by: ['title'],
    where: {
      scanId:        { in: scans.map(s => s.id) },
      findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
    },
    _count: { title: true },
  });

  const titles = new Set<string>(rows.map(r => r.title));
  const counts = new Map<string, number>(rows.map(r => [r.title, r._count.title]));
  return { titles, counts };
}

/**
 * GET /api/azure/compliance?subscriptionId=X
 * Returns compliance scores for all 5 frameworks for a subscription.
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    const { subscriptionId } = req.query as Record<string, string>;
    if (!subscriptionId) {
      res.status(400).json({ error: 'subscriptionId is required' });
      return;
    }

    const sub = await prisma.azureSubscription.findUnique({
      where: { id: subscriptionId },
      select: { id: true },
    });
    if (!sub) {
      res.status(404).json({ error: 'Azure subscription not found' });
      return;
    }

    const { titles, counts } = await getActiveFindingData(subscriptionId);
    const scores = scoreAzureFrameworks(titles, counts);

    res.json({ data: scores });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * GET /api/azure/compliance/all
 * Returns per-subscription scores (summary only) for all subscriptions.
 */
router.get('/all', async (_req: Request, res: Response) => {
  try {
    const subscriptions = await prisma.azureSubscription.findMany({
      select: { id: true, name: true, subscriptionId: true },
      orderBy: { name: 'asc' },
    });

    const result = await Promise.all(
      subscriptions.map(async (sub) => {
        const { titles, counts } = await getActiveFindingData(sub.id);
        const scores = scoreAzureFrameworks(titles, counts).map(
          ({ controls: _c, ...summary }) => summary,
        );
        return { subscriptionId: sub.id, subscriptionName: sub.name, azureSubscriptionId: sub.subscriptionId, scores };
      }),
    );

    res.json({ data: result });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * GET /api/azure/compliance/frameworks
 * Returns the full list of frameworks and their controls (no scoring).
 */
router.get('/frameworks', (_req: Request, res: Response) => {
  res.json({ data: AZURE_FRAMEWORKS });
});

/**
 * GET /api/azure/compliance/:frameworkId?subscriptionId=X
 * Returns detailed score for a single framework.
 */
router.get('/:frameworkId', async (req: Request, res: Response) => {
  try {
    const { frameworkId } = req.params;
    const { subscriptionId } = req.query as Record<string, string>;

    if (!subscriptionId) {
      res.status(400).json({ error: 'subscriptionId is required' });
      return;
    }

    const { titles, counts } = await getActiveFindingData(subscriptionId);
    const scores = scoreAzureFrameworks(titles, counts);
    const score  = scores.find(s => s.frameworkId === frameworkId);

    if (!score) {
      res.status(404).json({ error: `Framework "${frameworkId}" not found` });
      return;
    }

    res.json({ data: score });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

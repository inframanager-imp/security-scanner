import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

// GET /api/risk-register
router.get('/', async (req: Request, res: Response) => {
  try {
    const { provider, accountId, status, category } = req.query as Record<string, string>;
    const where: Record<string, unknown> = {};
    if (provider)   where.provider   = provider;
    if (accountId)  where.accountId  = accountId;
    if (status)     where.status     = status;
    if (category)   where.category   = category;

    const items = await prisma.riskItem.findMany({
      where,
      orderBy: [{ riskScore: 'desc' }, { createdAt: 'desc' }],
    });
    res.json({ data: items });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/risk-register/:id
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const item = await prisma.riskItem.findUnique({ where: { id: req.params.id } });
    if (!item) { res.status(404).json({ error: 'Not found' }); return; }
    res.json({ data: item });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// POST /api/risk-register
router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      title, description, category, likelihood, impact, owner, dueDate,
      provider, accountId, linkedFindingIds, linkedControlIds,
      mitigationPlan, acceptanceRationale, status,
    } = req.body as {
      title: string; description: string; category: string;
      likelihood: number; impact: number;
      owner?: string; dueDate?: string;
      provider?: string; accountId?: string;
      linkedFindingIds?: string[]; linkedControlIds?: string[];
      mitigationPlan?: string; acceptanceRationale?: string;
      status?: string;
    };

    if (!title || !description || !category || !likelihood || !impact) {
      res.status(400).json({ error: 'title, description, category, likelihood, impact are required' });
      return;
    }

    const riskScore = Math.min(25, likelihood * impact);
    const item = await prisma.riskItem.create({
      data: {
        title, description, category,
        likelihood, impact, riskScore,
        status:    status ?? 'OPEN',
        owner,
        dueDate:   dueDate ? new Date(dueDate) : undefined,
        provider, accountId,
        linkedFindingIds:    linkedFindingIds    ?? [],
        linkedControlIds:    linkedControlIds    ?? [],
        mitigationPlan, acceptanceRationale,
      },
    });
    res.status(201).json({ data: item });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// PATCH /api/risk-register/:id
router.patch('/:id', async (req: Request, res: Response) => {
  try {
    const existing = await prisma.riskItem.findUnique({ where: { id: req.params.id } });
    if (!existing) { res.status(404).json({ error: 'Not found' }); return; }

    const {
      title, description, category, likelihood, impact, owner, dueDate,
      provider, accountId, linkedFindingIds, linkedControlIds,
      mitigationPlan, acceptanceRationale, status,
    } = req.body as Partial<{
      title: string; description: string; category: string;
      likelihood: number; impact: number;
      owner: string; dueDate: string;
      provider: string; accountId: string;
      linkedFindingIds: string[]; linkedControlIds: string[];
      mitigationPlan: string; acceptanceRationale: string;
      status: string;
    }>;

    const newLikelihood = likelihood ?? existing.likelihood;
    const newImpact     = impact     ?? existing.impact;
    const riskScore     = Math.min(25, newLikelihood * newImpact);

    const item = await prisma.riskItem.update({
      where: { id: req.params.id },
      data: {
        ...(title       !== undefined && { title }),
        ...(description !== undefined && { description }),
        ...(category    !== undefined && { category }),
        likelihood: newLikelihood,
        impact:     newImpact,
        riskScore,
        ...(status    !== undefined && { status }),
        ...(owner     !== undefined && { owner }),
        ...(dueDate   !== undefined && { dueDate: dueDate ? new Date(dueDate) : null }),
        ...(provider  !== undefined && { provider }),
        ...(accountId !== undefined && { accountId }),
        ...(linkedFindingIds !== undefined && { linkedFindingIds }),
        ...(linkedControlIds !== undefined && { linkedControlIds }),
        ...(mitigationPlan      !== undefined && { mitigationPlan }),
        ...(acceptanceRationale !== undefined && { acceptanceRationale }),
      },
    });
    res.json({ data: item });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// DELETE /api/risk-register/:id
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    await prisma.riskItem.delete({ where: { id: req.params.id } });
    res.json({ data: { deleted: true } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

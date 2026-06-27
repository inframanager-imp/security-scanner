/**
 * DSPM API
 *
 * POST /api/dspm/scan                        — enqueue DSPM scan
 * GET  /api/dspm/classifications             — list classifications (filters)
 * GET  /api/dspm/resources/:resourceId       — per-resource classifications
 * GET  /api/dspm/stats/:provider/:accountId  — summary metrics
 */

import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { enqueueDspmScan } from '../workers/dspmScanWorker';

const router = Router();
router.use(authenticate);

router.post('/scan', async (req: Request, res: Response) => {
  const { provider, accountId } = req.body as { provider: 'AWS' | 'AZURE' | 'GCP'; accountId: string };
  if (!['AWS', 'AZURE', 'GCP'].includes(provider) || !accountId) {
    res.status(400).json({ error: 'provider and accountId required' });
    return;
  }
  try {
    const jobId = await enqueueDspmScan({ provider, accountId, triggeredBy: 'MANUAL' });
    res.json({ data: { jobId, status: 'QUEUED' } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/classifications', async (req: Request, res: Response) => {
  const { provider, accountId, dataType, minConfidence } = req.query as Record<string, string | undefined>;
  const page = Math.max(parseInt((req.query.page as string) ?? '1', 10), 1);
  const pageSize = Math.min(Math.max(parseInt((req.query.pageSize as string) ?? '50', 10), 1), 500);

  const where: any = {};
  if (provider)  where.provider  = provider;
  if (accountId) where.accountId = accountId;
  if (dataType)  where.dataType  = dataType;
  if (minConfidence) {
    const order = ['LOW', 'MEDIUM', 'HIGH'];
    const idx = order.indexOf(minConfidence.toUpperCase());
    if (idx >= 0) where.confidence = { in: order.slice(idx) };
  }

  const [rows, total] = await Promise.all([
    prisma.dataClassification.findMany({
      where,
      orderBy: [{ confidence: 'desc' }, { classifiedAt: 'desc' }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: {
        resource: { select: { id: true, nativeId: true, resourceType: true, region: true, dataSensitivity: true } },
      },
    }),
    prisma.dataClassification.count({ where }),
  ]);

  res.json({ data: rows, meta: { total, page, pageSize, totalPages: Math.ceil(total / pageSize) } });
});

router.get('/resources/:resourceId', async (req: Request, res: Response) => {
  const rows = await prisma.dataClassification.findMany({
    where: { resourceInventoryId: req.params.resourceId },
    orderBy: { classifiedAt: 'desc' },
  });
  res.json({ data: rows });
});

router.get('/stats/:provider/:accountId', async (req: Request, res: Response) => {
  const { provider, accountId } = req.params;
  const [byType, sensitiveAndPublic, totalClassifiedResources] = await Promise.all([
    prisma.dataClassification.groupBy({
      by: ['dataType'],
      where: { provider, accountId },
      _count: { _all: true },
    }),
    prisma.resourceInventory.count({
      where: {
        ...(provider === 'AWS' ? { awsAccountId: accountId } : provider === 'AZURE' ? { azureSubId: accountId } : { gcpProjectId: accountId }),
        dataSensitivity: { in: ['HIGH', 'CRITICAL'] },
        exposurePaths: { some: { exposureType: 'PUBLIC_INTERNET' } },
      },
    }),
    prisma.dataClassification.groupBy({
      by: ['resourceInventoryId'],
      where: { provider, accountId },
    }),
  ]);

  res.json({
    data: {
      byDataType: byType.map((g) => ({ dataType: g.dataType, count: g._count._all })),
      sensitiveAndPublic,
      classifiedResources: totalClassifiedResources.length,
    },
  });
});

export default router;

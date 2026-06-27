/**
 * CIEM API
 *
 * GET  /api/ciem/attack-paths?provider=&accountId=&kind=&severity=&status=
 * GET  /api/ciem/attack-paths/:id
 * PATCH /api/ciem/attack-paths/:id           — { status, notes }
 * GET  /api/ciem/principals/:arn/permissions?provider=&accountId=
 * GET  /api/ciem/stats/:provider/:accountId
 */

import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

router.get('/attack-paths', async (req: Request, res: Response) => {
  const { provider, accountId, kind, severity, status } = req.query as Record<string, string | undefined>;
  const page = Math.max(parseInt((req.query.page as string) ?? '1', 10), 1);
  const pageSize = Math.min(Math.max(parseInt((req.query.pageSize as string) ?? '50', 10), 1), 200);

  const where: any = {};
  if (provider)  where.provider  = provider;
  if (accountId) where.accountId = accountId;
  if (kind)      where.kind      = kind;
  if (severity)  where.severity  = severity;
  if (status)    where.status    = status;

  const [rows, total] = await Promise.all([
    prisma.attackPath.findMany({
      where,
      orderBy: [{ severity: 'asc' }, { lastSeenAt: 'desc' }],
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
    prisma.attackPath.count({ where }),
  ]);

  res.json({
    data: rows,
    meta: { total, page, pageSize, totalPages: Math.ceil(total / pageSize) },
  });
});

router.get('/attack-paths/:id', async (req: Request, res: Response) => {
  const row = await prisma.attackPath.findUnique({ where: { id: req.params.id } });
  if (!row) {
    res.status(404).json({ error: 'AttackPath not found' });
    return;
  }
  res.json({ data: row });
});

router.patch('/attack-paths/:id', async (req: Request, res: Response) => {
  const { status, notes } = req.body as { status?: string; notes?: string };
  const update: any = {};
  if (status) {
    update.status = status;
    if (status === 'ACKNOWLEDGED') update.acknowledgedAt = new Date();
    if (status === 'RESOLVED')    update.resolvedAt = new Date();
  }
  if (notes !== undefined) update.notes = notes;
  try {
    const row = await prisma.attackPath.update({ where: { id: req.params.id }, data: update });
    res.json({ data: row });
  } catch (err) {
    res.status(404).json({ error: 'AttackPath not found' });
  }
});

router.get('/principals/:arn/permissions', async (req: Request, res: Response) => {
  const { provider, accountId } = req.query as Record<string, string | undefined>;
  if (!provider || !accountId) {
    res.status(400).json({ error: 'provider and accountId are required' });
    return;
  }
  const rows = await prisma.principalPermission.findMany({
    where: { provider, accountId, principalArn: req.params.arn },
    orderBy: [{ action: 'asc' }],
    take: 500,
  });
  res.json({ data: rows });
});

router.get('/stats/:provider/:accountId', async (req: Request, res: Response) => {
  const { provider, accountId } = req.params;
  const [byKind, bySeverity, principals] = await Promise.all([
    prisma.attackPath.groupBy({
      by: ['kind'],
      where: { provider, accountId, status: 'OPEN' },
      _count: { _all: true },
    }),
    prisma.attackPath.groupBy({
      by: ['severity'],
      where: { provider, accountId, status: 'OPEN' },
      _count: { _all: true },
    }),
    prisma.principalPermission.groupBy({
      by: ['principalArn'],
      where: { provider, accountId },
      _count: { _all: true },
      orderBy: { _count: { principalArn: 'desc' } },
      take: 10,
    }),
  ]);

  res.json({
    data: {
      attackPathsByKind: byKind.map((g) => ({ kind: g.kind, count: g._count._all })),
      attackPathsBySeverity: bySeverity.map((g) => ({ severity: g.severity, count: g._count._all })),
      topPrincipalsByPermissionCount: principals.map((g) => ({
        principalArn: g.principalArn,
        permissionCount: g._count._all,
      })),
    },
  });
});

export default router;

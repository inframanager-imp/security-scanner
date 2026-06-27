/**
 * CWPP API
 *
 * POST /api/cwpp/scan                                  — enqueue an agentless scan
 * GET  /api/cwpp/vulnerabilities                       — list vulns (filters)
 * GET  /api/cwpp/hosts/:resourceInventoryId            — per-host CVE list
 * GET  /api/cwpp/stats/:provider/:accountId            — summary metrics for dashboard
 * PATCH /api/cwpp/vulnerabilities/:id                  — { status, suppressedReason }
 */

import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { enqueueCwppScan } from '../workers/cwppScanWorker';

const router = Router();
router.use(authenticate);

router.post('/scan', async (req: Request, res: Response) => {
  const { provider, accountId } = req.body as { provider: 'AWS' | 'AZURE' | 'GCP'; accountId: string };
  if (!['AWS', 'AZURE', 'GCP'].includes(provider) || !accountId) {
    res.status(400).json({ error: 'provider and accountId required' });
    return;
  }
  try {
    const jobId = await enqueueCwppScan({ provider, accountId, triggeredBy: 'MANUAL' });
    res.json({ data: { jobId, status: 'QUEUED' } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/vulnerabilities', async (req: Request, res: Response) => {
  const { provider, accountId, severity, status, cveId } = req.query as Record<string, string | undefined>;
  const page = Math.max(parseInt((req.query.page as string) ?? '1', 10), 1);
  const pageSize = Math.min(Math.max(parseInt((req.query.pageSize as string) ?? '50', 10), 1), 500);

  const where: any = {};
  if (provider)  where.provider  = provider;
  if (accountId) where.accountId = accountId;
  if (severity)  where.severity  = severity;
  if (status)    where.status    = status;
  if (cveId)     where.cveId     = cveId;

  const [rows, total] = await Promise.all([
    prisma.workloadVulnerability.findMany({
      where,
      orderBy: [{ severity: 'asc' }, { observedAt: 'desc' }],
      skip: (page - 1) * pageSize,
      take: pageSize,
      include: {
        resource: { select: { id: true, nativeId: true, resourceType: true, region: true } },
      },
    }),
    prisma.workloadVulnerability.count({ where }),
  ]);

  res.json({ data: rows, meta: { total, page, pageSize, totalPages: Math.ceil(total / pageSize) } });
});

router.get('/hosts/:resourceInventoryId', async (req: Request, res: Response) => {
  const rows = await prisma.workloadVulnerability.findMany({
    where: { resourceInventoryId: req.params.resourceInventoryId },
    orderBy: [{ severity: 'asc' }, { cvssScore: 'desc' }],
    include: { resource: { select: { id: true, nativeId: true, resourceType: true, region: true } } },
  });
  res.json({ data: rows });
});

router.get('/stats/:provider/:accountId', async (req: Request, res: Response) => {
  const { provider, accountId } = req.params;
  const [bySeverity, hosts, openTotal] = await Promise.all([
    prisma.workloadVulnerability.groupBy({
      by: ['severity'],
      where: { provider, accountId, status: 'OPEN' },
      _count: { _all: true },
    }),
    prisma.workloadVulnerability.groupBy({
      by: ['resourceInventoryId'],
      where: { provider, accountId, status: 'OPEN' },
      _count: { _all: true },
    }),
    prisma.workloadVulnerability.count({ where: { provider, accountId, status: 'OPEN' } }),
  ]);

  res.json({
    data: {
      bySeverity: bySeverity.map((g) => ({ severity: g.severity, count: g._count._all })),
      hostsAffected: hosts.length,
      openTotal,
    },
  });
});

router.patch('/vulnerabilities/:id', async (req: Request, res: Response) => {
  const { status, suppressedReason } = req.body as { status?: string; suppressedReason?: string };
  const update: any = {};
  if (status) {
    update.status = status;
    if (status === 'FIXED') update.resolvedAt = new Date();
  }
  if (suppressedReason !== undefined) update.suppressedReason = suppressedReason;
  try {
    const row = await prisma.workloadVulnerability.update({ where: { id: req.params.id }, data: update });
    res.json({ data: row });
  } catch (err) {
    res.status(404).json({ error: 'WorkloadVulnerability not found' });
  }
});

export default router;

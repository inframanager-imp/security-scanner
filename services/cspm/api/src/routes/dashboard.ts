import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';

const router = Router();
router.use(authenticate);

// GET /api/dashboard/summary  — aggregates AWS + Azure + GCP
router.get('/summary', async (_req: Request, res: Response) => {
  try {
    const [
      awsAccounts,
      azureSubscriptions,
      gcpProjects,
      awsScans,
      azureScans,
      gcpScans,
      awsActiveScans,
      azureActiveScans,
      gcpActiveScans,
      awsFindings,
      azureFindings,
      gcpFindings,
    ] = await Promise.all([
      prisma.account.count(),
      prisma.azureSubscription.count(),
      prisma.gcpProject.count(),
      prisma.scan.count(),
      prisma.azureScan.count(),
      prisma.gcpScan.count(),
      prisma.scan.count({ where: { status: { in: ['QUEUED', 'RUNNING'] } } }),
      prisma.azureScan.count({ where: { status: { in: ['QUEUED', 'RUNNING'] } } }),
      prisma.gcpScan.count({ where: { status: { in: ['QUEUED', 'RUNNING'] } } }),
      prisma.finding.groupBy({ by: ['severity'], _count: { id: true } }),
      prisma.azureFinding.groupBy({ by: ['severity'], _count: { id: true } }),
      prisma.gcpFinding.groupBy({ by: ['severity'], _count: { id: true } }),
    ]);

    const findingsBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const fc of [...awsFindings, ...azureFindings, ...gcpFindings]) {
      const key = fc.severity.toLowerCase();
      findingsBySeverity[key] = (findingsBySeverity[key] ?? 0) + fc._count.id;
    }

    res.json({
      data: {
        totalAccounts: awsAccounts + azureSubscriptions + gcpProjects,
        totalScans:    awsScans + azureScans + gcpScans,
        activeScans:   awsActiveScans + azureActiveScans + gcpActiveScans,
        findingsBySeverity,
        accountsAtRisk: 0, // kept for compat
        // per-cloud breakdown for the stat cards
        breakdown: {
          aws:   { accounts: awsAccounts,   scans: awsScans   },
          azure: { accounts: azureSubscriptions, scans: azureScans },
          gcp:   { accounts: gcpProjects,   scans: gcpScans   },
        },
      },
    });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/dashboard/trends  — combines AWS + Azure + GCP findings
router.get('/trends', async (req: Request, res: Response) => {
  try {
    const days  = parseInt(req.query.days as string) || 30;
    const since = new Date();
    since.setDate(since.getDate() - days);

    const [awsFindings, azureFindings, gcpFindings] = await Promise.all([
      prisma.finding.findMany({
        where: { discoveredAt: { gte: since } },
        select: { severity: true, discoveredAt: true },
      }),
      prisma.azureFinding.findMany({
        where: { discoveredAt: { gte: since } },
        select: { severity: true, discoveredAt: true },
      }),
      prisma.gcpFinding.findMany({
        where: { discoveredAt: { gte: since } },
        select: { severity: true, discoveredAt: true },
      }),
    ]);

    const dateMap = new Map<string, { date: string; critical: number; high: number; medium: number; low: number; info: number }>();
    for (let i = 0; i <= days; i++) {
      const d = new Date(since);
      d.setDate(d.getDate() + i);
      const dateStr = d.toISOString().split('T')[0];
      dateMap.set(dateStr, { date: dateStr, critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    }

    for (const f of [...awsFindings, ...azureFindings, ...gcpFindings]) {
      const dateStr = f.discoveredAt.toISOString().split('T')[0];
      const entry   = dateMap.get(dateStr);
      if (entry) {
        const key = f.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info';
        entry[key] = (entry[key] || 0) + 1;
      }
    }

    res.json({ data: Array.from(dateMap.values()).sort((a, b) => a.date.localeCompare(b.date)) });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/dashboard/accounts  — returns AWS + Azure + GCP rows unified
router.get('/accounts', async (_req: Request, res: Response) => {
  try {
    // ── AWS ────────────────────────────────────────────────────────────────────
    const awsAccounts = await prisma.account.findMany({
      include: { scans: { orderBy: { createdAt: 'desc' }, take: 1, include: { summary: true } } },
    });

    const awsNeedFallback = awsAccounts.filter(a => a.scans[0] && !a.scans[0].summary).map(a => a.id);
    const awsFallbackMap  = new Map<string, { critical: number; high: number; medium: number; low: number; info: number; total: number }>();
    if (awsNeedFallback.length > 0) {
      const completed = await prisma.scan.findMany({
        where: { accountId: { in: awsNeedFallback }, status: 'COMPLETED', summary: { isNot: null } },
        orderBy: { createdAt: 'desc' },
        include: { summary: true },
        distinct: ['accountId'],
      });
      for (const s of completed) {
        if (s.summary) awsFallbackMap.set(s.accountId, { critical: s.summary.critical, high: s.summary.high, medium: s.summary.medium, low: s.summary.low, info: s.summary.info, total: s.summary.total });
      }
    }

    const awsRows = awsAccounts.map(a => {
      const ls = a.scans[0] ?? null;
      const summary = ls?.summary
        ? { critical: ls.summary.critical, high: ls.summary.high, medium: ls.summary.medium, low: ls.summary.low, info: ls.summary.info, total: ls.summary.total }
        : (awsFallbackMap.get(a.id) ?? null);
      return { id: a.id, provider: 'AWS', name: a.name, accountId: a.awsAccountId, lastScanAt: ls?.createdAt ?? null, lastScanStatus: ls?.status ?? null, summary, detailPath: `/accounts/${a.id}` };
    });

    // ── Azure ──────────────────────────────────────────────────────────────────
    const azureSubs = await prisma.azureSubscription.findMany({
      include: { scans: { orderBy: { createdAt: 'desc' }, take: 1, include: { summary: true } } },
    });

    const azureNeedFallback = azureSubs.filter(s => s.scans[0] && !s.scans[0].summary).map(s => s.id);
    const azureFallbackMap  = new Map<string, { critical: number; high: number; medium: number; low: number; info: number; total: number }>();
    if (azureNeedFallback.length > 0) {
      const completed = await prisma.azureScan.findMany({
        where: { subscriptionId: { in: azureNeedFallback }, status: 'COMPLETED', summary: { isNot: null } },
        orderBy: { createdAt: 'desc' },
        include: { summary: true },
        distinct: ['subscriptionId'],
      });
      for (const s of completed) {
        if (s.summary) azureFallbackMap.set(s.subscriptionId, { critical: s.summary.critical, high: s.summary.high, medium: s.summary.medium, low: s.summary.low, info: s.summary.info, total: s.summary.total });
      }
    }

    const azureRows = azureSubs.map(s => {
      const ls = s.scans[0] ?? null;
      const summary = ls?.summary
        ? { critical: ls.summary.critical, high: ls.summary.high, medium: ls.summary.medium, low: ls.summary.low, info: ls.summary.info, total: ls.summary.total }
        : (azureFallbackMap.get(s.id) ?? null);
      return { id: s.id, provider: 'AZURE', name: s.name, accountId: s.subscriptionId, lastScanAt: ls?.startedAt ?? ls?.createdAt ?? null, lastScanStatus: ls?.status ?? null, summary, detailPath: `/azure/${s.id}` };
    });

    // ── GCP ────────────────────────────────────────────────────────────────────
    const gcpProjects = await prisma.gcpProject.findMany({
      include: { scans: { orderBy: { createdAt: 'desc' }, take: 1, include: { summary: true } } },
    });

    const gcpNeedFallback = gcpProjects.filter(p => p.scans[0] && !p.scans[0].summary).map(p => p.id);
    const gcpFallbackMap  = new Map<string, { critical: number; high: number; medium: number; low: number; info: number; total: number }>();
    if (gcpNeedFallback.length > 0) {
      const completed = await prisma.gcpScan.findMany({
        where: { projectId: { in: gcpNeedFallback }, status: 'COMPLETED', summary: { isNot: null } },
        orderBy: { createdAt: 'desc' },
        include: { summary: true },
        distinct: ['projectId'],
      });
      for (const s of completed) {
        if (s.summary) gcpFallbackMap.set(s.projectId, { critical: s.summary.critical, high: s.summary.high, medium: s.summary.medium, low: s.summary.low, info: s.summary.info, total: s.summary.total });
      }
    }

    const gcpRows = gcpProjects.map(p => {
      const ls = p.scans[0] ?? null;
      const summary = ls?.summary
        ? { critical: ls.summary.critical, high: ls.summary.high, medium: ls.summary.medium, low: ls.summary.low, info: ls.summary.info, total: ls.summary.total }
        : (gcpFallbackMap.get(p.id) ?? null);
      return { id: p.id, provider: 'GCP', name: p.name, accountId: p.projectId, lastScanAt: ls?.startedAt ?? ls?.createdAt ?? null, lastScanStatus: ls?.status ?? null, summary, detailPath: `/gcp/${p.id}` };
    });

    const all = [...awsRows, ...azureRows, ...gcpRows].sort((a, b) => a.name.localeCompare(b.name));
    res.json({ data: all });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/dashboard/top-findings  (AWS only — existing behaviour kept)
router.get('/top-findings', async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 10;
    const findings = await prisma.finding.findMany({
      where: { severity: { in: ['CRITICAL', 'HIGH'] }, findingStatus: 'OPEN' },
      orderBy: [{ severity: 'asc' }, { discoveredAt: 'desc' }],
      take: limit,
      include: { scan: { select: { id: true, account: { select: { id: true, name: true, awsAccountId: true } } } } },
    });
    res.json({ data: findings });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;

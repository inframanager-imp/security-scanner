import { Router, Request, Response } from 'express';
import type { Prisma } from '@prisma/client';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { scoreFrameworks, FRAMEWORKS } from '../services/complianceService';
import {
  collectEvidenceForAccount,
  getEvidenceForControl,
  getEvidenceSummaryForFramework,
  exportEvidencePackage,
} from '../services/evidenceService';

const router = Router();
router.use(authenticate);

/**
 * Build active finding sets for one or all accounts.
 * Only OPEN and ACKNOWLEDGED findings count as non-compliant.
 *
 * Findings with a stable registry checkId go into the checkId set/counts;
 * legacy findings (checkId = null) go into the title set/counts so they can
 * still be matched by byte-identical title.
 */
async function getActiveFindingData(accountId?: string): Promise<{
  titles: Set<string>;
  counts: Map<string, number>;
  checkIds: Set<string>;
  checkIdCounts: Map<string, number>;
}> {
  // groupBy does not reliably support nested relation filters in Prisma,
  // so resolve scan IDs first when filtering by account.
  const scanIdFilter: Record<string, unknown> = {};
  if (accountId) {
    const scans = await prisma.scan.findMany({
      where: { accountId },
      select: { id: true },
    });
    scanIdFilter.scanId = { in: scans.map((s) => s.id) };
  }

  const rows = await prisma.finding.groupBy({
    by: ['title', 'checkId'],
    where: {
      findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
      ...scanIdFilter,
    },
    _count: { _all: true },
  });

  const titles = new Set<string>();
  const counts = new Map<string, number>();
  const checkIds = new Set<string>();
  const checkIdCounts = new Map<string, number>();
  for (const r of rows) {
    const n = r._count._all;
    if (r.checkId) {
      checkIds.add(r.checkId);
      checkIdCounts.set(r.checkId, (checkIdCounts.get(r.checkId) ?? 0) + n);
    } else {
      titles.add(r.title);
      counts.set(r.title, (counts.get(r.title) ?? 0) + n);
    }
  }
  return { titles, counts, checkIds, checkIdCounts };
}

// GET /api/compliance?accountId=X
// Returns compliance scores for all 4 frameworks for a single account.
router.get('/', async (req: Request, res: Response) => {
  try {
    const { accountId } = req.query as Record<string, string>;
    if (!accountId) {
      res.status(400).json({ error: 'accountId is required' });
      return;
    }

    const { titles, counts, checkIds, checkIdCounts } = await getActiveFindingData(accountId);
    const scores = scoreFrameworks(titles, counts, checkIds, checkIdCounts);

    res.json({ data: scores });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/compliance/all
// Returns per-account scores (summary only — no control detail) for all accounts.
router.get('/all', async (req: Request, res: Response) => {
  try {
    const accounts = await prisma.account.findMany({
      select: { id: true, name: true, awsAccountId: true },
      orderBy: { name: 'asc' },
    });

    const result = await Promise.all(
      accounts.map(async (acct) => {
        const { titles, counts, checkIds, checkIdCounts } = await getActiveFindingData(acct.id);
        const scores = scoreFrameworks(titles, counts, checkIds, checkIdCounts).map(
          ({ controls: _c, ...summary }) => summary,
        );
        return { accountId: acct.id, accountName: acct.name, awsAccountId: acct.awsAccountId, scores };
      }),
    );

    res.json({ data: result });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/compliance/frameworks
// Returns the framework definitions (controls without scoring) for the UI.
router.get('/frameworks', (_req: Request, res: Response) => {
  res.json({ data: FRAMEWORKS });
});

// ─── Evidence endpoints ───────────────────────────────────────────────────────

// POST /api/compliance/evidence/collect
// Trigger auto-collection of evidence for an account.
router.post('/evidence/collect', async (req: Request, res: Response) => {
  try {
    const { accountId, provider, frameworkId } = req.body as {
      accountId: string;
      provider: 'AWS' | 'AZURE' | 'GCP';
      frameworkId?: string;
    };
    if (!accountId || !provider) {
      res.status(400).json({ error: 'accountId and provider are required' });
      return;
    }
    const result = await collectEvidenceForAccount(
      accountId,
      provider,
      frameworkId as Parameters<typeof collectEvidenceForAccount>[2],
    );
    res.json({ data: result });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/compliance/evidence?frameworkId=&controlId=&provider=&accountId=
router.get('/evidence', async (req: Request, res: Response) => {
  try {
    const { frameworkId, controlId, provider, accountId } = req.query as Record<string, string>;
    if (!frameworkId || !controlId) {
      res.status(400).json({ error: 'frameworkId and controlId are required' });
      return;
    }
    const data = await getEvidenceForControl(frameworkId, controlId, provider, accountId);
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/compliance/evidence/summary?frameworkId=&provider=&accountId=
router.get('/evidence/summary', async (req: Request, res: Response) => {
  try {
    const { frameworkId, provider, accountId } = req.query as Record<string, string>;
    if (!frameworkId) {
      res.status(400).json({ error: 'frameworkId is required' });
      return;
    }
    const data = await getEvidenceSummaryForFramework(frameworkId, provider, accountId);
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// POST /api/compliance/evidence — create manual evidence record
router.post('/evidence', async (req: Request, res: Response) => {
  try {
    const { frameworkId, controlId, provider, accountId, summary, detail, status } = req.body as {
      frameworkId: string;
      controlId: string;
      provider: string;
      accountId?: string;
      summary: string;
      detail?: Record<string, unknown>;
      status: 'COMPLIANT' | 'NON_COMPLIANT' | 'INSUFFICIENT';
    };
    if (!frameworkId || !controlId || !provider || !summary || !status) {
      res.status(400).json({ error: 'frameworkId, controlId, provider, summary, status are required' });
      return;
    }
    const expiresAt = new Date(Date.now() + 90 * 86_400_000);
    const record = await prisma.complianceEvidence.create({
      data: { frameworkId, controlId, provider, accountId, evidenceType: 'MANUAL', status, summary, detail: (detail ?? {}) as Prisma.InputJsonValue, expiresAt },
    });
    res.json({ data: record });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// DELETE /api/compliance/evidence/:id
router.delete('/evidence/:id', async (req: Request, res: Response) => {
  try {
    await prisma.complianceEvidence.delete({ where: { id: req.params.id } });
    res.json({ data: { deleted: true } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// POST /api/compliance/evidence/refresh — force re-capture of evidence
router.post('/evidence/refresh', async (req: Request, res: Response) => {
  try {
    const { accountId, provider, frameworkId } = req.body as {
      accountId: string;
      provider: 'AWS' | 'AZURE' | 'GCP';
      frameworkId?: string;
    };
    if (!accountId || !provider) {
      res.status(400).json({ error: 'accountId and provider are required' });
      return;
    }
    const result = await collectEvidenceForAccount(accountId, provider, frameworkId as any);
    res.json({ data: result });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// GET /api/compliance/evidence/export?frameworkId=&provider=&accountId=
router.get('/evidence/export', async (req: Request, res: Response) => {
  try {
    const { frameworkId, provider, accountId } = req.query as Record<string, string>;
    if (!frameworkId || !provider || !accountId) {
      res.status(400).json({ error: 'frameworkId, provider, and accountId are required' });
      return;
    }
    const bundle = await exportEvidencePackage(frameworkId, provider, accountId);
    res.setHeader('Content-Disposition', `attachment; filename="evidence-${frameworkId}-${accountId}.json"`);
    res.setHeader('Content-Type', 'application/json');
    res.send(JSON.stringify(bundle, null, 2));
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

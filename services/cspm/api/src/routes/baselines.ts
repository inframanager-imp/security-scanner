/**
 * Baseline & Drift Detection Routes
 *
 * POST  /api/baselines                         — request approval to capture new baseline
 * GET   /api/baselines                         — list baselines (filtered by provider+targetId)
 * GET   /api/baselines/:id                     — get baseline + drift summary
 * DELETE /api/baselines/:id                    — delete baseline
 * POST  /api/baselines/:id/detect             — run drift detection now
 * POST  /api/baselines/:id/refresh            — request approval to refresh baseline in-place
 * GET   /api/baselines/:id/drift              — list drift results
 * GET   /api/baselines/:id/drift/:driftId     — get drift detail (with before/after config)
 * GET   /api/baselines/:id/drift/:driftId/related-controls — compliance controls related to this drift (BCDD-F13)
 * PATCH /api/baselines/:id/drift/:driftId     — update drift status
 * POST  /api/baselines/:id/drift/:driftId/revert-plan  — generate revert plan
 * POST  /api/baselines/:id/drift/:driftId/revert       — request approval to revert
 * GET   /api/baselines/:id/remediation-log    — immutable remediation audit trail (BCDD-F25)
 * GET   /api/baselines/:id/versions           — list version history
 * GET   /api/baselines/:id/versions/:vId      — get version detail with snapshots
 * GET   /api/baselines/:id/versions/:vId/compare/:vId2 — compare two versions
 */

import { Router, Request, Response } from 'express';
import { prisma }               from '../config/database';
import {
  captureBaseline, detectDrift, refreshBaseline,
  listBaselineVersions, getBaselineVersion,
} from '../services/baselineService';
import { generateRevertPlan }   from '../services/revertService';
import { requestApproval }      from '../services/approvalService';
import { getRelatedControls }   from '../services/complianceService';
import { logger }               from '../config/logger';

const router = Router();

// ─── List baselines ───────────────────────────────────────────────────────────

router.get('/', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.query as Record<string, string>;
    const where: Record<string, unknown> = {};
    if (provider) where.provider = provider;
    if (targetId) where.targetId = targetId;

    const baselines = await prisma.configBaseline.findMany({
      where,
      orderBy: { capturedAt: 'desc' },
      include: {
        _count: { select: { driftResults: true } },
        driftResults: {
          where:  { status: 'OPEN' },
          select: { severity: true },
        },
      },
    });

    // Also attach any pending approvals for each baseline
    const baselineIds = baselines.map((b) => b.id);
    const pendingApprovals = baselineIds.length > 0
      ? await prisma.approvalRequest.findMany({
          where:  { baselineId: { in: baselineIds }, status: 'PENDING' },
          select: { id: true, baselineId: true, action: true, requestedBy: true, requestedAt: true, expiresAt: true },
        })
      : [];

    const approvalMap = new Map<string, typeof pendingApprovals[number][]>();
    for (const a of pendingApprovals) {
      if (!a.baselineId) continue;
      if (!approvalMap.has(a.baselineId)) approvalMap.set(a.baselineId, []);
      approvalMap.get(a.baselineId)!.push(a);
    }

    const result = baselines.map((b) => ({
      id:             b.id,
      name:           b.name,
      description:    b.description,
      provider:       b.provider,
      targetId:       b.targetId,
      resourceCount:  b.resourceCount,
      isActive:       b.isActive,
      capturedAt:     b.capturedAt,
      currentVersion: b.currentVersion,
      openDrift:      b.driftResults.length,
      criticalDrift:  b.driftResults.filter((d) => d.severity === 'CRITICAL').length,
      highDrift:      b.driftResults.filter((d) => d.severity === 'HIGH').length,
      pendingApprovals: approvalMap.get(b.id) ?? [],
    }));

    res.json(result);
  } catch (err) {
    logger.error('[baselines] list failed', err);
    res.status(500).json({ error: 'Failed to list baselines' });
  }
});

// ─── Create baseline — via approval request ───────────────────────────────────

router.post('/', async (req: Request, res: Response) => {
  try {
    const {
      provider, targetId, name, description, resourceTypes, nameSearch, region,
      requestedBy, requestedByName, notes, immediate,
    } = req.body as {
      provider: string; targetId: string; name: string; description?: string;
      resourceTypes?: string[]; nameSearch?: string; region?: string;
      requestedBy?: string; requestedByName?: string; notes?: string;
      immediate?: boolean;
    };

    if (!provider || !targetId || !name) {
      return res.status(400).json({ error: 'provider, targetId, and name are required' });
    }

    // immediate=true bypasses approval (e.g., dev/test mode or single-user environments)
    if (immediate || !requestedBy) {
      const id = await captureBaseline(provider, targetId, name, description, resourceTypes, nameSearch, requestedBy, region);
      const baseline = await prisma.configBaseline.findUnique({ where: { id } });
      return res.status(201).json(baseline);
    }

    // Create approval request for production governance
    const approval = await requestApproval({
      action:          'CAPTURE',
      requestedBy,
      requestedByName,
      notes,
      metadata: { provider, targetId, name, description, resourceTypes, nameSearch, region },
    });

    res.status(202).json({
      approvalRequired: true,
      approvalId:       approval.id,
      message:          `Baseline capture request submitted. Awaiting approval from ${requestedBy}.`,
      expiresAt:        approval.expiresAt,
    });
  } catch (err) {
    logger.error('[baselines] create failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Get single baseline ──────────────────────────────────────────────────────

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const baseline = await prisma.configBaseline.findUnique({
      where:   { id: req.params.id },
      include: {
        _count:      { select: { snapshots: true, driftResults: true, versions: true } },
        driftResults: {
          where:   { status: 'OPEN' },
          orderBy: { detectedAt: 'desc' },
          take:    5,
          select:  { id: true, driftType: true, severity: true, resourceType: true, resourceName: true, detectedAt: true },
        },
      },
    });
    if (!baseline) return res.status(404).json({ error: 'Not found' });
    res.json(baseline);
  } catch (err) {
    logger.error('[baselines] get failed', err);
    res.status(500).json({ error: 'Failed to get baseline' });
  }
});

// ─── Delete baseline ──────────────────────────────────────────────────────────

router.delete('/:id', async (req: Request, res: Response) => {
  try {
    await prisma.configBaseline.delete({ where: { id: req.params.id } });
    res.status(204).end();
  } catch (err) {
    logger.error('[baselines] delete failed', err);
    res.status(500).json({ error: 'Failed to delete baseline' });
  }
});

// ─── Refresh baseline — via approval request ──────────────────────────────────

router.post('/:id/refresh', async (req: Request, res: Response) => {
  try {
    const { requestedBy, requestedByName, notes, immediate } = req.body as {
      requestedBy?: string; requestedByName?: string; notes?: string; immediate?: boolean;
    };

    if (immediate || !requestedBy) {
      await refreshBaseline(req.params.id, requestedBy);
      const baseline = await prisma.configBaseline.findUnique({ where: { id: req.params.id } });
      return res.json(baseline);
    }

    const approval = await requestApproval({
      action:          'REFRESH',
      baselineId:      req.params.id,
      requestedBy,
      requestedByName,
      notes,
    });

    res.status(202).json({
      approvalRequired: true,
      approvalId:       approval.id,
      message:          'Baseline refresh request submitted. Awaiting approval.',
      expiresAt:        approval.expiresAt,
    });
  } catch (err) {
    logger.error('[baselines] refresh failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Run drift detection ──────────────────────────────────────────────────────

router.post('/:id/detect', async (req: Request, res: Response) => {
  try {
    const result = await detectDrift(req.params.id);
    res.json(result);
  } catch (err) {
    logger.error('[baselines] detect failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── List drift results ───────────────────────────────────────────────────────

router.get('/:id/drift', async (req: Request, res: Response) => {
  try {
    const page      = Math.max(1, parseInt(req.query.page     as string) || 1);
    const pageSize  = Math.min(100, parseInt(req.query.pageSize as string) || 25);
    const status        = (req.query.status as string) || 'OPEN';
    const driftType     = req.query.driftType as string | undefined;
    const controlDomain = req.query.controlDomain as string | undefined;

    const where: Record<string, unknown> = { baselineId: req.params.id };
    if (status !== 'ALL') where.status = status;
    if (driftType) where.driftType = driftType;
    if (controlDomain) where.controlDomain = controlDomain;

    const [total, results] = await Promise.all([
      prisma.driftResult.count({ where }),
      prisma.driftResult.findMany({
        where,
        orderBy: [{ severity: 'asc' }, { detectedAt: 'desc' }],
        skip:    (page - 1) * pageSize,
        take:    pageSize,
        select: {
          id: true, driftType: true, severity: true, nativeId: true,
          resourceType: true, resourceName: true, region: true, controlDomain: true,
          driftedFields: true, status: true, detectedAt: true,
          acknowledgedAt: true, resolvedAt: true,
        },
      }),
    ]);

    // Attach any pending revert approvals for drift items on this page
    const driftIds = results.map((r) => r.id);
    const revertApprovals = driftIds.length > 0
      ? await prisma.approvalRequest.findMany({
          where:  { driftId: { in: driftIds }, status: { in: ['PENDING', 'EXECUTING'] } },
          select: { id: true, driftId: true, status: true, requestedBy: true },
        })
      : [];
    const revertMap = new Map(revertApprovals.map((a) => [a.driftId, a]));

    res.json({
      total, page, pageSize,
      results: results.map((r) => ({
        ...r,
        pendingRevert: revertMap.get(r.id) ?? null,
      })),
    });
  } catch (err) {
    logger.error('[baselines] drift list failed', err);
    res.status(500).json({ error: 'Failed to list drift results' });
  }
});

// ─── Get drift result detail ──────────────────────────────────────────────────

router.get('/:id/drift/:driftId', async (req: Request, res: Response) => {
  try {
    const [result, baseline] = await Promise.all([
      prisma.driftResult.findFirst({
        where: { id: req.params.driftId, baselineId: req.params.id },
      }),
      prisma.configBaseline.findUnique({
        where:  { id: req.params.id },
        select: { capturedAt: true },
      }),
    ]);
    if (!result) return res.status(404).json({ error: 'Not found' });

    const [inventoryRecord, pendingRevert] = await Promise.all([
      result.driftType !== 'DELETED'
        ? prisma.resourceInventory.findFirst({
            where:  { nativeId: { equals: result.nativeId, mode: 'insensitive' } },
            select: { lastSeenAt: true },
          })
        : null,
      prisma.approvalRequest.findFirst({
        where:  { driftId: result.id, status: { in: ['PENDING', 'EXECUTING'] } },
        select: { id: true, status: true, requestedBy: true, expiresAt: true },
      }),
    ]);

    const currentLastSeenAt =
      result.driftType === 'DELETED'
        ? (result as Record<string, unknown>).lastSeenAt ?? null
        : inventoryRecord?.lastSeenAt ?? null;

    res.json({
      ...result,
      baselineCapturedAt: baseline?.capturedAt ?? null,
      currentLastSeenAt,
      pendingRevert,
    });
  } catch (err) {
    logger.error('[baselines] drift get failed', err);
    res.status(500).json({ error: 'Failed to get drift result' });
    return;
  }
});

// ─── Related compliance controls (BCDD-F13) ────────────────────────────────────

router.get('/:id/drift/:driftId/related-controls', async (req: Request, res: Response) => {
  try {
    const drift = await prisma.driftResult.findFirst({
      where:  { id: req.params.driftId, baselineId: req.params.id },
      select: { controlDomain: true, resourceType: true },
    });
    if (!drift) return res.status(404).json({ error: 'Not found' });

    const related = getRelatedControls(drift.controlDomain, drift.resourceType);
    res.json({ controlDomain: drift.controlDomain, resourceType: drift.resourceType, related });
  } catch (err) {
    logger.error('[baselines] related-controls failed', err);
    res.status(500).json({ error: 'Failed to fetch related controls' });
  }
});

// ─── Update drift status ──────────────────────────────────────────────────────

const DRIFT_STATUSES = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'REVERTED', 'SUPPRESSED', 'CLOSED'] as const;

router.patch('/:id/drift/:driftId', async (req: Request, res: Response) => {
  try {
    const { status, suppressionReason, suppressionExpiresAt } = req.body as {
      status: typeof DRIFT_STATUSES[number];
      suppressionReason?: string;
      suppressionExpiresAt?: string;
    };
    if (!DRIFT_STATUSES.includes(status)) {
      return res.status(400).json({ error: `status must be one of ${DRIFT_STATUSES.join(' | ')}` });
    }

    if (status === 'SUPPRESSED') {
      if (!suppressionReason?.trim()) {
        return res.status(400).json({ error: 'suppressionReason is required to suppress a finding' });
      }
      if (!suppressionExpiresAt || Number.isNaN(Date.parse(suppressionExpiresAt))) {
        return res.status(400).json({ error: 'suppressionExpiresAt (ISO date) is required to suppress a finding' });
      }
      if (new Date(suppressionExpiresAt) <= new Date()) {
        return res.status(400).json({ error: 'suppressionExpiresAt must be in the future' });
      }
    }

    const before = await prisma.driftResult.findUnique({
      where: { id: req.params.driftId },
      select: { baselineId: true, currentConfig: true, baselineConfig: true },
    });

    const updated = await prisma.driftResult.update({
      where: { id: req.params.driftId },
      data:  {
        status,
        ...(status === 'ACKNOWLEDGED' && { acknowledgedAt: new Date() }),
        ...(status === 'RESOLVED'     && { resolvedAt:     new Date() }),
        ...(status === 'CLOSED'       && { closedAt:       new Date() }),
        ...(status === 'SUPPRESSED'   && {
          suppressedAt: new Date(),
          suppressedBy: req.user?.id ?? null,
          suppressionReason,
          suppressionExpiresAt: new Date(suppressionExpiresAt!),
        }),
      },
      select: {
        id: true, status: true, acknowledgedAt: true, resolvedAt: true, closedAt: true,
        suppressedAt: true, suppressedBy: true, suppressionReason: true, suppressionExpiresAt: true,
      },
    });

    if (status === 'RESOLVED' && before) {
      await prisma.remediationLog.create({
        data: {
          driftResultId: req.params.driftId,
          baselineId:    before.baselineId,
          action:        'MANUAL_RESOLVE',
          actor:         req.user?.id ?? 'unknown',
          outcome:       'SUCCESS',
          message:       'Operator marked finding resolved outside the auto-revert path.',
          beforeState:   before.currentConfig ?? undefined,
          afterState:    before.baselineConfig ?? undefined,
        },
      }).catch((err) => logger.error(`[baselines] Failed to write remediation audit log: ${(err as Error).message}`));
    }

    res.json(updated);
  } catch (err) {
    logger.error('[baselines] drift update failed', err);
    res.status(500).json({ error: 'Failed to update drift status' });
  }
});

// ─── Generate revert plan ─────────────────────────────────────────────────────

router.post('/:id/drift/:driftId/revert-plan', async (req: Request, res: Response) => {
  try {
    const plan = await generateRevertPlan(req.params.id, req.params.driftId);

    await prisma.remediationLog.create({
      data: {
        driftResultId: req.params.driftId,
        baselineId:    req.params.id,
        action:        'GUIDED_PLAN_GENERATED',
        actor:         req.user?.id ?? 'unknown',
        outcome:       'SUCCESS',
        message:       plan.canAutoRevert ? 'Auto-revert plan generated.' : 'Manual remediation script generated.',
      },
    }).catch((err) => logger.error(`[baselines] Failed to write remediation audit log: ${(err as Error).message}`));

    res.json(plan);
  } catch (err) {
    logger.error('[baselines] revert-plan failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Remediation audit trail (BCDD-F25 / N05) ──────────────────────────────────

router.get('/:id/remediation-log', async (req: Request, res: Response) => {
  try {
    const page     = Math.max(1, parseInt(String(req.query.page ?? '1'), 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(String(req.query.pageSize ?? '25'), 10)));

    const [total, results] = await Promise.all([
      prisma.remediationLog.count({ where: { baselineId: req.params.id } }),
      prisma.remediationLog.findMany({
        where:   { baselineId: req.params.id },
        orderBy: { createdAt: 'desc' },
        skip:    (page - 1) * pageSize,
        take:    pageSize,
      }),
    ]);

    res.json({ total, page, pageSize, results });
  } catch (err) {
    logger.error('[baselines] remediation-log fetch failed', err);
    res.status(500).json({ error: 'Failed to fetch remediation log' });
  }
});

// ─── Request revert approval ──────────────────────────────────────────────────

router.post('/:id/drift/:driftId/revert', async (req: Request, res: Response) => {
  try {
    const { requestedBy, requestedByName, notes, immediate } = req.body as {
      requestedBy?: string; requestedByName?: string; notes?: string; immediate?: boolean;
    };

    if (!requestedBy) {
      return res.status(400).json({ error: 'requestedBy (email) is required' });
    }

    if (immediate) {
      // Skip approval — execute directly (for dev/low-risk environments)
      const { executeRevert } = await import('../services/revertService');
      const result = await executeRevert(req.params.id, req.params.driftId, requestedBy);
      return res.json(result);
    }

    // Check if there's already a pending revert for this drift
    const existing = await prisma.approvalRequest.findFirst({
      where: { driftId: req.params.driftId, status: 'PENDING' },
    });
    if (existing) {
      return res.status(409).json({
        error:      'A revert approval for this drift item is already pending',
        approvalId: existing.id,
      });
    }

    const approval = await requestApproval({
      action:          'REVERT',
      baselineId:      req.params.id,
      driftId:         req.params.driftId,
      requestedBy,
      requestedByName,
      notes,
      metadata: { driftId: req.params.driftId },
    });

    res.status(202).json({
      approvalRequired: true,
      approvalId:       approval.id,
      message:          'Revert request submitted. Awaiting approval before config is pushed to cloud.',
      expiresAt:        approval.expiresAt,
    });
  } catch (err) {
    logger.error('[baselines] revert failed', err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── List version history ─────────────────────────────────────────────────────

router.get('/:id/versions', async (req: Request, res: Response) => {
  try {
    const versions = await listBaselineVersions(req.params.id);
    res.json(versions);
  } catch (err) {
    logger.error('[baselines] versions list failed', err);
    res.status(500).json({ error: 'Failed to list baseline versions' });
  }
});

// ─── Get version detail ───────────────────────────────────────────────────────

router.get('/:id/versions/:vId', async (req: Request, res: Response) => {
  try {
    const version = await getBaselineVersion(req.params.id, req.params.vId);
    if (!version) return res.status(404).json({ error: 'Version not found' });
    res.json(version);
  } catch (err) {
    logger.error('[baselines] version get failed', err);
    res.status(500).json({ error: 'Failed to get baseline version' });
  }
});

// ─── Compare two versions ─────────────────────────────────────────────────────

router.get('/:id/versions/:vId/compare/:vId2', async (req: Request, res: Response) => {
  try {
    const [v1, v2] = await Promise.all([
      getBaselineVersion(req.params.id, req.params.vId),
      getBaselineVersion(req.params.id, req.params.vId2),
    ]);
    if (!v1 || !v2) return res.status(404).json({ error: 'One or both versions not found' });

    const v1Map = new Map(v1.snapshots.map((s) => [s.nativeId, s]));
    const v2Map = new Map(v2.snapshots.map((s) => [s.nativeId, s]));

    const added:    typeof v1.snapshots = [];
    const deleted:  typeof v1.snapshots = [];
    const modified: { nativeId: string; resourceType: string; resourceName: string | null; changedFields: string[] }[] = [];

    for (const [nativeId, snap] of v2Map) {
      if (!v1Map.has(nativeId)) { added.push(snap); continue; }
      const old = v1Map.get(nativeId)!;
      if (JSON.stringify(old.configState) !== JSON.stringify(snap.configState)) {
        const changedFields = diffTopLevelKeys(
          old.configState  as Record<string, unknown>,
          snap.configState as Record<string, unknown>,
        );
        modified.push({ nativeId, resourceType: snap.resourceType, resourceName: snap.resourceName, changedFields });
      }
    }
    for (const [nativeId, snap] of v1Map) {
      if (!v2Map.has(nativeId)) deleted.push(snap);
    }

    res.json({
      v1: { id: v1.id, versionNumber: v1.versionNumber, label: v1.label, capturedAt: v1.capturedAt, resourceCount: v1.resourceCount },
      v2: { id: v2.id, versionNumber: v2.versionNumber, label: v2.label, capturedAt: v2.capturedAt, resourceCount: v2.resourceCount },
      summary: { added: added.length, deleted: deleted.length, modified: modified.length },
      added, deleted, modified,
    });
  } catch (err) {
    logger.error('[baselines] version compare failed', err);
    res.status(500).json({ error: 'Failed to compare versions' });
  }
});

function diffTopLevelKeys(a: Record<string, unknown>, b: Record<string, unknown>): string[] {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));
}

export default router;

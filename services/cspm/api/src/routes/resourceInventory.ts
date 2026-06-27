/**
 * Resource Inventory API
 *
 * POST /api/resource-inventory/discover      — trigger background discovery for a target
 * GET  /api/resource-inventory               — list resources (paginated, filterable)
 * GET  /api/resource-inventory/stats         — counts by provider / type / state
 * GET  /api/resource-inventory/:id           — full resource detail + latest config
 * GET  /api/resource-inventory/:id/timeline  — all snapshots ordered by time
 * GET  /api/resource-inventory/:id/deps      — dependency edges (from + to)
 * GET  /api/resource-inventory/discover/runs — list discovery run history for a target
 */
import { Router, Request, Response } from 'express';
import { prisma }       from '../config/database';
import { authenticate } from '../middleware/authenticate';
import {
  discoverAwsResources,
  discoverAzureResources,
  discoverGcpResources,
} from '../services/resourceDiscoveryService';

const router = Router();
router.use(authenticate);

// ─── Discovery ────────────────────────────────────────────────────────────────

router.post('/discover', async (req: Request, res: Response) => {
  const { provider, targetId } = req.body as { provider: string; targetId: string };
  if (!provider || !targetId) {
    res.status(400).json({ error: 'provider and targetId are required' });
    return;
  }

  res.json({ data: { status: 'RUNNING', message: 'Discovery started in background' } });

  void (async () => {
    try {
      if      (provider === 'AWS')   await discoverAwsResources(targetId);
      else if (provider === 'AZURE') await discoverAzureResources(targetId);
      else if (provider === 'GCP')   await discoverGcpResources(targetId);
    } catch (err) {
      console.error('[resource-discovery] error:', (err as Error).message);
    }
  })();
});

// ─── Stats ────────────────────────────────────────────────────────────────────

router.get('/stats', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.query as Record<string, string>;
    const windowDays = Math.min(Math.max(parseInt(req.query.windowDays as string) || 0, 0), 365);
    const where = buildWhere(provider, targetId);

    // Snapshot activity counts only when a time window is requested
    let created = 0, modified = 0, deleted = 0;
    if (windowDays > 0) {
      const windowStart = new Date(Date.now() - windowDays * 86_400_000);

      // Two-step: get inventoryIds matching the target, then group snapshots
      const invIds = await prisma.resourceInventory.findMany({
        where,
        select: { id: true },
      });
      const idSet = invIds.map((r) => r.id);

      if (idSet.length > 0) {
        const snapCounts = await prisma.resourceSnapshot.groupBy({
          by: ['changeType'],
          where: {
            inventoryId: { in: idSet },
            capturedAt:  { gte: windowStart },
          },
          _count: { id: true },
        });
        for (const row of snapCounts) {
          if (row.changeType === 'CREATED')  created  = row._count.id;
          if (row.changeType === 'MODIFIED') modified = row._count.id;
          if (row.changeType === 'DELETED')  deleted  = row._count.id;
        }
      }
    }

    const [byProvider, byType, byState, total] = await Promise.all([
      prisma.resourceInventory.groupBy({ by: ['provider'], where, _count: { id: true } }),
      prisma.resourceInventory.groupBy({
        by: ['resourceType'], where,
        _count: { id: true }, orderBy: { _count: { id: 'desc' } }, take: 20,
      }),
      prisma.resourceInventory.groupBy({ by: ['state'], where, _count: { id: true } }),
      prisma.resourceInventory.count({ where }),
    ]);

    res.json({
      data: {
        total,
        byProvider: Object.fromEntries(byProvider.map((r) => [r.provider, r._count.id])),
        byType:     byType.map((r) => ({ type: r.resourceType, count: r._count.id })),
        byState:    Object.fromEntries(byState.map((r) => [r.state, r._count.id])),
        ...(windowDays > 0 && { windowDays, created, modified, deleted }),
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Activity Log (MODIFIED + DELETED snapshots only) ────────────────────────

router.get('/activity-log', async (req: Request, res: Response) => {
  try {
    const { provider, targetId } = req.query as Record<string, string>;
    const page     = Math.max(parseInt(req.query.page     as string) || 1, 1);
    const pageSize = Math.min(parseInt(req.query.pageSize as string) || 25, 100);
    const skip     = (page - 1) * pageSize;

    const inventoryWhere = buildWhere(provider, targetId);

    // Get matching inventory IDs first (avoids nested-relation groupBy issues)
    const invIds = await prisma.resourceInventory.findMany({
      where: inventoryWhere,
      select: { id: true },
    });
    const idSet = invIds.map((r) => r.id);

    if (idSet.length === 0) {
      res.json({ data: [], total: 0, page, pageSize, totalPages: 0 });
      return;
    }

    const snapWhere = {
      inventoryId: { in: idSet },
      changeType:  { in: ['MODIFIED', 'DELETED'] as string[] },
    };

    const [rows, total] = await Promise.all([
      prisma.resourceSnapshot.findMany({
        where:   snapWhere,
        orderBy: { capturedAt: 'desc' },
        skip,
        take:    pageSize,
        select: {
          id:         true,
          changeType: true,
          capturedAt: true,
          inventory: {
            select: {
              id:           true,
              nativeId:     true,
              resourceType: true,
              resourceName: true,
              region:       true,
              provider:     true,
              state:        true,
            },
          },
        },
      }),
      prisma.resourceSnapshot.count({ where: snapWhere }),
    ]);

    res.json({
      data:       rows,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── List ─────────────────────────────────────────────────────────────────────

function buildWhere(provider?: string, targetId?: string): Record<string, unknown> {
  const base: Record<string, unknown> = {};
  if (provider === 'AWS'   && targetId) base.awsAccountId  = targetId;
  if (provider === 'AZURE' && targetId) base.azureSubId    = targetId;
  if (provider === 'GCP'   && targetId) base.gcpProjectId  = targetId;
  if (provider && !targetId)            base.provider      = provider;
  return base;
}

router.get('/', async (req: Request, res: Response) => {
  try {
    const {
      provider, targetId, resourceType, state, region, search,
      sortBy = 'lastSeenAt', sortOrder = 'desc',
    } = req.query as Record<string, string>;

    const page     = parseInt(req.query.page     as string) || 1;
    const pageSize = Math.min(parseInt(req.query.pageSize as string) || 50, 200);
    const skip     = (page - 1) * pageSize;

    const where: Record<string, unknown> = buildWhere(provider, targetId);
    if (resourceType) where.resourceType = { contains: resourceType, mode: 'insensitive' };
    if (state)        where.state        = state;
    if (region)       where.region       = { contains: region, mode: 'insensitive' };
    if (search) {
      where.OR = [
        { resourceName: { contains: search, mode: 'insensitive' } },
        { resourceType: { contains: search, mode: 'insensitive' } },
        { nativeId:     { contains: search, mode: 'insensitive' } },
        { region:       { contains: search, mode: 'insensitive' } },
      ];
    }

    const validSort: Record<string, string> = {
      lastSeenAt: 'lastSeenAt', discoveredAt: 'discoveredAt',
      resourceType: 'resourceType', resourceName: 'resourceName',
    };
    const orderField = validSort[sortBy] ?? 'lastSeenAt';

    const [rows, total] = await Promise.all([
      prisma.resourceInventory.findMany({
        where,
        skip,
        take: pageSize,
        orderBy: { [orderField]: sortOrder === 'asc' ? 'asc' : 'desc' },
        select: {
          id: true, provider: true, resourceType: true, resourceName: true,
          nativeId: true, region: true, resourceGroup: true, state: true,
          discoveredAt: true, lastSeenAt: true, deletedAt: true, tags: true,
          // omit configState from list — fetch on detail
          _count: { select: { snapshots: true, depsFrom: true, depsTo: true } },
        },
      }),
      prisma.resourceInventory.count({ where }),
    ]);

    res.json({
      data: rows,
      meta: { total, page, pageSize, totalPages: Math.ceil(total / pageSize) },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Snapshot timeline ────────────────────────────────────────────────────────

router.get('/:id/timeline', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const limit  = Math.min(parseInt(req.query.limit as string) || 50, 200);

    const snapshots = await prisma.resourceSnapshot.findMany({
      where: { inventoryId: id },
      orderBy: { capturedAt: 'desc' },
      take: limit,
    });

    // Build diffs between consecutive snapshots
    const timeline = snapshots.map((snap, idx) => {
      const next = snapshots[idx + 1]; // older snapshot
      let diff: Record<string, { from: unknown; to: unknown }> | null = null;

      if (next && snap.changeType === 'MODIFIED') {
        const curr = snap.configState as Record<string, unknown>;
        const prev = next.configState as Record<string, unknown>;
        diff = {};
        const allKeys = new Set([...Object.keys(curr), ...Object.keys(prev)]);
        for (const key of allKeys) {
          if (JSON.stringify(curr[key]) !== JSON.stringify(prev[key])) {
            diff[key] = { from: prev[key] ?? null, to: curr[key] ?? null };
          }
        }
        if (Object.keys(diff).length === 0) diff = null;
      }

      return { id: snap.id, changeType: snap.changeType, capturedAt: snap.capturedAt, diff };
    });

    res.json({ data: timeline });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Snapshot detail (full config for a specific point in time) ────────────────

router.get('/snapshots/:snapshotId', async (req: Request, res: Response) => {
  try {
    const snap = await prisma.resourceSnapshot.findUnique({ where: { id: req.params.snapshotId } });
    if (!snap) { res.status(404).json({ error: 'Snapshot not found' }); return; }
    res.json({ data: snap });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Dependencies ─────────────────────────────────────────────────────────────

router.get('/:id/deps', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const [depsFrom, depsTo] = await Promise.all([
      prisma.resourceDependency.findMany({
        where: { fromId: id },
        include: { toResource: { select: { id: true, resourceType: true, resourceName: true, nativeId: true, provider: true, state: true } } },
      }),
      prisma.resourceDependency.findMany({
        where: { toId: id },
        include: { fromResource: { select: { id: true, resourceType: true, resourceName: true, nativeId: true, provider: true, state: true } } },
      }),
    ]);

    res.json({
      data: {
        dependsOn:  depsFrom.map((d) => ({ id: d.id, depType: d.depType, description: d.description, resource: d.toResource })),
        usedBy:     depsTo.map((d)   => ({ id: d.id, depType: d.depType, description: d.description, resource: d.fromResource })),
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ─── Single resource detail ────────────────────────────────────────────────────

router.get('/:id', async (req: Request, res: Response) => {
  try {
    const resource = await prisma.resourceInventory.findUnique({
      where: { id: req.params.id },
      include: {
        _count: { select: { snapshots: true, depsFrom: true, depsTo: true } },
      },
    });
    if (!resource) { res.status(404).json({ error: 'Resource not found' }); return; }
    res.json({ data: resource });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

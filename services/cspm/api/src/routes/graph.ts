/**
 * Asset Graph API
 *
 * POST /api/graph/build/:provider/:targetId  — enqueue a graph rebuild
 * GET  /api/graph/resource/:id               — subgraph around a single resource
 * GET  /api/graph/exposure/:provider/:targetId — internet-exposed resources for an account
 * GET  /api/graph/edge-types                 — list DependencyType enum values for filter UIs
 */

import { Router, Request, Response } from 'express';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { DependencyType } from '@prisma/client';
import {
  queryNeighborhood,
  listExposedResources,
} from '../services/graphEnrichmentService';
import { enqueueGraphBuild } from '../workers/graphBuildWorker';

const router = Router();
router.use(authenticate);

router.post('/build/:provider/:targetId', async (req: Request, res: Response) => {
  const { provider, targetId } = req.params;
  if (!['AWS', 'AZURE', 'GCP'].includes(provider)) {
    res.status(400).json({ error: 'provider must be AWS | AZURE | GCP' });
    return;
  }
  try {
    const jobId = await enqueueGraphBuild({
      provider: provider as 'AWS' | 'AZURE' | 'GCP',
      accountId: targetId,
      triggeredBy: 'MANUAL',
    });
    res.json({ data: { jobId, status: 'QUEUED' } });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/resource/:id', async (req: Request, res: Response) => {
  const { id } = req.params;
  const edgeTypesParam = (req.query.edges as string | undefined) ?? '';
  const depthParam = parseInt((req.query.depth as string) ?? '2', 10);
  const direction = (req.query.direction as 'both' | 'in' | 'out' | undefined) ?? 'both';

  const requestedEdges = edgeTypesParam
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean) as DependencyType[];
  const validEdgeTypes = Object.values(DependencyType);
  const edgeTypes = requestedEdges.filter((t) => validEdgeTypes.includes(t));

  try {
    const result = await queryNeighborhood(id, {
      edgeTypes: edgeTypes.length > 0 ? edgeTypes : undefined,
      depth: Number.isFinite(depthParam) ? depthParam : 2,
      direction,
    });
    res.json({ data: result });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/exposure/:provider/:targetId', async (req: Request, res: Response) => {
  const { provider, targetId } = req.params;
  if (!['AWS', 'AZURE', 'GCP'].includes(provider)) {
    res.status(400).json({ error: 'provider must be AWS | AZURE | GCP' });
    return;
  }
  try {
    const rows = await listExposedResources(
      provider as 'AWS' | 'AZURE' | 'GCP',
      targetId,
    );
    res.json({ data: rows });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

router.get('/edge-types', (_req: Request, res: Response) => {
  res.json({ data: Object.values(DependencyType) });
});

router.get('/stats/:provider/:targetId', async (req: Request, res: Response) => {
  const { provider, targetId } = req.params;
  const idField =
    provider === 'AWS' ? 'awsAccountId' : provider === 'AZURE' ? 'azureSubId' : 'gcpProjectId';

  try {
    const [nodes, edgesByType, exposedCount] = await Promise.all([
      prisma.resourceInventory.count({
        where: { [idField]: targetId, state: 'ACTIVE' },
      }),
      prisma.resourceDependency.groupBy({
        by: ['depType'],
        where: { provider, fromResource: { [idField]: targetId } },
        _count: { _all: true },
      }),
      prisma.exposurePath.count({
        where: {
          provider,
          exposureType: 'PUBLIC_INTERNET',
          resource: { [idField]: targetId },
        },
      }),
    ]);

    res.json({
      data: {
        nodes,
        edgesByType: edgesByType.map((g) => ({ type: g.depType, count: g._count._all })),
        exposedCount,
      },
    });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

export default router;

import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { startTestServer, TestServer } from './testServer';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

jest.mock('../../../src/config/database', () => ({
  prisma: {
    resourceInventory: { count: jest.fn() },
    resourceDependency: { groupBy: jest.fn() },
    exposurePath: { count: jest.fn() },
  },
}));

jest.mock('../../../src/services/graphEnrichmentService', () => ({
  queryNeighborhood: jest.fn(),
  listExposedResources: jest.fn(),
}));

jest.mock('../../../src/workers/graphBuildWorker', () => ({
  enqueueGraphBuild: jest.fn(),
}));

import { prisma } from '../../../src/config/database';
import { queryNeighborhood, listExposedResources } from '../../../src/services/graphEnrichmentService';
import { enqueueGraphBuild } from '../../../src/workers/graphBuildWorker';

describe('routes/graph', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/graph')).default;
    server = await startTestServer('/api/graph', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /build/:provider/:targetId', () => {
    it('enqueues a graph build for a valid provider', async () => {
      (enqueueGraphBuild as jest.Mock).mockResolvedValue('job-1');

      const res = await fetch(`${server.baseUrl}/build/AWS/acc-1`, { method: 'POST' });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual({ jobId: 'job-1', status: 'QUEUED' });
    });

    it('returns 400 for an invalid provider', async () => {
      const res = await fetch(`${server.baseUrl}/build/BOGUS/acc-1`, { method: 'POST' });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('provider must be AWS | AZURE | GCP');
      expect(enqueueGraphBuild).not.toHaveBeenCalled();
    });

    it('returns 500 when enqueueing throws', async () => {
      (enqueueGraphBuild as jest.Mock).mockRejectedValue(new Error('queue down'));

      const res = await fetch(`${server.baseUrl}/build/GCP/proj-1`, { method: 'POST' });
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('queue down');
    });
  });

  describe('GET /resource/:id', () => {
    it('queries the neighborhood with defaults (depth=2, direction=both)', async () => {
      (queryNeighborhood as jest.Mock).mockResolvedValue({ nodes: [], edges: [] });

      const res = await fetch(`${server.baseUrl}/resource/r1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual({ nodes: [], edges: [] });
      expect(queryNeighborhood).toHaveBeenCalledWith('r1', { edgeTypes: undefined, depth: 2, direction: 'both' });
    });

    it('returns 500 when the query throws', async () => {
      (queryNeighborhood as jest.Mock).mockRejectedValue(new Error('graph error'));

      const res = await fetch(`${server.baseUrl}/resource/r1`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('graph error');
    });
  });

  describe('GET /exposure/:provider/:targetId', () => {
    it('returns exposed resources for a valid provider', async () => {
      (listExposedResources as jest.Mock).mockResolvedValue([{ id: 'r1' }]);

      const res = await fetch(`${server.baseUrl}/exposure/AWS/acc-1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual([{ id: 'r1' }]);
    });

    it('returns 400 for an invalid provider', async () => {
      const res = await fetch(`${server.baseUrl}/exposure/BOGUS/acc-1`);
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('provider must be AWS | AZURE | GCP');
    });
  });

  describe('GET /edge-types', () => {
    it('returns the DependencyType enum values', async () => {
      const res = await fetch(`${server.baseUrl}/edge-types`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual(expect.arrayContaining(['NETWORK', 'IAM', 'STORAGE']));
    });
  });

  describe('GET /stats/:provider/:targetId', () => {
    it('returns node counts, edge counts by type, and exposed count', async () => {
      (prisma.resourceInventory.count as jest.Mock).mockResolvedValue(5);
      (prisma.resourceDependency.groupBy as jest.Mock).mockResolvedValue([{ depType: 'NETWORK', _count: { _all: 3 } }]);
      (prisma.exposurePath.count as jest.Mock).mockResolvedValue(2);

      const res = await fetch(`${server.baseUrl}/stats/AWS/acc-1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.nodes).toBe(5);
      expect(body.data.edgesByType).toEqual([{ type: 'NETWORK', count: 3 }]);
      expect(body.data.exposedCount).toBe(2);
    });

    it('returns 500 when a Prisma call throws', async () => {
      (prisma.resourceInventory.count as jest.Mock).mockRejectedValue(new Error('db error'));

      const res = await fetch(`${server.baseUrl}/stats/AWS/acc-1`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('db error');
    });
  });
});

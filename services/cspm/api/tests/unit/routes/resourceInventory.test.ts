import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockInventoryFindMany = jest.fn();
const mockInventoryCount = jest.fn();
const mockInventoryGroupBy = jest.fn();
const mockInventoryFindUnique = jest.fn();
const mockSnapshotFindMany = jest.fn();
const mockSnapshotFindUnique = jest.fn();
const mockSnapshotCount = jest.fn();
const mockSnapshotGroupBy = jest.fn();
const mockDepFindMany = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    resourceInventory: {
      findMany: mockInventoryFindMany,
      count: mockInventoryCount,
      groupBy: mockInventoryGroupBy,
      findUnique: mockInventoryFindUnique,
    },
    resourceSnapshot: {
      findMany: mockSnapshotFindMany,
      findUnique: mockSnapshotFindUnique,
      count: mockSnapshotCount,
      groupBy: mockSnapshotGroupBy,
    },
    resourceDependency: {
      findMany: mockDepFindMany,
    },
  },
}));

const mockDiscoverAws = jest.fn(async () => undefined);
const mockDiscoverAzure = jest.fn(async () => undefined);
const mockDiscoverGcp = jest.fn(async () => undefined);

jest.mock('../../../src/services/resourceDiscoveryService', () => ({
  discoverAwsResources: mockDiscoverAws,
  discoverAzureResources: mockDiscoverAzure,
  discoverGcpResources: mockDiscoverGcp,
}));

import router from '../../../src/routes/resourceInventory';

describe('routes/resourceInventory', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    app = buildTestApp('/api/resource-inventory', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('authentication', () => {
    it('still succeeds because authenticate is mocked to always attach a user', async () => {
      mockInventoryFindMany.mockResolvedValueOnce([]);
      mockInventoryCount.mockResolvedValueOnce(0);

      const res = await server.get('/api/resource-inventory', AUTH_HEADER);

      expect(res.status).toBe(200);
    });
  });

  describe('POST /api/resource-inventory/discover', () => {
    it('returns 400 when provider or targetId is missing', async () => {
      const res = await server.post('/api/resource-inventory/discover', { provider: 'AWS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'provider and targetId are required' });
    });

    it('responds immediately with RUNNING status for a valid request', async () => {
      const res = await server.post(
        '/api/resource-inventory/discover',
        { provider: 'AWS', targetId: 'acc-1' },
        AUTH_HEADER
      );

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ data: { status: 'RUNNING', message: 'Discovery started in background' } });
    });
  });

  describe('GET /api/resource-inventory/stats', () => {
    it('returns aggregate counts without a time window', async () => {
      mockInventoryGroupBy
        .mockResolvedValueOnce([{ provider: 'AWS', _count: { id: 5 } }])
        .mockResolvedValueOnce([{ resourceType: 'S3Bucket', _count: { id: 3 } }])
        .mockResolvedValueOnce([{ state: 'ACTIVE', _count: { id: 5 } }]);
      mockInventoryCount.mockResolvedValueOnce(5);

      const res = await server.get('/api/resource-inventory/stats?provider=AWS&targetId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.total).toBe(5);
      expect(res.body.data.byProvider).toEqual({ AWS: 5 });
      expect(res.body.data.byType).toEqual([{ type: 'S3Bucket', count: 3 }]);
      expect(res.body.data.byState).toEqual({ ACTIVE: 5 });
      expect(res.body.data.windowDays).toBeUndefined();
    });

    it('returns 500 when a query fails', async () => {
      mockInventoryGroupBy.mockRejectedValueOnce(new Error('db down'));

      const res = await server.get('/api/resource-inventory/stats', AUTH_HEADER);

      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/resource-inventory', () => {
    it('returns paginated resources', async () => {
      mockInventoryFindMany.mockResolvedValueOnce([{ id: 'r1', resourceType: 'S3Bucket' }]);
      mockInventoryCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/resource-inventory', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ id: 'r1', resourceType: 'S3Bucket' }]);
      expect(res.body.meta).toEqual({ total: 1, page: 1, pageSize: 50, totalPages: 1 });
    });
  });

  describe('GET /api/resource-inventory/:id', () => {
    it('returns resource detail when found', async () => {
      mockInventoryFindUnique.mockResolvedValueOnce({ id: 'r1', resourceType: 'S3Bucket' });

      const res = await server.get('/api/resource-inventory/r1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ data: { id: 'r1', resourceType: 'S3Bucket' } });
    });

    it('returns 404 when the resource does not exist', async () => {
      mockInventoryFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/resource-inventory/missing', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Resource not found' });
    });
  });

  describe('GET /api/resource-inventory/:id/timeline', () => {
    it('builds a diff between consecutive MODIFIED snapshots', async () => {
      mockSnapshotFindMany.mockResolvedValueOnce([
        { id: 'snap2', changeType: 'MODIFIED', capturedAt: '2026-08-02', configState: { size: 20 } },
        { id: 'snap1', changeType: 'CREATED', capturedAt: '2026-08-01', configState: { size: 10 } },
      ]);

      const res = await server.get('/api/resource-inventory/r1/timeline', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(2);
      expect(res.body.data[0].diff).toEqual({ size: { from: 10, to: 20 } });
      expect(res.body.data[1].diff).toBeNull();
    });
  });

  describe('GET /api/resource-inventory/snapshots/:snapshotId', () => {
    it('returns 404 when the snapshot does not exist', async () => {
      mockSnapshotFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/resource-inventory/snapshots/missing', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Snapshot not found' });
    });
  });

  describe('GET /api/resource-inventory/:id/deps', () => {
    it('returns dependsOn and usedBy edges', async () => {
      mockDepFindMany
        .mockResolvedValueOnce([{ id: 'd1', depType: 'USES', description: null, toResource: { id: 'r2' } }])
        .mockResolvedValueOnce([{ id: 'd2', depType: 'USED_BY', description: null, fromResource: { id: 'r3' } }]);

      const res = await server.get('/api/resource-inventory/r1/deps', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.dependsOn).toEqual([{ id: 'd1', depType: 'USES', description: null, resource: { id: 'r2' } }]);
      expect(res.body.data.usedBy).toEqual([{ id: 'd2', depType: 'USED_BY', description: null, resource: { id: 'r3' } }]);
    });
  });
});

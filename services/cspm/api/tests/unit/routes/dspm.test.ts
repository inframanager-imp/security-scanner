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
    dataClassification: { findMany: jest.fn(), count: jest.fn(), groupBy: jest.fn() },
    resourceInventory: { count: jest.fn() },
  },
}));

jest.mock('../../../src/workers/dspmScanWorker', () => ({
  enqueueDspmScan: jest.fn(),
}));

import { prisma } from '../../../src/config/database';
import { enqueueDspmScan } from '../../../src/workers/dspmScanWorker';

describe('routes/dspm', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/dspm')).default;
    server = await startTestServer('/api/dspm', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /scan', () => {
    it('enqueues a scan and returns the job id when provider and accountId are valid', async () => {
      (enqueueDspmScan as jest.Mock).mockResolvedValue('job-123');

      const res = await fetch(`${server.baseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'AWS', accountId: 'acc-1' }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual({ jobId: 'job-123', status: 'QUEUED' });
      expect(enqueueDspmScan).toHaveBeenCalledWith({ provider: 'AWS', accountId: 'acc-1', triggeredBy: 'MANUAL' });
    });

    it('returns 400 when provider is invalid', async () => {
      const res = await fetch(`${server.baseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'BOGUS', accountId: 'acc-1' }),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('provider and accountId required');
      expect(enqueueDspmScan).not.toHaveBeenCalled();
    });

    it('returns 400 when accountId is missing', async () => {
      const res = await fetch(`${server.baseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'AWS' }),
      });

      expect(res.status).toBe(400);
    });

    it('returns 500 when enqueueing throws', async () => {
      (enqueueDspmScan as jest.Mock).mockRejectedValue(new Error('queue unavailable'));

      const res = await fetch(`${server.baseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'GCP', accountId: 'acc-2' }),
      });
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('queue unavailable');
    });
  });

  describe('GET /classifications', () => {
    it('lists classifications with pagination metadata', async () => {
      (prisma.dataClassification.findMany as jest.Mock).mockResolvedValue([{ id: 'c1' }]);
      (prisma.dataClassification.count as jest.Mock).mockResolvedValue(1);

      const res = await fetch(`${server.baseUrl}/classifications?provider=AWS&accountId=acc-1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
      expect(body.meta).toEqual({ total: 1, page: 1, pageSize: 50, totalPages: 1 });
    });

    it('filters by minConfidence, translating to an "in" clause of higher-or-equal tiers', async () => {
      (prisma.dataClassification.findMany as jest.Mock).mockResolvedValue([]);
      (prisma.dataClassification.count as jest.Mock).mockResolvedValue(0);

      const res = await fetch(`${server.baseUrl}/classifications?minConfidence=medium`);
      expect(res.status).toBe(200);

      const whereArg = (prisma.dataClassification.findMany as jest.Mock).mock.calls[0][0].where;
      expect(whereArg.confidence).toEqual({ in: ['MEDIUM', 'HIGH'] });
    });
  });

  describe('GET /resources/:resourceId', () => {
    it('returns classifications for a single resource', async () => {
      (prisma.dataClassification.findMany as jest.Mock).mockResolvedValue([{ id: 'c1', resourceInventoryId: 'r1' }]);

      const res = await fetch(`${server.baseUrl}/resources/r1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
    });
  });

  describe('GET /stats/:provider/:accountId', () => {
    it('returns byDataType, sensitiveAndPublic count, and classifiedResources count', async () => {
      (prisma.dataClassification.groupBy as jest.Mock)
        .mockResolvedValueOnce([{ dataType: 'PII', _count: { _all: 4 } }]) // byType
        .mockResolvedValueOnce([{ resourceInventoryId: 'r1' }, { resourceInventoryId: 'r2' }]); // totalClassifiedResources
      (prisma.resourceInventory.count as jest.Mock).mockResolvedValue(2);

      const res = await fetch(`${server.baseUrl}/stats/AWS/acc-1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.byDataType).toEqual([{ dataType: 'PII', count: 4 }]);
      expect(body.data.sensitiveAndPublic).toBe(2);
      expect(body.data.classifiedResources).toBe(2);
    });
  });
});

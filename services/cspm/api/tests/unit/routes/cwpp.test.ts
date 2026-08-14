import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockVulnFindMany = jest.fn();
const mockVulnCount = jest.fn();
const mockVulnGroupBy = jest.fn();
const mockVulnUpdate = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    workloadVulnerability: {
      findMany: mockVulnFindMany,
      count: mockVulnCount,
      groupBy: mockVulnGroupBy,
      update: mockVulnUpdate,
    },
  },
}));

const mockEnqueueCwppScan = jest.fn();
jest.mock('../../../src/workers/cwppScanWorker', () => ({
  enqueueCwppScan: mockEnqueueCwppScan,
}));

import router from '../../../src/routes/cwpp';

describe('cwpp routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/cwpp', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /scan', () => {
    it('returns 400 when provider is invalid', async () => {
      const res = await server.post('/api/cwpp/scan', { provider: 'BOGUS', accountId: 'acct-1' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and accountId required');
      expect(mockEnqueueCwppScan).not.toHaveBeenCalled();
    });

    it('returns 400 when accountId is missing', async () => {
      const res = await server.post('/api/cwpp/scan', { provider: 'AWS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
    });

    it('enqueues a scan for a valid request', async () => {
      mockEnqueueCwppScan.mockResolvedValueOnce('job-1');

      const res = await server.post('/api/cwpp/scan', { provider: 'AWS', accountId: 'acct-1' }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.jobId).toBe('job-1');
      expect(res.body.data.status).toBe('QUEUED');
      expect(mockEnqueueCwppScan).toHaveBeenCalledWith({ provider: 'AWS', accountId: 'acct-1', triggeredBy: 'MANUAL' });
    });

    it('returns 500 with the error message when enqueue throws', async () => {
      mockEnqueueCwppScan.mockRejectedValueOnce(new Error('queue unavailable'));

      const res = await server.post('/api/cwpp/scan', { provider: 'AWS', accountId: 'acct-1' }, AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('queue unavailable');
    });
  });

  describe('GET /vulnerabilities', () => {
    it('returns paginated vulnerabilities', async () => {
      mockVulnFindMany.mockResolvedValueOnce([{ id: 'v-1', cveId: 'CVE-2026-0001' }]);
      mockVulnCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/cwpp/vulnerabilities?provider=AWS&accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.meta.total).toBe(1);
    });

    it('clamps pageSize to the 1-500 range', async () => {
      mockVulnFindMany.mockResolvedValueOnce([]);
      mockVulnCount.mockResolvedValueOnce(0);

      const res = await server.get('/api/cwpp/vulnerabilities?pageSize=9999', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.meta.pageSize).toBe(500);
    });
  });

  describe('GET /hosts/:resourceInventoryId', () => {
    it('returns vulnerabilities for the given host', async () => {
      mockVulnFindMany.mockResolvedValueOnce([{ id: 'v-1', cveId: 'CVE-2026-0002' }]);

      const res = await server.get('/api/cwpp/hosts/ri-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
    });
  });

  describe('GET /stats/:provider/:accountId', () => {
    it('returns aggregated vulnerability stats', async () => {
      mockVulnGroupBy
        .mockResolvedValueOnce([{ severity: 'CRITICAL', _count: { _all: 2 } }])
        .mockResolvedValueOnce([{ resourceInventoryId: 'ri-1', _count: { _all: 2 } }, { resourceInventoryId: 'ri-2', _count: { _all: 1 } }]);
      mockVulnCount.mockResolvedValueOnce(3);

      const res = await server.get('/api/cwpp/stats/AWS/acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.bySeverity).toEqual([{ severity: 'CRITICAL', count: 2 }]);
      expect(res.body.data.hostsAffected).toBe(2);
      expect(res.body.data.openTotal).toBe(3);
    });
  });

  describe('PATCH /vulnerabilities/:id', () => {
    it('sets resolvedAt when status is FIXED', async () => {
      mockVulnUpdate.mockResolvedValueOnce({ id: 'v-1', status: 'FIXED' });

      const res = await server.patch('/api/cwpp/vulnerabilities/v-1', { status: 'FIXED' }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('FIXED');
      expect(mockVulnUpdate).toHaveBeenCalledWith({
        where: { id: 'v-1' },
        data: expect.objectContaining({ status: 'FIXED', resolvedAt: expect.any(Date) }),
      });
    });

    it('returns 404 when the vulnerability does not exist', async () => {
      mockVulnUpdate.mockRejectedValueOnce(new Error('Record not found'));

      const res = await server.patch('/api/cwpp/vulnerabilities/missing-id', { status: 'SUPPRESSED' }, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('WorkloadVulnerability not found');
    });
  });
});

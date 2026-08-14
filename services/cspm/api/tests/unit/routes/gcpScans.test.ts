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
    gcpScan: { findMany: jest.fn(), count: jest.fn(), findUnique: jest.fn() },
    gcpFinding: { findMany: jest.fn(), count: jest.fn() },
  },
}));

import { prisma } from '../../../src/config/database';

describe('routes/gcpScans', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/gcpScans')).default;
    server = await startTestServer('/api/gcp/scans', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /', () => {
    it('lists scans with pagination and applies projectId/status filters', async () => {
      (prisma.gcpScan.findMany as jest.Mock).mockResolvedValue([{ id: 's1', status: 'COMPLETED' }]);
      (prisma.gcpScan.count as jest.Mock).mockResolvedValue(1);

      const res = await fetch(`${server.baseUrl}/?projectId=p1&status=COMPLETED`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
      expect(body.meta).toEqual({ total: 1, page: 1, limit: 20, totalPages: 1 });

      const whereArg = (prisma.gcpScan.findMany as jest.Mock).mock.calls[0][0].where;
      expect(whereArg).toEqual({ projectId: 'p1', status: 'COMPLETED' });
    });

    it('returns 500 when the query throws', async () => {
      (prisma.gcpScan.findMany as jest.Mock).mockRejectedValue(new Error('db down'));

      const res = await fetch(`${server.baseUrl}/`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Internal server error');
    });
  });

  describe('GET /:id', () => {
    it('returns scan detail', async () => {
      (prisma.gcpScan.findUnique as jest.Mock).mockResolvedValue({ id: 's1', status: 'COMPLETED' });

      const res = await fetch(`${server.baseUrl}/s1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.id).toBe('s1');
    });

    it('returns 404 when the scan does not exist', async () => {
      (prisma.gcpScan.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`);
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Scan not found');
    });
  });

  describe('GET /:id/findings', () => {
    it('returns paginated findings, applying severity/service/status filters', async () => {
      (prisma.gcpFinding.findMany as jest.Mock).mockResolvedValue([{ id: 'f1', severity: 'HIGH' }]);
      (prisma.gcpFinding.count as jest.Mock).mockResolvedValue(1);

      const res = await fetch(`${server.baseUrl}/s1/findings?severity=HIGH&service=iam`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
      const whereArg = (prisma.gcpFinding.findMany as jest.Mock).mock.calls[0][0].where;
      expect(whereArg).toEqual({ scanId: 's1', severity: 'HIGH', service: 'iam' });
    });
  });

  describe('GET /:id/findings/export', () => {
    it('returns 404 when the scan does not exist', async () => {
      (prisma.gcpScan.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing/findings/export`);
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Scan not found');
    });

    it('returns a CSV with a header row and one row per finding', async () => {
      (prisma.gcpScan.findUnique as jest.Mock).mockResolvedValue({ id: 's1', project: { name: 'Proj1' } });
      (prisma.gcpFinding.findMany as jest.Mock).mockResolvedValue([
        {
          severity: 'HIGH', service: 'iam', title: 'Test "quoted" title', description: 'desc',
          resourceName: 'res1', region: 'us-central1', findingStatus: 'OPEN', tags: ['a', 'b'],
          discoveredAt: new Date('2024-01-01T00:00:00Z'),
        },
      ]);

      const res = await fetch(`${server.baseUrl}/s1/findings/export`);
      const text = await res.text();

      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/csv');
      expect(res.headers.get('content-disposition')).toContain('gcp-scan-s1-findings.csv');
      const lines = text.trim().split('\n');
      expect(lines).toHaveLength(2);
      expect(lines[0]).toBe('Severity,Service,Title,Description,Resource Name,Region,Status,Tags,Discovered At');
      expect(lines[1]).toContain('"Test ""quoted"" title"');
    });
  });
});

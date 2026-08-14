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
    finding: {
      findMany: jest.fn(),
      count: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      deleteMany: jest.fn(),
    },
    azureFinding: { findMany: jest.fn() },
    gcpFinding: { findMany: jest.fn() },
  },
}));

jest.mock('../../../src/services/complianceService', () => ({
  getComplianceTags: jest.fn(() => []),
}));

import { prisma } from '../../../src/config/database';

describe('routes/findings', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/findings')).default;
    server = await startTestServer('/api/findings', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /prioritized', () => {
    it('merges AWS, Azure, and GCP findings sorted by riskScore desc', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([
        { id: 'a1', riskScore: 90, scan: { account: { id: 'acc1', name: 'A', awsAccountId: '1' } } },
      ]);
      (prisma.azureFinding.findMany as jest.Mock).mockResolvedValue([
        { id: 'z1', riskScore: 95, scan: { subscription: { id: 'sub1', name: 'Z', subscriptionId: '2' } } },
      ]);
      (prisma.gcpFinding.findMany as jest.Mock).mockResolvedValue([]);

      const res = await fetch(`${server.baseUrl}/prioritized`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data[0].id).toBe('z1'); // highest riskScore first
      expect(body.data[1].id).toBe('a1');
    });

    it('returns 500 when a Prisma call throws', async () => {
      (prisma.finding.findMany as jest.Mock).mockRejectedValue(new Error('db error'));
      (prisma.azureFinding.findMany as jest.Mock).mockResolvedValue([]);
      (prisma.gcpFinding.findMany as jest.Mock).mockResolvedValue([]);

      const res = await fetch(`${server.baseUrl}/prioritized`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('db error');
    });
  });

  describe('GET /services', () => {
    it('returns distinct service names, excluding THREAT by default', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([{ service: 's3' }, { service: 'ec2' }]);

      const res = await fetch(`${server.baseUrl}/services`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual(['s3', 'ec2']);
      const whereArg = (prisma.finding.findMany as jest.Mock).mock.calls[0][0].where;
      expect(whereArg.service).toEqual({ not: 'THREAT' });
    });
  });

  describe('GET /', () => {
    it('returns paginated findings with metadata', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([
        { id: 'f1', severity: 'CRITICAL', scan: { account: { id: 'a1', name: 'Acct' } }, title: 't', checkId: null },
      ]);
      (prisma.finding.count as jest.Mock).mockResolvedValue(1);

      const res = await fetch(`${server.baseUrl}/?page=1&pageSize=20`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
      expect(body.meta).toEqual({ total: 1, page: 1, limit: 20, totalPages: 1 });
    });

    it('excludes THREAT service by default, but allows explicit service=THREAT', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([]);
      (prisma.finding.count as jest.Mock).mockResolvedValue(0);

      const res = await fetch(`${server.baseUrl}/?service=THREAT`);
      expect(res.status).toBe(200);

      const whereArg = (prisma.finding.findMany as jest.Mock).mock.calls[0][0].where;
      expect(whereArg.service).toBe('THREAT');
    });

    it('returns 500 when the underlying query throws', async () => {
      (prisma.finding.findMany as jest.Mock).mockRejectedValue(new Error('boom'));

      const res = await fetch(`${server.baseUrl}/`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Internal server error');
    });
  });

  describe('POST /deduplicate', () => {
    it('reports zero deleted when there are no duplicates', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([
        { id: 'f1', service: 's3', title: 't1', checkId: 'c1', evidence: { bucket: 'b1' }, findingStatus: 'OPEN', createdAt: new Date(), scan: { accountId: 'acc1' } },
      ]);

      const res = await fetch(`${server.baseUrl}/deduplicate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.deleted).toBe(0);
      expect(prisma.finding.deleteMany).not.toHaveBeenCalled();
    });

    it('deletes duplicates, keeping the OPEN/oldest member of each identity+resource group', async () => {
      const older = { id: 'keep', service: 's3', title: 't1', checkId: 'c1', evidence: { bucket: 'b1' }, findingStatus: 'OPEN', createdAt: new Date('2024-01-01'), scan: { accountId: 'acc1' } };
      const newer = { id: 'dup', service: 's3', title: 't1', checkId: 'c1', evidence: { bucket: 'b1' }, findingStatus: 'OPEN', createdAt: new Date('2024-02-01'), scan: { accountId: 'acc1' } };
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([older, newer]);
      (prisma.finding.deleteMany as jest.Mock).mockResolvedValue({ count: 1 });

      const res = await fetch(`${server.baseUrl}/deduplicate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.deleted).toBe(1);
      expect(prisma.finding.deleteMany).toHaveBeenCalledWith({ where: { id: { in: ['dup'] } } });
    });
  });

  describe('PATCH /:id', () => {
    it('updates finding status for a valid body', async () => {
      (prisma.finding.findUnique as jest.Mock).mockResolvedValue({ id: 'f1' });
      (prisma.finding.update as jest.Mock).mockResolvedValue({ id: 'f1', findingStatus: 'RESOLVED' });

      const res = await fetch(`${server.baseUrl}/f1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findingStatus: 'RESOLVED' }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.findingStatus).toBe('RESOLVED');
    });

    it('returns 400 with field errors when findingStatus is invalid', async () => {
      const res = await fetch(`${server.baseUrl}/f1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findingStatus: 'NOT_A_STATUS' }),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('Validation error');
      expect(body.details.findingStatus).toBeDefined();
    });

    it('returns 404 when the finding does not exist', async () => {
      (prisma.finding.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findingStatus: 'RESOLVED' }),
      });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Finding not found');
    });

    it('returns 500 when the update throws', async () => {
      (prisma.finding.findUnique as jest.Mock).mockResolvedValue({ id: 'f1' });
      (prisma.finding.update as jest.Mock).mockRejectedValue(new Error('db error'));

      const res = await fetch(`${server.baseUrl}/f1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findingStatus: 'RESOLVED' }),
      });
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Internal server error');
    });
  });
});

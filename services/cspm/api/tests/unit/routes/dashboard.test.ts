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
    account: { count: jest.fn(), findMany: jest.fn() },
    azureSubscription: { count: jest.fn(), findMany: jest.fn() },
    gcpProject: { count: jest.fn(), findMany: jest.fn() },
    scan: { count: jest.fn(), findMany: jest.fn() },
    azureScan: { count: jest.fn(), findMany: jest.fn() },
    gcpScan: { count: jest.fn(), findMany: jest.fn() },
    finding: { groupBy: jest.fn(), findMany: jest.fn() },
    azureFinding: { groupBy: jest.fn(), findMany: jest.fn() },
    gcpFinding: { groupBy: jest.fn(), findMany: jest.fn() },
  },
}));

import { prisma } from '../../../src/config/database';

describe('routes/dashboard', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/dashboard')).default;
    server = await startTestServer('/api/dashboard', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /summary', () => {
    it('aggregates counts across AWS, Azure, and GCP into one payload', async () => {
      (prisma.account.count as jest.Mock).mockResolvedValue(2);
      (prisma.azureSubscription.count as jest.Mock).mockResolvedValue(1);
      (prisma.gcpProject.count as jest.Mock).mockResolvedValue(3);
      (prisma.scan.count as jest.Mock)
        .mockResolvedValueOnce(10) // total scans
        .mockResolvedValueOnce(1); // active scans
      (prisma.azureScan.count as jest.Mock)
        .mockResolvedValueOnce(5)
        .mockResolvedValueOnce(0);
      (prisma.gcpScan.count as jest.Mock)
        .mockResolvedValueOnce(4)
        .mockResolvedValueOnce(2);
      (prisma.finding.groupBy as jest.Mock).mockResolvedValue([
        { severity: 'CRITICAL', _count: { id: 3 } },
      ]);
      (prisma.azureFinding.groupBy as jest.Mock).mockResolvedValue([
        { severity: 'HIGH', _count: { id: 2 } },
      ]);
      (prisma.gcpFinding.groupBy as jest.Mock).mockResolvedValue([]);

      const res = await fetch(`${server.baseUrl}/summary`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.totalAccounts).toBe(6);
      expect(body.data.totalScans).toBe(19);
      expect(body.data.activeScans).toBe(3);
      expect(body.data.findingsBySeverity.critical).toBe(3);
      expect(body.data.findingsBySeverity.high).toBe(2);
      expect(body.data.breakdown.aws.accounts).toBe(2);
      expect(body.data.breakdown.azure.accounts).toBe(1);
      expect(body.data.breakdown.gcp.accounts).toBe(3);
    });

    it('returns 500 when a Prisma call throws', async () => {
      (prisma.account.count as jest.Mock).mockRejectedValue(new Error('db down'));
      (prisma.azureSubscription.count as jest.Mock).mockResolvedValue(0);
      (prisma.gcpProject.count as jest.Mock).mockResolvedValue(0);
      (prisma.scan.count as jest.Mock).mockResolvedValue(0);
      (prisma.azureScan.count as jest.Mock).mockResolvedValue(0);
      (prisma.gcpScan.count as jest.Mock).mockResolvedValue(0);
      (prisma.finding.groupBy as jest.Mock).mockResolvedValue([]);
      (prisma.azureFinding.groupBy as jest.Mock).mockResolvedValue([]);
      (prisma.gcpFinding.groupBy as jest.Mock).mockResolvedValue([]);

      const res = await fetch(`${server.baseUrl}/summary`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Internal server error');
    });
  });

  describe('GET /trends', () => {
    it('buckets findings by day across all three clouds, defaulting to 30 days', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([]);
      (prisma.azureFinding.findMany as jest.Mock).mockResolvedValue([]);
      (prisma.gcpFinding.findMany as jest.Mock).mockResolvedValue([]);

      const res = await fetch(`${server.baseUrl}/trends`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(Array.isArray(body.data)).toBe(true);
      expect(body.data.length).toBe(31); // days=30 inclusive of both ends
    });

    it('respects an explicit ?days= query param', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([]);
      (prisma.azureFinding.findMany as jest.Mock).mockResolvedValue([]);
      (prisma.gcpFinding.findMany as jest.Mock).mockResolvedValue([]);

      const res = await fetch(`${server.baseUrl}/trends?days=5`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.length).toBe(6);
    });
  });

  describe('GET /top-findings', () => {
    it('returns AWS critical/high open findings only', async () => {
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([
        { id: 'f1', severity: 'CRITICAL', scan: { id: 's1', account: { id: 'a1', name: 'Acct', awsAccountId: '111' } } },
      ]);

      const res = await fetch(`${server.baseUrl}/top-findings`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
      expect(body.data[0].id).toBe('f1');
    });

    it('returns 500 when the underlying query throws', async () => {
      (prisma.finding.findMany as jest.Mock).mockRejectedValue(new Error('boom'));

      const res = await fetch(`${server.baseUrl}/top-findings`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Internal server error');
    });
  });
});

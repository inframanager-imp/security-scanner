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
    account: { findUnique: jest.fn() },
    scan: { findFirst: jest.fn() },
    finding: { findMany: jest.fn() },
  },
}));

import { prisma } from '../../../src/config/database';

describe('routes/iamUsers', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/iamUsers')).default;
    server = await startTestServer('/api/iam-users', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /', () => {
    it('returns 400 when accountId is missing', async () => {
      const res = await fetch(`${server.baseUrl}/`);
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('accountId is required');
    });

    it('returns 404 when the account does not exist', async () => {
      (prisma.account.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/?accountId=acc-1`);
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Account not found');
    });

    it('returns empty data with null lastScanAt when there is no completed scan', async () => {
      (prisma.account.findUnique as jest.Mock).mockResolvedValue({ id: 'acc-1' });
      (prisma.scan.findFirst as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/?accountId=acc-1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toEqual([]);
      expect(body.meta.lastScanAt).toBeNull();
    });

    it('maps IAM user inventory findings and sorts open-ended-access users first', async () => {
      (prisma.account.findUnique as jest.Mock).mockResolvedValue({ id: 'acc-1' });
      (prisma.scan.findFirst as jest.Mock).mockResolvedValue({ id: 'scan-1', completedAt: new Date('2024-01-01') });
      (prisma.finding.findMany as jest.Mock).mockResolvedValue([
        {
          severity: 'LOW', discoveredAt: new Date('2024-01-01'),
          evidence: { userName: 'safe-user', arn: 'arn:1', hasOpenEndedAccess: false, mfaEnabled: true, mfaMissing: false, passwordStale: false, keyStale: false },
        },
        {
          severity: 'CRITICAL', discoveredAt: new Date('2024-01-02'),
          evidence: { userName: 'risky-user', arn: 'arn:2', hasOpenEndedAccess: true, mfaEnabled: false, mfaMissing: true, passwordStale: true, keyStale: true },
        },
      ]);

      const res = await fetch(`${server.baseUrl}/?accountId=acc-1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(2);
      expect(body.data[0].userName).toBe('risky-user'); // open-ended access sorts first
      expect(body.data[0].hasOpenEndedAccess).toBe(true);
      expect(body.meta.lastScanAt).toBe('2024-01-01T00:00:00.000Z');
    });

    it('returns 500 when a Prisma call throws', async () => {
      (prisma.account.findUnique as jest.Mock).mockRejectedValue(new Error('db down'));

      const res = await fetch(`${server.baseUrl}/?accountId=acc-1`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('db down');
    });
  });
});

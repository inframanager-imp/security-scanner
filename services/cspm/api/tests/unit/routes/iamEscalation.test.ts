import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { startTestServer, TestServer } from './testServer';

// Note: iamEscalation.ts does not use the `authenticate` middleware.

jest.mock('../../../src/config/database', () => ({
  prisma: {
    iamEscalationEvent: {
      groupBy: jest.fn(),
      count: jest.fn(),
      findMany: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
    },
  },
}));

jest.mock('../../../src/config/logger', () => ({
  logger: { error: jest.fn(), info: jest.fn(), warn: jest.fn(), debug: jest.fn() },
}));

jest.mock('../../../src/services/iamEscalationService', () => ({
  backfillEscalationScan: jest.fn(),
}));

import { prisma } from '../../../src/config/database';
import { backfillEscalationScan } from '../../../src/services/iamEscalationService';

describe('routes/iamEscalation', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/iamEscalation')).default;
    server = await startTestServer('/api/iam-escalation', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /stats', () => {
    it('returns grouped counts by type, severity, and status', async () => {
      (prisma.iamEscalationEvent.groupBy as jest.Mock)
        .mockResolvedValueOnce([{ escalationType: 'POLICY_ATTACH', _count: { id: 2 } }])
        .mockResolvedValueOnce([{ severity: 'HIGH', _count: { id: 2 } }])
        .mockResolvedValueOnce([{ status: 'OPEN', _count: { id: 2 } }]);
      (prisma.iamEscalationEvent.count as jest.Mock).mockResolvedValue(2);

      const res = await fetch(`${server.baseUrl}/stats`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.total).toBe(2);
      expect(body.byType).toEqual([{ type: 'POLICY_ATTACH', count: 2 }]);
      expect(body.bySeverity).toEqual({ HIGH: 2 });
      expect(body.byStatus).toEqual({ OPEN: 2 });
    });

    it('returns 500 when the query throws', async () => {
      (prisma.iamEscalationEvent.groupBy as jest.Mock).mockRejectedValue(new Error('db down'));

      const res = await fetch(`${server.baseUrl}/stats`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Failed to load stats');
    });
  });

  describe('GET /', () => {
    it('lists events with pagination', async () => {
      (prisma.iamEscalationEvent.count as jest.Mock).mockResolvedValue(1);
      (prisma.iamEscalationEvent.findMany as jest.Mock).mockResolvedValue([{ id: 'e1' }]);

      const res = await fetch(`${server.baseUrl}/`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.total).toBe(1);
      expect(body.events).toHaveLength(1);
    });

    it('caps pageSize at 100', async () => {
      (prisma.iamEscalationEvent.count as jest.Mock).mockResolvedValue(0);
      (prisma.iamEscalationEvent.findMany as jest.Mock).mockResolvedValue([]);

      const res = await fetch(`${server.baseUrl}/?pageSize=500`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.pageSize).toBe(100);
    });
  });

  describe('GET /:id', () => {
    it('returns event detail', async () => {
      (prisma.iamEscalationEvent.findUnique as jest.Mock).mockResolvedValue({ id: 'e1' });

      const res = await fetch(`${server.baseUrl}/e1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.id).toBe('e1');
    });

    it('returns 404 when not found', async () => {
      (prisma.iamEscalationEvent.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`);
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Not found');
    });
  });

  describe('PATCH /:id', () => {
    it('updates status to ACKNOWLEDGED and stamps acknowledgedAt', async () => {
      (prisma.iamEscalationEvent.update as jest.Mock).mockResolvedValue({ id: 'e1', status: 'ACKNOWLEDGED', acknowledgedAt: new Date(), resolvedAt: null, notes: null });

      const res = await fetch(`${server.baseUrl}/e1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ACKNOWLEDGED' }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.status).toBe('ACKNOWLEDGED');
    });

    it('returns 400 for an invalid status', async () => {
      const res = await fetch(`${server.baseUrl}/e1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'BOGUS' }),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('status must be OPEN | ACKNOWLEDGED | RESOLVED');
    });
  });

  describe('POST /backfill', () => {
    it('starts a background backfill and responds immediately', async () => {
      (backfillEscalationScan as jest.Mock).mockResolvedValue(3);

      const res = await fetch(`${server.baseUrl}/backfill`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'AWS', targetId: 'acc-1' }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.message).toBe('Backfill scan started in background');
      expect(backfillEscalationScan).toHaveBeenCalledWith('AWS', 'acc-1');
    });

    it('returns 400 when provider or targetId is missing', async () => {
      const res = await fetch(`${server.baseUrl}/backfill`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'AWS' }),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('provider and targetId are required');
    });
  });
});

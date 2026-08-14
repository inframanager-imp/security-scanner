import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockAnomalyEventFindMany = jest.fn();
const mockAnomalyEventCount = jest.fn();
const mockAnomalyEventFindUnique = jest.fn();
const mockAnomalyEventUpdate = jest.fn();
const mockAnomalyEventGroupBy = jest.fn();
// $queryRaw is called as a tagged template — implement it to just resolve to [].
const mockQueryRaw = jest.fn(() => ({ catch: (fn: any) => Promise.resolve([]).catch(fn) })) as any;

jest.mock('../../../src/config/database', () => ({
  prisma: {
    anomalyEvent: {
      findMany: mockAnomalyEventFindMany,
      count: mockAnomalyEventCount,
      findUnique: mockAnomalyEventFindUnique,
      update: mockAnomalyEventUpdate,
      groupBy: mockAnomalyEventGroupBy,
    },
    $queryRaw: mockQueryRaw,
  },
}));

jest.mock('../../../src/services/anomalyBaselineService', () => ({
  getBaselineStats: jest.fn(async () => ({ mean: 1, stdDev: 0.5 })),
  resetBaselines: jest.fn(async () => 3),
  seedAwsBaseline: jest.fn(async () => ({})),
  seedAzureBaseline: jest.fn(async () => ({})),
  seedGcpBaseline: jest.fn(async () => ({})),
}));

import anomalyRouter from '../../../src/routes/anomaly';

describe('routes/anomaly', () => {
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockQueryRaw.mockImplementation(() => ({ catch: (fn: any) => Promise.resolve([]).catch(fn) }));
    server = await TestServer.start(buildTestApp('/api/anomaly', anomalyRouter));
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/anomaly/events', () => {
    it('returns filtered events with total', async () => {
      mockAnomalyEventFindMany.mockResolvedValue([{ id: 'a-1', provider: 'AWS' }]);
      mockAnomalyEventCount.mockResolvedValue(1);

      const res = await server.get('/api/anomaly/events?provider=AWS', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.total).toBe(1);
      expect(mockAnomalyEventFindMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { provider: 'AWS' } })
      );
    });

    it('returns 500 when prisma throws', async () => {
      mockAnomalyEventFindMany.mockRejectedValue(new Error('db down'));

      const res = await server.get('/api/anomaly/events', AUTH_HEADER);

      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/anomaly/events/:id', () => {
    it('returns 404 when not found', async () => {
      mockAnomalyEventFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/anomaly/events/missing', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Not found' });
    });

    it('returns the event when found', async () => {
      mockAnomalyEventFindUnique.mockResolvedValue({ id: 'a-1' });

      const res = await server.get('/api/anomaly/events/a-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe('a-1');
    });
  });

  describe('PATCH /api/anomaly/events/:id', () => {
    it('sets resolvedAt when status transitions to RESOLVED', async () => {
      mockAnomalyEventUpdate.mockResolvedValue({ id: 'a-1', status: 'RESOLVED' });

      const res = await server.patch('/api/anomaly/events/a-1', { status: 'RESOLVED' }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(mockAnomalyEventUpdate).toHaveBeenCalledWith({
        where: { id: 'a-1' },
        data: expect.objectContaining({ status: 'RESOLVED', resolvedAt: expect.any(Date) }),
      });
    });
  });

  describe('GET /api/anomaly/baselines', () => {
    it('returns 400 when provider or accountId missing', async () => {
      const res = await server.get('/api/anomaly/baselines', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'provider and accountId required' });
    });

    it('returns baseline stats when params provided', async () => {
      const res = await server.get('/api/anomaly/baselines?provider=AWS&accountId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ mean: 1, stdDev: 0.5 });
    });
  });

  describe('DELETE /api/anomaly/baselines', () => {
    it('returns 400 when provider or accountId missing', async () => {
      const res = await server.delete('/api/anomaly/baselines', AUTH_HEADER);

      expect(res.status).toBe(400);
    });

    it('resets baselines and returns deleted count', async () => {
      const res = await server.delete('/api/anomaly/baselines?provider=AWS&accountId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ deleted: 3 });
    });
  });

  describe('POST /api/anomaly/baselines/seed', () => {
    it('returns 400 when provider or accountId missing', async () => {
      const res = await server.post('/api/anomaly/baselines/seed', {}, AUTH_HEADER);

      expect(res.status).toBe(400);
    });

    it('accepts the request and responds immediately', async () => {
      const res = await server.post(
        '/api/anomaly/baselines/seed',
        { provider: 'AWS', accountId: 'acc-1' },
        AUTH_HEADER
      );

      expect(res.status).toBe(200);
      expect(res.body.data.message).toBe('Baseline seeding started');
    });
  });

  describe('GET /api/anomaly/actors', () => {
    it('returns actor anomaly counts', async () => {
      mockAnomalyEventGroupBy.mockResolvedValue([
        { actorId: 'user-1', _count: { id: 5 }, _max: { score: 90, detectedAt: new Date() } },
      ]);

      const res = await server.get('/api/anomaly/actors', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data[0]).toEqual(
        expect.objectContaining({ actorId: 'user-1', anomalyCount: 5, maxScore: 90 })
      );
    });
  });

  describe('GET /api/anomaly/summary', () => {
    it('aggregates counts by type/severity/status', async () => {
      mockAnomalyEventGroupBy
        .mockResolvedValueOnce([{ anomalyType: 'LOGIN', _count: { id: 2 } }])
        .mockResolvedValueOnce([{ severity: 'HIGH', _count: { id: 2 } }])
        .mockResolvedValueOnce([{ status: 'OPEN', _count: { id: 2 } }]);

      const res = await server.get('/api/anomaly/summary', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.total).toBe(2);
      expect(res.body.data.byType).toEqual({ LOGIN: 2 });
    });
  });
});

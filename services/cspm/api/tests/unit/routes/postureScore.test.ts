import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp } from './testHttp';

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockFindFirst = jest.fn();
const mockFindMany = jest.fn();
const mockQueryRaw = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    postureScore: {
      findFirst: mockFindFirst,
      findMany: mockFindMany,
    },
    $queryRaw: (...args: unknown[]) => mockQueryRaw(...args),
  },
}));

const mockCompute = jest.fn();
jest.mock('../../../src/services/postureScoreService', () => ({
  computePostureScore: mockCompute,
}));

import router from '../../../src/routes/postureScore';

describe('routes/postureScore', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    app = buildTestApp('/api/posture-score', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/posture-score/current', () => {
    it('returns the latest score for a target', async () => {
      mockFindFirst.mockResolvedValueOnce({ score: 82, grade: 'B' });

      const res = await server.get('/api/posture-score/current?provider=AWS&targetId=acc-1');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ score: 82, grade: 'B' });
    });

    it('returns 400 when provider or targetId is missing', async () => {
      const res = await server.get('/api/posture-score/current?provider=AWS');

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'provider and targetId are required' });
      expect(mockFindFirst).not.toHaveBeenCalled();
    });

    it('returns 404 when no score has been computed yet', async () => {
      mockFindFirst.mockResolvedValueOnce(null);

      const res = await server.get('/api/posture-score/current?provider=AWS&targetId=acc-1');

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'No posture score yet — run compute first' });
    });
  });

  describe('GET /api/posture-score/history', () => {
    it('returns 400 when provider or targetId is missing', async () => {
      const res = await server.get('/api/posture-score/history');

      expect(res.status).toBe(400);
      expect(mockFindMany).not.toHaveBeenCalled();
    });

    it('returns history bounded by the days window', async () => {
      mockFindMany.mockResolvedValueOnce([{ score: 90, grade: 'A', calculatedAt: '2026-08-01' }]);

      const res = await server.get('/api/posture-score/history?provider=AWS&targetId=acc-1&days=7');

      expect(res.status).toBe(200);
      expect(res.body.provider).toBe('AWS');
      expect(res.body.targetId).toBe('acc-1');
      expect(res.body.days).toBe(7);
      expect(res.body.history).toEqual([{ score: 90, grade: 'A', calculatedAt: '2026-08-01' }]);
    });
  });

  describe('GET /api/posture-score/summary', () => {
    it('aggregates grade counts and average score across accounts', async () => {
      mockQueryRaw.mockResolvedValueOnce([
        { provider: 'AWS', targetId: 'acc-1', score: 80, grade: 'B', calculatedAt: '2026-08-01' },
        { provider: 'AWS', targetId: 'acc-2', score: 100, grade: 'A', calculatedAt: '2026-08-01' },
      ]);

      const res = await server.get('/api/posture-score/summary');

      expect(res.status).toBe(200);
      expect(res.body.total).toBe(2);
      expect(res.body.avgScore).toBe(90);
      expect(res.body.gradeCount).toEqual({ A: 1, B: 1, C: 0, D: 0, F: 0 });
    });

    it('returns null avgScore when there are no scores', async () => {
      mockQueryRaw.mockResolvedValueOnce([]);

      const res = await server.get('/api/posture-score/summary');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ total: 0, avgScore: null, gradeCount: { A: 0, B: 0, C: 0, D: 0, F: 0 }, scores: [] });
    });

    it('returns 500 when the raw query fails', async () => {
      mockQueryRaw.mockRejectedValueOnce(new Error('db down'));

      const res = await server.get('/api/posture-score/summary');

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to get posture summary' });
    });
  });

  describe('POST /api/posture-score/compute', () => {
    it('triggers an on-demand computation and returns the result', async () => {
      mockCompute.mockResolvedValueOnce({ score: 75, grade: 'C' });

      const res = await server.post('/api/posture-score/compute', { provider: 'AWS', targetId: 'acc-1' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ score: 75, grade: 'C' });
      expect(mockCompute).toHaveBeenCalledWith('AWS', 'acc-1');
    });

    it('returns 400 when provider or targetId is missing', async () => {
      const res = await server.post('/api/posture-score/compute', { provider: 'AWS' });

      expect(res.status).toBe(400);
      expect(mockCompute).not.toHaveBeenCalled();
    });

    it('returns 500 with the underlying error message when compute throws', async () => {
      mockCompute.mockRejectedValueOnce(new Error('scan not ready'));

      const res = await server.post('/api/posture-score/compute', { provider: 'AWS', targetId: 'acc-1' });

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'scan not ready' });
    });
  });
});

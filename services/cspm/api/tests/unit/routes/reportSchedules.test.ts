import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp } from './testHttp';

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockFindMany = jest.fn();
const mockCreate = jest.fn();
const mockFindUnique = jest.fn();
const mockUpdate = jest.fn();
const mockDelete = jest.fn();
const mockRunFindMany = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    reportSchedule: {
      findMany: mockFindMany,
      create: mockCreate,
      findUnique: mockFindUnique,
      update: mockUpdate,
      delete: mockDelete,
    },
    reportRun: {
      findMany: mockRunFindMany,
    },
  },
}));

const mockComputeNextRun = jest.fn(() => new Date('2026-08-20T08:00:00Z'));
const mockGenerateOnDemandReport = jest.fn();

jest.mock('../../../src/services/reportService', () => ({
  computeNextRun: mockComputeNextRun,
  generateOnDemandReport: mockGenerateOnDemandReport,
}));

import router from '../../../src/routes/reportSchedules';

describe('routes/reportSchedules', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockComputeNextRun.mockReturnValue(new Date('2026-08-20T08:00:00Z'));
    app = buildTestApp('/api/report-schedules', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/report-schedules', () => {
    it('returns the list of schedules', async () => {
      mockFindMany.mockResolvedValueOnce([{ id: 's1', name: 'Weekly digest' }]);

      const res = await server.get('/api/report-schedules');

      expect(res.status).toBe(200);
      expect(res.body).toEqual([{ id: 's1', name: 'Weekly digest' }]);
    });

    it('returns 500 when prisma throws', async () => {
      mockFindMany.mockRejectedValueOnce(new Error('db down'));

      const res = await server.get('/api/report-schedules');

      expect(res.status).toBe(500);
    });
  });

  describe('POST /api/report-schedules', () => {
    it('creates a schedule with a computed nextRunAt', async () => {
      mockCreate.mockResolvedValueOnce({ id: 's2', name: 'Monthly report' });

      const res = await server.post('/api/report-schedules', {
        name: 'Monthly report',
        frequency: 'MONTHLY',
        dayOfMonth: 1,
      });

      expect(res.status).toBe(201);
      expect(res.body).toEqual({ id: 's2', name: 'Monthly report' });
      expect(mockComputeNextRun).toHaveBeenCalled();
    });

    it('returns 400 when name is missing', async () => {
      const res = await server.post('/api/report-schedules', { frequency: 'WEEKLY' });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'name is required' });
      expect(mockCreate).not.toHaveBeenCalled();
    });

    it('returns 400 for an invalid frequency', async () => {
      const res = await server.post('/api/report-schedules', { name: 'Bad freq', frequency: 'HOURLY' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/frequency must be one of/);
    });

    it('returns 400 for invalid sections', async () => {
      const res = await server.post('/api/report-schedules', {
        name: 'Bad sections',
        sections: ['SUMMARY', 'NOT_A_SECTION'],
      });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/Invalid sections/);
    });

    it('skips computeNextRun for ON_DEMAND frequency', async () => {
      mockCreate.mockResolvedValueOnce({ id: 's3', name: 'On demand only' });

      const res = await server.post('/api/report-schedules', {
        name: 'On demand only',
        frequency: 'ON_DEMAND',
      });

      expect(res.status).toBe(201);
      expect(mockComputeNextRun).not.toHaveBeenCalled();
    });
  });

  describe('PUT /api/report-schedules/:id', () => {
    it('returns 404 when the schedule does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.put('/api/report-schedules/missing', { name: 'New name' });

      expect(res.status).toBe(404);
      expect(mockUpdate).not.toHaveBeenCalled();
    });

    it('updates an existing schedule', async () => {
      mockFindUnique.mockResolvedValueOnce({
        id: 's1', frequency: 'WEEKLY', hour: 8, dayOfWeek: 1, dayOfMonth: null,
      });
      mockUpdate.mockResolvedValueOnce({ id: 's1', name: 'Renamed' });

      const res = await server.put('/api/report-schedules/s1', { name: 'Renamed' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ id: 's1', name: 'Renamed' });
    });
  });

  describe('DELETE /api/report-schedules/:id', () => {
    it('deletes and returns 204', async () => {
      mockDelete.mockResolvedValueOnce({});

      const res = await server.delete('/api/report-schedules/s1');

      expect(res.status).toBe(204);
    });
  });

  describe('POST /api/report-schedules/:id/run', () => {
    it('kicks off generation in the background and responds immediately', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 's1', name: 'Weekly digest' });
      mockGenerateOnDemandReport.mockResolvedValueOnce('<html></html>');

      const res = await server.post('/api/report-schedules/s1/run');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ message: 'Report generation started' });
    });

    it('returns 404 when the schedule does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/report-schedules/missing/run');

      expect(res.status).toBe(404);
      expect(mockGenerateOnDemandReport).not.toHaveBeenCalled();
    });
  });

  describe('GET /api/report-schedules/:id/preview', () => {
    it('returns the generated HTML report', async () => {
      mockGenerateOnDemandReport.mockResolvedValueOnce('<html><body>report</body></html>');

      const res = await server.get('/api/report-schedules/s1/preview');

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
      expect(res.text).toBe('<html><body>report</body></html>');
    });

    it('returns 500 with the underlying error message when generation fails', async () => {
      mockGenerateOnDemandReport.mockRejectedValueOnce(new Error('no findings'));

      const res = await server.get('/api/report-schedules/s1/preview');

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'no findings' });
    });
  });

  describe('GET /api/report-schedules/:id/runs', () => {
    it('returns run history', async () => {
      mockRunFindMany.mockResolvedValueOnce([{ id: 'r1', status: 'SUCCESS' }]);

      const res = await server.get('/api/report-schedules/s1/runs');

      expect(res.status).toBe(200);
      expect(res.body).toEqual([{ id: 'r1', status: 'SUCCESS' }]);
    });
  });
});

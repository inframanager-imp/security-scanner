import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockAzureScanFindMany = jest.fn();
const mockAzureScanCount = jest.fn();
const mockAzureScanFindUnique = jest.fn();
const mockAzureFindingFindMany = jest.fn();
const mockAzureFindingCount = jest.fn();
const mockAzureFindingDeleteMany = jest.fn();
const mockAzureFindingUpdate = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    azureScan: {
      findMany: mockAzureScanFindMany,
      count: mockAzureScanCount,
      findUnique: mockAzureScanFindUnique,
    },
    azureFinding: {
      findMany: mockAzureFindingFindMany,
      count: mockAzureFindingCount,
      deleteMany: mockAzureFindingDeleteMany,
      update: mockAzureFindingUpdate,
    },
  },
}));

import azureScansRouter from '../../../src/routes/azureScans';

describe('routes/azureScans', () => {
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = await TestServer.start(buildTestApp('/api/azure/scans', azureScansRouter));
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/azure/scans', () => {
    it('returns paginated scans', async () => {
      mockAzureScanFindMany.mockResolvedValue([{ id: 'scan-1' }]);
      mockAzureScanCount.mockResolvedValue(1);

      const res = await server.get('/api/azure/scans', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.meta).toEqual({ total: 1, page: 1, limit: 20, totalPages: 1 });
    });

    it('filters by subscriptionId and status query params', async () => {
      mockAzureScanFindMany.mockResolvedValue([]);
      mockAzureScanCount.mockResolvedValue(0);

      await server.get('/api/azure/scans?subscriptionId=sub-1&status=COMPLETED', AUTH_HEADER);

      expect(mockAzureScanFindMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { subscriptionId: 'sub-1', status: 'COMPLETED' } })
      );
    });

    it('returns 500 when prisma throws', async () => {
      mockAzureScanFindMany.mockRejectedValue(new Error('db down'));
      mockAzureScanCount.mockResolvedValue(0);

      const res = await server.get('/api/azure/scans', AUTH_HEADER);

      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/azure/scans/:id', () => {
    it('returns 404 when not found', async () => {
      mockAzureScanFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/azure/scans/missing', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Scan not found' });
    });

    it('returns the scan', async () => {
      mockAzureScanFindUnique.mockResolvedValue({ id: 'scan-1' });

      const res = await server.get('/api/azure/scans/scan-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe('scan-1');
    });
  });

  describe('GET /api/azure/scans/:id/findings', () => {
    it('returns paginated findings filtered by severity/service', async () => {
      mockAzureFindingFindMany.mockResolvedValue([{ id: 'f-1', severity: 'HIGH' }]);
      mockAzureFindingCount.mockResolvedValue(1);

      const res = await server.get('/api/azure/scans/scan-1/findings?severity=HIGH&service=storage', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(mockAzureFindingFindMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { scanId: 'scan-1', severity: 'HIGH', service: 'storage' } })
      );
    });
  });

  describe('GET /api/azure/scans/:id/findings/export', () => {
    it('returns 404 when the scan does not exist', async () => {
      mockAzureScanFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/azure/scans/missing/findings/export', AUTH_HEADER);

      expect(res.status).toBe(404);
    });

    it('returns a CSV body with the expected header row', async () => {
      mockAzureScanFindUnique.mockResolvedValue({ id: 'scan-1', subscription: { name: 'Sub One' } });
      mockAzureFindingFindMany.mockResolvedValue([
        {
          severity: 'HIGH', service: 'storage', title: 'Public bucket',
          description: 'desc, with comma', resourceGroup: 'rg-1', resourceId: 'res-1',
          findingStatus: 'OPEN', tags: ['a', 'b'], discoveredAt: new Date('2026-01-01'),
        },
      ]);

      const res = await server.get('/api/azure/scans/scan-1/findings/export', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/csv');
      expect(res.text).toContain('Severity,Service,Title,Description,Resource Group,Resource ID,Status,Tags,Discovered At');
      expect(res.text).toContain('Public bucket');
    });
  });

  describe('DELETE /api/azure/scans/findings/cleanup-scanner-errors', () => {
    it('deletes scanner-error findings and reports the count', async () => {
      mockAzureFindingDeleteMany.mockResolvedValue({ count: 2 });

      const res = await server.delete('/api/azure/scans/findings/cleanup-scanner-errors', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ deleted: 2, message: 'Removed 2 scanner-error findings' });
    });

    it('reports no findings found when count is zero', async () => {
      mockAzureFindingDeleteMany.mockResolvedValue({ count: 0 });

      const res = await server.delete('/api/azure/scans/findings/cleanup-scanner-errors', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.message).toBe('No scanner-error findings found');
    });
  });

  describe('PATCH /api/azure/scans/findings/:findingId/status', () => {
    it('returns 400 for an invalid status value', async () => {
      const res = await server.patch('/api/azure/scans/findings/f-1/status', { status: 'BOGUS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'Invalid status value' });
      expect(mockAzureFindingUpdate).not.toHaveBeenCalled();
    });

    it('updates status for a valid value', async () => {
      mockAzureFindingUpdate.mockResolvedValue({ id: 'f-1', findingStatus: 'RESOLVED' });

      const res = await server.patch('/api/azure/scans/findings/f-1/status', { status: 'RESOLVED' }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.findingStatus).toBe('RESOLVED');
    });
  });
});

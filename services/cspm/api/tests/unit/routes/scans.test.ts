import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockScanFindMany = jest.fn();
const mockScanCount = jest.fn();
const mockScanFindUnique = jest.fn();
const mockScanCreate = jest.fn();
const mockScanUpdate = jest.fn();
const mockAccountFindUnique = jest.fn();
const mockAwsCredentialFindUnique = jest.fn();
const mockFindingGroupBy = jest.fn();
const mockFindingFindMany = jest.fn();
const mockFindingCount = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    scan: {
      findMany: mockScanFindMany,
      count: mockScanCount,
      findUnique: mockScanFindUnique,
      create: mockScanCreate,
      update: mockScanUpdate,
    },
    account: { findUnique: mockAccountFindUnique },
    awsCredential: { findUnique: mockAwsCredentialFindUnique },
    finding: {
      groupBy: mockFindingGroupBy,
      findMany: mockFindingFindMany,
      count: mockFindingCount,
    },
  },
}));

const mockEnqueueScan = jest.fn();
const mockRemoveJob = jest.fn();
jest.mock('../../../src/services/scanJobService', () => ({
  enqueueScan: mockEnqueueScan,
  removeJob: mockRemoveJob,
}));

const mockGetAvailableServices = jest.fn(() => ['s3', 'iam', 'ec2']);
const mockGetAvailableRegions = jest.fn(() => ['us-east-1', 'us-west-2']);
jest.mock('../../../../src/scanners/engine', () => ({
  ScanEngine: jest.fn().mockImplementation(() => ({
    getAvailableServices: mockGetAvailableServices,
    getAvailableRegions: mockGetAvailableRegions,
  })),
}));

import router from '../../../src/routes/scans';

const VALID_ACCOUNT_ID = '11111111-1111-1111-1111-111111111111';

describe('routes/scans', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    app = buildTestApp('/api/scans', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/scans', () => {
    it('returns paginated scans', async () => {
      mockScanFindMany.mockResolvedValueOnce([{ id: 'scan-1', status: 'COMPLETED' }]);
      mockScanCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/scans', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ id: 'scan-1', status: 'COMPLETED' }]);
      expect(res.body.meta).toEqual({ total: 1, page: 1, limit: 20, totalPages: 1 });
    });

    it('returns 500 when prisma throws', async () => {
      mockScanFindMany.mockRejectedValueOnce(new Error('db down'));

      const res = await server.get('/api/scans', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Internal server error' });
    });
  });

  describe('POST /api/scans', () => {
    it('returns 400 with zod validation details for an invalid body', async () => {
      const res = await server.post('/api/scans', { accountId: 'not-a-uuid' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation error');
      expect(res.body.details).toBeDefined();
      expect(res.body.details.accountId).toBeDefined();
    });

    it('returns 404 when the account does not exist', async () => {
      mockAccountFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/scans', { accountId: VALID_ACCOUNT_ID }, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Account not found' });
    });

    it('returns 400 when the account has no credentials configured', async () => {
      mockAccountFindUnique.mockResolvedValueOnce({ id: VALID_ACCOUNT_ID });
      mockAwsCredentialFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/scans', { accountId: VALID_ACCOUNT_ID }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'No credentials configured for this account' });
    });

    it('creates and enqueues a scan for a valid request', async () => {
      mockAccountFindUnique.mockResolvedValueOnce({ id: VALID_ACCOUNT_ID });
      mockAwsCredentialFindUnique.mockResolvedValueOnce({
        accountId: VALID_ACCOUNT_ID, defaultRegion: 'us-east-1', additionalRegions: [],
      });
      mockScanCreate.mockResolvedValueOnce({ id: 'scan-1', status: 'QUEUED' });
      mockEnqueueScan.mockResolvedValueOnce('job-1');
      mockScanUpdate.mockResolvedValueOnce({ id: 'scan-1', status: 'QUEUED', jobId: 'job-1' });

      const res = await server.post('/api/scans', { accountId: VALID_ACCOUNT_ID }, AUTH_HEADER);

      expect(res.status).toBe(201);
      expect(res.body.data).toEqual({ id: 'scan-1', status: 'QUEUED', jobId: 'job-1' });
      expect(mockEnqueueScan).toHaveBeenCalledWith(
        'scan-1', VALID_ACCOUNT_ID, ['s3', 'iam', 'ec2'], ['us-east-1', 'us-west-2']
      );
    });
  });

  describe('GET /api/scans/:id', () => {
    it('returns 404 when the scan does not exist', async () => {
      mockScanFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/scans/missing', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Scan not found' });
    });

    it('returns scan detail with findings grouped by severity', async () => {
      mockScanFindUnique.mockResolvedValueOnce({ id: 'scan-1', status: 'COMPLETED' });
      mockFindingGroupBy.mockResolvedValueOnce([
        { severity: 'CRITICAL', _count: { id: 2 } },
        { severity: 'HIGH', _count: { id: 3 } },
      ]);

      const res = await server.get('/api/scans/scan-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.findingsBySeverity).toEqual({
        CRITICAL: 2, HIGH: 3, MEDIUM: 0, LOW: 0, INFO: 0,
      });
    });
  });

  describe('DELETE /api/scans/:id', () => {
    it('returns 404 when the scan does not exist', async () => {
      mockScanFindUnique.mockResolvedValueOnce(null);

      const res = await server.delete('/api/scans/missing', AUTH_HEADER);

      expect(res.status).toBe(404);
    });

    it('returns 400 when the scan is not cancellable', async () => {
      mockScanFindUnique.mockResolvedValueOnce({ id: 'scan-1', status: 'COMPLETED' });

      const res = await server.delete('/api/scans/scan-1', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'Cannot cancel scan in status: COMPLETED' });
    });

    it('cancels a queued scan and removes its job', async () => {
      mockScanFindUnique.mockResolvedValueOnce({ id: 'scan-1', status: 'QUEUED', jobId: 'job-1' });
      mockScanUpdate.mockResolvedValueOnce({ id: 'scan-1', status: 'CANCELLED' });

      const res = await server.delete('/api/scans/scan-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ data: { id: 'scan-1', status: 'CANCELLED' } });
      expect(mockRemoveJob).toHaveBeenCalledWith('job-1');
    });
  });

  describe('GET /api/scans/:id/findings', () => {
    it('returns 404 when the scan does not exist', async () => {
      mockScanFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/scans/missing/findings', AUTH_HEADER);

      expect(res.status).toBe(404);
    });

    it('returns paginated findings for an existing scan', async () => {
      mockScanFindUnique.mockResolvedValueOnce({ id: 'scan-1' });
      mockFindingFindMany.mockResolvedValueOnce([{ id: 'f1', severity: 'HIGH' }]);
      mockFindingCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/scans/scan-1/findings', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ id: 'f1', severity: 'HIGH' }]);
      expect(res.body.meta).toEqual({ total: 1, page: 1, limit: 20, totalPages: 1 });
    });
  });

  describe('GET /api/scans/:id/findings/export', () => {
    it('exports findings as JSON by default', async () => {
      mockScanFindUnique.mockResolvedValueOnce({ id: 'scan-1' });
      mockFindingFindMany.mockResolvedValueOnce([{ id: 'f1', severity: 'HIGH' }]);

      const res = await server.get('/api/scans/scan-1/findings/export', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.headers['content-disposition']).toContain('scan-1-findings.json');
      expect(res.body).toEqual({ data: [{ id: 'f1', severity: 'HIGH' }] });
    });

    it('exports findings as CSV when format=csv', async () => {
      mockScanFindUnique.mockResolvedValueOnce({ id: 'scan-1' });
      mockFindingFindMany.mockResolvedValueOnce([{
        id: 'f1', service: 's3', severity: 'HIGH', title: 'Public bucket',
        description: 'desc', remediation: 'fix it', findingStatus: 'OPEN',
        tags: ['pci'], discoveredAt: new Date('2026-08-01T00:00:00Z'),
      }]);

      const res = await server.get('/api/scans/scan-1/findings/export?format=csv', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/csv');
      expect(res.text).toContain('Public bucket');
      expect(res.text).toContain('f1,s3,HIGH');
    });

    it('returns 404 when the scan does not exist', async () => {
      mockScanFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/scans/missing/findings/export', AUTH_HEADER);

      expect(res.status).toBe(404);
    });
  });
});

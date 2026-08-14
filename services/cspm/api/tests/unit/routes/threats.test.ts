import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockAccountFindUnique = jest.fn();
const mockAccountFindMany = jest.fn();
const mockAwsCredentialFindUnique = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    account: { findUnique: mockAccountFindUnique, findMany: mockAccountFindMany },
    awsCredential: { findUnique: mockAwsCredentialFindUnique },
  },
}));

const mockStartMonitoring = jest.fn(async () => undefined);
const mockStopMonitoring = jest.fn(async () => undefined);
const mockIsMonitoring = jest.fn(async () => false);
const mockGetLastCheck = jest.fn(async () => new Date('2026-08-12T00:00:00Z'));

jest.mock('../../../src/services/threatMonitorService', () => ({
  startMonitoring: mockStartMonitoring,
  stopMonitoring: mockStopMonitoring,
  isMonitoring: mockIsMonitoring,
  getLastCheck: mockGetLastCheck,
}));

import router from '../../../src/routes/threats';

describe('routes/threats', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    app = buildTestApp('/api/threats', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('POST /api/threats/monitor/:accountId/start', () => {
    it('returns 404 when the account does not exist', async () => {
      mockAccountFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/threats/monitor/missing/start', undefined, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Account not found' });
      expect(mockStartMonitoring).not.toHaveBeenCalled();
    });

    it('returns 422 when no AWS credentials are configured', async () => {
      mockAccountFindUnique.mockResolvedValueOnce({ id: 'acc-1', name: 'Prod' });
      mockAwsCredentialFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/threats/monitor/acc-1/start', undefined, AUTH_HEADER);

      expect(res.status).toBe(422);
      expect(res.body).toEqual({ error: 'No AWS credentials configured for this account' });
    });

    it('starts monitoring for a valid account', async () => {
      mockAccountFindUnique.mockResolvedValueOnce({ id: 'acc-1', name: 'Prod' });
      mockAwsCredentialFindUnique.mockResolvedValueOnce({ id: 'cred-1' });

      const res = await server.post('/api/threats/monitor/acc-1/start', undefined, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        data: { accountId: 'acc-1', monitoring: true, message: 'Real-time threat monitoring started for Prod' },
      });
      expect(mockStartMonitoring).toHaveBeenCalledWith('acc-1');
    });
  });

  describe('POST /api/threats/monitor/:accountId/stop', () => {
    it('returns 404 when the account does not exist', async () => {
      mockAccountFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/threats/monitor/missing/stop', undefined, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(mockStopMonitoring).not.toHaveBeenCalled();
    });

    it('stops monitoring for a valid account', async () => {
      mockAccountFindUnique.mockResolvedValueOnce({ id: 'acc-1', name: 'Prod' });

      const res = await server.post('/api/threats/monitor/acc-1/stop', undefined, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        data: { accountId: 'acc-1', monitoring: false, message: 'Real-time threat monitoring stopped for Prod' },
      });
    });
  });

  describe('GET /api/threats/monitor/:accountId/status', () => {
    it('returns monitoring status and last check time', async () => {
      mockIsMonitoring.mockResolvedValueOnce(true);
      mockGetLastCheck.mockResolvedValueOnce(new Date('2026-08-12T10:00:00Z'));

      const res = await server.get('/api/threats/monitor/acc-1/status', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        data: { accountId: 'acc-1', monitoring: true, lastCheck: '2026-08-12T10:00:00.000Z' },
      });
    });

    it('falls back to null lastCheck when getLastCheck rejects', async () => {
      mockIsMonitoring.mockResolvedValueOnce(false);
      mockGetLastCheck.mockRejectedValueOnce(new Error('no record'));

      const res = await server.get('/api/threats/monitor/acc-1/status', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.lastCheck).toBeNull();
    });
  });

  describe('GET /api/threats/monitor/all', () => {
    it('returns monitoring status for every account', async () => {
      mockAccountFindMany.mockResolvedValueOnce([
        { id: 'acc-1', name: 'Prod', awsAccountId: '111111111111' },
        { id: 'acc-2', name: 'Dev', awsAccountId: '222222222222' },
      ]);
      mockIsMonitoring.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
      mockGetLastCheck
        .mockResolvedValueOnce(new Date('2026-08-12T10:00:00Z'))
        .mockRejectedValueOnce(new Error('no record'));

      const res = await server.get('/api/threats/monitor/all', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([
        { accountId: 'acc-1', name: 'Prod', awsAccountId: '111111111111', monitoring: true, lastCheck: '2026-08-12T10:00:00.000Z' },
        { accountId: 'acc-2', name: 'Dev', awsAccountId: '222222222222', monitoring: false, lastCheck: null },
      ]);
    });
  });
});

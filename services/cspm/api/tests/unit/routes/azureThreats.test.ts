import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockSubFindUnique = jest.fn();
const mockSubFindMany = jest.fn();
const mockCredFindUnique = jest.fn();
const mockFindingFindMany = jest.fn();
const mockFindingCount = jest.fn();
const mockFindingGroupBy = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    azureSubscription: {
      findUnique: mockSubFindUnique,
      findMany: mockSubFindMany,
    },
    azureCredential: {
      findUnique: mockCredFindUnique,
    },
    azureFinding: {
      findMany: mockFindingFindMany,
      count: mockFindingCount,
      groupBy: mockFindingGroupBy,
    },
  },
}));

const mockStartAzureMonitoring = jest.fn(async () => undefined);
const mockStopAzureMonitoring = jest.fn(async () => undefined);
const mockIsAzureMonitoring = jest.fn(async () => false);
const mockGetAzureLastCheck = jest.fn(async () => null as Date | null);
const mockGetAzureMonitoredSubscriptions = jest.fn(async () => [] as string[]);

jest.mock('../../../src/services/azureThreatMonitorService', () => ({
  startAzureMonitoring: mockStartAzureMonitoring,
  stopAzureMonitoring: mockStopAzureMonitoring,
  isAzureMonitoring: mockIsAzureMonitoring,
  getAzureLastCheck: mockGetAzureLastCheck,
  getAzureMonitoredSubscriptions: mockGetAzureMonitoredSubscriptions,
}));

import router from '../../../src/routes/azureThreats';

describe('azureThreats routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/azure/threats', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /monitor/:subscriptionId/start', () => {
    it('returns 404 when the subscription does not exist', async () => {
      mockSubFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/azure/threats/monitor/sub-1/start', {}, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Azure subscription not found');
    });

    it('returns 422 when no credentials are configured', async () => {
      mockSubFindUnique.mockResolvedValueOnce({ id: 'sub-1', name: 'Sub One' });
      mockCredFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/azure/threats/monitor/sub-1/start', {}, AUTH_HEADER);

      expect(res.status).toBe(422);
      expect(res.body.error).toBe('No Azure credentials configured for this subscription');
    });

    it('starts monitoring when subscription and credentials exist', async () => {
      mockSubFindUnique.mockResolvedValueOnce({ id: 'sub-1', name: 'Sub One' });
      mockCredFindUnique.mockResolvedValueOnce({ id: 'cred-1' });

      const res = await server.post('/api/azure/threats/monitor/sub-1/start', {}, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.monitoring).toBe(true);
      expect(mockStartAzureMonitoring).toHaveBeenCalledWith('sub-1');
    });
  });

  describe('POST /monitor/:subscriptionId/stop', () => {
    it('returns 404 when the subscription does not exist', async () => {
      mockSubFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/azure/threats/monitor/sub-1/stop', {}, AUTH_HEADER);

      expect(res.status).toBe(404);
    });

    it('stops monitoring when subscription exists', async () => {
      mockSubFindUnique.mockResolvedValueOnce({ id: 'sub-1', name: 'Sub One' });

      const res = await server.post('/api/azure/threats/monitor/sub-1/stop', {}, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.monitoring).toBe(false);
      expect(mockStopAzureMonitoring).toHaveBeenCalledWith('sub-1');
    });
  });

  describe('GET /monitor/:subscriptionId/status', () => {
    it('returns monitoring status and last check time', async () => {
      mockIsAzureMonitoring.mockResolvedValueOnce(true);
      mockGetAzureLastCheck.mockResolvedValueOnce(new Date('2026-01-01T00:00:00.000Z'));

      const res = await server.get('/api/azure/threats/monitor/sub-1/status', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.monitoring).toBe(true);
      expect(res.body.data.lastCheck).toBe('2026-01-01T00:00:00.000Z');
    });
  });

  describe('GET /monitor/all', () => {
    it('returns monitoring status for every subscription', async () => {
      mockSubFindMany.mockResolvedValueOnce([
        { id: 'sub-1', name: 'Sub One', subscriptionId: 'azure-1' },
      ]);
      mockIsAzureMonitoring.mockResolvedValueOnce(true);
      mockGetAzureLastCheck.mockResolvedValueOnce(null);

      const res = await server.get('/api/azure/threats/monitor/all', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].subscriptionId).toBe('sub-1');
      expect(res.body.data[0].monitoring).toBe(true);
    });
  });

  describe('GET /findings', () => {
    it('returns 400 when subscriptionId is missing', async () => {
      const res = await server.get('/api/azure/threats/findings', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('subscriptionId is required');
    });

    it('returns findings when subscriptionId is provided', async () => {
      mockFindingFindMany.mockResolvedValueOnce([{ id: 'f-1', title: 'Threat 1' }]);
      mockFindingCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/azure/threats/findings?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.meta.total).toBe(1);
    });

    it('returns 500 with the error message when prisma throws', async () => {
      mockFindingFindMany.mockRejectedValueOnce(new Error('query failed'));

      const res = await server.get('/api/azure/threats/findings?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('query failed');
    });
  });

  describe('GET /summary', () => {
    it('returns severity counts across monitored subscriptions', async () => {
      mockGetAzureMonitoredSubscriptions.mockResolvedValueOnce(['sub-1', 'sub-2']);
      mockFindingGroupBy.mockResolvedValueOnce([
        { severity: 'HIGH', _count: { severity: 3 } },
        { severity: 'CRITICAL', _count: { severity: 1 } },
      ]);

      const res = await server.get('/api/azure/threats/summary', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.monitoredSubscriptions).toBe(2);
      expect(res.body.data.findings.HIGH).toBe(3);
      expect(res.body.data.findings.CRITICAL).toBe(1);
      expect(res.body.data.total).toBe(4);
    });
  });
});

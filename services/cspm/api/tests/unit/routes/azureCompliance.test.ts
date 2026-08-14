import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockAzureSubscriptionFindUnique = jest.fn();
const mockAzureSubscriptionFindMany = jest.fn();
const mockAzureScanFindMany = jest.fn();
const mockAzureFindingGroupBy = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    azureSubscription: {
      findUnique: mockAzureSubscriptionFindUnique,
      findMany: mockAzureSubscriptionFindMany,
    },
    azureScan: { findMany: mockAzureScanFindMany },
    azureFinding: { groupBy: mockAzureFindingGroupBy },
  },
}));

const mockScoreAzureFrameworks = jest.fn();
jest.mock('../../../src/services/azureComplianceService', () => ({
  scoreAzureFrameworks: mockScoreAzureFrameworks,
  AZURE_FRAMEWORKS: [{ id: 'CIS_AZURE', name: 'CIS Azure', controls: [] }],
}));

import azureComplianceRouter from '../../../src/routes/azureCompliance';

describe('routes/azureCompliance', () => {
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockAzureScanFindMany.mockResolvedValue([{ id: 'scan-1' }]);
    mockAzureFindingGroupBy.mockResolvedValue([{ title: 'Some finding', _count: { title: 2 } }]);
    server = await TestServer.start(buildTestApp('/api/azure/compliance', azureComplianceRouter));
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/azure/compliance', () => {
    it('returns 400 when subscriptionId is missing', async () => {
      const res = await server.get('/api/azure/compliance', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'subscriptionId is required' });
    });

    it('returns 404 when the subscription does not exist', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/azure/compliance?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Azure subscription not found' });
    });

    it('returns compliance scores for a valid subscription', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValue({ id: 'sub-1' });
      mockScoreAzureFrameworks.mockReturnValue([{ frameworkId: 'CIS_AZURE', score: 80, controls: [] }]);

      const res = await server.get('/api/azure/compliance?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ frameworkId: 'CIS_AZURE', score: 80, controls: [] }]);
    });

    it('returns 500 when prisma throws', async () => {
      mockAzureSubscriptionFindUnique.mockRejectedValue(new Error('db down'));

      const res = await server.get('/api/azure/compliance?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/azure/compliance/all', () => {
    it('returns per-subscription summary scores', async () => {
      mockAzureSubscriptionFindMany.mockResolvedValue([
        { id: 'sub-1', name: 'Sub One', subscriptionId: 'azure-sub-1' },
      ]);
      mockScoreAzureFrameworks.mockReturnValue([
        { frameworkId: 'CIS_AZURE', score: 80, controls: [{ id: 'c1' }] },
      ]);

      const res = await server.get('/api/azure/compliance/all', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].subscriptionId).toBe('sub-1');
      expect(res.body.data[0].scores[0].controls).toBeUndefined();
    });
  });

  describe('GET /api/azure/compliance/frameworks', () => {
    it('returns the static framework list', async () => {
      const res = await server.get('/api/azure/compliance/frameworks', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ id: 'CIS_AZURE', name: 'CIS Azure', controls: [] }]);
    });
  });

  describe('GET /api/azure/compliance/:frameworkId', () => {
    it('returns 400 when subscriptionId is missing', async () => {
      const res = await server.get('/api/azure/compliance/CIS_AZURE', AUTH_HEADER);

      expect(res.status).toBe(400);
    });

    it('returns 404 when the framework id does not match any score', async () => {
      mockScoreAzureFrameworks.mockReturnValue([{ frameworkId: 'CIS_AZURE', score: 80 }]);

      const res = await server.get('/api/azure/compliance/UNKNOWN?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toContain('UNKNOWN');
    });

    it('returns the matching framework score', async () => {
      mockScoreAzureFrameworks.mockReturnValue([{ frameworkId: 'CIS_AZURE', score: 80 }]);

      const res = await server.get('/api/azure/compliance/CIS_AZURE?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ frameworkId: 'CIS_AZURE', score: 80 });
    });
  });
});

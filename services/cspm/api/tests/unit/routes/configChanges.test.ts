import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockConfigChangeFindMany = jest.fn();
const mockConfigChangeFindUnique = jest.fn();
const mockConfigChangeCount = jest.fn();
const mockConfigChangeGroupBy = jest.fn();
const mockConfigChangeUpdate = jest.fn();
const mockConfigChangeUpdateMany = jest.fn();
const mockConfigSyncRunCreate = jest.fn();
const mockConfigSyncRunUpdate = jest.fn();
const mockConfigSyncRunFindMany = jest.fn();
const mockConfigSyncRunFindFirst = jest.fn();
const mockResourceInventoryCount = jest.fn();
const mockQueryRaw = jest.fn(async () => [] as any[]);

jest.mock('../../../src/config/database', () => ({
  prisma: {
    configChange: {
      findMany: mockConfigChangeFindMany,
      findUnique: mockConfigChangeFindUnique,
      count: mockConfigChangeCount,
      groupBy: mockConfigChangeGroupBy,
      update: mockConfigChangeUpdate,
      updateMany: mockConfigChangeUpdateMany,
      upsert: jest.fn(),
    },
    configSyncRun: {
      create: mockConfigSyncRunCreate,
      update: mockConfigSyncRunUpdate,
      findMany: mockConfigSyncRunFindMany,
      findFirst: mockConfigSyncRunFindFirst,
    },
    resourceInventory: {
      count: mockResourceInventoryCount,
    },
    $queryRaw: mockQueryRaw,
  },
}));

jest.mock('../../../src/services/credentialService', () => ({
  decryptCredentials: jest.fn(() => ({ accessKeyId: 'AKIAFAKE', secretAccessKey: 'fake-secret' })),
}));
jest.mock('../../../src/services/azureCredentialService', () => ({
  decryptAzureCredentials: jest.fn(() => ({})),
}));
jest.mock('../../../src/services/azureArmFetch', () => ({
  fetchAzureResourceState: jest.fn(async () => null),
}));
jest.mock('../../../src/services/gcpCredentialService', () => ({
  decryptGcpCredentials: jest.fn(() => ({})),
}));
jest.mock('../../../../src/azure/client', () => ({
  __esModule: true,
  default: class FakeAzureClient {
    monitor() {
      return { activityLogs: { list: async function* () {} } };
    }
  },
}));
jest.mock('../../../../src/gcp/client', () => ({
  __esModule: true,
  default: class FakeGcpClient {},
}));
jest.mock('../../../src/services/configChangeClassifier', () => ({
  classifyAwsEvent: jest.fn(),
  classifyAzureEvent: jest.fn(),
  classifyGcpEvent: jest.fn(),
  isAzureNoiseEvent: jest.fn(() => false),
}));
jest.mock('../../../src/services/awsResourceFetch', () => ({
  fetchAwsResourceState: jest.fn(async () => null),
}));
jest.mock('../../../src/services/gcpResourceFetch', () => ({
  fetchGcpResourceState: jest.fn(async () => null),
}));
jest.mock('../../../src/services/inventorySync', () => ({
  syncInventoryFromChange: jest.fn(async () => undefined),
}));
jest.mock('../../../src/services/inventoryPipeline', () => ({
  markSyncedReady: jest.fn(async () => undefined),
}));

import router from '../../../src/routes/configChanges';

describe('configChanges routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/config-changes', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    mockQueryRaw.mockResolvedValue([]);
  });

  describe('POST /reconcile-inventory', () => {
    it('returns 400 when provider or targetId are missing', async () => {
      const res = await server.post('/api/config-changes/reconcile-inventory', { provider: 'AWS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and targetId are required');
    });

    it('reconciles stored deletion changes and reports the count', async () => {
      mockConfigChangeFindMany.mockResolvedValueOnce([]);

      const res = await server.post(
        '/api/config-changes/reconcile-inventory',
        { provider: 'AWS', targetId: 'acct-1' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.reconciled).toBe(0);
    });
  });

  describe('POST /sync', () => {
    it('returns 400 when provider or targetId are missing', async () => {
      const res = await server.post('/api/config-changes/sync', { provider: 'AWS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and targetId are required');
    });

    it('creates a sync run and responds immediately with RUNNING status', async () => {
      mockConfigSyncRunCreate.mockResolvedValueOnce({ id: 'run-1' });
      // Background AWS branch will fail fast (account not found) — that's fine,
      // we only assert on the synchronous response returned before it runs.
      mockConfigSyncRunUpdate.mockResolvedValue({ id: 'run-1', status: 'FAILED' });

      const res = await server.post(
        '/api/config-changes/sync',
        { provider: 'AWS', targetId: 'acct-1' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.runId).toBe('run-1');
      expect(res.body.data.status).toBe('RUNNING');
    });
  });

  describe('GET /stats', () => {
    it('returns 400 when provider or targetId are missing', async () => {
      const res = await server.get('/api/config-changes/stats', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and targetId are required');
    });

    it('returns aggregated stats for a valid request', async () => {
      mockConfigChangeGroupBy
        .mockResolvedValueOnce([{ severity: 'HIGH', _count: { id: 3 } }])
        .mockResolvedValueOnce([{ category: 'IAM', _count: { id: 3 } }])
        .mockResolvedValueOnce([{ actor: 'user@example.com', _count: { id: 3 } }]);
      mockQueryRaw.mockResolvedValueOnce([{ date: '2026-01-01', severity: 'HIGH', count: BigInt(3) }]);

      const res = await server.get('/api/config-changes/stats?provider=AWS&targetId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.bySeverity.HIGH).toBe(3);
      expect(res.body.data.total).toBe(3);
      expect(res.body.data.timeline).toHaveLength(1);
    });

    it('returns 500 with the error message when prisma throws', async () => {
      mockConfigChangeGroupBy.mockRejectedValueOnce(new Error('query failed'));

      const res = await server.get('/api/config-changes/stats?provider=AWS&targetId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('query failed');
    });
  });

  describe('GET /', () => {
    it('returns 400 when provider or targetId are missing', async () => {
      const res = await server.get('/api/config-changes', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and targetId are required');
    });

    it('returns a paginated list of changes', async () => {
      mockConfigChangeFindMany.mockResolvedValueOnce([{ id: 'cc-1', eventName: 'CreateUser' }]);
      mockConfigChangeCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/config-changes?provider=AWS&targetId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.meta.total).toBe(1);
    });
  });

  describe('GET /export/csv', () => {
    it('returns 400 when provider or targetId are missing', async () => {
      const res = await server.get('/api/config-changes/export/csv', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and targetId are required');
    });

    it('returns a CSV attachment for a valid request', async () => {
      mockConfigChangeFindMany.mockResolvedValueOnce([
        {
          eventTime: new Date('2026-01-01T00:00:00.000Z'),
          changeAction: 'CREATE',
          severity: 'HIGH',
          category: 'IAM',
          riskScore: 70,
          eventName: 'CreateUser',
          actor: 'user@example.com',
          resourceType: 'AWS::IAM::User',
          resourceName: 'new-user',
          summary: 'Created a new IAM user',
          changeStatus: 'OPEN',
          sourceIp: '1.2.3.4',
        },
      ]);

      const res = await server.get('/api/config-changes/export/csv?provider=AWS&targetId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/csv');
      expect(res.headers['content-disposition']).toContain('attachment');
      expect(res.text).toContain('CreateUser');
    });
  });

  describe('GET /runs', () => {
    it('returns 400 when provider or targetId are missing', async () => {
      const res = await server.get('/api/config-changes/runs', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and targetId are required');
    });

    it('returns runs with the last successful sync time', async () => {
      mockConfigSyncRunFindMany.mockResolvedValueOnce([{ id: 'run-1', status: 'COMPLETED' }]);
      mockConfigSyncRunFindFirst.mockResolvedValueOnce({ completedAt: new Date('2026-01-01T00:00:00.000Z'), changesStored: 5 });

      const res = await server.get('/api/config-changes/runs?provider=AWS&targetId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.runs).toHaveLength(1);
      expect(res.body.lastChangesStored).toBe(5);
    });
  });

  describe('GET /:id', () => {
    it('returns 404 when the change does not exist', async () => {
      mockConfigChangeFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/config-changes/missing-id', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Change not found');
    });

    it('returns the change detail when found', async () => {
      mockConfigChangeFindUnique.mockResolvedValueOnce({ id: 'cc-1', eventName: 'CreateUser' });

      const res = await server.get('/api/config-changes/cc-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe('cc-1');
    });
  });

  describe('PATCH /:id/status', () => {
    it('returns 400 for an invalid status', async () => {
      const res = await server.patch('/api/config-changes/cc-1/status', { status: 'BOGUS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid status');
    });

    it('updates status and stamps acknowledgedBy when ACKNOWLEDGED', async () => {
      mockConfigChangeUpdate.mockResolvedValueOnce({ id: 'cc-1', changeStatus: 'ACKNOWLEDGED' });

      const res = await server.patch('/api/config-changes/cc-1/status', { status: 'ACKNOWLEDGED' }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(mockConfigChangeUpdate).toHaveBeenCalledWith({
        where: { id: 'cc-1' },
        data: expect.objectContaining({ changeStatus: 'ACKNOWLEDGED', acknowledgedBy: 'test-user-id' }),
      });
    });
  });

  describe('POST /bulk-status', () => {
    it('returns 400 when ids array is missing or empty', async () => {
      const res = await server.post('/api/config-changes/bulk-status', { status: 'RESOLVED', ids: [] }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('ids array is required');
    });

    it('returns 422 when more than 200 ids are supplied', async () => {
      const ids = Array.from({ length: 201 }, (_, i) => `id-${i}`);

      const res = await server.post('/api/config-changes/bulk-status', { ids, status: 'RESOLVED' }, AUTH_HEADER);

      expect(res.status).toBe(422);
      expect(res.body.error).toBe('Maximum 200 IDs per bulk request');
    });

    it('returns 400 for an invalid status', async () => {
      const res = await server.post('/api/config-changes/bulk-status', { ids: ['cc-1'], status: 'BOGUS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Invalid status');
    });

    it('bulk-updates valid ids', async () => {
      mockConfigChangeUpdateMany.mockResolvedValueOnce({ count: 2 });

      const res = await server.post(
        '/api/config-changes/bulk-status',
        { ids: ['cc-1', 'cc-2'], status: 'RESOLVED' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.updated).toBe(2);
    });
  });
});

import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockFindMany = jest.fn();
const mockCount = jest.fn();
const mockFindUnique = jest.fn();
const mockCreate = jest.fn();
const mockUpdate = jest.fn();
const mockDelete = jest.fn();
const mockScanFindMany = jest.fn();
const mockScanFindFirst = jest.fn();
const mockScanCreate = jest.fn();
const mockScanUpdate = jest.fn();
const mockCredentialUpsert = jest.fn();
const mockCredentialFindUnique = jest.fn();
const mockFindingFindMany = jest.fn();
const mockFindingCount = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    azureSubscription: {
      findMany: mockFindMany,
      count: mockCount,
      findUnique: mockFindUnique,
      create: mockCreate,
      update: mockUpdate,
      delete: mockDelete,
    },
    azureScan: {
      findMany: mockScanFindMany,
      findFirst: mockScanFindFirst,
      create: mockScanCreate,
      update: mockScanUpdate,
    },
    azureCredential: {
      upsert: mockCredentialUpsert,
      findUnique: mockCredentialFindUnique,
    },
    azureFinding: {
      findMany: mockFindingFindMany,
      count: mockFindingCount,
    },
  },
}));

jest.mock('../../../src/services/azureCredentialService', () => ({
  encryptAzureCredentials: jest.fn(() => ({
    encryptedTenantId: 'enc-tenant',
    encryptedClientId: 'enc-client',
    encryptedClientSecret: 'enc-secret',
  })),
  decryptAzureCredentials: jest.fn(() => ({
    tenantId: 'tenant-1',
    clientId: 'client-1',
    clientSecret: 'secret-1',
  })),
}));

jest.mock('../../../../src/azure/client', () => ({
  __esModule: true,
  default: class FakeAzureClient {},
}));

const mockQueueAdd = jest.fn(async () => ({ id: 'job-1' }));
jest.mock('../../../src/workers/azureScanWorker', () => ({
  azureScanQueue: { add: mockQueueAdd },
}));

jest.mock('../../../../src/azure/engine', () => ({
  AZURE_SERVICES: ['compute', 'storage'],
}));

jest.mock('../../../src/services/inventoryPipeline', () => ({
  triggerInitialPipeline: jest.fn(),
}));

jest.mock('../../../src/services/azureComplianceService', () => ({
  getAzureComplianceTags: jest.fn(() => []),
}));

import router from '../../../src/routes/azureSubscriptions';

describe('azureSubscriptions routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/azure/subscriptions', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /', () => {
    it('returns paginated subscriptions', async () => {
      mockFindMany.mockResolvedValueOnce([
        {
          id: 'sub-1',
          name: 'Sub One',
          subscriptionId: 'azure-sub-1',
          tenantId: 't-1',
          description: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          credential: { id: 'cred-1', authMethod: 'SERVICE_PRINCIPAL' },
          inventoryStatus: 'READY',
          inventoryInitAt: null,
          lastDiscoveryAt: null,
          lastConfigSyncAt: null,
          pipelineError: null,
          scans: [],
        },
      ]);
      mockCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/azure/subscriptions', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].hasCredentials).toBe(true);
      expect(res.body.meta.total).toBe(1);
    });

    it('returns 500 when prisma throws', async () => {
      mockFindMany.mockRejectedValueOnce(new Error('db down'));

      const res = await server.get('/api/azure/subscriptions', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('Internal server error');
    });
  });

  describe('POST /', () => {
    it('creates a subscription with valid body', async () => {
      mockCreate.mockResolvedValueOnce({ id: 'sub-2', name: 'New Sub', subscriptionId: 'azure-sub-2' });

      const res = await server.post(
        '/api/azure/subscriptions',
        { name: 'New Sub', subscriptionId: 'azure-sub-2' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(201);
      expect(res.body.data.id).toBe('sub-2');
      expect(mockCreate).toHaveBeenCalledWith({
        data: expect.objectContaining({ name: 'New Sub', subscriptionId: 'azure-sub-2', createdById: 'test-user-id' }),
      });
    });

    it('returns 400 with field errors when body fails validation', async () => {
      const res = await server.post('/api/azure/subscriptions', { name: '' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation error');
      expect(res.body.details).toBeDefined();
      expect(mockCreate).not.toHaveBeenCalled();
    });
  });

  describe('GET /:id', () => {
    it('returns 404 when subscription not found', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/azure/subscriptions/missing-id', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Subscription not found');
    });

    it('returns subscription detail when found', async () => {
      mockFindUnique.mockResolvedValueOnce({
        id: 'sub-1',
        name: 'Sub One',
        subscriptionId: 'azure-sub-1',
        tenantId: 't-1',
        description: null,
        createdAt: new Date(),
        updatedAt: new Date(),
        credential: null,
        scans: [],
      });

      const res = await server.get('/api/azure/subscriptions/sub-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe('sub-1');
      expect(res.body.data.hasCredentials).toBe(false);
      expect(res.body.data.latestScan).toBeNull();
    });
  });

  describe('PUT /:id', () => {
    it('returns 404 when updating a subscription that does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.put('/api/azure/subscriptions/missing-id', { name: 'Renamed' }, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Subscription not found');
      expect(mockUpdate).not.toHaveBeenCalled();
    });

    it('updates the subscription when it exists', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'sub-1' });
      mockUpdate.mockResolvedValueOnce({ id: 'sub-1', name: 'Renamed' });

      const res = await server.put('/api/azure/subscriptions/sub-1', { name: 'Renamed' }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.name).toBe('Renamed');
    });
  });

  describe('DELETE /:id', () => {
    it('returns 404 when subscription does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.delete('/api/azure/subscriptions/missing-id', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(mockDelete).not.toHaveBeenCalled();
    });

    it('deletes the subscription when it exists', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'sub-1' });
      mockDelete.mockResolvedValueOnce({ id: 'sub-1' });

      const res = await server.delete('/api/azure/subscriptions/sub-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.message).toBe('Subscription deleted successfully');
    });
  });

  describe('POST /:id/credentials', () => {
    it('returns 404 when subscription does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.post(
        '/api/azure/subscriptions/missing-id/credentials',
        { authMethod: 'SERVICE_PRINCIPAL' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(404);
    });

    it('returns 400 for an invalid authMethod', async () => {
      const res = await server.post(
        '/api/azure/subscriptions/sub-1/credentials',
        { authMethod: 'NOT_A_METHOD' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation error');
    });

    it('upserts credentials when subscription exists', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'sub-1' });
      mockCredentialUpsert.mockResolvedValueOnce({
        id: 'cred-1',
        subscriptionId: 'sub-1',
        authMethod: 'SERVICE_PRINCIPAL',
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const res = await server.post(
        '/api/azure/subscriptions/sub-1/credentials',
        { authMethod: 'SERVICE_PRINCIPAL', tenantId: 't', clientId: 'c', clientSecret: 's' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.body.data.authMethod).toBe('SERVICE_PRINCIPAL');
    });
  });

  describe('POST /:id/scan', () => {
    it('returns 404 when subscription does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/azure/subscriptions/missing-id/scan', {}, AUTH_HEADER);

      expect(res.status).toBe(404);
    });

    it('returns 400 when no credentials are configured', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'sub-1' });
      mockCredentialFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/azure/subscriptions/sub-1/scan', {}, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('No credentials configured for this subscription');
    });

    it('enqueues a scan job when credentials exist', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'sub-1' });
      mockCredentialFindUnique.mockResolvedValueOnce({ id: 'cred-1' });
      mockScanCreate.mockResolvedValueOnce({ id: 'scan-1' });
      mockScanUpdate.mockResolvedValueOnce({ id: 'scan-1', jobId: 'job-1' });

      const res = await server.post('/api/azure/subscriptions/sub-1/scan', {}, AUTH_HEADER);

      expect(res.status).toBe(202);
      expect(res.body.data.scanId).toBe('scan-1');
      expect(res.body.data.jobId).toBe('job-1');
      expect(res.body.data.status).toBe('QUEUED');
      expect(mockQueueAdd).toHaveBeenCalled();
    });
  });

  describe('GET /:id/services', () => {
    it('returns distinct service names', async () => {
      mockFindingFindMany.mockResolvedValueOnce([{ service: 'storage' }, { service: 'compute' }]);

      const res = await server.get('/api/azure/subscriptions/sub-1/services', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual(['storage', 'compute']);
    });
  });

  describe('GET /:id/findings', () => {
    it('returns findings with pagination metadata', async () => {
      mockFindingFindMany.mockResolvedValueOnce([{ id: 'f-1', title: 'Finding 1' }]);
      mockFindingCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/azure/subscriptions/sub-1/findings?page=1&limit=10', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.meta.total).toBe(1);
    });
  });
});

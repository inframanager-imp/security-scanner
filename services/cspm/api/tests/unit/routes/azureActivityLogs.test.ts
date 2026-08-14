import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockAzureSubscriptionFindUnique = jest.fn();
const mockAzureCredentialFindUnique = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    azureSubscription: { findUnique: mockAzureSubscriptionFindUnique },
    azureCredential: { findUnique: mockAzureCredentialFindUnique },
  },
}));

jest.mock('../../../src/services/azureCredentialService', () => ({
  decryptAzureCredentials: jest.fn(() => ({
    tenantId: 'tenant-1',
    clientId: 'client-1',
    clientSecret: 'secret-1',
  })),
}));

async function* fakeActivityLogs(events: any[]) {
  for (const e of events) yield e;
}

const mockActivityLogsList = jest.fn();
jest.mock('../../../../src/azure/client', () => {
  return jest.fn().mockImplementation(() => ({
    monitor: () => ({
      activityLogs: { list: mockActivityLogsList },
    }),
  }));
});

import azureActivityLogsRouter from '../../../src/routes/azureActivityLogs';

describe('routes/azureActivityLogs', () => {
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = await TestServer.start(buildTestApp('/api/azure/activity-logs', azureActivityLogsRouter));
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/azure/activity-logs', () => {
    it('returns 400 when subscriptionId is missing', async () => {
      const res = await server.get('/api/azure/activity-logs', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'subscriptionId query parameter is required' });
    });

    it('returns 404 when the subscription does not exist', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/azure/activity-logs?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Subscription not found' });
    });

    it('returns 400 when no credentials are configured', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValue({ id: 'sub-1', subscriptionId: 'azure-sub-1' });
      mockAzureCredentialFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/azure/activity-logs?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'No credentials configured for this subscription' });
    });

    it('returns events with severity mapping and summary counts', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValue({ id: 'sub-1', subscriptionId: 'azure-sub-1' });
      mockAzureCredentialFindUnique.mockResolvedValue({ authMethod: 'SERVICE_PRINCIPAL' });
      mockActivityLogsList.mockReturnValue(
        fakeActivityLogs([
          {
            eventDataId: 'evt-1',
            eventTimestamp: new Date('2026-08-01T00:00:00Z'),
            operationName: { value: 'Microsoft.Compute/virtualMachines/write' },
            status: { value: 'Succeeded' },
            caller: 'user@example.com',
            level: 'Error',
            resourceGroupName: 'rg-1',
            resourceId: '/subscriptions/x/resourceGroups/rg-1',
            description: 'desc',
            category: { value: 'Administrative' },
          },
        ])
      );

      const res = await server.get('/api/azure/activity-logs?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.events).toHaveLength(1);
      expect(res.body.data.events[0].severity).toBe('HIGH');
      expect(res.body.data.summary.high).toBe(1);
      expect(res.body.data.summary.total).toBe(1);
    });

    it('returns 500 when the Azure client throws', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValue({ id: 'sub-1', subscriptionId: 'azure-sub-1' });
      mockAzureCredentialFindUnique.mockResolvedValue({ authMethod: 'SERVICE_PRINCIPAL' });
      mockActivityLogsList.mockImplementation(() => {
        throw new Error('ARM auth failed');
      });

      const res = await server.get('/api/azure/activity-logs?subscriptionId=sub-1', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'ARM auth failed' });
    });
  });
});

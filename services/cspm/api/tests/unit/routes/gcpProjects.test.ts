import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { startTestServer, TestServer } from './testServer';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

jest.mock('../../../src/config/database', () => ({
  prisma: {
    gcpProject: { findMany: jest.fn(), count: jest.fn(), create: jest.fn(), findUnique: jest.fn(), update: jest.fn(), delete: jest.fn() },
    gcpScan: { findMany: jest.fn(), create: jest.fn(), update: jest.fn(), findFirst: jest.fn() },
    gcpCredential: { upsert: jest.fn(), findUnique: jest.fn() },
  },
}));

jest.mock('../../../src/services/gcpCredentialService', () => ({
  encryptGcpCredentials: jest.fn(() => ({ encryptedServiceAccountKey: 'enc-key', serviceAccountEmail: 'svc@example.com' })),
  decryptGcpCredentials: jest.fn(() => ({ serviceAccountKey: '{"type":"service_account"}', serviceAccountEmail: 'svc@example.com' })),
}));

const verifyCredentialsMock = jest.fn();
jest.mock('../../../../src/gcp/client', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => ({
    verifyCredentials: verifyCredentialsMock,
  })),
}));

jest.mock('../../../src/workers/gcpScanWorker', () => ({
  gcpScanQueue: { add: jest.fn() },
}));

jest.mock('../../../../src/gcp/engine', () => ({
  GCP_SERVICES: ['iam', 'storage'],
}));

jest.mock('../../../src/services/inventoryPipeline', () => ({
  triggerInitialPipeline: jest.fn(),
}));

import { prisma } from '../../../src/config/database';
import { gcpScanQueue } from '../../../src/workers/gcpScanWorker';
import { triggerInitialPipeline } from '../../../src/services/inventoryPipeline';

describe('routes/gcpProjects', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/gcpProjects')).default;
    server = await startTestServer('/api/gcp/projects', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /', () => {
    it('lists projects with pagination and a hasCredentials flag', async () => {
      (prisma.gcpProject.findMany as jest.Mock).mockResolvedValue([
        { id: 'p1', name: 'Proj1', projectId: 'gcp-1', description: null, createdAt: new Date(), updatedAt: new Date(), credential: { id: 'c1', authMethod: 'SERVICE_ACCOUNT_KEY' }, scans: [], inventoryStatus: 'READY', inventoryInitAt: null, lastDiscoveryAt: null, lastConfigSyncAt: null, pipelineError: null },
      ]);
      (prisma.gcpProject.count as jest.Mock).mockResolvedValue(1);

      const res = await fetch(`${server.baseUrl}/`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data).toHaveLength(1);
      expect(body.data[0].hasCredentials).toBe(true);
      expect(body.meta).toEqual({ total: 1, page: 1, limit: 20, totalPages: 1 });
    });
  });

  describe('POST /', () => {
    it('creates a project for a valid body', async () => {
      (prisma.gcpProject.create as jest.Mock).mockResolvedValue({ id: 'p1', name: 'Proj1', projectId: 'gcp-1' });

      const res = await fetch(`${server.baseUrl}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Proj1', projectId: 'gcp-1' }),
      });
      const body = await res.json();

      expect(res.status).toBe(201);
      expect(body.data.id).toBe('p1');
    });

    it('returns 400 with field errors when required fields are missing', async () => {
      const res = await fetch(`${server.baseUrl}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: '' }),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('Validation error');
      expect(body.details).toBeDefined();
    });
  });

  describe('GET /:id', () => {
    it('returns 404 when the project does not exist', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`);
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('GCP project not found');
    });

    it('returns project detail with latest scan summary', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue({
        id: 'p1', name: 'Proj1', projectId: 'gcp-1', description: null, createdAt: new Date(), updatedAt: new Date(),
        credential: null,
        scans: [{ id: 's1', status: 'COMPLETED', createdAt: new Date(), completedAt: new Date(), startedAt: new Date(), durationMs: 100, services: ['iam'], errorMessage: null, summary: { critical: 1 } }],
      });

      const res = await fetch(`${server.baseUrl}/p1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.id).toBe('p1');
      expect(body.data.latestScan.summary).toEqual({ critical: 1 });
    });
  });

  describe('PUT /:id', () => {
    it('updates the project', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue({ id: 'p1', name: 'Old' });
      (prisma.gcpProject.update as jest.Mock).mockResolvedValue({ id: 'p1', name: 'New' });

      const res = await fetch(`${server.baseUrl}/p1`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'New' }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.name).toBe('New');
    });

    it('returns 404 when updating a missing project', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'New' }),
      });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('GCP project not found');
    });
  });

  describe('DELETE /:id', () => {
    it('deletes an existing project', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue({ id: 'p1' });
      (prisma.gcpProject.delete as jest.Mock).mockResolvedValue({ id: 'p1' });

      const res = await fetch(`${server.baseUrl}/p1`, { method: 'DELETE' });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.message).toBe('GCP project deleted successfully');
    });

    it('returns 404 when deleting a missing project', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`, { method: 'DELETE' });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('GCP project not found');
    });
  });

  describe('POST /:id/credentials', () => {
    it('stores encrypted credentials for an existing project', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue({ id: 'p1' });
      (prisma.gcpCredential.upsert as jest.Mock).mockResolvedValue({
        id: 'c1', projectId: 'p1', authMethod: 'SERVICE_ACCOUNT_KEY', serviceAccountEmail: 'svc@example.com', createdAt: new Date(), updatedAt: new Date(),
      });

      const res = await fetch(`${server.baseUrl}/p1/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authMethod: 'SERVICE_ACCOUNT_KEY', serviceAccountKey: '{}' }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.id).toBe('c1');
    });

    it('returns 404 when the project does not exist', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authMethod: 'SERVICE_ACCOUNT_KEY' }),
      });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('GCP project not found');
    });

    it('returns 400 for an invalid authMethod', async () => {
      const res = await fetch(`${server.baseUrl}/p1/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authMethod: 'BOGUS' }),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('Validation error');
    });
  });

  describe('POST /:id/credentials/verify', () => {
    it('returns 404 when the project does not exist', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing/credentials/verify`, { method: 'POST' });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('GCP project not found');
    });

    it('returns 404 when no credentials are configured', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue({ id: 'p1', projectId: 'gcp-1' });
      (prisma.gcpCredential.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/p1/credentials/verify`, { method: 'POST' });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Credentials not found');
    });

    it('verifies valid credentials and re-triggers pipeline when project is PENDING', async () => {
      (prisma.gcpProject.findUnique as jest.Mock)
        .mockResolvedValueOnce({ id: 'p1', projectId: 'gcp-1' })
        .mockResolvedValueOnce({ inventoryStatus: 'PENDING' });
      (prisma.gcpCredential.findUnique as jest.Mock).mockResolvedValue({ id: 'c1', projectId: 'p1' });
      verifyCredentialsMock.mockResolvedValue({ valid: true, projectId: 'gcp-1' });

      const res = await fetch(`${server.baseUrl}/p1/credentials/verify`, { method: 'POST' });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.data.valid).toBe(true);
      expect(triggerInitialPipeline).toHaveBeenCalledWith('GCP', 'p1');
    });
  });

  describe('POST /:id/scan', () => {
    it('returns 400 when no credentials are configured', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue({ id: 'p1' });
      (prisma.gcpCredential.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/p1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('No credentials configured for this project');
    });

    it('returns 404 when the project does not exist', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('GCP project not found');
    });

    it('queues a scan and returns 202 with the job id', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValue({ id: 'p1' });
      (prisma.gcpCredential.findUnique as jest.Mock).mockResolvedValue({ id: 'c1' });
      (prisma.gcpScan.create as jest.Mock).mockResolvedValue({ id: 'scan1' });
      (gcpScanQueue.add as jest.Mock).mockResolvedValue({ id: 'job-1' });
      (prisma.gcpScan.update as jest.Mock).mockResolvedValue({ id: 'scan1', jobId: 'job-1' });

      const res = await fetch(`${server.baseUrl}/p1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const body = await res.json();

      expect(res.status).toBe(202);
      expect(body.data.scanId).toBe('scan1');
      expect(body.data.jobId).toBe('job-1');
      expect(body.data.status).toBe('QUEUED');
    });
  });
});

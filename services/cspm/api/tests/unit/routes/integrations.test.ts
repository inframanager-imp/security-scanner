import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp } from './testHttp';

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockFindMany = jest.fn();
const mockFindUnique = jest.fn();
const mockCreate = jest.fn();
const mockUpdate = jest.fn();
const mockDelete = jest.fn();
const mockLogFindMany = jest.fn();
const mockLogCount = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    integrationConfig: {
      findMany: mockFindMany,
      findUnique: mockFindUnique,
      create: mockCreate,
      update: mockUpdate,
      delete: mockDelete,
    },
    integrationLog: {
      findMany: mockLogFindMany,
      count: mockLogCount,
    },
  },
}));

const mockEncrypt = jest.fn(() => 'encrypted-blob');
const mockDecrypt = jest.fn(() => ({ url: 'https://example.com/webhook' }));
const mockDispatch = jest.fn(async () => undefined);

jest.mock('../../../src/services/integrationService', () => ({
  encryptIntegrationConfig: mockEncrypt,
  decryptIntegrationConfig: mockDecrypt,
  dispatchIntegrations: mockDispatch,
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
import router from '../../../src/routes/integrations';

describe('routes/integrations', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    app = buildTestApp('/api/integrations', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/integrations', () => {
    it('returns the list of integration configs', async () => {
      mockFindMany.mockResolvedValueOnce([
        { id: 'i1', name: 'Slack webhook', integrationType: 'WEBHOOK', isActive: true },
      ]);

      const res = await server.get('/api/integrations');

      expect(res.status).toBe(200);
      expect(res.body).toEqual([
        { id: 'i1', name: 'Slack webhook', integrationType: 'WEBHOOK', isActive: true },
      ]);
    });

    it('returns 500 when prisma throws', async () => {
      mockFindMany.mockRejectedValueOnce(new Error('db down'));

      const res = await server.get('/api/integrations');

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to list integrations' });
    });
  });

  describe('GET /api/integrations/:id', () => {
    it('returns the decrypted config for an existing integration', async () => {
      mockFindUnique.mockResolvedValueOnce({
        id: 'i1', name: 'Slack webhook', integrationType: 'WEBHOOK', isActive: true,
        minSeverity: 'HIGH', providers: ['AWS'], targetIds: [], onFreezeOnly: false,
        encryptedConfig: 'blob',
      });

      const res = await server.get('/api/integrations/i1');

      expect(res.status).toBe(200);
      expect(res.body.config).toEqual({ url: 'https://example.com/webhook' });
      expect(mockDecrypt).toHaveBeenCalledWith('blob');
    });

    it('returns 404 when not found', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/integrations/missing');

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Not found' });
    });
  });

  describe('POST /api/integrations', () => {
    it('creates an integration when the body is valid', async () => {
      mockCreate.mockResolvedValueOnce({
        id: 'i2', name: 'Jira', integrationType: 'JIRA', isActive: true, createdAt: '2026-01-01',
      });

      const res = await server.post('/api/integrations', {
        name: 'Jira',
        integrationType: 'JIRA',
        config: { token: 'secret' },
      });

      expect(res.status).toBe(201);
      expect(res.body).toEqual({
        id: 'i2', name: 'Jira', integrationType: 'JIRA', isActive: true, createdAt: '2026-01-01',
      });
      expect(mockEncrypt).toHaveBeenCalledWith({ token: 'secret' });
    });

    it('returns 400 when required fields are missing', async () => {
      const res = await server.post('/api/integrations', { name: 'Missing type' });

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'name, integrationType, and config are required' });
      expect(mockCreate).not.toHaveBeenCalled();
    });

    it('returns 400 when integrationType is not one of the valid types', async () => {
      const res = await server.post('/api/integrations', {
        name: 'Bad type',
        integrationType: 'CARRIER_PIGEON',
        config: { a: 'b' },
      });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/integrationType must be/);
    });
  });

  describe('PUT /api/integrations/:id', () => {
    it('returns 404 when the integration does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.put('/api/integrations/missing', { name: 'New name' });

      expect(res.status).toBe(404);
      expect(mockUpdate).not.toHaveBeenCalled();
    });

    it('updates an existing integration', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'i1', encryptedConfig: 'old-blob' });
      mockUpdate.mockResolvedValueOnce({ id: 'i1', name: 'Renamed', integrationType: 'WEBHOOK', isActive: true, updatedAt: '2026-01-02' });

      const res = await server.put('/api/integrations/i1', { name: 'Renamed' });

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('Renamed');
    });
  });

  describe('DELETE /api/integrations/:id', () => {
    it('deletes and returns 204', async () => {
      mockDelete.mockResolvedValueOnce({});

      const res = await server.delete('/api/integrations/i1');

      expect(res.status).toBe(204);
    });

    it('returns 500 when delete fails', async () => {
      mockDelete.mockRejectedValueOnce(new Error('fk constraint'));

      const res = await server.delete('/api/integrations/i1');

      expect(res.status).toBe(500);
    });
  });

  describe('POST /api/integrations/:id/test', () => {
    it('dispatches a synthetic test event for an existing integration', async () => {
      mockFindUnique.mockResolvedValueOnce({
        id: 'i1', name: 'Slack webhook', integrationType: 'WEBHOOK',
        providers: ['AWS'], minSeverity: 'HIGH',
      });

      const res = await server.post('/api/integrations/i1/test');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, message: 'Test dispatched via WEBHOOK' });
    });

    it('returns 404 when the integration does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.post('/api/integrations/missing/test');

      expect(res.status).toBe(404);
    });
  });

  describe('GET /api/integrations/:id/logs', () => {
    it('returns paginated delivery logs', async () => {
      mockLogCount.mockResolvedValueOnce(1);
      mockLogFindMany.mockResolvedValueOnce([{ id: 'l1', status: 'SUCCESS' }]);

      const res = await server.get('/api/integrations/i1/logs');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ total: 1, page: 1, pageSize: 20, logs: [{ id: 'l1', status: 'SUCCESS' }] });
    });
  });

  describe('GET /api/integrations/logs/recent', () => {
    it('returns global recent logs', async () => {
      mockLogFindMany.mockResolvedValueOnce([{ id: 'l2', status: 'FAILED' }]);

      const res = await server.get('/api/integrations/logs/recent');

      expect(res.status).toBe(200);
      expect(res.body).toEqual([{ id: 'l2', status: 'FAILED' }]);
    });
  });
});

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { TestServer, buildTestApp } from './testHttp';

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockAlertConfigFindMany = jest.fn();
const mockAlertConfigFindUnique = jest.fn();
const mockAlertConfigCreate = jest.fn();
const mockAlertConfigUpdate = jest.fn();
const mockAlertConfigDelete = jest.fn();
const mockAlertLogFindMany = jest.fn();
const mockAlertLogCount = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    alertConfig: {
      findMany: mockAlertConfigFindMany,
      findUnique: mockAlertConfigFindUnique,
      create: mockAlertConfigCreate,
      update: mockAlertConfigUpdate,
      delete: mockAlertConfigDelete,
    },
    alertLog: {
      findMany: mockAlertLogFindMany,
      count: mockAlertLogCount,
    },
  },
}));

jest.mock('@prisma/client', () => ({
  AlertChannel: {
    SLACK: 'SLACK',
    EMAIL_SMTP: 'EMAIL_SMTP',
    EMAIL_O365: 'EMAIL_O365',
    EMAIL_GMAIL: 'EMAIL_GMAIL',
  },
}));

jest.mock('../../../src/services/alertService', () => ({
  encryptAlertConfig: jest.fn(() => 'encrypted-blob'),
  decryptAlertConfig: jest.fn(() => ({ webhookUrl: 'https://hooks.example.com/x' })),
  buildSlackPayload: jest.fn(() => ({ text: 'test' })),
  buildEmailHtml: jest.fn(() => '<p>test</p>'),
  sendSlack: jest.fn(async () => {}),
  sendSmtp: jest.fn(async () => {}),
  sendO365: jest.fn(async () => {}),
  sendGmail: jest.fn(async () => {}),
}));

import alertsRouter from '../../../src/routes/alerts';

describe('routes/alerts', () => {
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = await TestServer.start(buildTestApp('/api/alerts', alertsRouter));
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/alerts', () => {
    it('lists alert configs without the encrypted config field', async () => {
      mockAlertConfigFindMany.mockResolvedValue([
        { id: 'cfg-1', name: 'Slack Alerts', isActive: true, channel: 'SLACK' },
      ]);

      const res = await server.get('/api/alerts');

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].id).toBe('cfg-1');
    });

    it('returns 500 when prisma throws', async () => {
      mockAlertConfigFindMany.mockRejectedValue(new Error('db down'));

      const res = await server.get('/api/alerts');

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to list alert configs' });
    });
  });

  describe('GET /api/alerts/:id', () => {
    it('returns 404 when not found', async () => {
      mockAlertConfigFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/alerts/missing');

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Not found' });
    });

    it('returns the config with decrypted fields', async () => {
      mockAlertConfigFindUnique.mockResolvedValue({
        id: 'cfg-1',
        name: 'Slack Alerts',
        isActive: true,
        channel: 'SLACK',
        minSeverity: 'LOW',
        categories: [],
        providers: ['AWS'],
        targetIds: [],
        onFreezeOnly: false,
        encryptedConfig: 'encrypted-blob',
      });

      const res = await server.get('/api/alerts/cfg-1');

      expect(res.status).toBe(200);
      expect(res.body.config).toEqual({ webhookUrl: 'https://hooks.example.com/x' });
    });
  });

  describe('POST /api/alerts', () => {
    it('creates an alert config for a valid body', async () => {
      mockAlertConfigCreate.mockResolvedValue({
        id: 'cfg-2', name: 'New', channel: 'SLACK', isActive: true, createdAt: new Date(),
      });

      const res = await server.post('/api/alerts', {
        name: 'New', channel: 'SLACK', config: { webhookUrl: 'https://hooks.example.com/y' },
      });

      expect(res.status).toBe(201);
      expect(res.body.id).toBe('cfg-2');
    });

    it('returns 400 when required fields are missing', async () => {
      const res = await server.post('/api/alerts', { name: 'Missing channel/config' });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('name, channel, and config are required');
      expect(mockAlertConfigCreate).not.toHaveBeenCalled();
    });

    it('returns 400 for an unknown channel value', async () => {
      const res = await server.post('/api/alerts', {
        name: 'Bad channel', channel: 'CARRIER_PIGEON', config: { x: '1' },
      });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('channel must be one of');
      expect(mockAlertConfigCreate).not.toHaveBeenCalled();
    });

    it('returns 500 when prisma create throws', async () => {
      mockAlertConfigCreate.mockRejectedValue(new Error('constraint'));

      const res = await server.post('/api/alerts', {
        name: 'New', channel: 'SLACK', config: { webhookUrl: 'https://hooks.example.com/y' },
      });

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to create alert config' });
    });
  });

  describe('PUT /api/alerts/:id', () => {
    it('returns 404 when the config does not exist', async () => {
      mockAlertConfigFindUnique.mockResolvedValue(null);

      const res = await server.put('/api/alerts/missing', { name: 'Renamed' });

      expect(res.status).toBe(404);
      expect(mockAlertConfigUpdate).not.toHaveBeenCalled();
    });

    it('updates an existing config', async () => {
      mockAlertConfigFindUnique.mockResolvedValue({ id: 'cfg-1', encryptedConfig: 'old-blob' });
      mockAlertConfigUpdate.mockResolvedValue({
        id: 'cfg-1', name: 'Renamed', channel: 'SLACK', isActive: true, updatedAt: new Date(),
      });

      const res = await server.put('/api/alerts/cfg-1', { name: 'Renamed' });

      expect(res.status).toBe(200);
      expect(res.body.name).toBe('Renamed');
    });
  });

  describe('DELETE /api/alerts/:id', () => {
    it('deletes and returns 204', async () => {
      mockAlertConfigDelete.mockResolvedValue({});

      const res = await server.delete('/api/alerts/cfg-1');

      expect(res.status).toBe(204);
    });

    it('returns 500 when delete throws', async () => {
      mockAlertConfigDelete.mockRejectedValue(new Error('not found'));

      const res = await server.delete('/api/alerts/missing');

      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/alerts/:id/logs', () => {
    it('returns paginated logs for a config', async () => {
      mockAlertLogCount.mockResolvedValue(1);
      mockAlertLogFindMany.mockResolvedValue([
        { id: 'log-1', status: 'SENT', subject: 'Test', errorMessage: null, sentAt: new Date(), change: null },
      ]);

      const res = await server.get('/api/alerts/cfg-1/logs');

      expect(res.status).toBe(200);
      expect(res.body.total).toBe(1);
      expect(res.body.logs).toHaveLength(1);
    });
  });

  describe('GET /api/alerts/logs/recent', () => {
    it('returns recent logs across all configs', async () => {
      mockAlertLogFindMany.mockResolvedValue([]);

      const res = await server.get('/api/alerts/logs/recent');

      expect(res.status).toBe(200);
      expect(res.body).toEqual([]);
    });
  });
});

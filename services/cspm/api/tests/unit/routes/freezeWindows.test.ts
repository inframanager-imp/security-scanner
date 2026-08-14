import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { startTestServer, TestServer } from './testServer';

// Note: freezeWindows.ts does not use the `authenticate` middleware, so no
// auth mock is needed here.

jest.mock('../../../src/config/database', () => ({
  prisma: {
    freezeWindow: {
      findMany: jest.fn(),
      findUnique: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    },
  },
}));

jest.mock('../../../src/config/logger', () => ({
  logger: { error: jest.fn(), info: jest.fn(), warn: jest.fn(), debug: jest.fn() },
}));

import { prisma } from '../../../src/config/database';

describe('routes/freezeWindows', () => {
  let server: TestServer;

  beforeAll(async () => {
    const router = (await import('../../../src/routes/freezeWindows')).default;
    server = await startTestServer('/api/freeze-windows', router);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /', () => {
    it('lists freeze windows ordered by createdAt desc', async () => {
      (prisma.freezeWindow.findMany as jest.Mock).mockResolvedValue([{ id: 'w1', name: 'Weekend' }]);

      const res = await fetch(`${server.baseUrl}/`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body).toHaveLength(1);
    });

    it('returns 500 when the query throws', async () => {
      (prisma.freezeWindow.findMany as jest.Mock).mockRejectedValue(new Error('db down'));

      const res = await fetch(`${server.baseUrl}/`);
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Failed to list freeze windows');
    });
  });

  describe('GET /:id', () => {
    it('returns a single freeze window', async () => {
      (prisma.freezeWindow.findUnique as jest.Mock).mockResolvedValue({ id: 'w1', name: 'Weekend' });

      const res = await fetch(`${server.baseUrl}/w1`);
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.id).toBe('w1');
    });

    it('returns 404 when not found', async () => {
      (prisma.freezeWindow.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`);
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Not found');
    });
  });

  describe('POST /', () => {
    it('creates a freeze window with defaults applied', async () => {
      (prisma.freezeWindow.create as jest.Mock).mockResolvedValue({ id: 'w1', name: 'Weekend' });

      const res = await fetch(`${server.baseUrl}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Weekend' }),
      });
      const body = await res.json();

      expect(res.status).toBe(201);
      expect(body.id).toBe('w1');
      expect(prisma.freezeWindow.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          name: 'Weekend',
          providers: [],
          targetIds: [],
          daysOfWeek: [],
          startTime: '00:00',
          endTime: '23:59',
          timezone: 'UTC',
          isActive: true,
        }),
      });
    });

    it('returns 400 when name is missing', async () => {
      const res = await fetch(`${server.baseUrl}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('name is required');
    });

    it('returns 400 when startTime/endTime are not HH:MM', async () => {
      const res = await fetch(`${server.baseUrl}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Bad', startTime: '9am' }),
      });
      const body = await res.json();

      expect(res.status).toBe(400);
      expect(body.error).toBe('startTime and endTime must be HH:MM format');
    });

    it('returns 500 when create throws', async () => {
      (prisma.freezeWindow.create as jest.Mock).mockRejectedValue(new Error('db down'));

      const res = await fetch(`${server.baseUrl}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Weekend' }),
      });
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Failed to create freeze window');
    });
  });

  describe('PUT /:id', () => {
    it('updates only the fields provided', async () => {
      (prisma.freezeWindow.findUnique as jest.Mock).mockResolvedValue({ id: 'w1', name: 'Old' });
      (prisma.freezeWindow.update as jest.Mock).mockResolvedValue({ id: 'w1', name: 'New' });

      const res = await fetch(`${server.baseUrl}/w1`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'New' }),
      });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.name).toBe('New');
      expect(prisma.freezeWindow.update).toHaveBeenCalledWith({
        where: { id: 'w1' },
        data: { name: 'New' },
      });
    });

    it('returns 404 when the freeze window does not exist', async () => {
      (prisma.freezeWindow.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'New' }),
      });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Not found');
    });
  });

  describe('DELETE /:id', () => {
    it('deletes and returns 204', async () => {
      (prisma.freezeWindow.delete as jest.Mock).mockResolvedValue({ id: 'w1' });

      const res = await fetch(`${server.baseUrl}/w1`, { method: 'DELETE' });

      expect(res.status).toBe(204);
    });

    it('returns 500 when delete throws', async () => {
      (prisma.freezeWindow.delete as jest.Mock).mockRejectedValue(new Error('db down'));

      const res = await fetch(`${server.baseUrl}/w1`, { method: 'DELETE' });
      const body = await res.json();

      expect(res.status).toBe(500);
      expect(body.error).toBe('Failed to delete freeze window');
    });
  });

  describe('PATCH /:id/toggle', () => {
    it('flips isActive', async () => {
      (prisma.freezeWindow.findUnique as jest.Mock).mockResolvedValue({ id: 'w1', isActive: true });
      (prisma.freezeWindow.update as jest.Mock).mockResolvedValue({ id: 'w1', name: 'Weekend', isActive: false });

      const res = await fetch(`${server.baseUrl}/w1/toggle`, { method: 'PATCH' });
      const body = await res.json();

      expect(res.status).toBe(200);
      expect(body.isActive).toBe(false);
      expect(prisma.freezeWindow.update).toHaveBeenCalledWith({
        where: { id: 'w1' },
        data: { isActive: false },
        select: { id: true, name: true, isActive: true },
      });
    });

    it('returns 404 when not found', async () => {
      (prisma.freezeWindow.findUnique as jest.Mock).mockResolvedValue(null);

      const res = await fetch(`${server.baseUrl}/missing/toggle`, { method: 'PATCH' });
      const body = await res.json();

      expect(res.status).toBe(404);
      expect(body.error).toBe('Not found');
    });
  });
});

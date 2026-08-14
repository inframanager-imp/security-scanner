import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockFindMany = jest.fn();
const mockFindUnique = jest.fn();
const mockCreate = jest.fn();
const mockUpdate = jest.fn();
const mockDelete = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    riskItem: {
      findMany: mockFindMany,
      findUnique: mockFindUnique,
      create: mockCreate,
      update: mockUpdate,
      delete: mockDelete,
    },
  },
}));

import router from '../../../src/routes/riskRegister';

describe('routes/riskRegister', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    app = buildTestApp('/api/risk-register', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/risk-register', () => {
    it('returns the list filtered by query params', async () => {
      mockFindMany.mockResolvedValueOnce([{ id: 'risk-1', title: 'Public S3 bucket' }]);

      const res = await server.get('/api/risk-register?provider=AWS&status=OPEN', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ data: [{ id: 'risk-1', title: 'Public S3 bucket' }] });
      expect(mockFindMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { provider: 'AWS', status: 'OPEN' } })
      );
    });

    it('returns 500 when prisma throws', async () => {
      mockFindMany.mockRejectedValueOnce(new Error('db down'));

      const res = await server.get('/api/risk-register', AUTH_HEADER);

      expect(res.status).toBe(500);
    });
  });

  describe('GET /api/risk-register/:id', () => {
    it('returns 404 when the risk item does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/risk-register/missing', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Not found' });
    });

    it('returns the risk item when found', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'risk-1', title: 'Public S3 bucket' });

      const res = await server.get('/api/risk-register/risk-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ data: { id: 'risk-1', title: 'Public S3 bucket' } });
    });
  });

  describe('POST /api/risk-register', () => {
    it('creates a risk item and clamps riskScore to 25', async () => {
      mockCreate.mockImplementation(async ({ data }: any) => ({ id: 'risk-2', ...data }));

      const res = await server.post('/api/risk-register', {
        title: 'Overly permissive IAM role',
        description: 'Wildcard action allowed',
        category: 'IAM',
        likelihood: 5,
        impact: 5,
      }, AUTH_HEADER);

      expect(res.status).toBe(201);
      expect(res.body.data.riskScore).toBe(25);
      expect(res.body.data.status).toBe('OPEN');
    });

    it('returns 400 when required fields are missing', async () => {
      const res = await server.post('/api/risk-register', { title: 'Incomplete' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(mockCreate).not.toHaveBeenCalled();
    });
  });

  describe('PATCH /api/risk-register/:id', () => {
    it('returns 404 when the risk item does not exist', async () => {
      mockFindUnique.mockResolvedValueOnce(null);

      const res = await server.patch('/api/risk-register/missing', { status: 'MITIGATED' }, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(mockUpdate).not.toHaveBeenCalled();
    });

    it('recomputes riskScore from existing values when only one changes', async () => {
      mockFindUnique.mockResolvedValueOnce({ id: 'risk-1', likelihood: 3, impact: 4 });
      mockUpdate.mockImplementation(async ({ data }: any) => ({ id: 'risk-1', ...data }));

      const res = await server.patch('/api/risk-register/risk-1', { impact: 5 }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.riskScore).toBe(15); // likelihood 3 * new impact 5
    });
  });

  describe('DELETE /api/risk-register/:id', () => {
    it('deletes and returns success', async () => {
      mockDelete.mockResolvedValueOnce({});

      const res = await server.delete('/api/risk-register/risk-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ data: { deleted: true } });
    });

    it('returns 500 when delete fails', async () => {
      mockDelete.mockRejectedValueOnce(new Error('fk constraint'));

      const res = await server.delete('/api/risk-register/risk-1', AUTH_HEADER);

      expect(res.status).toBe(500);
    });
  });
});

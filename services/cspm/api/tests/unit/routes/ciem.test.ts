import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockAttackPathFindMany = jest.fn();
const mockAttackPathCount = jest.fn();
const mockAttackPathFindUnique = jest.fn();
const mockAttackPathUpdate = jest.fn();
const mockAttackPathGroupBy = jest.fn();
const mockPrincipalPermissionFindMany = jest.fn();
const mockPrincipalPermissionGroupBy = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    attackPath: {
      findMany: mockAttackPathFindMany,
      count: mockAttackPathCount,
      findUnique: mockAttackPathFindUnique,
      update: mockAttackPathUpdate,
      groupBy: mockAttackPathGroupBy,
    },
    principalPermission: {
      findMany: mockPrincipalPermissionFindMany,
      groupBy: mockPrincipalPermissionGroupBy,
    },
  },
}));

import router from '../../../src/routes/ciem';

describe('ciem routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/ciem', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /attack-paths', () => {
    it('returns paginated attack paths', async () => {
      mockAttackPathFindMany.mockResolvedValueOnce([{ id: 'ap-1', kind: 'PRIVESC' }]);
      mockAttackPathCount.mockResolvedValueOnce(1);

      const res = await server.get('/api/ciem/attack-paths?provider=AWS&accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.meta.total).toBe(1);
    });

    it('clamps pageSize to the 1-200 range', async () => {
      mockAttackPathFindMany.mockResolvedValueOnce([]);
      mockAttackPathCount.mockResolvedValueOnce(0);

      const res = await server.get('/api/ciem/attack-paths?pageSize=9999', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.meta.pageSize).toBe(200);
    });
  });

  describe('GET /attack-paths/:id', () => {
    it('returns 404 when not found', async () => {
      mockAttackPathFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/ciem/attack-paths/missing-id', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('AttackPath not found');
    });

    it('returns the attack path when found', async () => {
      mockAttackPathFindUnique.mockResolvedValueOnce({ id: 'ap-1', kind: 'PRIVESC' });

      const res = await server.get('/api/ciem/attack-paths/ap-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe('ap-1');
    });
  });

  describe('PATCH /attack-paths/:id', () => {
    it('sets acknowledgedAt when status is ACKNOWLEDGED', async () => {
      mockAttackPathUpdate.mockResolvedValueOnce({ id: 'ap-1', status: 'ACKNOWLEDGED' });

      const res = await server.patch('/api/ciem/attack-paths/ap-1', { status: 'ACKNOWLEDGED' }, AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.status).toBe('ACKNOWLEDGED');
      expect(mockAttackPathUpdate).toHaveBeenCalledWith({
        where: { id: 'ap-1' },
        data: expect.objectContaining({ status: 'ACKNOWLEDGED', acknowledgedAt: expect.any(Date) }),
      });
    });

    it('returns 404 when the attack path does not exist', async () => {
      mockAttackPathUpdate.mockRejectedValueOnce(new Error('Record not found'));

      const res = await server.patch('/api/ciem/attack-paths/missing-id', { status: 'RESOLVED' }, AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('AttackPath not found');
    });
  });

  describe('GET /principals/:arn/permissions', () => {
    it('returns 400 when provider or accountId are missing', async () => {
      const res = await server.get('/api/ciem/principals/arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fx/permissions', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider and accountId are required');
    });

    it('returns permissions when provider and accountId are given', async () => {
      mockPrincipalPermissionFindMany.mockResolvedValueOnce([{ action: 's3:GetObject' }]);

      const res = await server.get(
        '/api/ciem/principals/arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fx/permissions?provider=AWS&accountId=acct-1',
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
    });
  });

  describe('GET /stats/:provider/:accountId', () => {
    it('returns aggregated stats', async () => {
      mockAttackPathGroupBy
        .mockResolvedValueOnce([{ kind: 'PRIVESC', _count: { _all: 2 } }])
        .mockResolvedValueOnce([{ severity: 'HIGH', _count: { _all: 2 } }]);
      mockPrincipalPermissionGroupBy.mockResolvedValueOnce([
        { principalArn: 'arn:aws:iam::1:role/x', _count: { _all: 5 } },
      ]);

      const res = await server.get('/api/ciem/stats/AWS/acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data.attackPathsByKind).toEqual([{ kind: 'PRIVESC', count: 2 }]);
      expect(res.body.data.attackPathsBySeverity).toEqual([{ severity: 'HIGH', count: 2 }]);
      expect(res.body.data.topPrincipalsByPermissionCount).toEqual([
        { principalArn: 'arn:aws:iam::1:role/x', permissionCount: 5 },
      ]);
    });
  });
});

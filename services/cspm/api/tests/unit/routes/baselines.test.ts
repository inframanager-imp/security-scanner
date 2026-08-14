import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { TestServer, buildTestApp } from './testHttp';

const mockBaselineFindMany = jest.fn();
const mockBaselineFindUnique = jest.fn();
const mockBaselineDelete = jest.fn();
const mockApprovalFindMany = jest.fn();
const mockDriftCount = jest.fn();
const mockDriftFindMany = jest.fn();
const mockDriftFindFirst = jest.fn();
const mockDriftUpdate = jest.fn();
const mockApprovalRequestFindFirst = jest.fn();
const mockResourceInventoryFindFirst = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    configBaseline: {
      findMany: mockBaselineFindMany,
      findUnique: mockBaselineFindUnique,
      delete: mockBaselineDelete,
    },
    approvalRequest: {
      findMany: mockApprovalFindMany,
      findFirst: mockApprovalRequestFindFirst,
    },
    driftResult: {
      count: mockDriftCount,
      findMany: mockDriftFindMany,
      findFirst: mockDriftFindFirst,
      update: mockDriftUpdate,
    },
    resourceInventory: {
      findFirst: mockResourceInventoryFindFirst,
    },
  },
}));

const mockCaptureBaseline = jest.fn();
const mockDetectDrift = jest.fn();
const mockRefreshBaseline = jest.fn();
const mockListBaselineVersions = jest.fn();
const mockGetBaselineVersion = jest.fn();

jest.mock('../../../src/services/baselineService', () => ({
  captureBaseline: mockCaptureBaseline,
  detectDrift: mockDetectDrift,
  refreshBaseline: mockRefreshBaseline,
  listBaselineVersions: mockListBaselineVersions,
  getBaselineVersion: mockGetBaselineVersion,
}));

const mockGenerateRevertPlan = jest.fn();
const mockExecuteRevert = jest.fn();
jest.mock('../../../src/services/revertService', () => ({
  generateRevertPlan: mockGenerateRevertPlan,
  executeRevert: mockExecuteRevert,
}));

const mockRequestApproval = jest.fn();
jest.mock('../../../src/services/approvalService', () => ({
  requestApproval: mockRequestApproval,
}));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

import router from '../../../src/routes/baselines';

describe('baselines routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/baselines', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /', () => {
    it('returns baselines with computed drift counts', async () => {
      mockBaselineFindMany.mockResolvedValueOnce([
        {
          id: 'b-1',
          name: 'Baseline 1',
          description: null,
          provider: 'AWS',
          targetId: 'acct-1',
          resourceCount: 10,
          isActive: true,
          capturedAt: new Date(),
          currentVersion: 1,
          driftResults: [{ severity: 'CRITICAL' }, { severity: 'HIGH' }, { severity: 'HIGH' }],
        },
      ]);
      mockApprovalFindMany.mockResolvedValueOnce([]);

      const res = await server.get('/api/baselines');

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].openDrift).toBe(3);
      expect(res.body[0].criticalDrift).toBe(1);
      expect(res.body[0].highDrift).toBe(2);
    });

    it('returns 500 when prisma throws', async () => {
      mockBaselineFindMany.mockRejectedValueOnce(new Error('db error'));

      const res = await server.get('/api/baselines');

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('Failed to list baselines');
    });
  });

  describe('POST /', () => {
    it('returns 400 when required fields are missing', async () => {
      const res = await server.post('/api/baselines', { provider: 'AWS' });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('provider, targetId, and name are required');
    });

    it('captures immediately when immediate=true', async () => {
      mockCaptureBaseline.mockResolvedValueOnce('b-1');
      mockBaselineFindUnique.mockResolvedValueOnce({ id: 'b-1', name: 'Baseline 1' });

      const res = await server.post('/api/baselines', {
        provider: 'AWS', targetId: 'acct-1', name: 'Baseline 1', immediate: true,
      });

      expect(res.status).toBe(201);
      expect(res.body.id).toBe('b-1');
    });

    it('creates an approval request when requestedBy is provided without immediate', async () => {
      mockRequestApproval.mockResolvedValueOnce({ id: 'appr-1', expiresAt: new Date('2026-01-02T00:00:00.000Z') });

      const res = await server.post('/api/baselines', {
        provider: 'AWS', targetId: 'acct-1', name: 'Baseline 1', requestedBy: 'user@example.com',
      });

      expect(res.status).toBe(202);
      expect(res.body.approvalRequired).toBe(true);
      expect(res.body.approvalId).toBe('appr-1');
    });
  });

  describe('GET /:id', () => {
    it('returns 404 when baseline is not found', async () => {
      mockBaselineFindUnique.mockResolvedValueOnce(null);

      const res = await server.get('/api/baselines/missing-id');

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Not found');
    });

    it('returns baseline detail when found', async () => {
      mockBaselineFindUnique.mockResolvedValueOnce({ id: 'b-1', name: 'Baseline 1', driftResults: [] });

      const res = await server.get('/api/baselines/b-1');

      expect(res.status).toBe(200);
      expect(res.body.id).toBe('b-1');
    });
  });

  describe('DELETE /:id', () => {
    it('deletes the baseline and returns 204', async () => {
      mockBaselineDelete.mockResolvedValueOnce({ id: 'b-1' });

      const res = await server.delete('/api/baselines/b-1');

      expect(res.status).toBe(204);
    });

    it('returns 500 when delete fails', async () => {
      mockBaselineDelete.mockRejectedValueOnce(new Error('not found'));

      const res = await server.delete('/api/baselines/missing-id');

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('Failed to delete baseline');
    });
  });

  describe('POST /:id/detect', () => {
    it('runs drift detection and returns the result', async () => {
      mockDetectDrift.mockResolvedValueOnce({ driftCount: 2 });

      const res = await server.post('/api/baselines/b-1/detect', {});

      expect(res.status).toBe(200);
      expect(res.body.driftCount).toBe(2);
    });
  });

  describe('GET /:id/drift', () => {
    it('returns paginated drift results defaulting to OPEN status', async () => {
      mockDriftCount.mockResolvedValueOnce(1);
      mockDriftFindMany.mockResolvedValueOnce([{ id: 'd-1', driftType: 'MODIFIED', severity: 'HIGH' }]);
      mockApprovalFindMany.mockResolvedValueOnce([]);

      const res = await server.get('/api/baselines/b-1/drift');

      expect(res.status).toBe(200);
      expect(res.body.total).toBe(1);
      expect(res.body.results).toHaveLength(1);
      expect(res.body.results[0].pendingRevert).toBeNull();
    });
  });

  describe('GET /:id/drift/:driftId', () => {
    it('returns 404 when drift result is not found', async () => {
      mockDriftFindFirst.mockResolvedValueOnce(null);
      mockBaselineFindUnique.mockResolvedValueOnce({ capturedAt: new Date() });

      const res = await server.get('/api/baselines/b-1/drift/missing-drift');

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Not found');
    });

    it('returns drift detail when found', async () => {
      mockDriftFindFirst.mockResolvedValueOnce({ id: 'd-1', driftType: 'MODIFIED', nativeId: 'n-1' });
      mockBaselineFindUnique.mockResolvedValueOnce({ capturedAt: new Date() });
      mockResourceInventoryFindFirst.mockResolvedValueOnce({ lastSeenAt: new Date() });
      mockApprovalRequestFindFirst.mockResolvedValueOnce(null);

      const res = await server.get('/api/baselines/b-1/drift/d-1');

      expect(res.status).toBe(200);
      expect(res.body.id).toBe('d-1');
    });
  });

  describe('PATCH /:id/drift/:driftId', () => {
    it('returns 400 for an invalid status value', async () => {
      const res = await server.patch('/api/baselines/b-1/drift/d-1', { status: 'BOGUS' });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('status must be');
      expect(mockDriftUpdate).not.toHaveBeenCalled();
    });

    it('updates drift status when valid', async () => {
      mockDriftUpdate.mockResolvedValueOnce({ id: 'd-1', status: 'ACKNOWLEDGED', acknowledgedAt: new Date(), resolvedAt: null });

      const res = await server.patch('/api/baselines/b-1/drift/d-1', { status: 'ACKNOWLEDGED' });

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('ACKNOWLEDGED');
    });
  });

  describe('POST /:id/drift/:driftId/revert-plan', () => {
    it('returns the generated revert plan', async () => {
      mockGenerateRevertPlan.mockResolvedValueOnce({ steps: ['revert step'] });

      const res = await server.post('/api/baselines/b-1/drift/d-1/revert-plan', {});

      expect(res.status).toBe(200);
      expect(res.body.steps).toEqual(['revert step']);
    });
  });

  describe('POST /:id/drift/:driftId/revert', () => {
    it('returns 400 when requestedBy is missing and not immediate', async () => {
      const res = await server.post('/api/baselines/b-1/drift/d-1/revert', {});

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('requestedBy (email) is required');
    });

    it('returns 409 when a revert approval is already pending', async () => {
      mockApprovalRequestFindFirst.mockResolvedValueOnce({ id: 'appr-existing' });

      const res = await server.post('/api/baselines/b-1/drift/d-1/revert', { requestedBy: 'user@example.com' });

      expect(res.status).toBe(409);
      expect(res.body.approvalId).toBe('appr-existing');
    });

    it('creates a new approval request when none is pending', async () => {
      mockApprovalRequestFindFirst.mockResolvedValueOnce(null);
      mockRequestApproval.mockResolvedValueOnce({ id: 'appr-1', expiresAt: new Date('2026-01-02T00:00:00.000Z') });

      const res = await server.post('/api/baselines/b-1/drift/d-1/revert', { requestedBy: 'user@example.com' });

      expect(res.status).toBe(202);
      expect(res.body.approvalId).toBe('appr-1');
    });
  });

  describe('GET /:id/versions', () => {
    it('returns version history', async () => {
      mockListBaselineVersions.mockResolvedValueOnce([{ id: 'v-1', versionNumber: 1 }]);

      const res = await server.get('/api/baselines/b-1/versions');

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
    });
  });

  describe('GET /:id/versions/:vId', () => {
    it('returns 404 when version is not found', async () => {
      mockGetBaselineVersion.mockResolvedValueOnce(null);

      const res = await server.get('/api/baselines/b-1/versions/missing-version');

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('Version not found');
    });
  });

  describe('GET /:id/versions/:vId/compare/:vId2', () => {
    it('returns 404 when either version is missing', async () => {
      mockGetBaselineVersion.mockResolvedValueOnce(null);
      mockGetBaselineVersion.mockResolvedValueOnce({ id: 'v-2', snapshots: [] });

      const res = await server.get('/api/baselines/b-1/versions/v-1/compare/v-2');

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('One or both versions not found');
    });

    it('computes added/deleted/modified diffs between versions', async () => {
      mockGetBaselineVersion.mockResolvedValueOnce({
        id: 'v-1', versionNumber: 1, label: null, capturedAt: new Date(), resourceCount: 2,
        snapshots: [
          { nativeId: 'n-1', resourceType: 'bucket', resourceName: 'a', configState: { x: 1 } },
          { nativeId: 'n-2', resourceType: 'bucket', resourceName: 'b', configState: { x: 1 } },
        ],
      });
      mockGetBaselineVersion.mockResolvedValueOnce({
        id: 'v-2', versionNumber: 2, label: null, capturedAt: new Date(), resourceCount: 2,
        snapshots: [
          { nativeId: 'n-1', resourceType: 'bucket', resourceName: 'a', configState: { x: 2 } },
          { nativeId: 'n-3', resourceType: 'bucket', resourceName: 'c', configState: { x: 1 } },
        ],
      });

      const res = await server.get('/api/baselines/b-1/versions/v-1/compare/v-2');

      expect(res.status).toBe(200);
      expect(res.body.summary.added).toBe(1);
      expect(res.body.summary.deleted).toBe(1);
      expect(res.body.summary.modified).toBe(1);
    });
  });
});

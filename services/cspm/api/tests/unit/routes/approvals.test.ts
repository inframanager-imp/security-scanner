import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { TestServer, buildTestApp } from './testHttp';

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockApprovalRequestFindMany = jest.fn();
const mockApprovalRequestCount = jest.fn();
const mockApprovalRequestFindUnique = jest.fn();
const mockConfigBaselineFindMany = jest.fn();
const mockConfigBaselineFindUnique = jest.fn();
const mockDriftResultFindUnique = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    approvalRequest: {
      findMany: mockApprovalRequestFindMany,
      count: mockApprovalRequestCount,
      findUnique: mockApprovalRequestFindUnique,
    },
    configBaseline: {
      findMany: mockConfigBaselineFindMany,
      findUnique: mockConfigBaselineFindUnique,
    },
    driftResult: {
      findUnique: mockDriftResultFindUnique,
    },
  },
}));

const mockApproveRequest = jest.fn();
const mockRejectRequest = jest.fn();
const mockCancelRequest = jest.fn();
jest.mock('../../../src/services/approvalService', () => ({
  approveRequest: mockApproveRequest,
  rejectRequest: mockRejectRequest,
  cancelRequest: mockCancelRequest,
}));

import approvalsRouter from '../../../src/routes/approvals';

describe('routes/approvals', () => {
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = await TestServer.start(buildTestApp('/api/approvals', approvalsRouter));
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/approvals', () => {
    it('lists approvals enriched with baseline names', async () => {
      mockApprovalRequestCount.mockResolvedValue(1);
      mockApprovalRequestFindMany.mockResolvedValue([
        { id: 'req-1', baselineId: 'bl-1', status: 'PENDING' },
      ]);
      mockConfigBaselineFindMany.mockResolvedValue([
        { id: 'bl-1', name: 'Prod Baseline', provider: 'AWS' },
      ]);

      const res = await server.get('/api/approvals');

      expect(res.status).toBe(200);
      expect(res.body.total).toBe(1);
      expect(res.body.items[0].baseline).toEqual({ id: 'bl-1', name: 'Prod Baseline', provider: 'AWS' });
    });

    it('returns 500 when prisma throws', async () => {
      mockApprovalRequestCount.mockRejectedValue(new Error('db down'));

      const res = await server.get('/api/approvals');

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Failed to list approvals' });
    });
  });

  describe('GET /api/approvals/pending', () => {
    it('returns the pending count', async () => {
      mockApprovalRequestCount.mockResolvedValue(4);

      const res = await server.get('/api/approvals/pending');

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ count: 4 });
    });
  });

  describe('GET /api/approvals/:id', () => {
    it('returns 404 when not found', async () => {
      mockApprovalRequestFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/approvals/missing');

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Not found' });
    });

    it('returns approval with baseline and drift detail', async () => {
      mockApprovalRequestFindUnique.mockResolvedValue({ id: 'req-1', baselineId: 'bl-1', driftId: 'drift-1' });
      mockConfigBaselineFindUnique.mockResolvedValue({ id: 'bl-1', name: 'Prod', provider: 'AWS', targetId: 't-1' });
      mockDriftResultFindUnique.mockResolvedValue({ id: 'drift-1', resourceType: 'S3', resourceName: 'bucket', driftType: 'MODIFIED', severity: 'HIGH' });

      const res = await server.get('/api/approvals/req-1');

      expect(res.status).toBe(200);
      expect(res.body.baseline.name).toBe('Prod');
      expect(res.body.drift.resourceType).toBe('S3');
    });
  });

  describe('POST /api/approvals/:id/approve', () => {
    it('returns 400 when reviewedBy is missing', async () => {
      const res = await server.post('/api/approvals/req-1/approve', {});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'reviewedBy (email) is required' });
      expect(mockApproveRequest).not.toHaveBeenCalled();
    });

    it('approves and returns the service result', async () => {
      mockApproveRequest.mockResolvedValue({ id: 'req-1', status: 'APPROVED' });

      const res = await server.post('/api/approvals/req-1/approve', { reviewedBy: 'admin@example.com' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ id: 'req-1', status: 'APPROVED' });
    });

    it('returns 404 when the service reports not found', async () => {
      mockApproveRequest.mockRejectedValue(new Error('Approval request not found'));

      const res = await server.post('/api/approvals/missing/approve', { reviewedBy: 'admin@example.com' });

      expect(res.status).toBe(404);
    });

    it('returns 422 for other service errors', async () => {
      mockApproveRequest.mockRejectedValue(new Error('Already reviewed'));

      const res = await server.post('/api/approvals/req-1/approve', { reviewedBy: 'admin@example.com' });

      expect(res.status).toBe(422);
    });
  });

  describe('POST /api/approvals/:id/reject', () => {
    it('returns 400 when reviewedBy is missing', async () => {
      const res = await server.post('/api/approvals/req-1/reject', {});

      expect(res.status).toBe(400);
      expect(mockRejectRequest).not.toHaveBeenCalled();
    });

    it('rejects and returns the service result', async () => {
      mockRejectRequest.mockResolvedValue({ id: 'req-1', status: 'REJECTED' });

      const res = await server.post('/api/approvals/req-1/reject', { reviewedBy: 'admin@example.com' });

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('REJECTED');
    });
  });

  describe('DELETE /api/approvals/:id', () => {
    it('cancels the approval request', async () => {
      mockCancelRequest.mockResolvedValue({ id: 'req-1', status: 'CANCELLED' });

      const res = await server.delete('/api/approvals/req-1');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('CANCELLED');
      expect(mockCancelRequest).toHaveBeenCalledWith('req-1', 'unknown');
    });

    it('returns 422 when cancel fails for a non-not-found reason', async () => {
      mockCancelRequest.mockRejectedValue(new Error('Cannot cancel a completed request'));

      const res = await server.delete('/api/approvals/req-1');

      expect(res.status).toBe(422);
    });
  });
});

import { describe, it, expect, beforeAll, afterAll, beforeEach, jest } from '@jest/globals';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

const mockScanFindMany = jest.fn();
const mockFindingGroupBy = jest.fn();
const mockAccountFindMany = jest.fn();
const mockComplianceEvidenceCreate = jest.fn();
const mockComplianceEvidenceDelete = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    scan: { findMany: mockScanFindMany },
    finding: { groupBy: mockFindingGroupBy },
    account: { findMany: mockAccountFindMany },
    complianceEvidence: {
      create: mockComplianceEvidenceCreate,
      delete: mockComplianceEvidenceDelete,
    },
  },
}));

const mockScoreFrameworks = jest.fn();
jest.mock('../../../src/services/complianceService', () => ({
  scoreFrameworks: mockScoreFrameworks,
  FRAMEWORKS: [{ id: 'PCI_DSS', name: 'PCI DSS' }],
}));

const mockCollectEvidenceForAccount = jest.fn();
const mockGetEvidenceForControl = jest.fn();
const mockGetEvidenceSummaryForFramework = jest.fn();
const mockExportEvidencePackage = jest.fn();

jest.mock('../../../src/services/evidenceService', () => ({
  collectEvidenceForAccount: mockCollectEvidenceForAccount,
  getEvidenceForControl: mockGetEvidenceForControl,
  getEvidenceSummaryForFramework: mockGetEvidenceSummaryForFramework,
  exportEvidencePackage: mockExportEvidencePackage,
}));

import router from '../../../src/routes/compliance';

describe('compliance routes', () => {
  let server: TestServer;

  beforeAll(async () => {
    const app = buildTestApp('/api/compliance', router);
    server = await TestServer.start(app);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /', () => {
    it('returns 400 when accountId is missing', async () => {
      const res = await server.get('/api/compliance', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('accountId is required');
    });

    it('returns scored frameworks for the account', async () => {
      mockScanFindMany.mockResolvedValueOnce([{ id: 'scan-1' }]);
      mockFindingGroupBy.mockResolvedValueOnce([
        { title: 'Finding A', checkId: null, _count: { _all: 2 } },
        { title: 'Finding B', checkId: 's3_bucket_x', _count: { _all: 1 } },
      ]);
      mockScoreFrameworks.mockReturnValueOnce([{ frameworkId: 'PCI_DSS', score: 80 }]);

      const res = await server.get('/api/compliance?accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ frameworkId: 'PCI_DSS', score: 80 }]);
    });

    it('returns 500 with the error message when prisma throws', async () => {
      mockScanFindMany.mockRejectedValueOnce(new Error('db error'));

      const res = await server.get('/api/compliance?accountId=acct-1', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('db error');
    });
  });

  describe('GET /all', () => {
    it('returns per-account summaries without control detail', async () => {
      mockAccountFindMany.mockResolvedValueOnce([{ id: 'acct-1', name: 'Acct One', awsAccountId: '111' }]);
      mockScanFindMany.mockResolvedValueOnce([]);
      mockFindingGroupBy.mockResolvedValueOnce([]);
      mockScoreFrameworks.mockReturnValueOnce([{ frameworkId: 'PCI_DSS', score: 100, controls: [{ id: 'c1' }] }]);

      const res = await server.get('/api/compliance/all', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveLength(1);
      expect(res.body.data[0].scores[0]).not.toHaveProperty('controls');
    });
  });

  describe('GET /frameworks', () => {
    it('returns the framework definitions', async () => {
      const res = await server.get('/api/compliance/frameworks', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ id: 'PCI_DSS', name: 'PCI DSS' }]);
    });
  });

  describe('POST /evidence/collect', () => {
    it('returns 400 when accountId or provider are missing', async () => {
      const res = await server.post('/api/compliance/evidence/collect', { accountId: 'acct-1' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('accountId and provider are required');
    });

    it('triggers evidence collection for a valid request', async () => {
      mockCollectEvidenceForAccount.mockResolvedValueOnce({ collected: 3 });

      const res = await server.post(
        '/api/compliance/evidence/collect',
        { accountId: 'acct-1', provider: 'AWS' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ collected: 3 });
    });
  });

  describe('GET /evidence', () => {
    it('returns 400 when frameworkId or controlId are missing', async () => {
      const res = await server.get('/api/compliance/evidence?frameworkId=PCI_DSS', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('frameworkId and controlId are required');
    });

    it('returns evidence for the control', async () => {
      mockGetEvidenceForControl.mockResolvedValueOnce([{ id: 'ev-1' }]);

      const res = await server.get('/api/compliance/evidence?frameworkId=PCI_DSS&controlId=1.1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual([{ id: 'ev-1' }]);
    });
  });

  describe('GET /evidence/summary', () => {
    it('returns 400 when frameworkId is missing', async () => {
      const res = await server.get('/api/compliance/evidence/summary', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('frameworkId is required');
    });

    it('returns the evidence summary', async () => {
      mockGetEvidenceSummaryForFramework.mockResolvedValueOnce({ total: 5 });

      const res = await server.get('/api/compliance/evidence/summary?frameworkId=PCI_DSS', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ total: 5 });
    });
  });

  describe('POST /evidence', () => {
    it('returns 400 when required fields are missing', async () => {
      const res = await server.post('/api/compliance/evidence', { frameworkId: 'PCI_DSS' }, AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('are required');
    });

    it('creates a manual evidence record', async () => {
      mockComplianceEvidenceCreate.mockResolvedValueOnce({ id: 'ev-1' });

      const res = await server.post(
        '/api/compliance/evidence',
        { frameworkId: 'PCI_DSS', controlId: '1.1', provider: 'AWS', summary: 'Manual check', status: 'COMPLIANT' },
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ id: 'ev-1' });
    });
  });

  describe('DELETE /evidence/:id', () => {
    it('deletes the evidence record', async () => {
      mockComplianceEvidenceDelete.mockResolvedValueOnce({ id: 'ev-1' });

      const res = await server.delete('/api/compliance/evidence/ev-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body.data).toEqual({ deleted: true });
    });

    it('returns 500 with the error message when delete fails', async () => {
      mockComplianceEvidenceDelete.mockRejectedValueOnce(new Error('Record to delete does not exist'));

      const res = await server.delete('/api/compliance/evidence/missing-id', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('Record to delete does not exist');
    });
  });

  describe('GET /evidence/export', () => {
    it('returns 400 when required query params are missing', async () => {
      const res = await server.get('/api/compliance/evidence/export?frameworkId=PCI_DSS', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('frameworkId, provider, and accountId are required');
    });

    it('streams the exported evidence bundle as a JSON attachment', async () => {
      mockExportEvidencePackage.mockResolvedValueOnce({ frameworkId: 'PCI_DSS', items: [] });

      const res = await server.get(
        '/api/compliance/evidence/export?frameworkId=PCI_DSS&provider=AWS&accountId=acct-1',
        AUTH_HEADER,
      );

      expect(res.status).toBe(200);
      expect(res.headers['content-disposition']).toContain('attachment');
      expect(res.body.frameworkId).toBe('PCI_DSS');
    });
  });
});

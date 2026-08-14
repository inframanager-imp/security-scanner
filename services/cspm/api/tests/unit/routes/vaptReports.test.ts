import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { Express } from 'express';
import { TestServer, buildTestApp, AUTH_HEADER } from './testHttp';

jest.mock('../../../src/middleware/authenticate', () => ({
  authenticate: (req: any, _res: any, next: any) => {
    req.user = { id: 'test-user-id', role: 'ADMIN' };
    next();
  },
}));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockBuildVaptReportModel = jest.fn();
const mockGetVaptFilterOptions = jest.fn();

jest.mock('../../../src/services/vaptReportService', () => ({
  buildVaptReportModel: mockBuildVaptReportModel,
  getVaptFilterOptions: mockGetVaptFilterOptions,
}));

const mockGenerateVaptReportHtml = jest.fn(() => '<html><body>VAPT report</body></html>');
jest.mock('../../../src/services/vaptReportTemplate', () => ({
  generateVaptReportHtml: mockGenerateVaptReportHtml,
}));

import router from '../../../src/routes/vaptReports';

describe('routes/vaptReports', () => {
  let app: Express;
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockGenerateVaptReportHtml.mockReturnValue('<html><body>VAPT report</body></html>');
    app = buildTestApp('/api/reports', router);
    server = await TestServer.start(app);
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /api/reports/vapt', () => {
    it('returns 400 when provider is missing or invalid', async () => {
      const res = await server.get('/api/reports/vapt?provider=BOGUS&targetId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'provider must be one of AWS, AZURE, GCP' });
      expect(mockBuildVaptReportModel).not.toHaveBeenCalled();
    });

    it('returns 400 when targetId is missing', async () => {
      const res = await server.get('/api/reports/vapt?provider=AWS', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'targetId is required' });
    });

    it('returns the generated HTML report for a valid request', async () => {
      mockBuildVaptReportModel.mockResolvedValueOnce({ accountName: 'Prod' });

      const res = await server.get('/api/reports/vapt?provider=AWS&targetId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toContain('text/html');
      expect(res.text).toBe('<html><body>VAPT report</body></html>');
      expect(mockBuildVaptReportModel).toHaveBeenCalledWith('AWS', 'acc-1', {
        tags: undefined, region: undefined, resourceGroup: undefined,
      });
    });

    it('parses comma-separated filter query params', async () => {
      mockBuildVaptReportModel.mockResolvedValueOnce({ accountName: 'Prod' });

      const res = await server.get(
        '/api/reports/vapt?provider=AWS&targetId=acc-1&tags=pci,soc2&region=us-east-1, eu-west-1',
        AUTH_HEADER
      );

      expect(res.status).toBe(200);
      expect(mockBuildVaptReportModel).toHaveBeenCalledWith('AWS', 'acc-1', {
        tags: ['pci', 'soc2'],
        region: ['us-east-1', 'eu-west-1'],
        resourceGroup: undefined,
      });
    });

    it('returns 404 when the underlying service reports "not found"', async () => {
      mockBuildVaptReportModel.mockRejectedValueOnce(new Error('Account not found'));

      const res = await server.get('/api/reports/vapt?provider=AWS&targetId=missing', AUTH_HEADER);

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'Account not found' });
    });

    it('returns 500 for other errors', async () => {
      mockBuildVaptReportModel.mockRejectedValueOnce(new Error('template render failed'));

      const res = await server.get('/api/reports/vapt?provider=AWS&targetId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'template render failed' });
    });
  });

  describe('GET /api/reports/vapt/filters', () => {
    it('returns 400 when provider is invalid', async () => {
      const res = await server.get('/api/reports/vapt/filters?provider=BOGUS&targetId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(mockGetVaptFilterOptions).not.toHaveBeenCalled();
    });

    it('returns 400 when targetId is missing', async () => {
      const res = await server.get('/api/reports/vapt/filters?provider=AWS', AUTH_HEADER);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'targetId is required' });
    });

    it('returns the available filter options', async () => {
      mockGetVaptFilterOptions.mockResolvedValueOnce({ tags: ['pci'], regions: ['us-east-1'] });

      const res = await server.get('/api/reports/vapt/filters?provider=AWS&targetId=acc-1', AUTH_HEADER);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ data: { tags: ['pci'], regions: ['us-east-1'] } });
    });

    it('returns 404 when the underlying service reports "not found"', async () => {
      mockGetVaptFilterOptions.mockRejectedValueOnce(new Error('Subscription not found'));

      const res = await server.get('/api/reports/vapt/filters?provider=AZURE&targetId=missing', AUTH_HEADER);

      expect(res.status).toBe(404);
    });
  });
});

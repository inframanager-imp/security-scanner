import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../../src/config/redis', () => ({ redis: {} }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockGcpScanUpdate = jest.fn(async () => ({}) as any);
const mockGcpCredentialFindUnique = jest.fn();
const mockGcpProjectFindUnique = jest.fn();
const mockGcpFindingFindMany = jest.fn(async () => [] as any[]);
const mockGcpFindingCreateMany = jest.fn(async () => ({ count: 0 }) as any);
const mockGcpScanSummaryCreate = jest.fn(async () => ({}) as any);

jest.mock('../../../src/config/database', () => ({
  prisma: {
    gcpScan: { update: mockGcpScanUpdate },
    gcpCredential: { findUnique: mockGcpCredentialFindUnique },
    gcpProject: { findUnique: mockGcpProjectFindUnique },
    gcpFinding: { findMany: mockGcpFindingFindMany, createMany: mockGcpFindingCreateMany },
    gcpScanSummary: { create: mockGcpScanSummaryCreate },
  },
}));

jest.mock('../../../src/services/gcpCredentialService', () => ({
  decryptGcpCredentials: jest.fn(() => ({
    serviceAccountKey: JSON.stringify({ type: 'service_account' }),
    serviceAccountEmail: 'sa@proj.iam.gserviceaccount.com',
  })),
}));

const mockEmit = jest.fn();
const mockTo = jest.fn(() => ({ emit: mockEmit }));
jest.mock('../../../src/socket/index', () => ({
  getIO: jest.fn(() => ({ to: mockTo })),
}));

const mockExecuteScan = jest.fn();
jest.mock('../../../../src/gcp/engine', () => ({
  GcpScanEngine: jest.fn().mockImplementation(() => ({ executeScan: mockExecuteScan })),
}));

jest.mock('../../../src/services/riskScoringService', () => ({
  enrichRecentFindings: jest.fn(async () => undefined),
}));
const mockEnqueueGraphBuild = jest.fn(async () => 'graph-job-id');
jest.mock('../../../src/workers/graphBuildWorker', () => ({
  enqueueGraphBuild: mockEnqueueGraphBuild,
}));
const mockEnqueueEvidenceRefresh = jest.fn(async () => 'evidence-job-id');
jest.mock('../../../src/workers/evidenceWorker', () => ({
  enqueueEvidenceRefresh: mockEnqueueEvidenceRefresh,
}));

class FakeQueue {
  add = jest.fn(async () => ({ id: 'fake-job-id' }));
}
class FakeWorker {
  public processor: (...args: any[]) => any;
  constructor(_name: string, processor: (...args: any[]) => any, _opts?: any) {
    this.processor = processor;
  }
  on() {
    return this;
  }
}

jest.mock('bullmq', () => ({
  Queue: FakeQueue,
  Worker: FakeWorker,
}));

import { logger } from '../../../src/config/logger';
import { createGcpScanWorker } from '../../../src/workers/gcpScanWorker';

function buildReport(findings: any[] = []) {
  return {
    findings,
    totalFindings: findings.length,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  };
}

describe('gcpScanWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGcpCredentialFindUnique.mockResolvedValue({ projectId: 'proj-1' } as any);
    mockGcpProjectFindUnique.mockResolvedValue({ projectId: 'gcp-proj-1' } as any);
    mockGcpFindingFindMany.mockResolvedValue([]);
    mockExecuteScan.mockResolvedValue(buildReport());
  });

  describe('createGcpScanWorker (processor wiring)', () => {
    it('marks the scan RUNNING, runs the engine, and marks it COMPLETED on success', async () => {
      mockExecuteScan.mockResolvedValueOnce(buildReport([
        { service: 'storage', title: 'Public bucket', severity: 'HIGH', description: 'd', evidence: { bucket: 'b1' }, remediation: 'r', tags: [], timestamp: new Date() },
      ]));

      const worker = createGcpScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'gcpscan-1', projectId: 'proj-1', services: ['storage'] } });

      expect(mockGcpScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'gcpscan-1' },
        data: expect.objectContaining({ status: 'RUNNING' }),
      }));
      expect(mockGcpFindingCreateMany).toHaveBeenCalledTimes(1);
      expect(mockGcpScanSummaryCreate).toHaveBeenCalledTimes(1);
      expect(mockGcpScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'gcpscan-1' },
        data: expect.objectContaining({ status: 'COMPLETED' }),
      }));
      expect(mockEmit).toHaveBeenCalledWith('gcp-scan:completed', expect.objectContaining({ scanId: 'gcpscan-1' }));
    });

    it('skips findings already tracked as OPEN/ACKNOWLEDGED (dedup by service:title:fingerprint)', async () => {
      mockGcpFindingFindMany.mockResolvedValueOnce([
        { service: 'storage', title: 'Public bucket', evidence: { bucket: 'b1' } },
      ] as any);
      mockExecuteScan.mockResolvedValueOnce(buildReport([
        { service: 'storage', title: 'Public bucket', severity: 'HIGH', description: 'd', evidence: { bucket: 'b1' }, remediation: 'r', tags: [], timestamp: new Date() },
      ]));

      const worker = createGcpScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'gcpscan-1', projectId: 'proj-1', services: ['storage'] } });

      expect(mockGcpFindingCreateMany).not.toHaveBeenCalled();
    });

    it('enqueues graph build and evidence refresh with provider GCP after a successful scan', async () => {
      const worker = createGcpScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'gcpscan-1', projectId: 'proj-1', services: ['storage'] } });

      expect(mockEnqueueGraphBuild).toHaveBeenCalledWith({ provider: 'GCP', accountId: 'proj-1', triggeredBy: 'SCAN' });
      expect(mockEnqueueEvidenceRefresh).toHaveBeenCalledWith({ provider: 'GCP', accountId: 'proj-1', triggeredBy: 'SCAN' });
    });

    it('marks the scan FAILED, emits gcp-scan:failed, and rethrows when no credentials exist', async () => {
      mockGcpCredentialFindUnique.mockResolvedValueOnce(null as any);

      const worker = createGcpScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'gcpscan-2', projectId: 'proj-missing', services: ['storage'] } }),
      ).rejects.toThrow('No GCP credentials configured for this project');

      expect(mockGcpScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'gcpscan-2' },
        data: expect.objectContaining({ status: 'FAILED' }),
      }));
      expect(mockEmit).toHaveBeenCalledWith('gcp-scan:failed', expect.objectContaining({ scanId: 'gcpscan-2' }));
      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('gcpscan-2'), expect.any(Object));
    });

    it('marks the scan FAILED and rethrows when the project record is missing', async () => {
      mockGcpProjectFindUnique.mockResolvedValueOnce(null as any);

      const worker = createGcpScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'gcpscan-3', projectId: 'proj-1', services: ['storage'] } }),
      ).rejects.toThrow('GCP project record not found');
    });

    it('marks the scan FAILED and rethrows when the service account key JSON is invalid', async () => {
      const { decryptGcpCredentials } = jest.requireMock('../../../src/services/gcpCredentialService') as any;
      decryptGcpCredentials.mockReturnValueOnce({ serviceAccountKey: 'not-json' });

      const worker = createGcpScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'gcpscan-4', projectId: 'proj-1', services: ['storage'] } }),
      ).rejects.toThrow('Invalid service account key JSON');
    });

    it('marks the scan FAILED and rethrows when the scan engine itself throws', async () => {
      mockExecuteScan.mockRejectedValueOnce(new Error('googleapis quota exceeded'));

      const worker = createGcpScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'gcpscan-5', projectId: 'proj-1', services: ['storage'] } }),
      ).rejects.toThrow('googleapis quota exceeded');

      expect(mockGcpScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'gcpscan-5' },
        data: expect.objectContaining({ status: 'FAILED', errorMessage: 'googleapis quota exceeded' }),
      }));
    });
  });
});

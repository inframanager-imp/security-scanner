import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../../src/config/redis', () => ({ redis: {} }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockAzureScanUpdate = jest.fn(async () => ({}) as any);
const mockAzureCredentialFindUnique = jest.fn();
const mockAzureSubscriptionFindUnique = jest.fn();
const mockAzureFindingFindMany = jest.fn(async () => [] as any[]);
const mockAzureFindingCreateMany = jest.fn(async () => ({ count: 0 }) as any);
const mockAzureScanSummaryCreate = jest.fn(async () => ({}) as any);

jest.mock('../../../src/config/database', () => ({
  prisma: {
    azureScan: { update: mockAzureScanUpdate },
    azureCredential: { findUnique: mockAzureCredentialFindUnique },
    azureSubscription: { findUnique: mockAzureSubscriptionFindUnique },
    azureFinding: { findMany: mockAzureFindingFindMany, createMany: mockAzureFindingCreateMany },
    azureScanSummary: { create: mockAzureScanSummaryCreate },
  },
}));

jest.mock('../../../src/services/azureCredentialService', () => ({
  decryptAzureCredentials: jest.fn(() => ({
    tenantId: 'tenant-1', clientId: 'client-1', clientSecret: 'secret',
  })),
}));

const mockEmit = jest.fn();
const mockTo = jest.fn(() => ({ emit: mockEmit }));
jest.mock('../../../src/socket/index', () => ({
  getIO: jest.fn(() => ({ to: mockTo })),
}));

const mockExecuteScan = jest.fn();
jest.mock('../../../../src/azure/engine', () => ({
  AzureScanEngine: jest.fn().mockImplementation(() => ({ executeScan: mockExecuteScan })),
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
import { createAzureScanWorker } from '../../../src/workers/azureScanWorker';

function buildReport(findings: any[] = []) {
  return {
    findings,
    totalFindings: findings.length,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  };
}

describe('azureScanWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockAzureCredentialFindUnique.mockResolvedValue({
      subscriptionId: 'sub-1',
      authMethod: 'SERVICE_PRINCIPAL',
    } as any);
    mockAzureSubscriptionFindUnique.mockResolvedValue({ subscriptionId: 'azure-guid-1' } as any);
    mockAzureFindingFindMany.mockResolvedValue([]);
    mockExecuteScan.mockResolvedValue(buildReport());
  });

  describe('createAzureScanWorker (processor wiring)', () => {
    it('marks the scan RUNNING, runs the engine, and marks it COMPLETED on success', async () => {
      mockExecuteScan.mockResolvedValueOnce(buildReport([
        { service: 'keyvault', title: 'Vault without soft-delete', severity: 'MEDIUM', description: 'd', evidence: { vault: 'kv-1' }, remediation: 'r', tags: [], timestamp: new Date() },
      ]));

      const worker = createAzureScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'azscan-1', subscriptionId: 'sub-1', services: ['keyvault'] } });

      expect(mockAzureScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'azscan-1' },
        data: expect.objectContaining({ status: 'RUNNING' }),
      }));
      expect(mockAzureFindingCreateMany).toHaveBeenCalledTimes(1);
      expect(mockAzureScanSummaryCreate).toHaveBeenCalledTimes(1);
      expect(mockAzureScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'azscan-1' },
        data: expect.objectContaining({ status: 'COMPLETED' }),
      }));
      expect(mockEmit).toHaveBeenCalledWith('azure-scan:completed', expect.objectContaining({ scanId: 'azscan-1' }));
    });

    it('skips findings already tracked as OPEN/ACKNOWLEDGED (dedup by service:title:fingerprint)', async () => {
      mockAzureFindingFindMany.mockResolvedValueOnce([
        { service: 'keyvault', title: 'Vault without soft-delete', evidence: { vault: 'kv-1' } },
      ] as any);
      mockExecuteScan.mockResolvedValueOnce(buildReport([
        { service: 'keyvault', title: 'Vault without soft-delete', severity: 'MEDIUM', description: 'd', evidence: { vault: 'kv-1' }, remediation: 'r', tags: [], timestamp: new Date() },
      ]));

      const worker = createAzureScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'azscan-1', subscriptionId: 'sub-1', services: ['keyvault'] } });

      expect(mockAzureFindingCreateMany).not.toHaveBeenCalled();
    });

    it('enqueues graph build and evidence refresh with provider AZURE after a successful scan', async () => {
      const worker = createAzureScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'azscan-1', subscriptionId: 'sub-1', services: ['keyvault'] } });

      expect(mockEnqueueGraphBuild).toHaveBeenCalledWith({ provider: 'AZURE', accountId: 'sub-1', triggeredBy: 'SCAN' });
      expect(mockEnqueueEvidenceRefresh).toHaveBeenCalledWith({ provider: 'AZURE', accountId: 'sub-1', triggeredBy: 'SCAN' });
    });

    it('marks the scan FAILED, emits azure-scan:failed, and rethrows when no credentials exist', async () => {
      mockAzureCredentialFindUnique.mockResolvedValueOnce(null as any);

      const worker = createAzureScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'azscan-2', subscriptionId: 'sub-missing', services: ['keyvault'] } }),
      ).rejects.toThrow('No Azure credentials configured for this subscription');

      expect(mockAzureScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'azscan-2' },
        data: expect.objectContaining({ status: 'FAILED' }),
      }));
      expect(mockEmit).toHaveBeenCalledWith('azure-scan:failed', expect.objectContaining({ scanId: 'azscan-2' }));
      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('azscan-2'), expect.any(Object));
    });

    it('marks the scan FAILED and rethrows when the subscription record is missing', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValueOnce(null as any);

      const worker = createAzureScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'azscan-3', subscriptionId: 'sub-1', services: ['keyvault'] } }),
      ).rejects.toThrow('Azure subscription record not found');
    });

    it('marks the scan FAILED and rethrows when the scan engine itself throws', async () => {
      mockExecuteScan.mockRejectedValueOnce(new Error('ARM throttled'));

      const worker = createAzureScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'azscan-4', subscriptionId: 'sub-1', services: ['keyvault'] } }),
      ).rejects.toThrow('ARM throttled');

      expect(mockAzureScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'azscan-4' },
        data: expect.objectContaining({ status: 'FAILED', errorMessage: 'ARM throttled' }),
      }));
    });
  });
});

import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../../src/config/redis', () => ({ redis: {} }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockAzureFindingFindFirst = jest.fn(async () => null as any);
const mockAzureFindingCreateMany = jest.fn(async () => ({ count: 0 }) as any);
const mockAzureScanFindFirst = jest.fn(async () => null as any);
const mockAzureScanCreate = jest.fn(async () => ({ id: 'monitor-scan-1' }) as any);
const mockAzureCredentialFindUnique = jest.fn();
const mockAzureSubscriptionFindUnique = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    azureCredential: { findUnique: mockAzureCredentialFindUnique },
    azureSubscription: { findUnique: mockAzureSubscriptionFindUnique },
    azureFinding: { findFirst: mockAzureFindingFindFirst, createMany: mockAzureFindingCreateMany },
    azureScan: { findFirst: mockAzureScanFindFirst, create: mockAzureScanCreate },
  },
}));

jest.mock('../../../src/services/azureCredentialService', () => ({
  decryptAzureCredentials: jest.fn(() => ({
    tenantId: 'tenant-1', clientId: 'client-1', clientSecret: 'secret',
  })),
}));

const mockGetAzureLastCheck = jest.fn(async () => new Date('2024-01-01T00:00:00.000Z'));
const mockSetAzureLastCheck = jest.fn(async () => undefined);
const mockMarkAzureEventSeen = jest.fn(async () => true);

jest.mock('../../../src/services/azureThreatMonitorService', () => ({
  AZURE_THREAT_QUEUE: 'azure-threat-monitoring',
  getAzureLastCheck: mockGetAzureLastCheck,
  setAzureLastCheck: mockSetAzureLastCheck,
  markAzureEventSeen: mockMarkAzureEventSeen,
}));

const mockEmit = jest.fn();
const mockTo = jest.fn(() => ({ emit: mockEmit }));
jest.mock('../../../src/socket/index', () => ({
  getIO: jest.fn(() => ({ to: mockTo })),
}));

jest.mock('../../../src/services/anomalyEngine', () => ({
  analyzeEvent: jest.fn(async () => []),
  normalizeAzureEvent: jest.fn((e: any) => e),
}));

jest.mock('../../../../src/azure/client', () => {
  return jest.fn().mockImplementation(() => ({}));
});

const mockScanSince = jest.fn(async () => [] as any[]);
const mockGetRawEvents = jest.fn(async () => [] as any[]);

jest.mock('../../../../src/azure/scanners/threatScanner', () => ({
  AzureThreatScanner: jest.fn().mockImplementation(() => ({
    scanSince: mockScanSince,
    getRawEvents: mockGetRawEvents,
  })),
}));

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
  Worker: FakeWorker,
}));

import { logger } from '../../../src/config/logger';
import { createAzureThreatMonitorWorker } from '../../../src/workers/azureThreatMonitorWorker';

describe('azureThreatMonitorWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockAzureCredentialFindUnique.mockResolvedValue({
      subscriptionId: 'sub-1',
      authMethod: 'SERVICE_PRINCIPAL',
    } as any);
    mockAzureSubscriptionFindUnique.mockResolvedValue({ subscriptionId: 'azure-guid-1' } as any);
    mockGetAzureLastCheck.mockResolvedValue(new Date('2024-01-01T00:00:00.000Z'));
    mockScanSince.mockResolvedValue([]);
    mockGetRawEvents.mockResolvedValue([]);
  });

  describe('createAzureThreatMonitorWorker (processor wiring)', () => {
    it('exits early without error when no credentials are configured', async () => {
      mockAzureCredentialFindUnique.mockResolvedValueOnce(null as any);

      const worker = createAzureThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { subscriptionId: 'sub-missing' } });

      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('sub-missing'));
      expect(mockScanSince).not.toHaveBeenCalled();
    });

    it('exits early when the subscription record is not found', async () => {
      mockAzureSubscriptionFindUnique.mockResolvedValueOnce(null as any);

      const worker = createAzureThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { subscriptionId: 'sub-1' } });

      expect(mockScanSince).not.toHaveBeenCalled();
    });

    it('scans since lastCheck, persists new findings, and emits azure-threat:detected + heartbeat', async () => {
      mockScanSince.mockResolvedValueOnce([
        {
          service: 'nsg', title: 'Open NSG rule detected', severity: 'HIGH',
          evidence: { resourceId: 'nsg-1', eventCorrelationId: 'corr-1' },
          description: 'd', remediation: 'r', tags: [],
        },
      ] as any);

      const worker = createAzureThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { subscriptionId: 'sub-1' } });

      expect(mockAzureFindingCreateMany).toHaveBeenCalledTimes(1);
      const createArgs = mockAzureFindingCreateMany.mock.calls[0][0] as any;
      expect(createArgs.data[0].title).toBe('Open NSG rule detected');

      expect(mockTo).toHaveBeenCalledWith('azure-threats:sub-1');
      expect(mockEmit).toHaveBeenCalledWith('azure-threat:detected', expect.objectContaining({ subscriptionId: 'sub-1' }));
      expect(mockSetAzureLastCheck).toHaveBeenCalledWith('sub-1', expect.any(Date));
    });

    it('skips findings whose correlation id was already seen (dedup)', async () => {
      mockMarkAzureEventSeen.mockResolvedValueOnce(false);
      mockScanSince.mockResolvedValueOnce([
        {
          service: 'nsg', title: 'Dup event', severity: 'MEDIUM',
          evidence: { eventCorrelationId: 'corr-dup' }, description: 'd', remediation: 'r', tags: [],
        },
      ] as any);

      const worker = createAzureThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { subscriptionId: 'sub-1' } });

      expect(mockAzureFindingCreateMany).not.toHaveBeenCalled();
      expect(mockEmit).toHaveBeenCalledWith('azure-threat:heartbeat', expect.objectContaining({ newThreats: 0 }));
    });

    it('swallows errors and logs rather than throwing, so the repeatable job keeps running', async () => {
      mockScanSince.mockRejectedValueOnce(new Error('activity log api error'));

      const worker = createAzureThreatMonitorWorker() as unknown as FakeWorker;
      await expect(worker.processor({ data: { subscriptionId: 'sub-1' } })).resolves.toBeUndefined();

      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('sub-1'),
        expect.objectContaining({ error: 'activity log api error' }),
      );
    });
  });
});

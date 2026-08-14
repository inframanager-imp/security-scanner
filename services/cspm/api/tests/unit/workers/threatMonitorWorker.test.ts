import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../../src/config/redis', () => ({ redis: {} }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockFindingFindFirst = jest.fn(async () => null as any);
const mockFindingCreateMany = jest.fn(async () => ({ count: 0 }) as any);
const mockScanFindFirst = jest.fn(async () => null as any);
const mockScanCreate = jest.fn(async () => ({ id: 'monitor-scan-1' }) as any);
const mockAwsCredentialFindUnique = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    awsCredential: { findUnique: mockAwsCredentialFindUnique },
    finding: { findFirst: mockFindingFindFirst, createMany: mockFindingCreateMany },
    scan: { findFirst: mockScanFindFirst, create: mockScanCreate },
  },
}));

jest.mock('../../../src/services/credentialService', () => ({
  decryptCredentials: jest.fn(() => ({ accessKeyId: 'AKIA...', secretAccessKey: 'secret' })),
}));

const mockGetLastCheck = jest.fn(async () => new Date('2024-01-01T00:00:00.000Z'));
const mockSetLastCheck = jest.fn(async () => undefined);
const mockMarkEventSeen = jest.fn(async () => true);

jest.mock('../../../src/services/threatMonitorService', () => ({
  THREAT_QUEUE: 'threat-monitoring',
  getLastCheck: mockGetLastCheck,
  setLastCheck: mockSetLastCheck,
  markEventSeen: mockMarkEventSeen,
}));

const mockEmit = jest.fn();
const mockTo = jest.fn(() => ({ emit: mockEmit }));
jest.mock('../../../src/socket/index', () => ({
  getIO: jest.fn(() => ({ to: mockTo })),
}));

jest.mock('../../../src/services/anomalyEngine', () => ({
  analyzeEvent: jest.fn(async () => []),
  normalizeAwsEvent: jest.fn((e: any) => e),
}));

const mockScanSince = jest.fn(async () => [] as any[]);
const mockGetRawEvents = jest.fn(async () => [] as any[]);
const mockAwsClientCleanup = jest.fn(async () => undefined);

jest.mock('../../../../src/aws/client', () => {
  return jest.fn().mockImplementation(() => ({
    cleanup: mockAwsClientCleanup,
  }));
});

jest.mock('../../../../src/scanners/threatdetection', () => ({
  ThreatDetectionScanner: jest.fn().mockImplementation(() => ({
    scanSince: mockScanSince,
    getRawEvents: mockGetRawEvents,
  })),
}));

jest.mock('@aws-sdk/client-sts', () => ({
  STSClient: jest.fn().mockImplementation(() => ({ send: jest.fn() })),
  AssumeRoleCommand: jest.fn(),
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
import { createThreatMonitorWorker } from '../../../src/workers/threatMonitorWorker';

describe('threatMonitorWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockAwsCredentialFindUnique.mockResolvedValue({
      accountId: 'acct-1',
      authMethod: 'ACCESS_KEY',
      defaultRegion: 'us-east-1',
      roleArn: null,
      externalId: null,
    } as any);
    mockGetLastCheck.mockResolvedValue(new Date('2024-01-01T00:00:00.000Z'));
    mockScanSince.mockResolvedValue([]);
    mockGetRawEvents.mockResolvedValue([]);
  });

  describe('createThreatMonitorWorker (processor wiring)', () => {
    it('exits early and logs a warning when no credentials are configured', async () => {
      mockAwsCredentialFindUnique.mockResolvedValueOnce(null as any);

      const worker = createThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { accountId: 'acct-missing' } });

      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('acct-missing'));
      expect(mockScanSince).not.toHaveBeenCalled();
    });

    it('scans since lastCheck, persists new findings, and emits threat:detected + heartbeat', async () => {
      mockScanSince.mockResolvedValueOnce([
        { _eventId: 'evt-1', service: 'iam', title: 'Root login detected', severity: 'CRITICAL', evidence: { resourceId: 'root' }, description: 'd', remediation: 'r', tags: [] },
      ] as any);

      const worker = createThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { accountId: 'acct-1' } });

      expect(mockFindingCreateMany).toHaveBeenCalledTimes(1);
      const createArgs = mockFindingCreateMany.mock.calls[0][0] as any;
      expect(createArgs.data).toHaveLength(1);
      expect(createArgs.data[0].title).toBe('Root login detected');

      expect(mockTo).toHaveBeenCalledWith('threats:acct-1');
      expect(mockEmit).toHaveBeenCalledWith('threat:detected', expect.objectContaining({ accountId: 'acct-1' }));
      expect(mockTo).toHaveBeenCalledWith('threats:all');
      expect(mockSetLastCheck).toHaveBeenCalledWith('acct-1', expect.any(Date));
      expect(mockAwsClientCleanup).toHaveBeenCalled();
    });

    it('skips findings whose eventId was already seen (dedup)', async () => {
      mockMarkEventSeen.mockResolvedValueOnce(false); // already seen
      mockScanSince.mockResolvedValueOnce([
        { _eventId: 'evt-dup', service: 'iam', title: 'Dup event', severity: 'HIGH', evidence: {}, description: 'd', remediation: 'r', tags: [] },
      ] as any);

      const worker = createThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { accountId: 'acct-1' } });

      expect(mockFindingCreateMany).not.toHaveBeenCalled();
      // still emits a heartbeat with 0 new threats
      expect(mockEmit).toHaveBeenCalledWith('threat:heartbeat', expect.objectContaining({ newThreats: 0 }));
    });

    it('emits only a heartbeat when the scan finds nothing new', async () => {
      mockScanSince.mockResolvedValueOnce([]);

      const worker = createThreatMonitorWorker() as unknown as FakeWorker;
      await worker.processor({ data: { accountId: 'acct-1' } });

      expect(mockEmit).toHaveBeenCalledWith('threat:heartbeat', expect.objectContaining({ newThreats: 0 }));
      expect(mockFindingCreateMany).not.toHaveBeenCalled();
      expect(mockSetLastCheck).toHaveBeenCalledWith('acct-1', expect.any(Date));
    });

    it('swallows errors and logs rather than throwing, so the repeatable job keeps running', async () => {
      mockScanSince.mockRejectedValueOnce(new Error('cloudtrail throttled'));

      const worker = createThreatMonitorWorker() as unknown as FakeWorker;
      await expect(worker.processor({ data: { accountId: 'acct-1' } })).resolves.toBeUndefined();

      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('acct-1'),
        expect.objectContaining({ error: 'cloudtrail throttled' }),
      );
    });
  });
});

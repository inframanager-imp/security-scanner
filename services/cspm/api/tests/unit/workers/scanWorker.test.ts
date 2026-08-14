import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../../src/config/redis', () => ({ redis: {} }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockScanUpdate = jest.fn(async () => ({}) as any);
const mockAwsCredentialFindUnique = jest.fn();
const mockScanFindFirst = jest.fn(async () => null as any);
const mockFindingFindMany = jest.fn(async () => [] as any[]);
const mockFindingCreateMany = jest.fn(async () => ({ count: 0 }) as any);
const mockScanSummaryCreate = jest.fn(async () => ({}) as any);

jest.mock('../../../src/config/database', () => ({
  prisma: {
    scan: { update: mockScanUpdate, findFirst: mockScanFindFirst },
    awsCredential: { findUnique: mockAwsCredentialFindUnique },
    finding: { findMany: mockFindingFindMany, createMany: mockFindingCreateMany },
    scanSummary: { create: mockScanSummaryCreate },
  },
}));

jest.mock('../../../src/services/credentialService', () => ({
  decryptCredentials: jest.fn(() => ({ accessKeyId: 'AKIA...', secretAccessKey: 'secret' })),
}));

// dedupKey is pure logic already unit-tested elsewhere; give scanWorker a
// simple deterministic stand-in here so we can assert on the dedup *wiring*
// (which findings get inserted) without re-testing dedupService itself.
jest.mock('../../../src/services/dedupService', () => ({
  dedupKey: jest.fn((service: string, title: string) => `${service}:${title}`),
}));

const mockEmit = jest.fn();
const mockTo = jest.fn(() => ({ emit: mockEmit }));
jest.mock('../../../src/socket/index', () => ({
  getIO: jest.fn(() => ({ to: mockTo })),
}));

const mockExecuteScan = jest.fn();
jest.mock('../../../../src/scanners/engine', () => ({
  ScanEngine: jest.fn().mockImplementation(() => ({ executeScan: mockExecuteScan })),
}));

jest.mock('@aws-sdk/client-sts', () => ({
  STSClient: jest.fn().mockImplementation(() => ({
    send: jest.fn(async () => ({
      Credentials: {
        AccessKeyId: 'ASIA...',
        SecretAccessKey: 'assumed-secret',
        SessionToken: 'assumed-token',
      },
    })),
  })),
  AssumeRoleCommand: jest.fn(),
}));

// Lazily-imported modules inside processScanJob — mocked so the dynamic
// import() calls resolve without pulling in real service code.
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

import { prisma } from '../../../src/config/database';
import { logger } from '../../../src/config/logger';
import { createScanWorker } from '../../../src/workers/scanWorker';

function buildReport(findings: any[] = []) {
  return {
    findings,
    totalFindings: findings.length,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  };
}

describe('scanWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockAwsCredentialFindUnique.mockResolvedValue({
      accountId: 'acct-1',
      authMethod: 'ACCESS_KEY',
      defaultRegion: 'us-east-1',
      roleArn: null,
      externalId: null,
    } as any);
    mockScanFindFirst.mockResolvedValue(null as any);
    mockFindingFindMany.mockResolvedValue([]);
    mockExecuteScan.mockResolvedValue(buildReport());
  });

  describe('createScanWorker (processor wiring)', () => {
    it('marks the scan RUNNING, runs the engine, and marks it COMPLETED on success', async () => {
      mockExecuteScan.mockResolvedValueOnce(buildReport([
        { service: 's3', title: 'Public bucket', checkId: 's3_bucket_public', severity: 'HIGH', description: 'd', evidence: {}, remediation: 'r', tags: [], timestamp: new Date() },
      ]));

      const worker = createScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'scan-1', accountId: 'acct-1', services: ['s3'], regions: ['us-east-1'] } });

      expect(mockScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'scan-1' },
        data: expect.objectContaining({ status: 'RUNNING' }),
      }));
      expect(mockExecuteScan).toHaveBeenCalledTimes(1);
      expect(mockFindingCreateMany).toHaveBeenCalledTimes(1);
      expect(mockScanSummaryCreate).toHaveBeenCalledTimes(1);
      expect(mockScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'scan-1' },
        data: expect.objectContaining({ status: 'COMPLETED' }),
      }));
      expect(mockEmit).toHaveBeenCalledWith('scan:completed', expect.objectContaining({ scanId: 'scan-1' }));
    });

    it('skips findings already tracked as OPEN/ACKNOWLEDGED (dedup against DB)', async () => {
      mockFindingFindMany.mockResolvedValueOnce([
        { service: 's3', title: 'Public bucket', checkId: 's3_bucket_public', evidence: {} },
      ] as any);
      mockExecuteScan.mockResolvedValueOnce(buildReport([
        { service: 's3', title: 'Public bucket', checkId: 's3_bucket_public', severity: 'HIGH', description: 'd', evidence: {}, remediation: 'r', tags: [], timestamp: new Date() },
      ]));

      const worker = createScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'scan-1', accountId: 'acct-1', services: ['s3'], regions: ['us-east-1'] } });

      expect(mockFindingCreateMany).not.toHaveBeenCalled();
    });

    it('deduplicates two identical findings within the same scan batch', async () => {
      mockExecuteScan.mockResolvedValueOnce(buildReport([
        { service: 's3', title: 'Public bucket', checkId: 's3_bucket_public', severity: 'HIGH', description: 'd', evidence: {}, remediation: 'r', tags: [], timestamp: new Date() },
        { service: 's3', title: 'Public bucket', checkId: 's3_bucket_public', severity: 'HIGH', description: 'd', evidence: {}, remediation: 'r', tags: [], timestamp: new Date() },
      ]));

      const worker = createScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'scan-1', accountId: 'acct-1', services: ['s3'], regions: ['us-east-1'] } });

      const createArgs = mockFindingCreateMany.mock.calls[0][0] as any;
      expect(createArgs.data).toHaveLength(1);
    });

    it('assumes role via STS when authMethod is ASSUME_ROLE and passes temp credentials to the engine', async () => {
      mockAwsCredentialFindUnique.mockResolvedValueOnce({
        accountId: 'acct-2',
        authMethod: 'ASSUME_ROLE',
        defaultRegion: 'us-west-2',
        roleArn: 'arn:aws:iam::123:role/scan-role',
        externalId: 'ext-1',
      } as any);

      const worker = createScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'scan-2', accountId: 'acct-2', services: ['ec2'], regions: ['us-west-2'] } });

      expect(mockExecuteScan).toHaveBeenCalledWith(expect.objectContaining({
        _explicitCredentials: expect.objectContaining({
          accessKeyId: 'ASIA...',
          secretAccessKey: 'assumed-secret',
          sessionToken: 'assumed-token',
        }),
      }));
    });

    it('enqueues graph build and evidence refresh after a successful scan', async () => {
      const worker = createScanWorker() as unknown as FakeWorker;
      await worker.processor({ data: { scanId: 'scan-1', accountId: 'acct-1', services: ['s3'], regions: ['us-east-1'] } });

      expect(mockEnqueueGraphBuild).toHaveBeenCalledWith({ provider: 'AWS', accountId: 'acct-1', triggeredBy: 'SCAN' });
      expect(mockEnqueueEvidenceRefresh).toHaveBeenCalledWith({ provider: 'AWS', accountId: 'acct-1', triggeredBy: 'SCAN' });
    });

    it('marks the scan FAILED, emits scan:failed, and rethrows when no credentials exist', async () => {
      mockAwsCredentialFindUnique.mockResolvedValueOnce(null as any);

      const worker = createScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'scan-3', accountId: 'acct-3', services: ['s3'], regions: ['us-east-1'] } }),
      ).rejects.toThrow('No credentials configured for this account');

      expect(mockScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'scan-3' },
        data: expect.objectContaining({ status: 'FAILED', errorMessage: 'No credentials configured for this account' }),
      }));
      expect(mockEmit).toHaveBeenCalledWith('scan:failed', expect.objectContaining({ scanId: 'scan-3' }));
      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('scan-3'), expect.any(Object));
    });

    it('marks the scan FAILED and rethrows when the scan engine itself throws', async () => {
      mockExecuteScan.mockRejectedValueOnce(new Error('engine crashed'));

      const worker = createScanWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { scanId: 'scan-4', accountId: 'acct-1', services: ['s3'], regions: ['us-east-1'] } }),
      ).rejects.toThrow('engine crashed');

      expect(mockScanUpdate).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'scan-4' },
        data: expect.objectContaining({ status: 'FAILED', errorMessage: 'engine crashed' }),
      }));
    });
  });
});

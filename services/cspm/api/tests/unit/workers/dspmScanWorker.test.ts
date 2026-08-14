import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../../src/config/redis', () => ({ redis: {} }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockAdd = jest.fn(async () => ({ id: 'fake-job-id' }));

class FakeQueue {
  add = mockAdd;
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

jest.mock('../../../src/services/dspmService', () => ({
  runDspmScanForAccount: jest.fn(),
}));

import { logger } from '../../../src/config/logger';
import { runDspmScanForAccount } from '../../../src/services/dspmService';
import {
  enqueueDspmScan,
  createDspmWorker,
  DSPM_QUEUE,
} from '../../../src/workers/dspmScanWorker';

describe('dspmScanWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('enqueueDspmScan', () => {
    it('adds a dspm-scan job with the given data and single-attempt options', async () => {
      const data = { provider: 'AWS' as const, accountId: 'acct-1', triggeredBy: 'SCHEDULED' as const };
      await enqueueDspmScan(data);

      expect(mockAdd).toHaveBeenCalledTimes(1);
      const [jobName, jobData, opts] = mockAdd.mock.calls[0];
      expect(jobName).toBe('dspm-scan');
      expect(jobData).toEqual(data);
      expect((opts as any).attempts).toBe(1);
      expect((opts as any).jobId).toContain('AWS');
      expect((opts as any).jobId).toContain('acct-1');
    });

    it('returns the BullMQ-assigned job id when present', async () => {
      const id = await enqueueDspmScan({ provider: 'GCP', accountId: 'acct-2' });
      expect(id).toBe('fake-job-id');
    });

    it('falls back to the computed jobId when the queue returns no id', async () => {
      mockAdd.mockResolvedValueOnce({ id: undefined } as any);
      const id = await enqueueDspmScan({ provider: 'AZURE', accountId: 'acct-3' });
      expect(id).toContain('AZURE');
      expect(id).toContain('acct-3');
    });
  });

  describe('createDspmWorker (processor wiring)', () => {
    it('calls runDspmScanForAccount with the job data on success', async () => {
      (runDspmScanForAccount as jest.Mock).mockResolvedValueOnce({ scannedBuckets: 2 } as any);

      const worker = createDspmWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1', triggeredBy: 'SCHEDULED' } };

      await worker.processor(job);

      expect(runDspmScanForAccount).toHaveBeenCalledWith('AWS', 'acct-1');
      expect(logger.info).toHaveBeenCalledWith('dspmWorker.start', expect.objectContaining({ accountId: 'acct-1' }));
      expect(logger.info).toHaveBeenCalledWith('dspmWorker.done', expect.objectContaining({ accountId: 'acct-1' }));
    });

    it('logs and rethrows when runDspmScanForAccount fails', async () => {
      const err = new Error('sampling failed');
      (runDspmScanForAccount as jest.Mock).mockRejectedValueOnce(err);

      const worker = createDspmWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1' } };

      await expect(worker.processor(job)).rejects.toThrow('sampling failed');
      expect(logger.error).toHaveBeenCalledWith(
        'dspmWorker.failed',
        expect.objectContaining({ accountId: 'acct-1', error: 'sampling failed' }),
      );
    });

    it('constructs the underlying Worker against the dspm-scans queue name', () => {
      const worker = createDspmWorker() as unknown as FakeWorker;
      expect(worker).toBeTruthy();
      expect(DSPM_QUEUE).toBe('dspm-scans');
    });
  });
});

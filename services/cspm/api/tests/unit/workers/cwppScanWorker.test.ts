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

jest.mock('../../../src/services/cwppService', () => ({
  runCwppScanForAccount: jest.fn(),
}));

import { logger } from '../../../src/config/logger';
import { runCwppScanForAccount } from '../../../src/services/cwppService';
import {
  enqueueCwppScan,
  createCwppWorker,
  CWPP_QUEUE,
} from '../../../src/workers/cwppScanWorker';

describe('cwppScanWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('enqueueCwppScan', () => {
    it('adds a cwpp-scan job with the given data and single-attempt options', async () => {
      const data = { provider: 'AWS' as const, accountId: 'acct-1', triggeredBy: 'MANUAL' as const };
      await enqueueCwppScan(data);

      expect(mockAdd).toHaveBeenCalledTimes(1);
      const [jobName, jobData, opts] = mockAdd.mock.calls[0];
      expect(jobName).toBe('cwpp-scan');
      expect(jobData).toEqual(data);
      expect((opts as any).attempts).toBe(1);
      expect((opts as any).jobId).toContain('AWS');
      expect((opts as any).jobId).toContain('acct-1');
    });

    it('returns the BullMQ-assigned job id when present', async () => {
      const id = await enqueueCwppScan({ provider: 'GCP', accountId: 'acct-2' });
      expect(id).toBe('fake-job-id');
    });

    it('falls back to the computed jobId when the queue returns no id', async () => {
      mockAdd.mockResolvedValueOnce({ id: undefined } as any);
      const id = await enqueueCwppScan({ provider: 'AZURE', accountId: 'acct-3' });
      expect(id).toContain('AZURE');
      expect(id).toContain('acct-3');
    });
  });

  describe('createCwppWorker (processor wiring)', () => {
    it('calls runCwppScanForAccount with the job data on success', async () => {
      (runCwppScanForAccount as jest.Mock).mockResolvedValueOnce({ scanned: 5 } as any);

      const worker = createCwppWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1', triggeredBy: 'MANUAL' } };

      await worker.processor(job);

      expect(runCwppScanForAccount).toHaveBeenCalledWith('AWS', 'acct-1');
      expect(logger.info).toHaveBeenCalledWith('cwppWorker.start', expect.objectContaining({ accountId: 'acct-1' }));
      expect(logger.info).toHaveBeenCalledWith('cwppWorker.done', expect.objectContaining({ accountId: 'acct-1' }));
    });

    it('logs and rethrows when runCwppScanForAccount fails', async () => {
      const err = new Error('scan engine crashed');
      (runCwppScanForAccount as jest.Mock).mockRejectedValueOnce(err);

      const worker = createCwppWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1' } };

      await expect(worker.processor(job)).rejects.toThrow('scan engine crashed');
      expect(logger.error).toHaveBeenCalledWith(
        'cwppWorker.failed',
        expect.objectContaining({ accountId: 'acct-1', error: 'scan engine crashed' }),
      );
    });

    it('constructs the underlying Worker against the cwpp-scans queue name', () => {
      const worker = createCwppWorker() as unknown as FakeWorker;
      expect(worker).toBeTruthy();
      expect(CWPP_QUEUE).toBe('cwpp-scans');
    });
  });
});

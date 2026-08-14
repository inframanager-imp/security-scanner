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
  private handlers: Record<string, (...args: any[]) => any> = {};
  constructor(_name: string, processor: (...args: any[]) => any, _opts?: any) {
    this.processor = processor;
  }
  on(event: string, handler: (...args: any[]) => any) {
    this.handlers[event] = handler;
    return this;
  }
}

jest.mock('bullmq', () => ({
  Queue: FakeQueue,
  Worker: FakeWorker,
}));

jest.mock('../../../src/services/evidenceService', () => ({
  collectEvidenceForAccount: jest.fn(),
}));

import { logger } from '../../../src/config/logger';
import { collectEvidenceForAccount } from '../../../src/services/evidenceService';
import {
  enqueueEvidenceRefresh,
  createEvidenceWorker,
  EVIDENCE_QUEUE,
} from '../../../src/workers/evidenceWorker';

describe('evidenceWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('enqueueEvidenceRefresh', () => {
    it('adds a refresh-evidence job to the evidence-refresh queue with the given data', async () => {
      const data = { provider: 'AWS' as const, accountId: 'acct-1', frameworkId: 'cis-1.4' };
      await enqueueEvidenceRefresh(data);

      expect(mockAdd).toHaveBeenCalledTimes(1);
      const [jobName, jobData, opts] = mockAdd.mock.calls[0];
      expect(jobName).toBe('refresh-evidence');
      expect(jobData).toEqual(data);
      expect((opts as any).attempts).toBe(2);
      expect((opts as any).jobId).toContain('AWS');
      expect((opts as any).jobId).toContain('acct-1');
      expect((opts as any).jobId).toContain('cis-1.4');
    });

    it('returns the BullMQ-assigned job id when present', async () => {
      const id = await enqueueEvidenceRefresh({ provider: 'AZURE', accountId: 'acct-2' });
      expect(id).toBe('fake-job-id');
    });

    it('falls back to the computed jobId when the queue returns no id', async () => {
      mockAdd.mockResolvedValueOnce({ id: undefined } as any);
      const id = await enqueueEvidenceRefresh({ provider: 'GCP', accountId: 'acct-3' });
      expect(id).toContain('GCP');
      expect(id).toContain('acct-3');
    });
  });

  describe('createEvidenceWorker (processor wiring)', () => {
    it('calls collectEvidenceForAccount with the job data on success', async () => {
      (collectEvidenceForAccount as jest.Mock).mockResolvedValueOnce({ passing: 3, failing: 1 } as any);

      const worker = createEvidenceWorker() as unknown as FakeWorker;
      const job = {
        data: { provider: 'AWS', accountId: 'acct-1', frameworkId: 'cis-1.4', triggeredBy: 'SCAN' },
      };

      await worker.processor(job);

      expect(collectEvidenceForAccount).toHaveBeenCalledWith('acct-1', 'AWS', 'cis-1.4');
      expect(logger.info).toHaveBeenCalledWith('evidenceWorker.start', expect.objectContaining({ accountId: 'acct-1' }));
      expect(logger.info).toHaveBeenCalledWith('evidenceWorker.done', expect.objectContaining({ accountId: 'acct-1' }));
    });

    it('logs and rethrows when collectEvidenceForAccount fails', async () => {
      const err = new Error('db unavailable');
      (collectEvidenceForAccount as jest.Mock).mockRejectedValueOnce(err);

      const worker = createEvidenceWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1' } };

      await expect(worker.processor(job)).rejects.toThrow('db unavailable');
      expect(logger.error).toHaveBeenCalledWith(
        'evidenceWorker.failed',
        expect.objectContaining({ accountId: 'acct-1', error: 'db unavailable' }),
      );
    });

    it('constructs the underlying Worker against the evidence-refresh queue name', () => {
      const worker = createEvidenceWorker() as unknown as FakeWorker;
      expect(worker).toBeTruthy();
      expect(EVIDENCE_QUEUE).toBe('evidence-refresh');
    });
  });
});

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

jest.mock('../../../src/services/graphEnrichmentService', () => ({
  buildGraphForAccount: jest.fn(),
}));

// ciemService is lazy-imported inside the processor via a dynamic import();
// it may not exist yet in this codebase (Phase 2), so mock it via
// virtual:true and let individual tests decide whether it resolves or throws.
jest.mock(
  '../../../src/services/ciemService',
  () => ({ runCiemPassForAccount: jest.fn() }),
  { virtual: true },
);

import { logger } from '../../../src/config/logger';
import { buildGraphForAccount } from '../../../src/services/graphEnrichmentService';
import { runCiemPassForAccount } from '../../../src/services/ciemService';
import {
  enqueueGraphBuild,
  createGraphBuildWorker,
  GRAPH_BUILD_QUEUE,
} from '../../../src/workers/graphBuildWorker';

describe('graphBuildWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('enqueueGraphBuild', () => {
    it('adds a build-graph job with the given data and a 2-attempt exponential backoff', async () => {
      const data = { provider: 'AWS' as const, accountId: 'acct-1', triggeredBy: 'SCAN' as const };
      await enqueueGraphBuild(data);

      expect(mockAdd).toHaveBeenCalledTimes(1);
      const [jobName, jobData, opts] = mockAdd.mock.calls[0];
      expect(jobName).toBe('build-graph');
      expect(jobData).toEqual(data);
      expect((opts as any).attempts).toBe(2);
      expect((opts as any).backoff).toEqual({ type: 'exponential', delay: 5000 });
      expect((opts as any).jobId).toContain('AWS');
      expect((opts as any).jobId).toContain('acct-1');
    });

    it('returns the BullMQ-assigned job id when present', async () => {
      const id = await enqueueGraphBuild({ provider: 'GCP', accountId: 'acct-2' });
      expect(id).toBe('fake-job-id');
    });

    it('falls back to the computed jobId when the queue returns no id', async () => {
      mockAdd.mockResolvedValueOnce({ id: undefined } as any);
      const id = await enqueueGraphBuild({ provider: 'AZURE', accountId: 'acct-3' });
      expect(id).toContain('AZURE');
      expect(id).toContain('acct-3');
    });
  });

  describe('createGraphBuildWorker (processor wiring)', () => {
    it('calls buildGraphForAccount and then chains into the CIEM pass on success', async () => {
      (buildGraphForAccount as jest.Mock).mockResolvedValueOnce({ nodes: 10, edges: 4 } as any);
      (runCiemPassForAccount as jest.Mock).mockResolvedValueOnce(undefined as any);

      const worker = createGraphBuildWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1', triggeredBy: 'SCAN' } };

      await worker.processor(job);

      expect(buildGraphForAccount).toHaveBeenCalledWith('AWS', 'acct-1');
      expect(runCiemPassForAccount).toHaveBeenCalledWith('AWS', 'acct-1');
      expect(logger.info).toHaveBeenCalledWith('graphBuildWorker.start', expect.objectContaining({ accountId: 'acct-1' }));
      expect(logger.info).toHaveBeenCalledWith('graphBuildWorker.done', expect.objectContaining({ accountId: 'acct-1' }));
    });

    it('does not fail the job when the CIEM pass throws — logs debug and continues', async () => {
      (buildGraphForAccount as jest.Mock).mockResolvedValueOnce({ nodes: 1, edges: 0 } as any);
      (runCiemPassForAccount as jest.Mock).mockRejectedValueOnce(new Error('ciem not ready'));

      const worker = createGraphBuildWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1' } };

      await expect(worker.processor(job)).resolves.toBeUndefined();
      expect(logger.debug).toHaveBeenCalledWith(
        'graphBuildWorker.ciem-skipped',
        expect.objectContaining({ accountId: 'acct-1', reason: 'ciem not ready' }),
      );
      expect(logger.info).toHaveBeenCalledWith('graphBuildWorker.done', expect.objectContaining({ accountId: 'acct-1' }));
    });

    it('logs and rethrows when buildGraphForAccount itself fails', async () => {
      const err = new Error('graph db unreachable');
      (buildGraphForAccount as jest.Mock).mockRejectedValueOnce(err);

      const worker = createGraphBuildWorker() as unknown as FakeWorker;
      const job = { data: { provider: 'AWS', accountId: 'acct-1' } };

      await expect(worker.processor(job)).rejects.toThrow('graph db unreachable');
      expect(logger.error).toHaveBeenCalledWith(
        'graphBuildWorker.failed',
        expect.objectContaining({ accountId: 'acct-1', error: 'graph db unreachable' }),
      );
      // Should not have attempted the CIEM chain when the graph build itself failed
      expect(runCiemPassForAccount).not.toHaveBeenCalled();
    });

    it('constructs the underlying Worker against the graph-build queue name', () => {
      const worker = createGraphBuildWorker() as unknown as FakeWorker;
      expect(worker).toBeTruthy();
      expect(GRAPH_BUILD_QUEUE).toBe('graph-build');
    });
  });
});

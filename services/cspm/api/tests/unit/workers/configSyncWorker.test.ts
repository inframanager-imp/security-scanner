import { describe, it, expect, beforeEach, jest } from '@jest/globals';

jest.mock('../../../src/config/redis', () => ({ redis: {} }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

const mockConfigSyncRunCreate = jest.fn();
const mockConfigSyncRunUpdate = jest.fn();
const mockConfigChangeFindMany = jest.fn(async () => [] as any[]);

jest.mock('../../../src/config/database', () => ({
  prisma: {
    configSyncRun: { create: mockConfigSyncRunCreate, update: mockConfigSyncRunUpdate },
    configChange: { findMany: mockConfigChangeFindMany },
  },
}));

const mockEmit = jest.fn();
const mockTo = jest.fn(() => ({ emit: mockEmit }));
jest.mock('../../../src/socket/index', () => ({
  getIO: jest.fn(() => ({ to: mockTo })),
}));

jest.mock('../../../src/services/inventoryPipeline', () => ({
  syncConfigChanges: jest.fn(),
  markSyncedReady: jest.fn(async () => undefined),
}));

jest.mock('../../../src/services/baselineService', () => ({
  runDriftForTarget: jest.fn(async () => undefined),
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

import { prisma } from '../../../src/config/database';
import { logger } from '../../../src/config/logger';
import { syncConfigChanges, markSyncedReady } from '../../../src/services/inventoryPipeline';
import { runDriftForTarget } from '../../../src/services/baselineService';
import { createConfigSyncWorker } from '../../../src/workers/configSyncWorker';

describe('configSyncWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockConfigSyncRunCreate.mockResolvedValue({ id: 'run-1' } as any);
    mockConfigSyncRunUpdate.mockResolvedValue({} as any);
  });

  describe('createConfigSyncWorker (processor wiring)', () => {
    it('creates a RUNNING sync run, calls syncConfigChanges, and marks it COMPLETED', async () => {
      (syncConfigChanges as jest.Mock).mockResolvedValueOnce({ eventsFound: 5, changesStored: 0 } as any);

      const worker = createConfigSyncWorker() as unknown as FakeWorker;
      await worker.processor({ data: { provider: 'AWS', targetId: 'target-1' } });

      expect(mockConfigSyncRunCreate).toHaveBeenCalledWith(
        expect.objectContaining({ data: expect.objectContaining({ provider: 'AWS', targetId: 'target-1', status: 'RUNNING' }) }),
      );
      expect(syncConfigChanges).toHaveBeenCalledWith('AWS', 'target-1', 6);
      expect(mockConfigSyncRunUpdate).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'run-1' },
          data: expect.objectContaining({ status: 'COMPLETED', eventsFound: 5, changesStored: 0 }),
        }),
      );
      expect(markSyncedReady).toHaveBeenCalledWith('AWS', 'target-1');
    });

    it('emits config:changes + heartbeat and triggers drift when new changes were stored', async () => {
      (syncConfigChanges as jest.Mock).mockResolvedValueOnce({ eventsFound: 3, changesStored: 2 } as any);
      mockConfigChangeFindMany.mockResolvedValueOnce([{ id: 'c1' }, { id: 'c2' }] as any);

      const worker = createConfigSyncWorker() as unknown as FakeWorker;
      await worker.processor({ data: { provider: 'AZURE', targetId: 'target-2' } });

      expect(mockTo).toHaveBeenCalledWith('config-changes:AZURE:target-2');
      expect(mockEmit).toHaveBeenCalledWith('config:changes', expect.objectContaining({ count: 2 }));
      expect(mockTo).toHaveBeenCalledWith('config-changes:all');
      expect(mockEmit).toHaveBeenCalledWith('config:heartbeat', expect.objectContaining({ changesStored: 2 }));
      expect(runDriftForTarget).toHaveBeenCalledWith('AZURE', 'target-2');
    });

    it('emits only a heartbeat (no drift trigger) when nothing new was found', async () => {
      (syncConfigChanges as jest.Mock).mockResolvedValueOnce({ eventsFound: 0, changesStored: 0 } as any);

      const worker = createConfigSyncWorker() as unknown as FakeWorker;
      await worker.processor({ data: { provider: 'GCP', targetId: 'target-3' } });

      expect(mockEmit).toHaveBeenCalledWith('config:heartbeat', expect.objectContaining({ changesStored: 0 }));
      expect(runDriftForTarget).not.toHaveBeenCalled();
    });

    it('marks the sync run FAILED and does not throw when syncConfigChanges fails (repeatable job keeps running)', async () => {
      (syncConfigChanges as jest.Mock).mockRejectedValueOnce(new Error('cloudtrail api error'));

      const worker = createConfigSyncWorker() as unknown as FakeWorker;
      await expect(
        worker.processor({ data: { provider: 'AWS', targetId: 'target-4' } }),
      ).resolves.toBeUndefined();

      expect(mockConfigSyncRunUpdate).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { id: 'run-1' },
          data: expect.objectContaining({ status: 'FAILED', errorMessage: 'cloudtrail api error' }),
        }),
      );
      expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('target-4'));
    });
  });
});

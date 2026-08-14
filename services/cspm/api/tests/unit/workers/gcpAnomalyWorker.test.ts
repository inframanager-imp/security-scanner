import { describe, it, expect, beforeEach, jest } from '@jest/globals';

const redisStore = new Map<string, string>();

const mockRedis = {
  set: jest.fn(async (key: string, val: string) => {
    redisStore.set(key, val);
    return 'OK';
  }),
  get: jest.fn(async (key: string) => redisStore.get(key) ?? null),
  del: jest.fn(async (key: string) => {
    redisStore.delete(key);
    return 1;
  }),
};

jest.mock('../../../src/config/redis', () => ({ redis: mockRedis }));

jest.mock('../../../src/config/logger', () => ({
  logger: { info: jest.fn(), debug: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

jest.mock('../../../src/config/database', () => ({
  prisma: {
    gcpProject: { findUnique: jest.fn() },
    gcpCredential: { findUnique: jest.fn() },
  },
}));

const mockQueueAdd = jest.fn(async () => ({ id: 'fake-job-id' }));
const mockGetRepeatableJobs = jest.fn(async () => [] as any[]);
const mockRemoveRepeatableByKey = jest.fn(async () => undefined);

class FakeQueue {
  add = mockQueueAdd;
  getRepeatableJobs = mockGetRepeatableJobs;
  removeRepeatableByKey = mockRemoveRepeatableByKey;
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

jest.mock('../../../src/services/anomalyEngine', () => ({
  analyzeEvent: jest.fn(async () => []),
  normalizeGcpEvent: jest.fn((entry: any) => entry),
}));

jest.mock('../../../src/services/gcpCredentialService', () => ({
  decryptGcpCredentials: jest.fn(() => ({ serviceAccountKey: undefined })),
}));

const mockEntriesList = jest.fn(async () => ({ data: { entries: [], nextPageToken: undefined } }));

jest.mock('../../../../src/gcp/client', () => {
  return jest.fn().mockImplementation(() => ({
    logging: () => ({ entries: { list: mockEntriesList } }),
  }));
});

import { logger } from '../../../src/config/logger';
import { prisma } from '../../../src/config/database';
import { analyzeEvent } from '../../../src/services/anomalyEngine';
import {
  startGcpAnomalyMonitor,
  stopGcpAnomalyMonitor,
  isGcpMonitoring,
  createGcpAnomalyWorker,
  GCP_ANOMALY_QUEUE,
  GCP_CHECK_INTERVAL,
} from '../../../src/workers/gcpAnomalyWorker';

describe('gcpAnomalyWorker', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    redisStore.clear();
  });

  describe('startGcpAnomalyMonitor', () => {
    it('marks the project as monitoring and seeds lastCheck when absent', async () => {
      await startGcpAnomalyMonitor('proj-1');

      expect(mockRedis.set).toHaveBeenCalledWith('gcp:anomaly:monitoring:proj-1', '1');
      expect(mockRedis.set).toHaveBeenCalledWith(
        'gcp:anomaly:lastCheck:proj-1',
        expect.any(String),
      );
    });

    it('does not overwrite an existing lastCheck', async () => {
      redisStore.set('gcp:anomaly:lastCheck:proj-1', '2024-01-01T00:00:00.000Z');
      await startGcpAnomalyMonitor('proj-1');

      expect(redisStore.get('gcp:anomaly:lastCheck:proj-1')).toBe('2024-01-01T00:00:00.000Z');
    });

    it('registers a repeatable monitor-gcp-project job with the 2-minute interval', async () => {
      await startGcpAnomalyMonitor('proj-1');

      expect(mockQueueAdd).toHaveBeenCalledWith(
        'monitor-gcp-project',
        { projectId: 'proj-1' },
        expect.objectContaining({
          jobId: 'gcp-anomaly-proj-1',
          repeat: { every: GCP_CHECK_INTERVAL },
        }),
      );
    });
  });

  describe('stopGcpAnomalyMonitor', () => {
    it('clears the monitoring flag and removes matching repeatable jobs', async () => {
      redisStore.set('gcp:anomaly:monitoring:proj-1', '1');
      mockGetRepeatableJobs.mockResolvedValueOnce([
        { key: 'monitor-gcp-project:gcp-anomaly-proj-1::' } as any,
        { key: 'monitor-gcp-project:gcp-anomaly-proj-2::' } as any,
      ]);

      await stopGcpAnomalyMonitor('proj-1');

      expect(mockRedis.del).toHaveBeenCalledWith('gcp:anomaly:monitoring:proj-1');
      expect(mockRemoveRepeatableByKey).toHaveBeenCalledTimes(1);
      expect(mockRemoveRepeatableByKey).toHaveBeenCalledWith('monitor-gcp-project:gcp-anomaly-proj-1::');
    });
  });

  describe('isGcpMonitoring', () => {
    it('returns true only when the Redis flag is exactly "1"', async () => {
      redisStore.set('gcp:anomaly:monitoring:proj-1', '1');
      expect(await isGcpMonitoring('proj-1')).toBe(true);
      expect(await isGcpMonitoring('proj-2')).toBe(false);
    });
  });

  describe('createGcpAnomalyWorker (processor wiring)', () => {
    it('fetches audit log entries and runs anomaly detection, then advances lastCheck', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValueOnce({ id: 'proj-1', projectId: 'gcp-proj-1' } as any);
      (prisma.gcpCredential.findUnique as jest.Mock).mockResolvedValueOnce({ projectId: 'proj-1' } as any);
      mockEntriesList.mockResolvedValueOnce({
        data: { entries: [{ id: 'e1' }, { id: 'e2' }], nextPageToken: undefined },
      } as any);

      const worker = createGcpAnomalyWorker() as unknown as FakeWorker;
      await worker.processor({ data: { projectId: 'proj-1' } });

      expect(analyzeEvent).toHaveBeenCalledTimes(2);
      expect(mockRedis.set).toHaveBeenCalledWith('gcp:anomaly:lastCheck:proj-1', expect.any(String));
    });

    it('logs a warning and exits early when the project is not found', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValueOnce(null as any);

      const worker = createGcpAnomalyWorker() as unknown as FakeWorker;
      await worker.processor({ data: { projectId: 'missing-proj' } });

      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('missing-proj'));
      expect(prisma.gcpCredential.findUnique).not.toHaveBeenCalled();
    });

    it('logs a warning and exits early when credentials are missing', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockResolvedValueOnce({ id: 'proj-1', projectId: 'gcp-proj-1' } as any);
      (prisma.gcpCredential.findUnique as jest.Mock).mockResolvedValueOnce(null as any);

      const worker = createGcpAnomalyWorker() as unknown as FakeWorker;
      await worker.processor({ data: { projectId: 'proj-1' } });

      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('proj-1'));
      expect(mockEntriesList).not.toHaveBeenCalled();
    });

    it('swallows errors and logs rather than throwing, so the repeatable job keeps running', async () => {
      (prisma.gcpProject.findUnique as jest.Mock).mockRejectedValueOnce(new Error('db down'));

      const worker = createGcpAnomalyWorker() as unknown as FakeWorker;
      await expect(worker.processor({ data: { projectId: 'proj-1' } })).resolves.toBeUndefined();

      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('proj-1'),
        expect.objectContaining({ error: 'db down' }),
      );
    });

    it('constructs the underlying Worker against the gcp-anomaly-monitoring queue name', () => {
      const worker = createGcpAnomalyWorker() as unknown as FakeWorker;
      expect(worker).toBeTruthy();
      expect(GCP_ANOMALY_QUEUE).toBe('gcp-anomaly-monitoring');
    });
  });
});

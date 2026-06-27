import { Queue } from 'bullmq';
import { redis } from '../config/redis';

export const scanQueue = new Queue('scans', { connection: redis });

export async function enqueueScan(
  scanId: string,
  accountId: string,
  services: string[],
  regions: string[]
): Promise<string | undefined> {
  const job = await scanQueue.add(
    'execute-scan',
    { scanId, accountId, services, regions },
    {
      attempts: 2,
      backoff: { type: 'exponential', delay: 5000 },
      removeOnComplete: 100,
      removeOnFail: 50,
    }
  );
  return job.id;
}

export async function removeJob(jobId: string): Promise<void> {
  const job = await scanQueue.getJob(jobId);
  if (job) {
    await job.remove();
  }
}

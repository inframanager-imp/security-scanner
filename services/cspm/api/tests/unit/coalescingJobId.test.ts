import { describe, it, expect } from '@jest/globals';
import { buildCoalescingJobId } from '../../src/services/coalescingJobId';

// Mirrors BullMQ's custom-jobId validation (bullmq/dist/cjs/classes/job.js):
// a jobId containing ':' is only accepted if it splits into exactly 3 parts.
function isAcceptedByBullMQ(jobId: string): boolean {
  if (!jobId.includes(':')) return true;
  return jobId.split(':').length === 3;
}

describe('coalescingJobId.buildCoalescingJobId', () => {
  it('never contains a colon, regardless of segment count', () => {
    expect(buildCoalescingJobId(['AWS', 'acct-1'], 0, 60000)).not.toContain(':');
    expect(buildCoalescingJobId(['AWS', 'acct-1', 'framework-1', 'extra'], 0, 60000)).not.toContain(':');
  });

  it('would be accepted by BullMQ regardless of segment count (2, 3, or 4+ parts)', () => {
    expect(isAcceptedByBullMQ(buildCoalescingJobId(['AWS'], 0, 60000))).toBe(true);
    expect(isAcceptedByBullMQ(buildCoalescingJobId(['AWS', 'acct-1'], 0, 60000))).toBe(true);
    expect(isAcceptedByBullMQ(buildCoalescingJobId(['AWS', 'acct-1', 'fw-1', 'x'], 0, 60000))).toBe(true);
  });

  it('joins key parts with the bucket appended last', () => {
    expect(buildCoalescingJobId(['AWS', 'acct-1'], 0, 60000)).toBe('AWS_acct-1_0');
  });

  it('coalesces calls within the same time bucket', () => {
    const bucketMs = 60000;
    const a = buildCoalescingJobId(['AWS', 'acct-1'], 0, bucketMs);
    const b = buildCoalescingJobId(['AWS', 'acct-1'], bucketMs - 1, bucketMs);
    expect(a).toBe(b);
  });

  it('produces distinct ids once the time bucket rolls over', () => {
    const bucketMs = 60000;
    const a = buildCoalescingJobId(['AWS', 'acct-1'], bucketMs - 1, bucketMs);
    const b = buildCoalescingJobId(['AWS', 'acct-1'], bucketMs, bucketMs);
    expect(a).not.toBe(b);
  });

  it('respects independently configured bucket sizes (e.g. 30s vs 60s)', () => {
    // graphBuildWorker uses a 30s bucket; evidence/cwpp/dspm use 60s.
    const at45s = 45000;
    const bucket30 = buildCoalescingJobId(['AWS', 'acct-1'], at45s, 30000); // new bucket (30s boundary passed)
    const bucket60 = buildCoalescingJobId(['AWS', 'acct-1'], at45s, 60000); // still bucket 0
    expect(bucket30).toBe('AWS_acct-1_1');
    expect(bucket60).toBe('AWS_acct-1_0');
  });

  it('produces distinct ids for different key parts', () => {
    const a = buildCoalescingJobId(['AWS', 'acct-1'], 0, 60000);
    const b = buildCoalescingJobId(['AZURE', 'acct-1'], 0, 60000);
    const c = buildCoalescingJobId(['AWS', 'acct-2'], 0, 60000);
    expect(a).not.toBe(b);
    expect(a).not.toBe(c);
  });
});

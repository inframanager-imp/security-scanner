import { describe, it, expect } from '@jest/globals';
import { buildEvidenceRefreshJobId } from '../../src/services/evidenceJobId';

// BullMQ's custom-jobId validation (bullmq/dist/cjs/classes/job.js): a jobId
// containing ':' is only accepted if it splits into exactly 3 parts (an old
// repeatable-job compat check). Anything else containing ':' throws
// "Custom Id cannot contain :". This test locks in that the generated id
// never contains ':' at all, so a future edit can't reintroduce the bug that
// silently broke evidence refresh in production for weeks.
function isAcceptedByBullMQ(jobId: string): boolean {
  if (!jobId.includes(':')) return true;
  return jobId.split(':').length === 3;
}

describe('evidenceJobId.buildEvidenceRefreshJobId', () => {
  it('never contains a colon', () => {
    const jobId = buildEvidenceRefreshJobId({ provider: 'AWS', accountId: 'acct-1', frameworkId: 'cis-1.4' }, 12345);
    expect(jobId).not.toContain(':');
  });

  it('would be accepted by BullMQ\'s custom-jobId validation', () => {
    const jobId = buildEvidenceRefreshJobId({ provider: 'AWS', accountId: 'acct-1', frameworkId: 'cis-1.4' }, 12345);
    expect(isAcceptedByBullMQ(jobId)).toBe(true);
  });

  it('defaults frameworkId to "all" when omitted', () => {
    const jobId = buildEvidenceRefreshJobId({ provider: 'AWS', accountId: 'acct-1' }, 12345);
    expect(jobId).toBe('AWS_acct-1_all_12345');
  });

  it('coalesces same account+framework within the same minute bucket', () => {
    const a = buildEvidenceRefreshJobId({ provider: 'AZURE', accountId: 'acct-2', frameworkId: 'iso27001' }, 999);
    const b = buildEvidenceRefreshJobId({ provider: 'AZURE', accountId: 'acct-2', frameworkId: 'iso27001' }, 999);
    expect(a).toBe(b);
  });

  it('produces distinct ids across different minute buckets', () => {
    const a = buildEvidenceRefreshJobId({ provider: 'GCP', accountId: 'acct-3' }, 1);
    const b = buildEvidenceRefreshJobId({ provider: 'GCP', accountId: 'acct-3' }, 2);
    expect(a).not.toBe(b);
  });

  it('produces distinct ids across different providers or accounts', () => {
    const aws = buildEvidenceRefreshJobId({ provider: 'AWS', accountId: 'acct-4' }, 100);
    const azure = buildEvidenceRefreshJobId({ provider: 'AZURE', accountId: 'acct-4' }, 100);
    const otherAccount = buildEvidenceRefreshJobId({ provider: 'AWS', accountId: 'acct-5' }, 100);
    expect(aws).not.toBe(azure);
    expect(aws).not.toBe(otherAccount);
  });
});

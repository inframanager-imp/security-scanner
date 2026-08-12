// Pure job-id logic for evidence-refresh, split out of evidenceWorker.ts so it
// can be unit tested without importing bullmq/redis/env (which connect to a
// live Redis and exit the process if required env vars are missing).

export interface EvidenceJobData {
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  frameworkId?: string;
  triggeredBy?: 'SCAN' | 'SCHEDULED' | 'MANUAL';
}

/**
 * Builds the coalescing jobId for an evidence-refresh job: same account +
 * framework within the same 1-minute window collapses to one BullMQ job.
 *
 * BullMQ only accepts a ':'-containing custom jobId if it splits into exactly
 * 3 parts (an old repeatable-job compat check) — this has 4 segments, so a
 * ':'-joined id always threw "Custom Id cannot contain :" and evidence
 * refresh silently never ran. Exported so the segment count can be locked in
 * by a test without needing a live Redis connection.
 */
export function buildEvidenceRefreshJobId(data: EvidenceJobData, minuteBucket: number): string {
  return `${data.provider}_${data.accountId}_${data.frameworkId ?? 'all'}_${minuteBucket}`;
}

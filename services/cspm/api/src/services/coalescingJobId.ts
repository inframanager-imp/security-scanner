// Shared, pure job-id builder for BullMQ "coalesce repeats within a time
// window" queues (evidence-refresh, cwpp-scans, dspm-scans, graph-build).
// Kept dependency-free (no bullmq/redis/env imports) so it's unit testable
// without a live Redis connection.
//
// BullMQ's custom-jobId validation (bullmq/dist/cjs/classes/job.js) only
// accepts a ':'-containing id if it splits into exactly 3 parts (an old
// repeatable-job compat check) — anything else throws "Custom Id cannot
// contain :". evidenceWorker.ts hit this in production for weeks because its
// id had 4 segments; the other 3 callers happen to have exactly 3 segments
// today so they don't currently trip it, but that's incidental, not
// guaranteed — any future extra segment (like evidenceWorker's frameworkId)
// would silently break them the same way. '_' carries no special meaning to
// BullMQ, so it's safe regardless of segment count.

/**
 * Builds a jobId that coalesces same-key calls within the same time bucket:
 * `key1_key2..._bucket`, where bucket = floor(nowMs / bucketMs).
 *
 * @param keyParts  identifying segments (e.g. provider, accountId, frameworkId)
 * @param nowMs     current time in ms (pass Date.now() at the call site)
 * @param bucketMs  window size in ms — same-key calls within this window collapse to one job
 */
export function buildCoalescingJobId(keyParts: string[], nowMs: number, bucketMs: number): string {
  const bucket = Math.floor(nowMs / bucketMs);
  return [...keyParts, String(bucket)].join('_');
}

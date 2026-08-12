// ── Deduplication (AWS scan worker) ────────────────────────────────────────
// Extracted from workers/scanWorker.ts so the logic can be unit tested
// directly. Behavior is unchanged — this is a pure extraction, not a rewrite.
//
// A finding is a duplicate if an OPEN or ACKNOWLEDGED finding with the
// same identity + resource already exists for this account. Duplicates
// are skipped; only net-new findings are inserted.
//
// Identity prefers the stable registry checkId (checkId:fingerprint) over
// service:title:fingerprint — titles are product copy and do get reworded
// (e.g. the IAM hardware-MFA checks' titles changed to match a policy fix
// without their checkId changing); keying on checkId means a future
// reword no longer orphans every existing OPEN finding as a "new" one
// and requires a manual DB cleanup, the way that one did. Legacy findings
// without a checkId (pre-registry-migration) still fall back to the old
// service:title key — there's no stable identity to use for those yet.

/**
 * Extracts a stable resource identifier from an evidence object.
 * Tries service-specific keys first, then generic fallbacks.
 */
export function resourceFingerprint(evidence: unknown): string {
  const e = (evidence ?? {}) as Record<string, unknown>;
  // resourceId is checked first — scanners that need per-sub-resource uniqueness
  // (e.g. Lambda CVEs, specific SG ports) set this explicitly.
  if (e.resourceId != null) return String(e.resourceId);
  for (const key of [
    'functionName', 'trailName', 'bucket', 'username', 'accessKeyId',
    'keyId', 'dbId', 'clusterId', 'secretName', 'sgId', 'instanceId',
    'naclId', 'vpcId', 'requirementId', 'peeringConnectionId',
    'resourceName', 'arn', 'name', 'id',
  ]) {
    if (e[key] != null) return String(e[key]);
  }
  return 'account-level';
}

/** checkId:fingerprint when checkId is known; service:title:fingerprint otherwise (legacy fallback). */
export function dedupKey(service: string, title: string, checkId: string | null, evidence: unknown): string {
  const fingerprint = resourceFingerprint(evidence);
  return checkId ? `${checkId}:${fingerprint}` : `${service}:${title}:${fingerprint}`;
}

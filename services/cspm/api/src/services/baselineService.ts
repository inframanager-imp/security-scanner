/**
 * Baseline & Drift Detection Service
 *
 * Captures point-in-time snapshots of all ACTIVE resources (configState)
 * from ResourceInventory, then detects drift by comparing the current state
 * against the baseline.
 *
 * Drift types:
 *   ADDED   — resource exists now but was not in baseline
 *   DELETED — resource was in baseline but no longer exists (ACTIVE)
 *   MODIFIED — resource exists in both; configState has changed fields
 *
 * Severity heuristics:
 *   IAM / ENCRYPTION / NETWORK resource types → CRITICAL/HIGH
 *   Other resource types → MEDIUM
 *   Simple tag-only changes → LOW
 *
 * Version history:
 *   Every capture and refresh creates a BaselineVersion record with full
 *   per-resource snapshots. Versions are kept indefinitely for audit trail.
 *   The latest N versions are shown in the UI; older ones remain in DB.
 */

import { prisma } from '../config/database';
import { logger }  from '../config/logger';

// ─── JSON diff helper ─────────────────────────────────────────────────────────

type JsonVal = string | number | boolean | null | JsonVal[] | { [k: string]: JsonVal };

function diffPaths(a: JsonVal, b: JsonVal, path = ''): string[] {
  if (JSON.stringify(a) === JSON.stringify(b)) return [];
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) {
    return [path || 'root'];
  }
  if (Array.isArray(a) || Array.isArray(b)) return [path || 'root'];

  const keys = new Set([...Object.keys(a as object), ...Object.keys(b as object)]);
  const changed: string[] = [];
  for (const k of keys) {
    const ap = (a as Record<string, JsonVal>)[k];
    const bp = (b as Record<string, JsonVal>)[k];
    changed.push(...diffPaths(ap ?? null, bp ?? null, path ? `${path}.${k}` : k));
  }
  return changed;
}

// ─── Severity classifier ──────────────────────────────────────────────────────

const HIGH_RISK_TYPES = /iam|role|policy|networksecurity|securitygroup|security\.group|firewall|kms|keyvault|key\.vault|encryption|acl|bucket\.policy|siem|log/i;

function driftSeverity(resourceType: string, driftedFields: string[]): string {
  if (HIGH_RISK_TYPES.test(resourceType)) return 'HIGH';
  const sensitiveField = driftedFields.some((f) =>
    /encrypt|policy|acl|public|auth|secret|password|key|permission/i.test(f)
  );
  if (sensitiveField) return 'HIGH';
  const tagOnly = driftedFields.every((f) => /^tags?/i.test(f));
  if (tagOnly) return 'LOW';
  return 'MEDIUM';
}

// ─── Version helpers ──────────────────────────────────────────────────────────

/**
 * Saves the current BaselineSnapshot rows as a new BaselineVersion record.
 * Called before every refresh so history is never lost.
 */
async function saveVersion(
  baselineId: string,
  versionNumber: number,
  label: string,
  capturedBy?: string,
): Promise<void> {
  const snapshots = await prisma.baselineSnapshot.findMany({
    where:  { baselineId },
    select: { nativeId: true, resourceType: true, resourceName: true, region: true, configState: true },
  });
  if (snapshots.length === 0) return;

  await prisma.baselineVersion.create({
    data: {
      baselineId,
      versionNumber,
      label,
      resourceCount: snapshots.length,
      capturedBy,
      snapshots: {
        createMany: {
          data: snapshots.map((s) => ({
            nativeId:     s.nativeId,
            resourceType: s.resourceType,
            resourceName: s.resourceName,
            region:       s.region,
            configState:  s.configState as object,
          })),
        },
      },
    },
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Captures a baseline snapshot of all ACTIVE resources for a provider+targetId.
 * Also saves the snapshot as version 1 in BaselineVersion history.
 * Returns the created ConfigBaseline id.
 */
export async function captureBaseline(
  provider: string,
  targetId: string,
  name: string,
  description?: string,
  resourceTypes?: string[],
  nameSearch?: string,
  capturedBy?: string,
): Promise<string> {
  const where =
    provider === 'AWS'   ? { awsAccountId: targetId } :
    provider === 'AZURE' ? { azureSubId:   targetId } :
    { gcpProjectId: targetId };

  const typeFilter = resourceTypes && resourceTypes.length > 0
    ? { resourceType: { in: resourceTypes } }
    : {};
  const nameFilter = nameSearch
    ? { resourceName: { contains: nameSearch, mode: 'insensitive' as const } }
    : {};

  const resources = await prisma.resourceInventory.findMany({
    where: { ...where, state: 'ACTIVE', ...typeFilter, ...nameFilter },
    select: {
      nativeId: true, resourceType: true, resourceName: true,
      region: true, configState: true,
    },
  });

  const snapshotData = resources.map((r) => ({
    nativeId:     r.nativeId,
    resourceType: r.resourceType,
    resourceName: r.resourceName,
    region:       r.region,
    configState:  r.configState as object,
  }));

  const baseline = await prisma.configBaseline.create({
    data: {
      provider, targetId, name, description,
      resourceCount: resources.length,
      currentVersion: 1,
      snapshots: { createMany: { data: snapshotData } },
    },
  });

  // Save v1 to version history
  await prisma.baselineVersion.create({
    data: {
      baselineId:    baseline.id,
      versionNumber: 1,
      label:         `v1 — Initial capture${capturedBy ? ` by ${capturedBy}` : ''}`,
      resourceCount: resources.length,
      capturedBy,
      snapshots: { createMany: { data: snapshotData } },
    },
  });

  logger.info(`[baseline] Captured "${name}" — ${resources.length} resources (${provider}:${targetId.slice(0, 8)})`);
  return baseline.id;
}

/**
 * Refreshes an existing baseline in-place:
 * 1. Saves current snapshots as a new BaselineVersion (audit history preserved)
 * 2. Replaces all BaselineSnapshot rows with fresh inventory state
 * 3. Updates capturedAt + resourceCount + currentVersion on the ConfigBaseline
 * 4. Clears all OPEN drift results (stale vs the new snapshot)
 * 5. Runs a fresh drift scan
 */
export async function refreshBaseline(baselineId: string, refreshedBy?: string): Promise<void> {
  const baseline = await prisma.configBaseline.findUnique({
    where: { id: baselineId },
  });
  if (!baseline) throw new Error('Baseline not found');

  const { provider, targetId, currentVersion } = baseline;
  const nextVersion = currentVersion + 1;

  // Save current state as a historical version BEFORE replacing snapshots
  await saveVersion(
    baselineId,
    currentVersion,
    `v${currentVersion} — Saved before refresh on ${new Date().toISOString().slice(0, 10)}${refreshedBy ? ` by ${refreshedBy}` : ''}`,
    refreshedBy,
  );

  const where =
    provider === 'AWS'   ? { awsAccountId: targetId } :
    provider === 'AZURE' ? { azureSubId:   targetId } :
    { gcpProjectId: targetId };

  const resources = await prisma.resourceInventory.findMany({
    where: { ...where, state: 'ACTIVE' },
    select: { nativeId: true, resourceType: true, resourceName: true, region: true, configState: true },
  });

  const snapshotData = resources.map((r) => ({
    baselineId,
    nativeId:     r.nativeId,
    resourceType: r.resourceType,
    resourceName: r.resourceName,
    region:       r.region,
    configState:  r.configState as object,
  }));

  // Replace snapshots + reset metadata in a transaction
  await prisma.$transaction([
    prisma.baselineSnapshot.deleteMany({ where: { baselineId } }),
    prisma.baselineSnapshot.createMany({ data: snapshotData }),
    prisma.driftResult.deleteMany({ where: { baselineId, status: 'OPEN' } }),
    prisma.configBaseline.update({
      where: { id: baselineId },
      data:  { capturedAt: new Date(), resourceCount: resources.length, currentVersion: nextVersion },
    }),
  ]);

  logger.info(`[baseline] Refreshed "${baseline.name}" → v${nextVersion} — ${resources.length} resources`);

  // Run fresh drift detection against the new snapshot
  await detectDrift(baselineId);
}

// Per-baseline scan guard — prevents concurrent scans on the same baseline
const _scanningBaselines = new Set<string>();

/**
 * Runs drift detection against a specific baseline.
 * Before inserting new OPEN drift results:
 *   - Any previously OPEN item that is no longer drifted is marked REVERTED (with timestamp).
 *   - Remaining OPEN items are deleted and re-created with current state.
 * ACKNOWLEDGED / RESOLVED / REVERTED results are kept for audit trail.
 * Returns counts by type.
 */
export async function detectDrift(baselineId: string): Promise<{
  added: number; deleted: number; modified: number; reverted: number; total: number;
}> {
  // Concurrency guard — skip if already running for this baseline
  if (_scanningBaselines.has(baselineId)) {
    return { added: 0, deleted: 0, modified: 0, reverted: 0, total: 0 };
  }
  _scanningBaselines.add(baselineId);

  try {
    const baseline = await prisma.configBaseline.findUnique({
      where: { id: baselineId },
      include: { snapshots: true },
    });
    if (!baseline) throw new Error('Baseline not found');

    const { provider, targetId } = baseline;
    const where =
      provider === 'AWS'   ? { awsAccountId: targetId } :
      provider === 'AZURE' ? { azureSubId:   targetId } :
      { gcpProjectId: targetId };

    // Current ACTIVE resources
    const current = await prisma.resourceInventory.findMany({
      where: { ...where, state: 'ACTIVE' },
      select: { nativeId: true, resourceType: true, resourceName: true, region: true, configState: true },
    });

    const baselineMap = new Map(baseline.snapshots.map((s) => [s.nativeId, s]));
    const currentMap  = new Map(current.map((r) => [r.nativeId, r]));

    // ── Detect reverts in previously OPEN results ──────────────────────────────
    // A REVERTED result = was drifted before, config/presence is now back to baseline.
    const openResults = await prisma.driftResult.findMany({
      where:  { baselineId, status: 'OPEN' },
      // Also fetch firstDetectedAt so we can carry it through to the re-created records
      select: { id: true, nativeId: true, driftType: true, firstDetectedAt: true },
    });

    // Map nativeId → firstDetectedAt for records that remain drifted (will be re-created)
    const firstDetectedMap = new Map<string, Date>();
    for (const open of openResults) {
      firstDetectedMap.set(`${open.nativeId}:${open.driftType}`, open.firstDetectedAt);
    }

    const revertedIds: string[] = [];
    for (const open of openResults) {
      if (open.driftType === 'DELETED') {
        // Resource was deleted — if it's back in inventory, it's been restored
        if (currentMap.has(open.nativeId)) revertedIds.push(open.id);
      } else if (open.driftType === 'ADDED') {
        // Resource was added (not in baseline) — if it's gone now, it's been removed
        if (!currentMap.has(open.nativeId)) revertedIds.push(open.id);
      } else if (open.driftType === 'MODIFIED') {
        // Config was changed — check if it matches baseline again
        const snap = baselineMap.get(open.nativeId);
        const cur  = currentMap.get(open.nativeId);
        if (snap && cur && diffPaths(snap.configState as JsonVal, cur.configState as JsonVal).length === 0) {
          revertedIds.push(open.id);
        }
      }
    }

    const now = new Date();
    if (revertedIds.length > 0) {
      await prisma.driftResult.updateMany({
        where: { id: { in: revertedIds } },
        data:  { status: 'REVERTED', resolvedAt: now },
      });
    }

    // Delete remaining OPEN results (non-reverted) — they'll be re-created below
    await prisma.driftResult.deleteMany({
      where: { baselineId, status: 'OPEN' },
    });

    // Fetch lastSeenAt for all nativeIds in baseline (needed for DELETED records)
    const deletedNativeIds = [...baselineMap.keys()].filter((id) => !currentMap.has(id));
    const inventoryLastSeen = deletedNativeIds.length > 0
      ? await prisma.resourceInventory.findMany({
          where:  { nativeId: { in: deletedNativeIds } },
          select: { nativeId: true, lastSeenAt: true },
        })
      : [];
    const lastSeenByNativeId = new Map(inventoryLastSeen.map((r) => [r.nativeId, r.lastSeenAt]));

    // ── Build fresh drift records ──────────────────────────────────────────────
    type DriftCreate = {
      baselineId: string; nativeId: string; resourceType: string; resourceName: string | null;
      region: string | null; driftType: string; severity: string;
      currentConfig: object | null; baselineConfig: object | null; driftedFields: string[];
      firstDetectedAt?: Date; lastSeenAt?: Date | null;
    };
    const driftRecords: DriftCreate[] = [];

    // ADDED (in current, not in baseline)
    for (const [nativeId, res] of currentMap) {
      if (!baselineMap.has(nativeId)) {
        driftRecords.push({
          baselineId,
          nativeId,
          resourceType:    res.resourceType,
          resourceName:    res.resourceName,
          region:          res.region,
          driftType:       'ADDED',
          severity:        driftSeverity(res.resourceType, []),
          currentConfig:   res.configState as object,
          baselineConfig:  null,
          driftedFields:   [],
          firstDetectedAt: firstDetectedMap.get(`${nativeId}:ADDED`) ?? now,
        });
      }
    }

    // DELETED (in baseline, not in current ACTIVE)
    for (const [nativeId, snap] of baselineMap) {
      if (!currentMap.has(nativeId)) {
        driftRecords.push({
          baselineId,
          nativeId,
          resourceType:    snap.resourceType,
          resourceName:    snap.resourceName,
          region:          snap.region,
          driftType:       'DELETED',
          severity:        driftSeverity(snap.resourceType, []),
          baselineConfig:  snap.configState as object,
          currentConfig:   null,
          driftedFields:   [],
          firstDetectedAt: firstDetectedMap.get(`${nativeId}:DELETED`) ?? now,
          lastSeenAt:      lastSeenByNativeId.get(nativeId) ?? null,
        });
      }
    }

    // MODIFIED (in both, config changed)
    for (const [nativeId, res] of currentMap) {
      const snap = baselineMap.get(nativeId);
      if (!snap) continue;
      const changed = diffPaths(snap.configState as JsonVal, res.configState as JsonVal);
      if (changed.length > 0) {
        driftRecords.push({
          baselineId,
          nativeId,
          resourceType:    res.resourceType,
          resourceName:    res.resourceName,
          region:          res.region,
          driftType:       'MODIFIED',
          severity:        driftSeverity(res.resourceType, changed),
          driftedFields:   changed,
          baselineConfig:  snap.configState as object,
          currentConfig:   res.configState  as object,
          firstDetectedAt: firstDetectedMap.get(`${nativeId}:MODIFIED`) ?? now,
        });
      }
    }

    if (driftRecords.length > 0) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await prisma.driftResult.createMany({ data: driftRecords as any });
    }

    const added    = driftRecords.filter((d) => d.driftType === 'ADDED').length;
    const deleted  = driftRecords.filter((d) => d.driftType === 'DELETED').length;
    const modified = driftRecords.filter((d) => d.driftType === 'MODIFIED').length;

    logger.info(
      `[baseline] Drift scan "${baseline.name}" — +${added} added, -${deleted} deleted, ~${modified} modified, ↩${revertedIds.length} reverted`
    );

    return { added, deleted, modified, reverted: revertedIds.length, total: driftRecords.length };
  } finally {
    _scanningBaselines.delete(baselineId);
  }
}

/**
 * Lists version history for a baseline (summary, no snapshots).
 */
export async function listBaselineVersions(baselineId: string) {
  return prisma.baselineVersion.findMany({
    where:   { baselineId },
    orderBy: { versionNumber: 'desc' },
    select: {
      id: true, versionNumber: true, label: true,
      resourceCount: true, capturedAt: true, capturedBy: true,
    },
  });
}

/**
 * Gets a specific version with its full snapshot list.
 */
export async function getBaselineVersion(baselineId: string, versionId: string) {
  return prisma.baselineVersion.findFirst({
    where:   { id: versionId, baselineId },
    include: { snapshots: true },
  });
}

/**
 * Runs drift detection for all active baselines of a provider+targetId.
 * Called from periodic sync after each successful config sync.
 */
export async function runDriftForTarget(provider: string, targetId: string): Promise<void> {
  const baselines = await prisma.configBaseline.findMany({
    where: { provider, targetId, isActive: true },
    select: { id: true, name: true },
  });

  await Promise.allSettled(
    baselines.map(async (b) => {
      try {
        await detectDrift(b.id);
      } catch (err) {
        logger.warn(`[baseline] Drift scan failed for "${b.name}": ${(err as Error).message}`);
      }
    }),
  );
}

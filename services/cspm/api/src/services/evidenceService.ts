/**
 * Evidence Auto-Collection Service
 *
 * Automatically generates ComplianceEvidence records by evaluating active
 * findings against each framework control. Findings with a stable registry
 * checkId are matched via control.checkIds; legacy findings (checkId = null)
 * fall back to byte-identical title matching via control.findingTitles.
 *
 * Evidence lifecycle:
 *  - AUTO_FINDING: derived from OPEN / ACKNOWLEDGED scanner findings
 *  - AUTO_SCAN:    derived from scan summary metrics (not yet implemented)
 *  - MANUAL:       created by users via the API
 *
 * Evidence expires after 90 days and must be re-collected.
 */

import { prisma } from '../config/database';
import { FRAMEWORKS, type FrameworkId } from './complianceService';

const EVIDENCE_TTL_DAYS = 90;

// ---------------------------------------------------------------------------
// Auto-collect for a single account + framework (or all frameworks)
// ---------------------------------------------------------------------------

export async function collectEvidenceForAccount(
  accountId: string,
  provider: 'AWS' | 'AZURE' | 'GCP',
  frameworkId?: FrameworkId,
): Promise<{ created: number; updated: number }> {
  // Load active findings for this account
  const scanIds = await getAccountScanIds(accountId, provider);
  if (scanIds.length === 0) return { created: 0, updated: 0 };

  const findings = await prisma.finding.findMany({
    where: {
      scanId: { in: scanIds },
      findingStatus: { in: ['OPEN', 'ACKNOWLEDGED'] },
    },
    select: { id: true, title: true, severity: true, checkId: true },
  });

  // Findings with a stable checkId are matched via control.checkIds; legacy
  // findings (checkId = null) fall back to title matching.
  const activeTitles = new Set<string>();
  const titleToIds = new Map<string, string[]>();
  const activeCheckIds = new Set<string>();
  const checkIdToIds = new Map<string, string[]>();
  const checkIdTitles = new Map<string, string>(); // representative title per checkId, for summaries
  for (const f of findings) {
    if (f.checkId) {
      activeCheckIds.add(f.checkId);
      const arr = checkIdToIds.get(f.checkId) ?? [];
      arr.push(f.id);
      checkIdToIds.set(f.checkId, arr);
      if (!checkIdTitles.has(f.checkId)) checkIdTitles.set(f.checkId, f.title);
    } else {
      activeTitles.add(f.title);
      const arr = titleToIds.get(f.title) ?? [];
      arr.push(f.id);
      titleToIds.set(f.title, arr);
    }
  }

  const targetFrameworks = frameworkId
    ? FRAMEWORKS.filter((fw) => fw.id === frameworkId)
    : FRAMEWORKS;

  const expiresAt = new Date(Date.now() + EVIDENCE_TTL_DAYS * 86_400_000);
  let created = 0;
  let updated = 0;

  for (const fw of targetFrameworks) {
    for (const ctrl of fw.controls) {
      if (ctrl.findingTitles.length === 0 && ctrl.checkIds.length === 0) continue; // NOT_EVALUATED — skip

      const failingTitles = ctrl.findingTitles.filter((t) => activeTitles.has(t));
      const failingCheckIds = ctrl.checkIds.filter((c) => activeCheckIds.has(c));
      const isCompliant = failingTitles.length === 0 && failingCheckIds.length === 0;
      const status = isCompliant ? 'COMPLIANT' : 'NON_COMPLIANT';

      const linkedFindingIds = [
        ...failingTitles.flatMap((t) => titleToIds.get(t) ?? []),
        ...failingCheckIds.flatMap((c) => checkIdToIds.get(c) ?? []),
      ];

      // Human-readable labels for the summary: legacy title matches plus the
      // representative finding titles of checkId matches (deduplicated).
      const failingLabels = [...failingTitles];
      for (const c of failingCheckIds) {
        const label = checkIdTitles.get(c) ?? c;
        if (!failingLabels.includes(label)) failingLabels.push(label);
      }

      const summary = isCompliant
        ? `All ${ctrl.findingTitles.length} monitored finding type(s) are clear.`
        : `${failingLabels.length} finding type(s) failing: ${failingLabels.slice(0, 3).join(', ')}${failingLabels.length > 3 ? ` +${failingLabels.length - 3} more` : ''}.`;

      const existing = await prisma.complianceEvidence.findFirst({
        where: {
          frameworkId: fw.id,
          controlId: ctrl.id,
          provider,
          accountId,
          evidenceType: 'AUTO_FINDING',
        },
        orderBy: { collectedAt: 'desc' },
      });

      // Phase 4 — enrich with resource counts + snapshot
      const evaluation = await evaluateControlResources(
        provider,
        accountId,
        ctrl.findingTitles,
        linkedFindingIds,
      );

      const nextEvaluationAt = new Date(Date.now() + 7 * 86_400_000); // 7 days

      if (existing) {
        await prisma.complianceEvidence.update({
          where: { id: existing.id },
          data: {
            status,
            summary,
            detail: { failingTitles, failingCheckIds, linkedFindingIds: linkedFindingIds.slice(0, 50) },
            evaluatedResources: evaluation.evaluatedResources as any,
            passingCount: evaluation.passingCount,
            failingCount: evaluation.failingCount,
            snapshotConfigState: evaluation.snapshotConfigState as any,
            nextEvaluationAt,
            collectedAt: new Date(),
            expiresAt,
          },
        });
        updated++;
      } else {
        await prisma.complianceEvidence.create({
          data: {
            frameworkId: fw.id,
            controlId: ctrl.id,
            provider,
            accountId,
            evidenceType: 'AUTO_FINDING',
            status,
            summary,
            detail: { failingTitles, failingCheckIds, linkedFindingIds: linkedFindingIds.slice(0, 50) },
            evaluatedResources: evaluation.evaluatedResources as any,
            passingCount: evaluation.passingCount,
            failingCount: evaluation.failingCount,
            snapshotConfigState: evaluation.snapshotConfigState as any,
            nextEvaluationAt,
            expiresAt,
          },
        });
        created++;
      }
    }
  }

  return { created, updated };
}

// ---------------------------------------------------------------------------
// Phase 4: per-control resource evaluation + snapshot capture
// ---------------------------------------------------------------------------

/**
 * For a given control, walk the failing findings → resources they point to,
 * sample a small set of related ResourceInventory rows for the snapshot,
 * and produce passing/failing counts at the resource (not finding) granularity.
 */
async function evaluateControlResources(
  provider: 'AWS' | 'AZURE' | 'GCP',
  accountId: string,
  controlFindingTitles: string[],
  linkedFindingIds: string[],
): Promise<{
  evaluatedResources: Array<{ resourceId: string; nativeId: string; resourceType: string; passed: boolean }>;
  passingCount: number;
  failingCount: number;
  snapshotConfigState: Record<string, unknown> | null;
}> {
  // Collect resource fingerprints from failing finding evidence
  const failingResourceIds = new Set<string>();
  if (linkedFindingIds.length > 0) {
    const model =
      provider === 'AWS'   ? prisma.finding :
      provider === 'AZURE' ? prisma.azureFinding :
      prisma.gcpFinding;
    const rows = await (model as any).findMany({
      where: { id: { in: linkedFindingIds } },
      select: { evidence: true },
    });
    for (const r of rows) {
      const e = (r.evidence ?? {}) as Record<string, unknown>;
      for (const key of ['resourceId', 'arn', 'bucket', 'functionName', 'tableName', 'dbId', 'instanceId', 'nativeId']) {
        const v = e[key];
        if (typeof v === 'string') failingResourceIds.add(v);
      }
    }
  }

  // Sample ResourceInventory: a few failing + a few passing
  const providerField =
    provider === 'AWS' ? 'awsAccountId' :
    provider === 'AZURE' ? 'azureSubId' :
    'gcpProjectId';

  const allRelevant = await prisma.resourceInventory.findMany({
    where: { [providerField]: accountId, state: 'ACTIVE' } as any,
    select: { id: true, nativeId: true, resourceType: true, configState: true },
    take: 200,
  });

  let passing = 0;
  let failing = 0;
  const evaluatedResources: Array<{ resourceId: string; nativeId: string; resourceType: string; passed: boolean }> = [];

  for (const r of allRelevant) {
    const fails = failingResourceIds.has(r.nativeId);
    if (fails) {
      failing++;
      if (evaluatedResources.filter((x) => !x.passed).length < 25) {
        evaluatedResources.push({ resourceId: r.id, nativeId: r.nativeId, resourceType: r.resourceType, passed: false });
      }
    } else {
      passing++;
      if (evaluatedResources.filter((x) => x.passed).length < 25) {
        evaluatedResources.push({ resourceId: r.id, nativeId: r.nativeId, resourceType: r.resourceType, passed: true });
      }
    }
  }

  // Build a compact snapshot: first failing resource's configState (truncated)
  let snapshotConfigState: Record<string, unknown> | null = null;
  const failingSample = allRelevant.find((r) => failingResourceIds.has(r.nativeId));
  if (failingSample) {
    snapshotConfigState = {
      sampleResource: failingSample.nativeId,
      sampleConfigState: truncateForSnapshot(failingSample.configState as any),
      capturedAt: new Date().toISOString(),
    };
  }

  return {
    evaluatedResources,
    passingCount: passing,
    failingCount: failing,
    snapshotConfigState,
  };
}

function truncateForSnapshot(obj: any, depth = 0): any {
  if (depth > 3) return '[truncated]';
  if (obj == null) return null;
  if (typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) {
    return obj.slice(0, 5).map((v) => truncateForSnapshot(v, depth + 1));
  }
  const out: any = {};
  let i = 0;
  for (const [k, v] of Object.entries(obj)) {
    if (i++ > 20) break;
    out[k] = truncateForSnapshot(v, depth + 1);
  }
  return out;
}

/**
 * Build an exportable evidence bundle for a framework + account (auditor-friendly JSON).
 */
export async function exportEvidencePackage(
  frameworkId: string,
  provider: string,
  accountId: string,
): Promise<{
  exportedAt: string;
  framework: { id: string };
  provider: string;
  accountId: string;
  evidence: any[];
}> {
  const rows = await prisma.complianceEvidence.findMany({
    where: { frameworkId, provider, accountId },
    orderBy: { collectedAt: 'desc' },
  });
  // Deduplicate to latest per controlId
  const seen = new Map<string, any>();
  for (const r of rows) {
    if (!seen.has(r.controlId)) seen.set(r.controlId, r);
  }
  return {
    exportedAt: new Date().toISOString(),
    framework: { id: frameworkId },
    provider,
    accountId,
    evidence: Array.from(seen.values()),
  };
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

export async function getEvidenceForControl(
  frameworkId: string,
  controlId: string,
  provider?: string,
  accountId?: string,
): Promise<typeof evidenceRecord[]> {
  return prisma.complianceEvidence.findMany({
    where: {
      frameworkId,
      controlId,
      ...(provider ? { provider } : {}),
      ...(accountId ? { accountId } : {}),
    },
    orderBy: { collectedAt: 'desc' },
  });
}

export async function getEvidenceSummaryForFramework(
  frameworkId: string,
  provider?: string,
  accountId?: string,
) {
  const rows = await prisma.complianceEvidence.findMany({
    where: {
      frameworkId,
      ...(provider ? { provider } : {}),
      ...(accountId ? { accountId } : {}),
    },
    select: { controlId: true, status: true, collectedAt: true, expiresAt: true, summary: true },
    orderBy: { collectedAt: 'desc' },
  });

  // Deduplicate — keep the most recent per controlId
  const seen = new Map<string, typeof rows[0]>();
  for (const r of rows) {
    if (!seen.has(r.controlId)) seen.set(r.controlId, r);
  }
  return Array.from(seen.values());
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function getAccountScanIds(accountId: string, provider: 'AWS' | 'AZURE' | 'GCP'): Promise<string[]> {
  if (provider === 'AWS') {
    const scans = await prisma.scan.findMany({ where: { accountId }, select: { id: true } });
    return scans.map((s) => s.id);
  }
  if (provider === 'AZURE') {
    const scans = await prisma.azureScan.findMany({ where: { subscriptionId: accountId }, select: { id: true } });
    return scans.map((s) => s.id);
  }
  if (provider === 'GCP') {
    const scans = await prisma.gcpScan.findMany({ where: { projectId: accountId }, select: { id: true } });
    return scans.map((s) => s.id);
  }
  return [];
}

// Dummy reference type for TS — the actual Prisma type is inferred
const evidenceRecord = {} as Awaited<ReturnType<typeof prisma.complianceEvidence.findFirst>>;

/**
 * VAPT (Vulnerability Assessment & Penetration Testing) style security report.
 *
 * Renders a single, professional, print-ready HTML document per cloud
 * account/subscription/project: executive summary, the same compliance
 * "Framework Score Overview" shown in the Compliance tab, and the full open
 * findings list with remediation guidance. No server-side PDF renderer —
 * the document is styled for `@media print` (cover page, running header/
 * footer, page-break control) so "File -> Print -> Save as PDF" produces a
 * clean paginated PDF straight out of the browser, matching the pattern
 * already used by services/cspm/api/src/services/reportService.ts.
 *
 * Optional filters narrow every section of the report consistently (exec
 * summary, framework scores, and the findings list all reflect the same
 * filtered subset): tags (all providers), region (AWS), resource group
 * (Azure). See vaptReports.ts for the query-param contract.
 */

import type { FindingStatus, Prisma } from '@prisma/client';
import { prisma } from '../config/database';
import { scoreFrameworks, FRAMEWORKS, getComplianceTags, type FrameworkScore } from './complianceService';
import { scoreAzureFrameworks, AZURE_FRAMEWORKS, getAzureComplianceTags, type AzureFrameworkScore } from './azureComplianceService';

/** Framework short names a finding maps to, deduplicated. */
function uniqueFrameworkNames(tags: Array<{ frameworkShortName: string }>): string[] {
  return [...new Set(tags.map(t => t.frameworkShortName))];
}

export type ReportProvider = 'AWS' | 'AZURE' | 'GCP';

export interface VaptReportFilters {
  tags?:           string[]; // all providers — OR-match (finding has ANY of these tags)
  region?:         string[]; // AWS only — best-effort, matched against evidence.region
  resourceGroup?:  string[]; // Azure only
}

export interface VaptFilterOptions {
  tags:            string[];
  regions?:        string[]; // AWS only
  resourceGroups?: string[]; // Azure only
}

export interface VaptFinding {
  severity:       string;
  service:        string;
  title:          string;
  description:    string;
  remediation:    string;
  resourceName:   string | null;
  discoveredAt:   Date;
  complianceTags: string[]; // e.g. ["CIS AWS", "PCI DSS"] — framework short names, deduplicated
}

export interface VaptFrameworkScoreSummary {
  frameworkId:           string;
  frameworkName:         string;
  shortName:             string;
  score:                 number;
  passingControls:       number;
  failingControls:       number;
  notEvaluatedControls:  number;
  totalControls:         number;
}

export interface VaptIamUserPolicyRef {
  name:              string;
  type:              'managed' | 'inline';
  isAdminEquivalent: boolean;
}
export interface VaptIamUserGroupPolicyRef {
  groupName:         string;
  policyName:        string;
  type:              'managed' | 'inline';
  isAdminEquivalent: boolean;
}
export interface VaptIamUserAssumableRole {
  roleName:          string;
  isAdminEquivalent: boolean;
  assumableBy:       'explicit' | 'wildcard';
}
export interface VaptIamUser {
  userName:              string;
  groups:                string[];
  directPolicies:        VaptIamUserPolicyRef[];
  groupPolicies:         VaptIamUserGroupPolicyRef[];
  assumableRoles:        VaptIamUserAssumableRole[];
  hasOpenEndedAccess:    boolean;
  mfaEnabled:            boolean;
  passwordEnabled:       boolean;
  passwordAgeDays:       number | null;
  passwordStale:         boolean;
  accessKeysActive:      number;
  accessKeyAgeDays:      number | null;
  keyStale:              boolean;
  hasNeverUsedActiveKey: boolean;
}

export interface VaptReportModel {
  provider:          ReportProvider;
  targetName:        string;
  targetExternalId:  string; // AWS account ID / Azure subscription ID / GCP project ID
  generatedAt:       Date;
  lastScanAt:        Date | null;
  appliedFilters:    Required<VaptReportFilters>;
  summary: {
    critical: number; high: number; medium: number; low: number; info: number; total: number;
  };
  riskScore:          number;
  riskRating:         'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
  frameworkScores:    VaptFrameworkScoreSummary[] | null; // null = not available for this provider (GCP)
  iamUsers:           VaptIamUser[] | null; // AWS only — null for Azure/GCP
  findings:           VaptFinding[];
  findingsTruncated:  boolean;
  findingsTotalCount: number;
}

const FINDINGS_CAP        = 500;
const FILTER_OPTIONS_SCAN_CAP = 3000; // best-effort sample size when deriving distinct tags/regions
const OPEN_STATUSES: FindingStatus[] = ['OPEN', 'ACKNOWLEDGED'];

function normalizeFilters(filters?: VaptReportFilters): Required<VaptReportFilters> {
  return {
    tags:          filters?.tags ?? [],
    region:        filters?.region ?? [],
    resourceGroup: filters?.resourceGroup ?? [],
  };
}

/**
 * AND-able extra conditions derived from the active filters. Kept separate
 * from scan-scoping (accountId/scanId) so the same logic works whether the
 * caller needs a nested relation filter (findMany/count) or a flat scanId
 * filter (groupBy — see the comment above each groupBy call for why).
 */
function extraFilterConditions(filters: Required<VaptReportFilters>, kind: 'aws' | 'azure' | 'gcp'): object[] {
  const conditions: object[] = [];
  if (filters.tags.length > 0) {
    conditions.push({ tags: { hasSome: filters.tags } });
  }
  if (kind === 'aws' && filters.region.length > 0) {
    // Region isn't a first-class column on Finding — it's recorded (when a
    // scanner populates it) inside the evidence JSON blob. Best-effort: OR
    // across the selected regions' JSON-path match. Findings from services
    // that don't record a region (e.g. IAM) won't match any region filter.
    conditions.push({ OR: filters.region.map(r => ({ evidence: { path: ['region'], equals: r } })) });
  }
  if (kind === 'azure' && filters.resourceGroup.length > 0) {
    conditions.push({ resourceGroup: { in: filters.resourceGroup } });
  }
  return conditions;
}

function computeRisk(critical: number, high: number, medium: number, low: number): number {
  return critical * 10 + high * 5 + medium * 2 + low;
}

function riskRating(score: number): VaptReportModel['riskRating'] {
  if (score > 50) return 'CRITICAL';
  if (score > 20) return 'HIGH';
  if (score > 0)  return 'MODERATE';
  return 'LOW';
}

function toSummary(counts: { critical: number; high: number; medium: number; low: number; info: number }) {
  return { ...counts, total: counts.critical + counts.high + counts.medium + counts.low + counts.info };
}

/**
 * Tally severities from a `groupBy(['severity'])` result into the stat-grid
 * shape. Deliberately NOT sourced from ScanSummary (a point-in-time snapshot
 * taken when the scan completed) — findings get triaged (resolved/marked
 * false-positive) afterwards, so ScanSummary drifts from what's *currently*
 * open, and wouldn't reflect filters at all. Tallying the same filtered
 * open-findings query used for the findings list keeps every section in sync.
 */
function tallyBySeverity(rows: Array<{ severity: string; _count: { severity: number } }>) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of rows) {
    const key = r.severity.toLowerCase();
    if (key in out) out[key as keyof typeof out] = r._count.severity;
  }
  return out;
}

// ─── AWS ────────────────────────────────────────────────────────────────────

async function buildAwsModel(targetId: string, filters: Required<VaptReportFilters>): Promise<VaptReportModel> {
  const account = await prisma.account.findUnique({ where: { id: targetId } });
  if (!account) throw new Error('AWS account not found');

  const latestScan = await prisma.scan.findFirst({
    where:   { accountId: targetId, status: 'COMPLETED' },
    orderBy: { completedAt: 'desc' },
    include: { summary: true },
  });

  const extra = extraFilterConditions(filters, 'aws');
  // Threat Detection (service THREAT) findings are anomaly/behavioral
  // signals, not static posture — excluded from the VAPT report for the
  // same reason they're excluded from Reports/AccountReport (see the
  // matching comment in engine.ts / routes/findings.ts).
  const findMany_where: Prisma.FindingWhereInput = {
    scan: { accountId: targetId }, findingStatus: { in: OPEN_STATUSES }, service: { not: 'THREAT' },
    ...(extra.length ? { AND: extra as Prisma.FindingWhereInput[] } : {}),
  };

  const [findings, findingsTotalCount] = await Promise.all([
    prisma.finding.findMany({
      where:   findMany_where,
      orderBy: { severity: 'asc' }, // enum declared CRITICAL..INFO, matches severity rank
      take:    FINDINGS_CAP,
    }),
    prisma.finding.count({ where: findMany_where }),
  ]);

  // Compliance scoring — same active-finding-set logic used by GET /api/compliance.
  // groupBy does not reliably support nested relation filters in Prisma, so
  // resolve scan IDs first (same workaround routes/compliance.ts uses).
  const scanIds = (await prisma.scan.findMany({ where: { accountId: targetId }, select: { id: true } })).map(s => s.id);
  const groupBy_where: Prisma.FindingWhereInput = {
    scanId: { in: scanIds }, findingStatus: { in: OPEN_STATUSES }, service: { not: 'THREAT' },
    ...(extra.length ? { AND: extra as Prisma.FindingWhereInput[] } : {}),
  };
  const [rows, severityRows] = await Promise.all([
    prisma.finding.groupBy({ by: ['title', 'checkId'], where: groupBy_where, _count: { _all: true } }),
    prisma.finding.groupBy({ by: ['severity'],          where: groupBy_where, _count: { severity: true } }),
  ]);
  const titles = new Set<string>();
  const counts = new Map<string, number>();
  const checkIds = new Set<string>();
  const checkIdCounts = new Map<string, number>();
  for (const r of rows) {
    const n = r._count._all;
    if (r.checkId) {
      checkIds.add(r.checkId);
      checkIdCounts.set(r.checkId, (checkIdCounts.get(r.checkId) ?? 0) + n);
    } else {
      titles.add(r.title);
      counts.set(r.title, (counts.get(r.title) ?? 0) + n);
    }
  }
  const frameworkScores: FrameworkScore[] = scoreFrameworks(titles, counts, checkIds, checkIdCounts);

  const summaryCounts = tallyBySeverity(severityRows);
  const risk = computeRisk(summaryCounts.critical, summaryCounts.high, summaryCounts.medium, summaryCounts.low);

  // IAM Users table — same dedup-aware query as routes/iamUsers.ts (an
  // unchanged user's inventory record stays attached to whichever scan
  // first created it, not necessarily the latest one — see that route for
  // the full explanation). Not narrowed by the report's tags/region filters:
  // IAM is account-wide, not a regional or taggable-resource concept.
  const iamUserFindings = await prisma.finding.findMany({
    where: {
      scan:          { accountId: targetId },
      checkId:       'iam_user_access_inventory',
      findingStatus: { in: OPEN_STATUSES },
    },
    orderBy: { discoveredAt: 'desc' },
  });
  const iamUsers: VaptIamUser[] = iamUserFindings.map(f => {
    const e = f.evidence as Record<string, unknown>;
    return {
      userName:              (e.userName as string) ?? 'Unknown',
      groups:                (e.groups as string[]) ?? [],
      directPolicies:        (e.directPolicies as VaptIamUserPolicyRef[]) ?? [],
      groupPolicies:         (e.groupPolicies as VaptIamUserGroupPolicyRef[]) ?? [],
      assumableRoles:        (e.assumableRoles as VaptIamUserAssumableRole[]) ?? [],
      hasOpenEndedAccess:    Boolean(e.hasOpenEndedAccess),
      mfaEnabled:            Boolean(e.mfaEnabled),
      passwordEnabled:       Boolean(e.passwordEnabled),
      passwordAgeDays:       (e.passwordAgeDays as number | null) ?? null,
      passwordStale:         Boolean(e.passwordStale),
      accessKeysActive:      (e.accessKeysActive as number) ?? 0,
      accessKeyAgeDays:      (e.accessKeyAgeDays as number | null) ?? null,
      keyStale:              Boolean(e.keyStale),
      hasNeverUsedActiveKey: Boolean(e.hasNeverUsedActiveKey),
    };
  });
  // Highest-risk users first, matching routes/iamUsers.ts.
  iamUsers.sort((a, b) => {
    if (a.hasOpenEndedAccess !== b.hasOpenEndedAccess) return a.hasOpenEndedAccess ? -1 : 1;
    const issues = (u: VaptIamUser) => Number(!u.mfaEnabled) + Number(u.passwordStale) + Number(u.keyStale);
    return issues(b) - issues(a);
  });

  return {
    provider:          'AWS',
    targetName:        account.name,
    targetExternalId:  account.awsAccountId,
    generatedAt:       new Date(),
    lastScanAt:        latestScan?.completedAt ?? null,
    appliedFilters:    filters,
    summary:           toSummary(summaryCounts),
    riskScore:         risk,
    riskRating:        riskRating(risk),
    frameworkScores:   frameworkScores.map(({ controls: _c, ...rest }) => rest),
    iamUsers,
    findings: findings.map(f => ({
      severity: f.severity, service: f.service, title: f.title, description: f.description,
      remediation: f.remediation, resourceName: null, discoveredAt: f.discoveredAt,
      complianceTags: uniqueFrameworkNames(getComplianceTags(f.title, f.checkId)),
    })),
    findingsTruncated:  findingsTotalCount > FINDINGS_CAP,
    findingsTotalCount,
  };
}

// ─── Azure ──────────────────────────────────────────────────────────────────

async function buildAzureModel(targetId: string, filters: Required<VaptReportFilters>): Promise<VaptReportModel> {
  const sub = await prisma.azureSubscription.findUnique({ where: { id: targetId } });
  if (!sub) throw new Error('Azure subscription not found');

  const latestScan = await prisma.azureScan.findFirst({
    where:   { subscriptionId: targetId, status: 'COMPLETED' },
    orderBy: { completedAt: 'desc' },
    include: { summary: true },
  });

  const extra = extraFilterConditions(filters, 'azure');
  const findMany_where: Prisma.AzureFindingWhereInput = {
    scan: { subscriptionId: targetId }, findingStatus: { in: OPEN_STATUSES },
    ...(extra.length ? { AND: extra as Prisma.AzureFindingWhereInput[] } : {}),
  };

  const [findings, findingsTotalCount] = await Promise.all([
    prisma.azureFinding.findMany({ where: findMany_where, orderBy: { severity: 'asc' }, take: FINDINGS_CAP }),
    prisma.azureFinding.count({ where: findMany_where }),
  ]);

  // groupBy needs a flat scanId filter — see the AWS block above for why.
  const azureScanIds = (await prisma.azureScan.findMany({ where: { subscriptionId: targetId }, select: { id: true } })).map(s => s.id);
  const groupBy_where: Prisma.AzureFindingWhereInput = {
    scanId: { in: azureScanIds }, findingStatus: { in: OPEN_STATUSES },
    ...(extra.length ? { AND: extra as Prisma.AzureFindingWhereInput[] } : {}),
  };
  const [rows, severityRows] = await Promise.all([
    prisma.azureFinding.groupBy({ by: ['title'],    where: groupBy_where, _count: { title: true } }),
    prisma.azureFinding.groupBy({ by: ['severity'], where: groupBy_where, _count: { severity: true } }),
  ]);
  const titles = new Set<string>(rows.map(r => r.title));
  const counts = new Map<string, number>(rows.map(r => [r.title, r._count.title]));
  const frameworkScores: AzureFrameworkScore[] = scoreAzureFrameworks(titles, counts);

  const summaryCounts = tallyBySeverity(severityRows);
  const risk = computeRisk(summaryCounts.critical, summaryCounts.high, summaryCounts.medium, summaryCounts.low);

  return {
    provider:          'AZURE',
    targetName:        sub.name,
    targetExternalId:  sub.subscriptionId,
    generatedAt:       new Date(),
    lastScanAt:        latestScan?.completedAt ?? null,
    appliedFilters:    filters,
    summary:           toSummary(summaryCounts),
    riskScore:         risk,
    riskRating:        riskRating(risk),
    frameworkScores:   frameworkScores.map(({ controls: _c, ...rest }) => rest),
    iamUsers: null, // Azure user/role inventory isn't built yet — see the AWS block for the pattern to extend
    findings: findings.map(f => ({
      severity: f.severity, service: f.service, title: f.title, description: f.description,
      remediation: f.remediation, resourceName: f.resourceId ?? f.resourceGroup ?? null, discoveredAt: f.discoveredAt,
      complianceTags: uniqueFrameworkNames(getAzureComplianceTags(f.title)),
    })),
    findingsTruncated:  findingsTotalCount > FINDINGS_CAP,
    findingsTotalCount,
  };
}

// ─── GCP (no compliance-framework engine yet — findings + summary only) ──────

async function buildGcpModel(targetId: string, filters: Required<VaptReportFilters>): Promise<VaptReportModel> {
  const project = await prisma.gcpProject.findUnique({ where: { id: targetId } });
  if (!project) throw new Error('GCP project not found');

  const latestScan = await prisma.gcpScan.findFirst({
    where:   { projectId: targetId, status: 'COMPLETED' },
    orderBy: { completedAt: 'desc' },
    include: { summary: true },
  });

  const extra = extraFilterConditions(filters, 'gcp'); // GCP has no provider-specific filter — tags only
  const findMany_where: Prisma.GcpFindingWhereInput = {
    scan: { projectId: targetId }, findingStatus: { in: OPEN_STATUSES },
    ...(extra.length ? { AND: extra as Prisma.GcpFindingWhereInput[] } : {}),
  };

  // groupBy needs a flat scanId filter — see the AWS block above for why.
  const gcpScanIds = (await prisma.gcpScan.findMany({ where: { projectId: targetId }, select: { id: true } })).map(s => s.id);
  const groupBy_where: Prisma.GcpFindingWhereInput = {
    scanId: { in: gcpScanIds }, findingStatus: { in: OPEN_STATUSES },
    ...(extra.length ? { AND: extra as Prisma.GcpFindingWhereInput[] } : {}),
  };

  const [findings, findingsTotalCount, severityRows] = await Promise.all([
    prisma.gcpFinding.findMany({ where: findMany_where, orderBy: { severity: 'asc' }, take: FINDINGS_CAP }),
    prisma.gcpFinding.count({ where: findMany_where }),
    prisma.gcpFinding.groupBy({ by: ['severity'], where: groupBy_where, _count: { severity: true } }),
  ]);

  const summaryCounts = tallyBySeverity(severityRows);
  const risk = computeRisk(summaryCounts.critical, summaryCounts.high, summaryCounts.medium, summaryCounts.low);

  return {
    provider:          'GCP',
    targetName:        project.name,
    targetExternalId:  project.projectId,
    generatedAt:       new Date(),
    lastScanAt:        latestScan?.completedAt ?? null,
    appliedFilters:    filters,
    summary:           toSummary(summaryCounts),
    riskScore:         risk,
    riskRating:        riskRating(risk),
    frameworkScores:   null,
    iamUsers:          null, // GCP has no IAM user inventory yet
    findings: findings.map(f => ({
      severity: f.severity, service: f.service, title: f.title, description: f.description,
      remediation: f.remediation, resourceName: f.resourceName ?? null, discoveredAt: f.discoveredAt,
      complianceTags: [], // GCP has no compliance-framework engine yet
    })),
    findingsTruncated:  findingsTotalCount > FINDINGS_CAP,
    findingsTotalCount,
  };
}

export async function buildVaptReportModel(
  provider: ReportProvider,
  targetId: string,
  filters?: VaptReportFilters,
): Promise<VaptReportModel> {
  const norm = normalizeFilters(filters);
  if (provider === 'AWS')   return buildAwsModel(targetId, norm);
  if (provider === 'AZURE') return buildAzureModel(targetId, norm);
  if (provider === 'GCP')   return buildGcpModel(targetId, norm);
  throw new Error(`Unknown provider "${provider as string}"`);
}

// ─── Filter option discovery (populates the filter UI with real values) ─────

export async function getVaptFilterOptions(provider: ReportProvider, targetId: string): Promise<VaptFilterOptions> {
  if (provider === 'AWS') {
    const account = await prisma.account.findUnique({ where: { id: targetId }, select: { id: true } });
    if (!account) throw new Error('AWS account not found');

    const rows = await prisma.finding.findMany({
      where:  { scan: { accountId: targetId }, findingStatus: { in: OPEN_STATUSES } },
      select: { tags: true, evidence: true },
      take:   FILTER_OPTIONS_SCAN_CAP,
    });
    const tags = new Set<string>();
    const regions = new Set<string>();
    for (const r of rows) {
      for (const t of r.tags) tags.add(t);
      const region = (r.evidence as { region?: unknown } | null)?.region;
      if (typeof region === 'string' && region) regions.add(region);
    }
    return { tags: [...tags].sort(), regions: [...regions].sort() };
  }

  if (provider === 'AZURE') {
    const sub = await prisma.azureSubscription.findUnique({ where: { id: targetId }, select: { id: true } });
    if (!sub) throw new Error('Azure subscription not found');

    const [tagRows, rgRows] = await Promise.all([
      prisma.azureFinding.findMany({
        where:  { scan: { subscriptionId: targetId }, findingStatus: { in: OPEN_STATUSES } },
        select: { tags: true },
        take:   FILTER_OPTIONS_SCAN_CAP,
      }),
      prisma.azureFinding.findMany({
        where:    { scan: { subscriptionId: targetId }, findingStatus: { in: OPEN_STATUSES }, resourceGroup: { not: null } },
        select:   { resourceGroup: true },
        distinct: ['resourceGroup'],
      }),
    ]);
    const tags = new Set<string>();
    for (const r of tagRows) for (const t of r.tags) tags.add(t);
    const resourceGroups = rgRows.map(r => r.resourceGroup).filter((x): x is string => !!x).sort();
    return { tags: [...tags].sort(), resourceGroups };
  }

  // GCP
  const project = await prisma.gcpProject.findUnique({ where: { id: targetId }, select: { id: true } });
  if (!project) throw new Error('GCP project not found');

  const rows = await prisma.gcpFinding.findMany({
    where:  { scan: { projectId: targetId }, findingStatus: { in: OPEN_STATUSES } },
    select: { tags: true },
    take:   FILTER_OPTIONS_SCAN_CAP,
  });
  const tags = new Set<string>();
  for (const r of rows) for (const t of r.tags) tags.add(t);
  return { tags: [...tags].sort() };
}

// Re-exported so callers/tests can enumerate framework metadata without a second import.
export const ALL_FRAMEWORK_DEFS = { AWS: FRAMEWORKS, AZURE: AZURE_FRAMEWORKS };

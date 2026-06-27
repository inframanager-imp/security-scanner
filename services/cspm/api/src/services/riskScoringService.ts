/**
 * Risk Scoring Service
 *
 * Enriches each finding with a composite risk score (0–100):
 *
 *   riskScore = base(severity) × reachabilityMult × businessMult × exploitMult
 *
 * Where:
 *   base:        CRITICAL=100, HIGH=70, MEDIUM=40, LOW=20, INFO=10
 *   reachability multiplier:  PUBLIC=1.0, INTERNAL=0.75, PRIVATE=0.6
 *   business multiplier:      prod or PCI=1.0, staging=0.75, dev=0.5, untagged=0.85
 *   exploit multiplier:       KNOWN_EXPLOIT=1.0, POC=0.95, THEORETICAL=0.85, null=0.9
 *
 * Reachability is read from ExposurePath; business context from resource tags;
 * exploitability is best-effort (Phase 5 will populate this from CWPP feeds).
 *
 * Used as a post-insert hook by scanWorker / azureScanWorker / gcpScanWorker.
 */

import { prisma } from '../config/database';
import { logger } from '../config/logger';

type Provider = 'AWS' | 'AZURE' | 'GCP';

const BASE_BY_SEVERITY: Record<string, number> = {
  CRITICAL: 100,
  HIGH:     70,
  MEDIUM:   40,
  LOW:      20,
  INFO:     10,
};

const REACHABILITY_MULT = { PUBLIC: 1.0, INTERNAL: 0.75, PRIVATE: 0.6 };
const EXPLOIT_MULT      = { KNOWN_EXPLOIT: 1.0, POC: 0.95, THEORETICAL: 0.85 };

const PROD_PATTERNS = /\b(prod|production|live|live-prod)\b/i;
const STAGING_PATTERNS = /\b(stag|stage|staging|preprod|uat)\b/i;
const DEV_PATTERNS = /\b(dev|development|test|sandbox|qa)\b/i;
const PCI_PATTERNS = /\b(pci|cardholder|payment)\b/i;
const PII_PATTERNS = /\b(pii|phi|hipaa)\b/i;

function pickModel(provider: Provider) {
  if (provider === 'AWS')   return prisma.finding;
  if (provider === 'AZURE') return prisma.azureFinding;
  return prisma.gcpFinding;
}

export async function enrichRecentFindings(
  provider: Provider,
  scanId: string,
): Promise<{ enriched: number }> {
  const model = pickModel(provider);
  const findings = await (model as any).findMany({
    where: { scanId, enrichedAt: null },
    select: { id: true, severity: true, evidence: true, tags: true },
  });

  if (findings.length === 0) return { enriched: 0 };

  // Map evidence.resourceId / nativeId → ResourceInventory to find exposure + tags
  const nativeIds = new Set<string>();
  for (const f of findings) {
    const e = (f.evidence ?? {}) as Record<string, unknown>;
    for (const key of ['resourceId', 'arn', 'bucket', 'functionName', 'tableName', 'dbId', 'clusterId', 'targetGroupArn', 'lbArn', 'aclArn']) {
      const v = e[key];
      if (typeof v === 'string' && v.length > 0) nativeIds.add(v);
    }
  }

  let inventoryByNativeId = new Map<string, any>();
  if (nativeIds.size > 0) {
    const inv = await prisma.resourceInventory.findMany({
      where: { nativeId: { in: Array.from(nativeIds) }, provider },
      select: {
        id: true, nativeId: true, tags: true,
        exposurePaths: { select: { exposureType: true }, take: 1 },
      },
    });
    inventoryByNativeId = new Map(inv.map((r) => [r.nativeId, r]));
  }

  const updates = findings.map(async (f: any) => {
    const reachability = lookupReachability(f.evidence, inventoryByNativeId);
    const businessContext = lookupBusinessContext(f.evidence, f.tags, inventoryByNativeId);
    const exploitability: 'KNOWN_EXPLOIT' | 'POC' | 'THEORETICAL' | null = null;
    const score = computeRiskScore(f.severity, reachability, businessContext, exploitability);
    return (model as any).update({
      where: { id: f.id },
      data: {
        riskScore: score,
        reachability,
        businessContext,
        exploitability,
        enrichedAt: new Date(),
      },
    });
  });
  await Promise.all(updates);

  logger.info('riskScoring.enriched', { provider, scanId, count: findings.length });
  return { enriched: findings.length };
}

function lookupReachability(
  evidence: any,
  inventoryByNativeId: Map<string, any>,
): 'PUBLIC' | 'INTERNAL' | 'PRIVATE' {
  const e = evidence ?? {};
  const candidates = [e.resourceId, e.arn, e.bucket, e.functionName, e.tableName, e.dbId, e.clusterId].filter(
    (v) => typeof v === 'string',
  );
  for (const c of candidates) {
    const r = inventoryByNativeId.get(c);
    if (r && r.exposurePaths.length > 0) {
      const exp = r.exposurePaths[0].exposureType;
      if (exp === 'PUBLIC_INTERNET') return 'PUBLIC';
      if (exp === 'VPN_ONLY') return 'INTERNAL';
    }
  }
  return 'PRIVATE';
}

function lookupBusinessContext(
  evidence: any,
  tags: string[] | undefined,
  inventoryByNativeId: Map<string, any>,
): { env?: string; sensitivity?: string; pciScope?: boolean; piiScope?: boolean } {
  const ctx: any = {};
  const text = [...(tags ?? []), JSON.stringify(evidence ?? {})].join(' ');

  // resource tags from inventory
  const candidates = [evidence?.resourceId, evidence?.arn, evidence?.bucket].filter((v) => typeof v === 'string');
  for (const c of candidates) {
    const r = inventoryByNativeId.get(c);
    if (r?.tags) {
      const t = r.tags as Record<string, string>;
      const envTag = Object.entries(t).find(([k]) => /env|environment/i.test(k))?.[1];
      if (envTag) ctx.env = String(envTag);
    }
  }
  if (!ctx.env) {
    if (PROD_PATTERNS.test(text)) ctx.env = 'prod';
    else if (STAGING_PATTERNS.test(text)) ctx.env = 'staging';
    else if (DEV_PATTERNS.test(text)) ctx.env = 'dev';
  }
  if (PCI_PATTERNS.test(text)) ctx.pciScope = true;
  if (PII_PATTERNS.test(text)) ctx.piiScope = true;
  return ctx;
}

function computeRiskScore(
  severity: string,
  reachability: 'PUBLIC' | 'INTERNAL' | 'PRIVATE',
  businessContext: { env?: string; pciScope?: boolean; piiScope?: boolean },
  exploitability: 'KNOWN_EXPLOIT' | 'POC' | 'THEORETICAL' | null,
): number {
  const base = BASE_BY_SEVERITY[severity] ?? 30;
  const reachMult = REACHABILITY_MULT[reachability];
  let bizMult: number;
  if (businessContext.pciScope || businessContext.piiScope) bizMult = 1.0;
  else if (businessContext.env === 'prod')    bizMult = 1.0;
  else if (businessContext.env === 'staging') bizMult = 0.75;
  else if (businessContext.env === 'dev')     bizMult = 0.5;
  else bizMult = 0.85;
  const exploitMult = exploitability ? EXPLOIT_MULT[exploitability] : 0.9;

  const raw = base * reachMult * bizMult * exploitMult;
  return Math.max(0, Math.min(100, Math.round(raw)));
}

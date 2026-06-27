/**
 * Risk Posture Score Service
 *
 * Computes a 0–100 score per subscription representing its current security posture.
 *
 * Scoring formula (penalties subtracted from 100):
 *   CRITICAL open changes      : -15 each  (cap 3  → max -45)
 *   HIGH open changes          : -8  each  (cap 4  → max -32)
 *   MEDIUM open changes        : -3  each  (cap 5  → max -15)
 *   LOW open changes           : -1  each  (cap 5  → max  -5)
 *   Unacknowledged CRITICAL >24h: -5 each  (cap 3  → max -15)
 *   Freeze violations (30d)    : -10 each  (cap 2  → max -20)
 *                                          ─────────────
 *                                    worst: -132 → floor 0
 *
 * Grade:   A 85–100 · B 70–84 · C 55–69 · D 40–54 · F 0–39
 */

import { prisma } from '../config/database';
import { logger } from '../config/logger';

export interface PostureResult {
  score:           number;
  grade:           'A' | 'B' | 'C' | 'D' | 'F';
  criticalOpen:    number;
  highOpen:        number;
  mediumOpen:      number;
  lowOpen:         number;
  freezeViolations: number;
}

function grade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function buildWhere(provider: string, targetId: string) {
  if (provider === 'AWS')   return { awsAccountId: targetId };
  if (provider === 'AZURE') return { azureSubId:   targetId };
  return { gcpProjectId: targetId };
}

export async function computePostureScore(provider: string, targetId: string): Promise<PostureResult> {
  const where = buildWhere(provider, targetId);
  const since24h  = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const since30d  = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [bySeverity, unackedCritical, freezeViol] = await Promise.all([
    // Open changes grouped by severity
    prisma.configChange.groupBy({
      by:    ['severity'],
      where: { ...where, changeStatus: 'OPEN' },
      _count: { id: true },
    }),
    // CRITICAL open changes not acknowledged within 24h
    prisma.configChange.count({
      where: {
        ...where,
        severity:     'CRITICAL',
        changeStatus: 'OPEN',
        createdAt:    { lt: since24h },
      },
    }),
    // Freeze violations in last 30 days
    prisma.configChange.count({
      where: {
        ...where,
        freezeViolation: true,
        eventTime:       { gte: since30d },
      },
    }),
  ]);

  const sevMap = Object.fromEntries(bySeverity.map((r) => [r.severity, r._count.id]));
  const criticalOpen = sevMap['CRITICAL'] ?? 0;
  const highOpen     = sevMap['HIGH']     ?? 0;
  const mediumOpen   = sevMap['MEDIUM']   ?? 0;
  const lowOpen      = sevMap['LOW']      ?? 0;

  const penalty =
    Math.min(criticalOpen,    3) * 15 +
    Math.min(highOpen,        4) * 8  +
    Math.min(mediumOpen,      5) * 3  +
    Math.min(lowOpen,         5) * 1  +
    Math.min(unackedCritical, 3) * 5  +
    Math.min(freezeViol,      2) * 10;

  const score  = Math.max(0, 100 - penalty);
  const result = { score, grade: grade(score), criticalOpen, highOpen, mediumOpen, lowOpen, freezeViolations: freezeViol };

  // Persist to history
  await prisma.postureScore.create({
    data: { provider, targetId, ...result },
  });

  return result;
}

/**
 * Compute and store posture scores for all READY accounts.
 * Called every 5 minutes from app.ts.
 */
export async function runPostureScoreUpdate(): Promise<void> {
  const [awsAccounts, azureSubs, gcpProjects] = await Promise.all([
    prisma.account.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
    prisma.azureSubscription.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
    prisma.gcpProject.findMany({ where: { inventoryStatus: 'READY' }, select: { id: true } }),
  ]);

  const targets = [
    ...awsAccounts.map(a => ({ provider: 'AWS',   targetId: a.id })),
    ...azureSubs.map(s  => ({ provider: 'AZURE',  targetId: s.id })),
    ...gcpProjects.map(p => ({ provider: 'GCP',   targetId: p.id })),
  ];

  await Promise.allSettled(
    targets.map(async ({ provider, targetId }) => {
      try {
        const result = await computePostureScore(provider, targetId);
        logger.debug(`[posture] ${provider}:${targetId.slice(0, 8)} → ${result.score} (${result.grade})`);
      } catch (err) {
        logger.warn(`[posture] Failed for ${provider}:${targetId.slice(0, 8)}: ${(err as Error).message}`);
      }
    }),
  );
}

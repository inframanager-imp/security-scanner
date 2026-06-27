/**
 * One-time deduplication script for existing Finding records.
 *
 * Duplicate definition: two or more findings in the same AWS account that share
 * the same  service + title + resource fingerprint.
 *
 * Strategy:
 *   - Keep the OLDEST finding in each duplicate group (lowest createdAt).
 *   - If an older duplicate is RESOLVED/FALSE_POSITIVE but a newer one is OPEN,
 *     keep the newer OPEN one instead so active issues stay visible.
 *   - Delete all others.
 *
 * Usage (from repo root):
 *   cd api
 *   npx ts-node src/scripts/deduplicateFindings.ts
 *
 * Optional: pass --dry-run to preview without deleting.
 */

import '../config/env';
import { prisma } from '../config/database';
import { logger } from '../config/logger';

const DRY_RUN = process.argv.includes('--dry-run');

// ─── Resource fingerprint ───────────────────────────────────────────────────
// Must match the same logic in scanWorker.ts so keys are comparable.
const FINGERPRINT_KEYS = [
  'functionName', 'trailName', 'bucket', 'username', 'accessKeyId',
  'keyId', 'dbId', 'clusterId', 'secretName', 'sgId', 'instanceId',
  'naclId', 'vpcId', 'requirementId', 'peeringConnectionId',
  'resourceId', 'resourceName', 'arn', 'name', 'id',
];

function resourceFingerprint(evidence: unknown): string {
  const e = (evidence ?? {}) as Record<string, unknown>;
  if (e.resourceId != null) return String(e.resourceId);
  for (const key of FINGERPRINT_KEYS) {
    if (e[key] != null) return String(e[key]);
  }
  return 'account-level';
}

// ─── Active status priority (lower = more worth keeping) ────────────────────
const STATUS_PRIORITY: Record<string, number> = {
  OPEN: 0,
  ACKNOWLEDGED: 1,
  RESOLVED: 2,
  FALSE_POSITIVE: 3,
};

async function run(): Promise<void> {
  logger.info(`=== Finding Deduplication ${DRY_RUN ? '[DRY RUN]' : ''} ===`);

  // 1. Load all findings with the account ID we need for grouping
  logger.info('Loading all findings...');
  const all = await prisma.finding.findMany({
    select: {
      id: true,
      service: true,
      title: true,
      evidence: true,
      findingStatus: true,
      createdAt: true,
      scan: { select: { accountId: true } },
    },
    orderBy: { createdAt: 'asc' }, // oldest first
  });

  logger.info(`Loaded ${all.length} total findings.`);

  // 2. Group by dedup key: accountId:service:title:resourceFingerprint
  const groups = new Map<string, typeof all>();

  for (const f of all) {
    const key = [
      f.scan.accountId,
      f.service,
      f.title,
      resourceFingerprint(f.evidence),
    ].join('::');

    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(f);
  }

  // 3. Identify duplicates within each group
  const toDelete: string[] = [];
  let groupsWithDuplicates = 0;

  for (const [key, members] of groups) {
    if (members.length <= 1) continue; // no duplicates
    groupsWithDuplicates++;

    // Sort: prefer OPEN/ACKNOWLEDGED over RESOLVED/FALSE_POSITIVE,
    // then oldest first within the same priority.
    members.sort((a, b) => {
      const pa = STATUS_PRIORITY[a.findingStatus] ?? 99;
      const pb = STATUS_PRIORITY[b.findingStatus] ?? 99;
      if (pa !== pb) return pa - pb;
      return a.createdAt.getTime() - b.createdAt.getTime();
    });

    const [keep, ...duplicates] = members;
    toDelete.push(...duplicates.map((d) => d.id));

    logger.info(
      `  Duplicate group: "${key.split('::').slice(1).join(' | ')}" — ` +
      `keeping ${keep.id} (${keep.findingStatus}, ${keep.createdAt.toISOString()}), ` +
      `removing ${duplicates.length} duplicate(s)`,
    );
  }

  logger.info(`\nSummary:`);
  logger.info(`  Duplicate groups found : ${groupsWithDuplicates}`);
  logger.info(`  Findings to delete     : ${toDelete.length}`);
  logger.info(`  Findings to keep       : ${all.length - toDelete.length}`);

  if (toDelete.length === 0) {
    logger.info('No duplicates found — database is clean.');
    await prisma.$disconnect();
    return;
  }

  if (DRY_RUN) {
    logger.info('\n[DRY RUN] No changes made. Re-run without --dry-run to apply.');
    await prisma.$disconnect();
    return;
  }

  // 4. Delete in batches of 500 to avoid query size limits
  const BATCH = 500;
  let deleted = 0;
  for (let i = 0; i < toDelete.length; i += BATCH) {
    const batch = toDelete.slice(i, i + BATCH);
    const result = await prisma.finding.deleteMany({
      where: { id: { in: batch } },
    });
    deleted += result.count;
    logger.info(`  Deleted batch ${Math.floor(i / BATCH) + 1}: ${result.count} records`);
  }

  logger.info(`\n✓ Done. Deleted ${deleted} duplicate findings.`);
  await prisma.$disconnect();
}

run().catch(async (err) => {
  logger.error('Deduplication failed', { error: (err as Error).message });
  await prisma.$disconnect();
  process.exit(1);
});

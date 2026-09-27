import { prisma } from './database';
import { runAsSystem, runWithTenant } from './tenantContext';
import { logger } from './logger';

/**
 * Tenant context helpers for background work (BullMQ workers, schedulers).
 *
 * Workers receive a target id in their job data but no tenant. Look the
 * organization up from the target row (in system context) and run the job
 * inside that tenant so every query the job makes is scoped automatically.
 */

export type TargetProvider = 'AWS' | 'AZURE' | 'GCP';

/** orgId of a cloud target row, or null if the target no longer exists. */
export async function orgIdOfTarget(provider: TargetProvider, targetId: string): Promise<string | null> {
  return runAsSystem(async () => {
    const select = { orgId: true } as const;
    switch (provider) {
      case 'AWS':   return (await prisma.account.findUnique({ where: { id: targetId }, select }))?.orgId ?? null;
      case 'AZURE': return (await prisma.azureSubscription.findUnique({ where: { id: targetId }, select }))?.orgId ?? null;
      case 'GCP':   return (await prisma.gcpProject.findUnique({ where: { id: targetId }, select }))?.orgId ?? null;
    }
  });
}

/** orgId of a scan row (AWS Scan / AzureScan / GcpScan). */
export async function orgIdOfScan(provider: TargetProvider, scanId: string): Promise<string | null> {
  return runAsSystem(async () => {
    const select = { orgId: true } as const;
    switch (provider) {
      case 'AWS':   return (await prisma.scan.findUnique({ where: { id: scanId }, select }))?.orgId ?? null;
      case 'AZURE': return (await prisma.azureScan.findUnique({ where: { id: scanId }, select }))?.orgId ?? null;
      case 'GCP':   return (await prisma.gcpScan.findUnique({ where: { id: scanId }, select }))?.orgId ?? null;
    }
  });
}

/**
 * Run `fn` inside the tenant that owns the given target. Throws when the
 * target is gone so the job fails loudly instead of running unscoped.
 */
export async function runForTarget<T>(provider: TargetProvider, targetId: string, fn: () => Promise<T>): Promise<T> {
  const orgId = await orgIdOfTarget(provider, targetId);
  if (!orgId) throw new Error(`[tenant] ${provider} target ${targetId} not found; refusing to run job unscoped`);
  return runWithTenant(orgId, fn);
}

export async function runForScan<T>(provider: TargetProvider, scanId: string, fn: () => Promise<T>): Promise<T> {
  const orgId = await orgIdOfScan(provider, scanId);
  if (!orgId) throw new Error(`[tenant] ${provider} scan ${scanId} not found; refusing to run job unscoped`);
  return runWithTenant(orgId, fn);
}

/** Run `fn` once per active tenant, sequentially; one tenant's failure never stops the others. */
export async function forEachTenant(label: string, fn: (tenantId: string) => Promise<void>): Promise<void> {
  const tenants = await runAsSystem(() => prisma.tenant.findMany({ where: { isActive: true }, select: { id: true, slug: true } }));
  for (const t of tenants) {
    try {
      await runWithTenant(t.id, () => fn(t.id));
    } catch (err) {
      logger.error(`[${label}] failed for tenant ${t.slug}: ${(err as Error).message}`);
    }
  }
}

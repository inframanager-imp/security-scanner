import { AsyncLocalStorage } from 'async_hooks';

/**
 * Tenant context for the current unit of work.
 *
 * Every HTTP request runs inside `runWithTenant(tenantId, …)` (set by the
 * `tenantScope` middleware from the JWT), and every background job must
 * wrap its work the same way so the Prisma tenant extension can scope
 * queries. Code that legitimately spans tenants (seeding, cross-tenant
 * schedulers that fan out per tenant) uses `runAsSystem`.
 *
 * The Prisma extension treats "no context" as a programming error for
 * tenant-owned models, so forgetting to set context fails closed.
 */

export interface TenantContext {
  tenantId: string | null; // null = system (unscoped) context
  system: boolean;
  userId?: string;
}

const storage = new AsyncLocalStorage<TenantContext>();

export function runWithTenant<T>(tenantId: string, fn: () => T, userId?: string): T {
  return storage.run({ tenantId, system: false, userId }, fn);
}

export function runAsSystem<T>(fn: () => T): T {
  return storage.run({ tenantId: null, system: true }, fn);
}

export function getTenantContext(): TenantContext | undefined {
  return storage.getStore();
}

/** Current tenant id, or throws when called outside any context. */
export function requireTenantId(): string {
  const ctx = storage.getStore();
  if (!ctx) throw new Error('No tenant context: wrap this call in runWithTenant() or runAsSystem()');
  if (ctx.system || !ctx.tenantId) throw new Error('System context has no tenant id');
  return ctx.tenantId;
}

export function isSystemContext(): boolean {
  return storage.getStore()?.system === true;
}

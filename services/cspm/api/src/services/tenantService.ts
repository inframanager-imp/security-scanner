import { Prisma } from '@prisma/client';
import { prisma } from '../config/database';
import { runAsSystem } from '../config/tenantContext';

/**
 * Tenant resolution for authentication.
 *
 * Everything here runs in system context because it is called before a
 * tenant context exists (login/refresh) or spans tenants (super admin).
 */

export const DEFAULT_TENANT_SLUG = 'default';
export const DEFAULT_TENANT_NAME = 'Default Organization';

export interface ActiveTenant {
  tenantId: string | null;
  role: string;
  isSuperAdmin: boolean;
}

export interface MembershipSummary {
  tenantId: string;
  slug: string;
  name: string;
  role: string;
}

export async function listMemberships(userId: string): Promise<MembershipSummary[]> {
  return runAsSystem(async () => {
    const rows = await prisma.tenantMembership.findMany({
      where: { userId, tenant: { isActive: true } },
      include: { tenant: { select: { id: true, slug: true, name: true } } },
      orderBy: { tenant: { name: 'asc' } },
    });
    return rows.map((m) => ({ tenantId: m.tenant.id, slug: m.tenant.slug, name: m.tenant.name, role: m.role }));
  });
}

/**
 * Pick the tenant a session should run in.
 *   1. `requested` if the user is a member (or a super admin) of it
 *   2. the user's lastTenantId if still a member
 *   3. the first membership
 *   4. super admin with no memberships: system context (tenantId null)
 * Returns null when a normal user has no memberships at all.
 */
export async function resolveActiveTenant(
  user: { id: string; role: string; isSuperAdmin: boolean; lastTenantId: string | null },
  requested?: string | null
): Promise<ActiveTenant | null> {
  return runAsSystem(async () => {
    const memberships = await prisma.tenantMembership.findMany({
      where: { userId: user.id, tenant: { isActive: true } },
      select: { tenantId: true, role: true },
    });
    const byId = new Map(memberships.map((m) => [m.tenantId, m.role]));

    const pick = (id: string | null | undefined): ActiveTenant | null => {
      if (!id) return null;
      if (byId.has(id)) return { tenantId: id, role: byId.get(id)!, isSuperAdmin: user.isSuperAdmin };
      return null;
    };

    if (requested) {
      const m = pick(requested);
      if (m) return m;
      if (user.isSuperAdmin) {
        const t = await prisma.tenant.findFirst({ where: { id: requested, isActive: true }, select: { id: true } });
        if (t) return { tenantId: t.id, role: 'ADMIN', isSuperAdmin: true };
      }
      return null;
    }

    return (
      pick(user.lastTenantId) ??
      (memberships[0] ? { tenantId: memberships[0].tenantId, role: memberships[0].role, isSuperAdmin: user.isSuperAdmin } : null) ??
      (user.isSuperAdmin ? { tenantId: null, role: 'ADMIN', isSuperAdmin: true } : null)
    );
  });
}

export async function rememberTenant(userId: string, tenantId: string | null): Promise<void> {
  await runAsSystem(() => prisma.user.update({ where: { id: userId }, data: { lastTenantId: tenantId } }));
}

export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'org';
}

export async function createTenant(input: { name: string; slug?: string; settings?: Prisma.InputJsonValue }) {
  return runAsSystem(async () => {
    const base = slugify(input.slug ?? input.name);
    let slug = base;
    for (let i = 2; await prisma.tenant.findUnique({ where: { slug } }); i++) slug = `${base}-${i}`;
    return prisma.tenant.create({ data: { name: input.name, slug, settings: input.settings ?? {} } });
  });
}

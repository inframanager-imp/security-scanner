import { prisma } from './config/database';
import { runAsSystem } from './config/tenantContext';
import * as authService from './services/authService';
import { DEFAULT_TENANT_NAME, DEFAULT_TENANT_SLUG } from './services/tenantService';
import { env } from './config/env';
import { logger } from './config/logger';

/** Fixed id so migrations and seed agree on the default organization. */
export const DEFAULT_TENANT_ID = '00000000-0000-4000-8000-000000000001';

/**
 * Idempotent bootstrap:
 *   1. the default organization exists,
 *   2. the ADMIN_EMAIL user exists, is a platform super admin, and is an
 *      ADMIN member of the default organization,
 *   3. every user has at least one membership (legacy users get the default
 *      organization with their legacy role).
 */
export async function seed(): Promise<void> {
  await runAsSystem(async () => {
    const tenant = await prisma.tenant.upsert({
      where: { id: DEFAULT_TENANT_ID },
      update: {},
      create: { id: DEFAULT_TENANT_ID, slug: DEFAULT_TENANT_SLUG, name: DEFAULT_TENANT_NAME },
    });

    let admin = await prisma.user.findUnique({ where: { email: env.ADMIN_EMAIL } });
    if (!admin) {
      logger.info('Creating platform admin user...');
      admin = await prisma.user.create({
        data: {
          email: env.ADMIN_EMAIL,
          passwordHash: await authService.hashPassword(env.ADMIN_PASSWORD),
          role: 'ADMIN',
          isSuperAdmin: true,
          lastTenantId: tenant.id,
        },
      });
      logger.info(`Admin user created: ${admin.email}`);
    } else if (!admin.isSuperAdmin) {
      admin = await prisma.user.update({ where: { id: admin.id }, data: { isSuperAdmin: true } });
      logger.info(`Promoted ${admin.email} to platform super admin`);
    }

    await prisma.tenantMembership.upsert({
      where: { tenantId_userId: { tenantId: tenant.id, userId: admin.id } },
      update: { role: 'ADMIN' },
      create: { tenantId: tenant.id, userId: admin.id, role: 'ADMIN' },
    });

    const orphans = await prisma.user.findMany({
      where: { memberships: { none: {} } },
      select: { id: true, email: true, role: true },
    });
    for (const u of orphans) {
      await prisma.tenantMembership.create({ data: { tenantId: tenant.id, userId: u.id, role: u.role } });
      logger.info(`Added ${u.email} to ${tenant.name} as ${u.role}`);
    }
  });
}

if (require.main === module) {
  seed()
    .then(() => {
      logger.info('Seed completed');
      process.exit(0);
    })
    .catch((err) => {
      logger.error('Seed failed', { error: err.message });
      process.exit(1);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}

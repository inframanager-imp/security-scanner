import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { prisma } from '../config/database';
import { runAsSystem } from '../config/tenantContext';
import { authenticate } from '../middleware/authenticate';
import * as authService from '../services/authService';
import * as tenantService from '../services/tenantService';

/**
 * Tenants (customer organizations) and their members.
 *
 * Super-admin (platform operator) only:
 *   GET    /api/tenants                 list all tenants
 *   POST   /api/tenants                 create a tenant (+ optional first admin)
 *   PATCH  /api/tenants/:id             rename / activate / settings
 *
 * Tenant ADMIN (of the active tenant) or super-admin:
 *   GET    /api/tenants/current                 the active tenant
 *   GET    /api/tenants/current/members         members with roles
 *   POST   /api/tenants/current/members         add an existing user or create+invite one
 *   PATCH  /api/tenants/current/members/:userId change a member's role
 *   DELETE /api/tenants/current/members/:userId remove a member
 *
 * Docs: docs/api/tenants.md, docs/api/internal/tenancy-internal.md
 */

const router = Router();
router.use(authenticate);

function requireSuperAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!req.user?.isSuperAdmin) {
    res.status(403).json({ error: 'Forbidden', detail: 'Platform administrator access required' });
    return;
  }
  next();
}

function requireTenantAdmin(req: Request, res: Response, next: NextFunction): void {
  if (!req.user?.tenantId) {
    res.status(400).json({ error: 'No active tenant' });
    return;
  }
  if (req.user.role !== 'ADMIN' && !req.user.isSuperAdmin) {
    res.status(403).json({ error: 'Forbidden', detail: 'Organization administrator access required' });
    return;
  }
  next();
}

const roleSchema = z.enum(['ADMIN', 'ANALYST', 'VIEWER']);

const createTenantSchema = z.object({
  name: z.string().min(2).max(120),
  slug: z.string().min(2).max(48).regex(/^[a-z0-9-]+$/).optional(),
  admin: z
    .object({
      email: z.string().email(),
      password: z.string().min(8).optional(),
    })
    .optional(),
});

const patchTenantSchema = z.object({
  name: z.string().min(2).max(120).optional(),
  isActive: z.boolean().optional(),
  settings: z.record(z.unknown()).optional(),
});

const addMemberSchema = z.object({
  email: z.string().email(),
  role: roleSchema.default('VIEWER'),
  /** Only used when the user does not exist yet. */
  password: z.string().min(8).optional(),
});

const patchMemberSchema = z.object({ role: roleSchema });

function zodError(err: unknown, res: Response): boolean {
  if (err instanceof z.ZodError) {
    res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
    return true;
  }
  return false;
}

// ─── Platform-level ───────────────────────────────────────────────────────────

router.get('/', requireSuperAdmin, async (_req, res) => {
  const tenants = await runAsSystem(() =>
    prisma.tenant.findMany({
      orderBy: { name: 'asc' },
      include: { _count: { select: { memberships: true } } },
    })
  );
  res.json({ data: tenants.map((t) => ({ ...t, memberCount: t._count.memberships, _count: undefined })) });
});

router.post('/', requireSuperAdmin, async (req, res) => {
  try {
    const body = createTenantSchema.parse(req.body);
    const tenant = await tenantService.createTenant({ name: body.name, slug: body.slug });

    let admin: { id: string; email: string; temporaryPassword?: string } | null = null;
    if (body.admin) {
      admin = await runAsSystem(async () => {
        let user = await prisma.user.findUnique({ where: { email: body.admin!.email } });
        let temporaryPassword: string | undefined;
        if (!user) {
          temporaryPassword = body.admin!.password ?? authService.generateTemporaryPassword();
          user = await prisma.user.create({
            data: { email: body.admin!.email, passwordHash: await authService.hashPassword(temporaryPassword), role: 'ADMIN' },
          });
        }
        await prisma.tenantMembership.create({ data: { tenantId: tenant.id, userId: user.id, role: 'ADMIN' } });
        return { id: user.id, email: user.email, temporaryPassword: body.admin!.password ? undefined : temporaryPassword };
      });
    }

    res.status(201).json({ data: { tenant, admin } });
  } catch (err) {
    if (!zodError(err, res)) res.status(500).json({ error: 'Failed to create tenant' });
  }
});

router.patch('/:id', requireSuperAdmin, async (req, res) => {
  try {
    const body = patchTenantSchema.parse(req.body);
    const tenant = await runAsSystem(() =>
      prisma.tenant.update({
        where: { id: req.params.id },
        data: { ...body, settings: body.settings as never },
      })
    );
    res.json({ data: tenant });
  } catch (err) {
    if (!zodError(err, res)) res.status(404).json({ error: 'Tenant not found' });
  }
});

// ─── Active tenant ────────────────────────────────────────────────────────────

router.get('/current', async (req, res) => {
  if (!req.user?.tenantId) {
    res.json({ data: null });
    return;
  }
  const tenant = await runAsSystem(() =>
    prisma.tenant.findUnique({
      where: { id: req.user!.tenantId! },
      include: { _count: { select: { memberships: true } } },
    })
  );
  res.json({ data: tenant ? { ...tenant, memberCount: tenant._count.memberships, _count: undefined } : null });
});

router.get('/current/members', requireTenantAdmin, async (req, res) => {
  const rows = await runAsSystem(() =>
    prisma.tenantMembership.findMany({
      where: { tenantId: req.user!.tenantId! },
      include: { user: { select: { id: true, email: true, isActive: true, isSuperAdmin: true, createdAt: true } } },
      orderBy: { user: { email: 'asc' } },
    })
  );
  res.json({
    data: rows.map((m) => ({
      userId: m.user.id,
      email: m.user.email,
      role: m.role,
      isActive: m.user.isActive,
      isSuperAdmin: m.user.isSuperAdmin,
      joinedAt: m.createdAt,
    })),
  });
});

router.post('/current/members', requireTenantAdmin, async (req, res) => {
  try {
    const body = addMemberSchema.parse(req.body);
    const tenantId = req.user!.tenantId!;
    const result = await runAsSystem(async () => {
      let user = await prisma.user.findUnique({ where: { email: body.email } });
      let temporaryPassword: string | undefined;
      if (!user) {
        temporaryPassword = body.password ?? authService.generateTemporaryPassword();
        user = await prisma.user.create({
          data: { email: body.email, passwordHash: await authService.hashPassword(temporaryPassword), role: body.role },
        });
      }
      const existing = await prisma.tenantMembership.findUnique({ where: { tenantId_userId: { tenantId, userId: user.id } } });
      if (existing) return { conflict: true as const };
      const membership = await prisma.tenantMembership.create({ data: { tenantId, userId: user.id, role: body.role } });
      return {
        conflict: false as const,
        member: { userId: user.id, email: user.email, role: membership.role, joinedAt: membership.createdAt },
        temporaryPassword: body.password ? undefined : temporaryPassword,
      };
    });
    if (result.conflict) {
      res.status(409).json({ error: 'User is already a member of this organization' });
      return;
    }
    res.status(201).json({ data: result });
  } catch (err) {
    if (!zodError(err, res)) res.status(500).json({ error: 'Failed to add member' });
  }
});

router.patch('/current/members/:userId', requireTenantAdmin, async (req, res) => {
  try {
    const { role } = patchMemberSchema.parse(req.body);
    const tenantId = req.user!.tenantId!;
    const userId = req.params.userId;

    if (userId === req.user!.id && role !== 'ADMIN') {
      res.status(400).json({ error: 'You cannot remove your own administrator role' });
      return;
    }
    const membership = await runAsSystem(() =>
      prisma.tenantMembership.update({ where: { tenantId_userId: { tenantId, userId } }, data: { role } })
    );
    res.json({ data: { userId, role: membership.role } });
  } catch (err) {
    if (!zodError(err, res)) res.status(404).json({ error: 'Member not found' });
  }
});

router.delete('/current/members/:userId', requireTenantAdmin, async (req, res) => {
  const tenantId = req.user!.tenantId!;
  const userId = req.params.userId;
  if (userId === req.user!.id) {
    res.status(400).json({ error: 'You cannot remove yourself from the organization' });
    return;
  }
  const admins = await runAsSystem(() => prisma.tenantMembership.count({ where: { tenantId, role: 'ADMIN' } }));
  const target = await runAsSystem(() => prisma.tenantMembership.findUnique({ where: { tenantId_userId: { tenantId, userId } } }));
  if (!target) {
    res.status(404).json({ error: 'Member not found' });
    return;
  }
  if (target.role === 'ADMIN' && admins <= 1) {
    res.status(400).json({ error: 'An organization must keep at least one administrator' });
    return;
  }
  await runAsSystem(async () => {
    await prisma.tenantMembership.delete({ where: { tenantId_userId: { tenantId, userId } } });
    // Kill live sessions so the removed user is logged out of this tenant immediately.
    await prisma.session.deleteMany({ where: { userId } });
  });
  res.status(204).send();
});

export default router;

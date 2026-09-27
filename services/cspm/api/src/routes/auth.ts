import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import { prisma } from '../config/database';
import { runAsSystem } from '../config/tenantContext';
import * as authService from '../services/authService';
import * as tenantService from '../services/tenantService';
import { authenticate } from '../middleware/authenticate';

/**
 * Session lifecycle.
 *
 * POST /api/auth/login          email+password -> tokens for the user's active tenant
 * POST /api/auth/refresh        rotate tokens, keeping the active tenant
 * POST /api/auth/logout         revoke a refresh token
 * GET  /api/auth/me             current user, active tenant, memberships
 * POST /api/auth/switch-tenant  re-issue tokens for another tenant the user belongs to
 *
 * Docs: docs/api/auth.md, docs/api/internal/tenancy-internal.md
 */

const router = Router();

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  tenantId: z.string().uuid().optional(),
});

const refreshSchema = z.object({ refreshToken: z.string().min(1) });
const logoutSchema = z.object({ refreshToken: z.string().min(1) });
const switchSchema = z.object({ tenantId: z.string().uuid(), refreshToken: z.string().min(1) });

const REFRESH_DAYS = 7;

async function issueSession(user: { id: string; email: string; isSuperAdmin: boolean }, active: tenantService.ActiveTenant) {
  const accessToken = authService.generateAccessToken(user.id, active.role, active.tenantId, user.isSuperAdmin);
  const refreshToken = authService.generateRefreshToken(user.id, active.tenantId);
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + REFRESH_DAYS);
  await runAsSystem(() =>
    prisma.session.create({ data: { userId: user.id, tokenHash: hashToken(refreshToken), expiresAt } })
  );
  const [memberships, tenant] = await Promise.all([
    tenantService.listMemberships(user.id),
    active.tenantId
      ? runAsSystem(() => prisma.tenant.findUnique({ where: { id: active.tenantId! }, select: { id: true, slug: true, name: true } }))
      : Promise.resolve(null),
  ]);
  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      role: active.role,
      isSuperAdmin: user.isSuperAdmin,
      tenant,
      memberships,
    },
  };
}

function handleError(err: unknown, res: Response): void {
  if (err instanceof z.ZodError) {
    res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
    return;
  }
  res.status(500).json({ error: 'Internal server error' });
}

// POST /api/auth/login
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password, tenantId } = loginSchema.parse(req.body);

    const user = await runAsSystem(() => prisma.user.findUnique({ where: { email } }));
    if (!user || !user.isActive) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    const valid = await authService.verifyPassword(password, user.passwordHash);
    if (!valid) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    const active = await tenantService.resolveActiveTenant(user, tenantId);
    if (!active) {
      res.status(403).json({ error: 'Your account is not a member of any organization yet.' });
      return;
    }
    await tenantService.rememberTenant(user.id, active.tenantId);

    res.json({ data: await issueSession(user, active) });
  } catch (err) {
    handleError(err, res);
  }
});

// POST /api/auth/refresh
router.post('/refresh', async (req: Request, res: Response) => {
  try {
    const { refreshToken } = refreshSchema.parse(req.body);

    let claims: { userId: string; tenantId: string | null };
    try {
      claims = authService.verifyRefreshToken(refreshToken);
    } catch {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    const tokenHash = hashToken(refreshToken);
    const session = await runAsSystem(() => prisma.session.findUnique({ where: { tokenHash } }));
    if (!session || session.expiresAt < new Date()) {
      res.status(401).json({ error: 'Session not found or expired' });
      return;
    }
    if (session.userId !== claims.userId) {
      res.status(401).json({ error: 'Token mismatch' });
      return;
    }

    const user = await runAsSystem(() => prisma.user.findUnique({ where: { id: claims.userId } }));
    if (!user || !user.isActive) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    // Membership may have been revoked since the token was issued: re-resolve.
    const active = await tenantService.resolveActiveTenant(user, claims.tenantId);
    if (!active) {
      res.status(403).json({ error: 'Your access to this organization has been removed.' });
      return;
    }

    await runAsSystem(() => prisma.session.deleteMany({ where: { tokenHash } }));
    const data = await issueSession(user, active);
    res.json({ data: { accessToken: data.accessToken, refreshToken: data.refreshToken, user: data.user } });
  } catch (err) {
    handleError(err, res);
  }
});

// POST /api/auth/logout
router.post('/logout', async (req: Request, res: Response) => {
  try {
    const { refreshToken } = logoutSchema.parse(req.body);
    await runAsSystem(() => prisma.session.deleteMany({ where: { tokenHash: hashToken(refreshToken) } }));
    res.status(200).json({ data: { message: 'Logged out successfully' } });
  } catch (err) {
    handleError(err, res);
  }
});

// GET /api/auth/me
router.get('/me', authenticate, async (req: Request, res: Response) => {
  try {
    const me = req.user!;
    const user = await runAsSystem(() =>
      prisma.user.findUnique({
        where: { id: me.id },
        select: { id: true, email: true, isSuperAdmin: true, createdAt: true, updatedAt: true },
      })
    );
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    const [memberships, tenant] = await Promise.all([
      tenantService.listMemberships(user.id),
      me.tenantId
        ? runAsSystem(() => prisma.tenant.findUnique({ where: { id: me.tenantId! }, select: { id: true, slug: true, name: true } }))
        : Promise.resolve(null),
    ]);
    res.json({ data: { ...user, role: me.role, tenant, memberships } });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/switch-tenant
router.post('/switch-tenant', authenticate, async (req: Request, res: Response) => {
  try {
    const { tenantId, refreshToken } = switchSchema.parse(req.body);
    const user = await runAsSystem(() => prisma.user.findUnique({ where: { id: req.user!.id } }));
    if (!user || !user.isActive) {
      res.status(401).json({ error: 'User not found' });
      return;
    }
    const active = await tenantService.resolveActiveTenant(user, tenantId);
    if (!active) {
      res.status(403).json({ error: 'You are not a member of that organization.' });
      return;
    }
    // Revoke the old session so the previous tenant's refresh token dies with the switch.
    await runAsSystem(() => prisma.session.deleteMany({ where: { tokenHash: hashToken(refreshToken), userId: user.id } }));
    await tenantService.rememberTenant(user.id, active.tenantId);
    res.json({ data: await issueSession(user, active) });
  } catch (err) {
    handleError(err, res);
  }
});

export default router;

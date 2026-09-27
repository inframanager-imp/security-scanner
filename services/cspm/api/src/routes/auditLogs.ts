import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { Prisma } from '@prisma/client';
import { prisma } from '../config/database';
import { authenticate } from '../middleware/authenticate';
import { authorize } from '../middleware/authorize';

/**
 * Audit log — ADMIN only.
 *
 * GET /api/audit-logs            list, newest first, with filters + pagination
 * GET /api/audit-logs/actions    distinct action names (for filter dropdowns)
 * GET /api/audit-logs/:id        one entry incl. redacted request body
 *
 * Docs: docs/api/audit-logs.md (user-facing), docs/api/internal/audit-logs-internal.md
 */

const router = Router();
router.use(authenticate);
router.use(authorize('ADMIN'));

const listSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  userId: z.string().optional(),
  email: z.string().optional(),
  action: z.string().optional(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).optional(),
  outcome: z.enum(['SUCCESS', 'FAILED', 'DENIED']).optional(),
  path: z.string().optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
});

function present<T extends { user?: { email: string } | null; actorEmail: string | null }>(row: T) {
  const { user, ...rest } = row;
  return { ...rest, userEmail: user?.email ?? row.actorEmail ?? null };
}

router.get('/', async (req: Request, res: Response) => {
  const q = listSchema.parse(req.query);
  const where: Prisma.AuditLogWhereInput = {
    ...(q.userId && { userId: q.userId }),
    ...(q.action && { action: { contains: q.action, mode: 'insensitive' } }),
    ...(q.method && { method: q.method }),
    ...(q.outcome && { outcome: q.outcome }),
    ...(q.path && { path: { contains: q.path, mode: 'insensitive' } }),
    ...((q.from || q.to) && {
      createdAt: { ...(q.from && { gte: q.from }), ...(q.to && { lte: q.to }) },
    }),
    ...(q.email && {
      OR: [
        { actorEmail: { contains: q.email, mode: 'insensitive' } },
        { user: { email: { contains: q.email, mode: 'insensitive' } } },
      ],
    }),
  };

  const [total, rows] = await Promise.all([
    prisma.auditLog.count({ where }),
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (q.page - 1) * q.limit,
      take: q.limit,
      select: {
        id: true,
        createdAt: true,
        userId: true,
        userRole: true,
        actorEmail: true,
        action: true,
        method: true,
        path: true,
        statusCode: true,
        outcome: true,
        ip: true,
        durationMs: true,
        user: { select: { email: true } },
      },
    }),
  ]);

  res.json({
    data: rows.map(present),
    page: q.page,
    limit: q.limit,
    total,
    totalPages: Math.ceil(total / q.limit),
  });
});

router.get('/actions', async (_req: Request, res: Response) => {
  const rows = await prisma.auditLog.findMany({
    distinct: ['action'],
    select: { action: true },
    orderBy: { action: 'asc' },
  });
  res.json({ data: rows.map((r) => r.action) });
});

router.get('/:id', async (req: Request, res: Response) => {
  const row = await prisma.auditLog.findUnique({
    where: { id: req.params.id },
    include: { user: { select: { email: true } } },
  });
  if (!row) {
    res.status(404).json({ error: 'Audit entry not found' });
    return;
  }
  res.json({ data: present(row) });
});

export default router;

import { Request, Response, NextFunction } from 'express';
import * as authService from '../services/authService';
import { runWithTenant, runAsSystem } from '../config/tenantContext';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        role: string;
        tenantId: string | null;
        isSuperAdmin: boolean;
      };
    }
  }
}

export function authenticate(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  const token = authHeader.slice(7);

  try {
    const { userId, role, tenantId, isSuperAdmin } = authService.verifyAccessToken(token);
    req.user = { id: userId, role, tenantId, isSuperAdmin };
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  // Everything downstream (routes, services, Prisma extension) runs inside
  // the tenant context so data access is scoped without per-route code.
  if (req.user.tenantId) {
    runWithTenant(req.user.tenantId, () => next(), req.user.id);
    return;
  }
  if (req.user.isSuperAdmin) {
    runAsSystem(() => next());
    return;
  }
  res.status(403).json({ error: 'No active tenant. Ask an administrator to add you to an organization.' });
}

export default authenticate;

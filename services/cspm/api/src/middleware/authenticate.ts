import { Request, Response, NextFunction } from 'express';
import * as authService from '../services/authService';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        role: string;
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
    const { userId, role } = authService.verifyAccessToken(token);
    req.user = { id: userId, role };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export default authenticate;

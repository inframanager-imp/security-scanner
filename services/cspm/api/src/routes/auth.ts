import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import { prisma } from '../config/database';
import * as authService from '../services/authService';
import { authenticate } from '../middleware/authenticate';
import { env } from '../config/env';

const router = Router();

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const logoutSchema = z.object({
  refreshToken: z.string().min(1),
});

// POST /api/auth/login
router.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    const valid = await authService.verifyPassword(password, user.passwordHash);
    if (!valid) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    const accessToken = authService.generateAccessToken(user.id, user.role);
    const refreshToken = authService.generateRefreshToken(user.id);
    const tokenHash = hashToken(refreshToken);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await prisma.session.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
      },
    });

    res.json({
      data: {
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
      },
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/refresh
router.post('/refresh', async (req: Request, res: Response) => {
  try {
    const { refreshToken } = refreshSchema.parse(req.body);

    let userId: string;
    try {
      const payload = authService.verifyRefreshToken(refreshToken);
      userId = payload.userId;
    } catch {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    const tokenHash = hashToken(refreshToken);
    const session = await prisma.session.findUnique({ where: { tokenHash } });

    if (!session || session.expiresAt < new Date()) {
      res.status(401).json({ error: 'Session not found or expired' });
      return;
    }

    if (session.userId !== userId) {
      res.status(401).json({ error: 'Token mismatch' });
      return;
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      res.status(401).json({ error: 'User not found' });
      return;
    }

    await prisma.session.deleteMany({ where: { tokenHash } });

    const newAccessToken = authService.generateAccessToken(user.id, user.role);
    const newRefreshToken = authService.generateRefreshToken(user.id);
    const newTokenHash = hashToken(newRefreshToken);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await prisma.session.create({
      data: {
        userId: user.id,
        tokenHash: newTokenHash,
        expiresAt,
      },
    });

    res.json({
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      },
    });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout
router.post('/logout', authenticate, async (req: Request, res: Response) => {
  try {
    const { refreshToken } = logoutSchema.parse(req.body);
    const tokenHash = hashToken(refreshToken);

    await prisma.session.deleteMany({ where: { tokenHash } });

    res.status(200).json({ data: { message: 'Logged out successfully' } });
  } catch (err) {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'Validation error', details: err.flatten().fieldErrors });
      return;
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/me
router.get('/me', authenticate, async (req: Request, res: Response) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      select: {
        id: true,
        email: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    res.json({ data: user });
  } catch {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { env } from '../config/env';

const BCRYPT_COST = 12;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_COST);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export interface AccessClaims {
  userId: string;
  role: string;
  tenantId: string | null;
  isSuperAdmin: boolean;
}

/**
 * Access token claims: `sub` user id, `role` = role inside the active tenant,
 * `tid` = active tenant id (null only for a super admin with no tenant
 * selected), `sa` = super admin flag. The Python services read the same claims.
 */
export function generateAccessToken(
  userId: string,
  role: string,
  tenantId: string | null = null,
  isSuperAdmin = false
): string {
  return jwt.sign(
    { sub: userId, role, tid: tenantId, sa: isSuperAdmin, type: 'access' },
    env.JWT_ACCESS_SECRET,
    { expiresIn: env.JWT_ACCESS_EXPIRY } as jwt.SignOptions
  );
}

export function generateRefreshToken(userId: string, tenantId: string | null = null): string {
  return jwt.sign(
    { sub: userId, tid: tenantId, type: 'refresh' },
    env.JWT_REFRESH_SECRET,
    { expiresIn: env.JWT_REFRESH_EXPIRY } as jwt.SignOptions
  );
}

export function verifyAccessToken(token: string): AccessClaims {
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as jwt.JwtPayload;

  if (payload.type !== 'access') {
    throw new Error('Invalid token type');
  }

  if (!payload.sub || !payload.role) {
    throw new Error('Invalid token payload');
  }

  return {
    userId: payload.sub,
    role: payload.role as string,
    tenantId: typeof payload.tid === 'string' ? payload.tid : null,
    isSuperAdmin: payload.sa === true,
  };
}

export function verifyRefreshToken(token: string): { userId: string; tenantId: string | null } {
  const payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as jwt.JwtPayload;

  if (payload.type !== 'refresh') {
    throw new Error('Invalid token type');
  }

  if (!payload.sub) {
    throw new Error('Invalid token payload');
  }

  return { userId: payload.sub, tenantId: typeof payload.tid === 'string' ? payload.tid : null };
}

/** 16-char URL-safe temporary password for invited users; shown once to the inviter. */
export function generateTemporaryPassword(): string {
  return crypto.randomBytes(12).toString('base64url').slice(0, 16);
}

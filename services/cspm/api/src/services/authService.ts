import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';

const BCRYPT_COST = 12;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_COST);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function generateAccessToken(userId: string, role: string): string {
  return jwt.sign(
    { sub: userId, role, type: 'access' },
    env.JWT_ACCESS_SECRET,
    { expiresIn: env.JWT_ACCESS_EXPIRY } as jwt.SignOptions
  );
}

export function generateRefreshToken(userId: string): string {
  return jwt.sign(
    { sub: userId, type: 'refresh' },
    env.JWT_REFRESH_SECRET,
    { expiresIn: env.JWT_REFRESH_EXPIRY } as jwt.SignOptions
  );
}

export function verifyAccessToken(token: string): { userId: string; role: string } {
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as jwt.JwtPayload;

  if (payload.type !== 'access') {
    throw new Error('Invalid token type');
  }

  if (!payload.sub || !payload.role) {
    throw new Error('Invalid token payload');
  }

  return { userId: payload.sub, role: payload.role as string };
}

export function verifyRefreshToken(token: string): { userId: string } {
  const payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as jwt.JwtPayload;

  if (payload.type !== 'refresh') {
    throw new Error('Invalid token type');
  }

  if (!payload.sub) {
    throw new Error('Invalid token payload');
  }

  return { userId: payload.sub };
}

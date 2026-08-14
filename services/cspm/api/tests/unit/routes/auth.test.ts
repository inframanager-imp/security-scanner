import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { TestServer, buildTestApp } from './testHttp';

// auth.ts -> authService.ts / authenticate.ts -> config/env, which validates
// process.env via zod at import time and process.exit(1)s if incomplete.
// Set the required vars before anything imports env.ts (directly or transitively).
process.env.DATABASE_URL = 'postgresql://user:pass@localhost:5432/test';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.JWT_ACCESS_SECRET = 'test-access-secret-0123456789';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-0123456789';
process.env.CREDENTIAL_ENCRYPTION_KEY = '0'.repeat(64);
process.env.ADMIN_EMAIL = 'admin@example.com';
process.env.ADMIN_PASSWORD = 'password123';
process.env.NODE_ENV = 'test';

const mockUserFindUnique = jest.fn();
const mockSessionCreate = jest.fn();
const mockSessionFindUnique = jest.fn();
const mockSessionDelete = jest.fn();
const mockSessionDeleteMany = jest.fn();

jest.mock('../../../src/config/database', () => ({
  prisma: {
    user: { findUnique: mockUserFindUnique },
    session: {
      create: mockSessionCreate,
      findUnique: mockSessionFindUnique,
      delete: mockSessionDelete,
      deleteMany: mockSessionDeleteMany,
    },
  },
}));

const mockVerifyPassword = jest.fn();
jest.mock('../../../src/services/authService', () => {
  const actual = jest.requireActual('../../../src/services/authService') as any;
  return {
    ...actual,
    verifyPassword: mockVerifyPassword,
  };
});

import authRouter from '../../../src/routes/auth';
import * as authService from '../../../src/services/authService';

describe('routes/auth', () => {
  let server: TestServer;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = await TestServer.start(buildTestApp('/api/auth', authRouter));
  });

  afterEach(async () => {
    await server.close();
  });

  describe('POST /api/auth/login', () => {
    it('returns 400 for an invalid email', async () => {
      const res = await server.post('/api/auth/login', { email: 'not-an-email', password: 'x' });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation error');
      expect(res.body.details.email).toBeDefined();
    });

    it('returns 401 when the user does not exist', async () => {
      mockUserFindUnique.mockResolvedValue(null);

      const res = await server.post('/api/auth/login', { email: 'nobody@example.com', password: 'x' });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'Invalid email or password' });
    });

    it('returns 401 when the password does not match', async () => {
      mockUserFindUnique.mockResolvedValue({ id: 'u-1', email: 'a@example.com', passwordHash: 'hash', role: 'ADMIN' });
      mockVerifyPassword.mockResolvedValue(false);

      const res = await server.post('/api/auth/login', { email: 'a@example.com', password: 'wrong' });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'Invalid email or password' });
    });

    it('returns tokens and creates a session on valid credentials', async () => {
      mockUserFindUnique.mockResolvedValue({ id: 'u-1', email: 'a@example.com', passwordHash: 'hash', role: 'ADMIN' });
      mockVerifyPassword.mockResolvedValue(true);
      mockSessionCreate.mockResolvedValue({});

      const res = await server.post('/api/auth/login', { email: 'a@example.com', password: 'correct' });

      expect(res.status).toBe(200);
      expect(res.body.data.accessToken).toEqual(expect.any(String));
      expect(res.body.data.refreshToken).toEqual(expect.any(String));
      expect(res.body.data.user).toEqual({ id: 'u-1', email: 'a@example.com', role: 'ADMIN' });
      expect(mockSessionCreate).toHaveBeenCalledTimes(1);
    });

    it('returns 500 when prisma throws', async () => {
      mockUserFindUnique.mockRejectedValue(new Error('db down'));

      const res = await server.post('/api/auth/login', { email: 'a@example.com', password: 'x' });

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Internal server error' });
    });
  });

  describe('POST /api/auth/refresh', () => {
    it('returns 400 when refreshToken is missing', async () => {
      const res = await server.post('/api/auth/refresh', {});

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Validation error');
    });

    it('returns 401 for a malformed/invalid refresh token', async () => {
      const res = await server.post('/api/auth/refresh', { refreshToken: 'not-a-real-jwt' });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'Invalid or expired refresh token' });
    });

    it('returns 401 when the session is missing', async () => {
      const refreshToken = authService.generateRefreshToken('u-1');
      mockSessionFindUnique.mockResolvedValue(null);

      const res = await server.post('/api/auth/refresh', { refreshToken });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'Session not found or expired' });
    });

    it('rotates tokens when the session is valid', async () => {
      const refreshToken = authService.generateRefreshToken('u-1');
      mockSessionFindUnique.mockResolvedValue({ userId: 'u-1', expiresAt: new Date(Date.now() + 100000) });
      mockUserFindUnique.mockResolvedValue({ id: 'u-1', role: 'ADMIN' });
      mockSessionDelete.mockResolvedValue({});
      mockSessionCreate.mockResolvedValue({});

      const res = await server.post('/api/auth/refresh', { refreshToken });

      expect(res.status).toBe(200);
      expect(res.body.data.accessToken).toEqual(expect.any(String));
      expect(res.body.data.refreshToken).toEqual(expect.any(String));
    });
  });

  describe('POST /api/auth/logout', () => {
    it('returns 401 without an Authorization header (real authenticate middleware)', async () => {
      const res = await server.post('/api/auth/logout', { refreshToken: 'x' });

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'No token provided' });
    });

    it('logs out with a valid access token', async () => {
      const accessToken = authService.generateAccessToken('u-1', 'ADMIN');
      mockSessionDeleteMany.mockResolvedValue({ count: 1 });

      const res = await server.post(
        '/api/auth/logout',
        { refreshToken: 'some-refresh-token' },
        { Authorization: `Bearer ${accessToken}` }
      );

      expect(res.status).toBe(200);
      expect(res.body.data.message).toBe('Logged out successfully');
    });
  });

  describe('GET /api/auth/me', () => {
    it('returns 401 without an Authorization header', async () => {
      const res = await server.get('/api/auth/me', {});

      expect(res.status).toBe(401);
    });

    it('returns the current user for a valid token', async () => {
      const accessToken = authService.generateAccessToken('u-1', 'ADMIN');
      mockUserFindUnique.mockResolvedValue({ id: 'u-1', email: 'a@example.com', role: 'ADMIN', createdAt: new Date(), updatedAt: new Date() });

      const res = await server.get('/api/auth/me', { Authorization: `Bearer ${accessToken}` });

      expect(res.status).toBe(200);
      expect(res.body.data.id).toBe('u-1');
    });

    it('returns 404 when the user record is gone', async () => {
      const accessToken = authService.generateAccessToken('u-1', 'ADMIN');
      mockUserFindUnique.mockResolvedValue(null);

      const res = await server.get('/api/auth/me', { Authorization: `Bearer ${accessToken}` });

      expect(res.status).toBe(404);
      expect(res.body).toEqual({ error: 'User not found' });
    });
  });
});

import { api } from './client';
import type { User } from '../types';

export const authApi = {
  login: (email: string, password: string) =>
    api.post<{ accessToken: string; refreshToken: string; user: User }>('/auth/login', {
      email,
      password,
    }),

  logout: (refreshToken: string) =>
    api.post<void>('/auth/logout', { refreshToken }),

  refresh: (refreshToken: string) =>
    api.post<{ accessToken: string; refreshToken: string; user?: User }>('/auth/refresh', { refreshToken }),

  me: () => api.get<User>('/auth/me'),

  /** Re-issue tokens for another organization the user belongs to. */
  switchTenant: (tenantId: string, refreshToken: string) =>
    api.post<{ accessToken: string; refreshToken: string; user: User }>('/auth/switch-tenant', {
      tenantId,
      refreshToken,
    }),
};

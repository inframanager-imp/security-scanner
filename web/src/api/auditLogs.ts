/**
 * Audit log API (ADMIN only). See docs/api/audit-logs.md.
 */
import { api } from './client';

export type AuditOutcome = 'SUCCESS' | 'FAILED' | 'DENIED';
export type AuditMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface AuditLogEntry {
  id: string;
  createdAt: string;
  userId: string | null;
  userEmail: string | null;
  userRole: string | null;
  action: string;
  method: AuditMethod;
  path: string;
  statusCode: number;
  outcome: AuditOutcome;
  ip: string | null;
  durationMs: number | null;
}

export interface AuditLogDetail extends AuditLogEntry {
  actorEmail: string | null;
  query: string | null;
  userAgent: string | null;
  requestBody: string | null;
}

export interface AuditLogFilters {
  page?: number;
  limit?: number;
  email?: string;
  action?: string;
  method?: AuditMethod | '';
  outcome?: AuditOutcome | '';
  path?: string;
  from?: string;
  to?: string;
}

export interface AuditLogPage {
  data: AuditLogEntry[];
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

function qs(filters: AuditLogFilters): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

export const auditLogsApi = {
  list: (filters: AuditLogFilters = {}) => api.get<AuditLogPage>(`/audit-logs${qs(filters)}`),
  actions: () => api.get<{ data: string[] }>('/audit-logs/actions'),
  get: (id: string) => api.get<{ data: AuditLogDetail }>(`/audit-logs/${id}`),
};

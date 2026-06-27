import { api } from './client';
import type { Finding, FindingStatus, PaginatedResponse, FindingsFilter } from '../types';

export const findingsApi = {
  list: (filter: FindingsFilter = {}) => {
    const params = new URLSearchParams();
    if (filter.severity) params.set('severity', filter.severity);
    if (filter.services && filter.services.length > 0) {
      params.set('services', filter.services.join(','));
    } else if (filter.service) {
      params.set('service', filter.service);
    }
    if (filter.findingStatus) params.set('findingStatus', filter.findingStatus);
    if (filter.search) params.set('search', filter.search);
    if (filter.page) params.set('page', String(filter.page));
    if (filter.pageSize) params.set('pageSize', String(filter.pageSize));
    if (filter.accountId) params.set('accountId', filter.accountId);
    if (filter.sortBy) params.set('sortBy', filter.sortBy);
    if (filter.sortOrder) params.set('sortOrder', filter.sortOrder);

    const query = params.toString();
    return api.get<PaginatedResponse<Finding>>(`/findings${query ? `?${query}` : ''}`);
  },

  getServices: (accountId?: string) => {
    const query = accountId ? `?accountId=${accountId}` : '';
    return api.get<string[]>(`/findings/services${query}`);
  },

  get: (id: string) => api.get<Finding>(`/findings/${id}`),

  updateStatus: (id: string, findingStatus: FindingStatus) =>
    api.patch<Finding>(`/findings/${id}`, { findingStatus }),

  bulkUpdateStatus: (ids: string[], findingStatus: FindingStatus) =>
    api.post<{ updated: number }>('/findings/bulk-status', { ids, findingStatus }),

  prioritized: (params: { accountId?: string; minRiskScore?: number; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.accountId)    qs.set('accountId',    params.accountId);
    if (params.minRiskScore !== undefined) qs.set('minRiskScore', String(params.minRiskScore));
    if (params.limit)        qs.set('limit',        String(params.limit));
    return api.get<Array<PrioritizedFinding>>(`/findings/prioritized${qs.toString() ? `?${qs}` : ''}`);
  },
};

export interface PrioritizedFinding {
  id: string;
  service: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  riskScore: number | null;
  reachability: string | null;
  businessContext: Record<string, unknown> | null;
  exploitability: string | null;
  tags: string[];
  provider: 'AWS' | 'AZURE' | 'GCP';
  account: { id: string; name: string; awsAccountId?: string; nativeId?: string } | null;
  discoveredAt: string;
}

import { api } from './client';
import type { Scan, Finding, PaginatedResponse, FindingsFilter } from '../types';

export interface TriggerScanPayload {
  accountId: string;
  services?: string[];
  regions?: string[];
}

export const scansApi = {
  trigger: (payload: TriggerScanPayload) =>
    api.post<Scan>('/scans', payload),

  list: (accountId?: string) => {
    const path = accountId ? `/scans?accountId=${accountId}&limit=50` : '/scans?limit=50';
    return api.get<PaginatedResponse<Scan>>(path);
  },

  get: (id: string) => api.get<Scan>(`/scans/${id}`),

  cancel: (id: string) => api.post<Scan>(`/scans/${id}/cancel`, {}),

  getFindings: (scanId: string, filter: FindingsFilter = {}) => {
    const params = new URLSearchParams();
    if (filter.severity) params.set('severity', filter.severity);
    if (filter.service) params.set('service', filter.service);
    if (filter.findingStatus) params.set('findingStatus', filter.findingStatus);
    if (filter.search) params.set('search', filter.search);
    if (filter.page) params.set('page', String(filter.page));
    if (filter.pageSize) params.set('pageSize', String(filter.pageSize));

    const query = params.toString();
    return api.get<PaginatedResponse<Finding>>(
      `/scans/${scanId}/findings${query ? `?${query}` : ''}`,
    );
  },

  exportFindings: (scanId: string, format: 'json' | 'csv') =>
    `/api/cspm/scans/${scanId}/findings/export?format=${format}`,
};

import { api } from './client';
import type { ConfigChange, ConfigChangeStats, ConfigSyncRun, CloudProvider, ChangeAction, ChangeCategory, ChangeStatus, Severity } from '../types';

export interface ConfigChangeListParams {
  provider:      CloudProvider;
  targetId:      string;
  changeAction?: ChangeAction;
  severity?:     Severity;
  category?:     ChangeCategory;
  changeStatus?: ChangeStatus;
  actor?:        string;
  search?:       string;
  startTime?:    string;
  endTime?:      string;
  page?:         number;
  pageSize?:     number;
  sortBy?:       'eventTime' | 'riskScore' | 'severity';
  sortOrder?:    'asc' | 'desc';
}

export interface ConfigChangeListResponse {
  data:       ConfigChange[];
  total:      number;
  page:       number;
  pageSize:   number;
  totalPages: number;
}

export const configChangesApi = {
  list: (params: ConfigChangeListParams) => {
    const qs = new URLSearchParams({ provider: params.provider, targetId: params.targetId });
    if (params.changeAction) qs.set('changeAction', params.changeAction);
    if (params.severity)     qs.set('severity',     params.severity);
    if (params.category)     qs.set('category',     params.category);
    if (params.changeStatus) qs.set('changeStatus', params.changeStatus);
    if (params.actor)        qs.set('actor',        params.actor);
    if (params.search)       qs.set('search',       params.search);
    if (params.startTime)    qs.set('startTime',    params.startTime);
    if (params.endTime)      qs.set('endTime',      params.endTime);
    if (params.page)         qs.set('page',         String(params.page));
    if (params.pageSize)     qs.set('pageSize',     String(params.pageSize));
    if (params.sortBy)       qs.set('sortBy',       params.sortBy);
    if (params.sortOrder)    qs.set('sortOrder',    params.sortOrder);
    return api.get<ConfigChangeListResponse>(`/config-changes?${qs}`);
  },

  getStats: (provider: CloudProvider, targetId: string, startTime?: string, endTime?: string) => {
    const qs = new URLSearchParams({ provider, targetId });
    if (startTime) qs.set('startTime', startTime);
    if (endTime)   qs.set('endTime',   endTime);
    return api.get<ConfigChangeStats>(`/config-changes/stats?${qs}`);
  },

  getById: (id: string) =>
    api.get<ConfigChange>(`/config-changes/${id}`),

  updateStatus: (id: string, status: ChangeStatus, notes?: string) =>
    api.patch<ConfigChange>(`/config-changes/${id}/status`, { status, notes }),

  bulkUpdateStatus: (ids: string[], status: ChangeStatus, notes?: string) =>
    api.post<{ updated: number }>('/config-changes/bulk-status', { ids, status, notes }),

  sync: (provider: CloudProvider, targetId: string, windowHours = 24) =>
    api.post<{ runId: string; status: string; windowStart: string; windowEnd: string }>(
      '/config-changes/sync', { provider, targetId, windowHours },
    ),

  getRuns: (provider: CloudProvider, targetId: string) =>
    api.get<{ runs: ConfigSyncRun[]; lastSuccessfulSyncAt: string | null; lastChangesStored: number | null }>(
      `/config-changes/runs?provider=${provider}&targetId=${targetId}`
    ),

  reconcileInventory: (provider: CloudProvider, targetId: string) =>
    api.post<{ message: string; reconciled: number }>('/config-changes/reconcile-inventory', { provider, targetId }),

  exportCsvUrl: (provider: CloudProvider, targetId: string, params?: Partial<ConfigChangeListParams>) => {
    const qs = new URLSearchParams({ provider, targetId });
    if (params?.severity)     qs.set('severity',     params.severity);
    if (params?.category)     qs.set('category',     params.category);
    if (params?.changeStatus) qs.set('changeStatus', params.changeStatus);
    return `/api/config-changes/export/csv?${qs}`;
  },
};

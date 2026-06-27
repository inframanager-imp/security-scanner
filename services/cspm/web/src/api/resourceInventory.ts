import { api } from './client';
import type {
  ResourceInventoryItem,
  ResourceDetail,
  ResourceSnapshot,
  ResourceDeps,
  ResourceInventoryStats,
  ResourceActivityLogResponse,
  CloudProvider,
} from '../types';

export interface ResourceListParams {
  provider?:     CloudProvider | '';
  targetId?:     string;
  resourceType?: string;
  state?:        'ACTIVE' | 'DELETED' | '';
  region?:       string;
  search?:       string;
  page?:         number;
  pageSize?:     number;
  sortBy?:       'lastSeenAt' | 'discoveredAt' | 'resourceType' | 'resourceName';
  sortOrder?:    'asc' | 'desc';
}

export interface ResourceListResponse {
  data:       ResourceInventoryItem[];
  meta: {
    total:      number;
    page:       number;
    pageSize:   number;
    totalPages: number;
  };
}

export const resourceInventoryApi = {
  discover: (provider: CloudProvider, targetId: string) =>
    api.post<{ status: string; message: string }>('/resource-inventory/discover', { provider, targetId }),

  getStats: (provider?: CloudProvider, targetId?: string, windowDays?: number) => {
    const qs = new URLSearchParams();
    if (provider)   qs.set('provider',   provider);
    if (targetId)   qs.set('targetId',   targetId);
    if (windowDays) qs.set('windowDays', String(windowDays));
    return api.get<ResourceInventoryStats>(`/resource-inventory/stats?${qs}`);
  },

  getActivityLog: (provider: CloudProvider, targetId: string, page = 1, pageSize = 25) => {
    const qs = new URLSearchParams({
      provider,
      targetId,
      page:     String(page),
      pageSize: String(pageSize),
    });
    return api.get<ResourceActivityLogResponse>(`/resource-inventory/activity-log?${qs}`);
  },

  list: (params: ResourceListParams) => {
    const qs = new URLSearchParams();
    if (params.provider)     qs.set('provider',     params.provider);
    if (params.targetId)     qs.set('targetId',     params.targetId);
    if (params.resourceType) qs.set('resourceType', params.resourceType);
    if (params.state)        qs.set('state',        params.state);
    if (params.region)       qs.set('region',       params.region);
    if (params.search)       qs.set('search',       params.search);
    if (params.page)         qs.set('page',         String(params.page));
    if (params.pageSize)     qs.set('pageSize',     String(params.pageSize));
    if (params.sortBy)       qs.set('sortBy',       params.sortBy);
    if (params.sortOrder)    qs.set('sortOrder',    params.sortOrder);
    return api.get<ResourceListResponse>(`/resource-inventory?${qs}`);
  },

  getById: (id: string) =>
    api.get<ResourceDetail>(`/resource-inventory/${id}`),

  getTimeline: (id: string, limit = 50) =>
    api.get<ResourceSnapshot[]>(`/resource-inventory/${id}/timeline?limit=${limit}`),

  getDeps: (id: string) =>
    api.get<ResourceDeps>(`/resource-inventory/${id}/deps`),

  getSnapshot: (snapshotId: string) =>
    api.get<ResourceSnapshot>(`/resource-inventory/snapshots/${snapshotId}`),
};

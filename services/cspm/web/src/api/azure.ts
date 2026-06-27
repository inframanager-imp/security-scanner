import { api } from './client';
import type {
  AzureSubscription,
  AzureCredential,
  AzureScan,
  AzureFinding,
  AzureActivityEvent,
  AzureScanSummary,
  AzureAuthMethod,
  PaginatedResponse,
} from '../types';

export interface CreateAzureSubscriptionPayload {
  name:           string;
  subscriptionId: string;
  tenantId?:      string;
  description?:   string;
}

export interface UpdateAzureSubscriptionPayload {
  name?:        string;
  description?: string;
}

export interface AzureCredentialPayload {
  authMethod:   AzureAuthMethod;
  tenantId?:    string;
  clientId?:    string;
  clientSecret?: string;
}

export interface AzureScanPayload {
  services?: string[];
}

export interface AzureActivityLogsParams {
  subscriptionId: string;
  startTime?:     string;
  endTime?:       string;
  maxResults?:    number;
}

export interface AzureActivityLogsResponse {
  events:    AzureActivityEvent[];
  summary:   AzureScanSummary;
  timeRange: { startTime: string; endTime: string };
}

export const azureApi = {
  // ─── Subscriptions ──────────────────────────────────────────────────────────

  listSubscriptions: (params?: { page?: number; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.page)  qs.set('page',  String(params.page));
    if (params?.limit) qs.set('limit', String(params.limit));
    return api.get<PaginatedResponse<AzureSubscription>>(
      `/azure/subscriptions${qs.toString() ? `?${qs}` : ''}`,
    );
  },

  getSubscription: (id: string) =>
    api.get<AzureSubscription>(`/azure/subscriptions/${id}`),

  createSubscription: (payload: CreateAzureSubscriptionPayload) =>
    api.post<AzureSubscription>('/azure/subscriptions', payload),

  updateSubscription: (id: string, payload: UpdateAzureSubscriptionPayload) =>
    api.put<AzureSubscription>(`/azure/subscriptions/${id}`, payload),

  deleteSubscription: (id: string) =>
    api.delete<void>(`/azure/subscriptions/${id}`),

  // ─── Credentials ────────────────────────────────────────────────────────────

  setCredentials: (subscriptionId: string, payload: AzureCredentialPayload) =>
    api.post<AzureCredential>(`/azure/subscriptions/${subscriptionId}/credentials`, payload),

  verifyCredentials: (subscriptionId: string) =>
    api.post<{ valid: boolean; error?: string }>(
      `/azure/subscriptions/${subscriptionId}/credentials/verify`,
    ),

  // ─── Scans ──────────────────────────────────────────────────────────────────

  triggerScan: (subscriptionId: string, payload?: AzureScanPayload) =>
    api.post<{ scanId: string; jobId: string; status: string; services: string[] }>(
      `/azure/subscriptions/${subscriptionId}/scan`,
      payload,
    ),

  listScans: (params?: { subscriptionId?: string; status?: string; page?: number; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.subscriptionId) qs.set('subscriptionId', params.subscriptionId);
    if (params?.status)         qs.set('status',         params.status);
    if (params?.page)           qs.set('page',           String(params.page));
    if (params?.limit)          qs.set('limit',          String(params.limit));
    return api.get<PaginatedResponse<AzureScan>>(
      `/azure/scans${qs.toString() ? `?${qs}` : ''}`,
    );
  },

  getScan: (id: string) =>
    api.get<AzureScan>(`/azure/scans/${id}`),

  getFindings: (
    scanId: string,
    params?: { page?: number; pageSize?: number; severity?: string; service?: string; status?: string },
  ) => {
    const qs = new URLSearchParams();
    if (params?.page)     qs.set('page',     String(params.page));
    if (params?.pageSize) qs.set('pageSize', String(params.pageSize));
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.service)  qs.set('service',  params.service);
    if (params?.status)   qs.set('status',   params.status);
    return api.get<PaginatedResponse<AzureFinding>>(
      `/azure/scans/${scanId}/findings${qs.toString() ? `?${qs}` : ''}`,
    );
  },

  exportFindings: (scanId: string) =>
    `/api/azure/scans/${scanId}/findings/export`,

  updateFindingStatus: (findingId: string, status: string) =>
    api.patch<AzureFinding>(`/azure/scans/findings/${findingId}/status`, { status }),

  getSubscriptionServices: (subscriptionId: string) =>
    api.get<string[]>(`/azure/subscriptions/${subscriptionId}/services`),

  getSubscriptionFindings: (
    subscriptionId: string,
    params?: { page?: number; pageSize?: number; severity?: string; services?: string[]; service?: string; status?: string; search?: string },
  ) => {
    const qs = new URLSearchParams();
    if (params?.page)     qs.set('page',     String(params.page));
    if (params?.pageSize) qs.set('pageSize', String(params.pageSize));
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.services?.length) qs.set('services', params.services.join(','));
    else if (params?.service) qs.set('service', params.service);
    if (params?.status)   qs.set('status',   params.status);
    if (params?.search)   qs.set('search',   params.search);
    return api.get<PaginatedResponse<AzureFinding>>(
      `/azure/subscriptions/${subscriptionId}/findings${qs.toString() ? `?${qs}` : ''}`,
    );
  },

  cleanupScannerErrors: () =>
    api.delete<{ deleted: number; message: string }>('/azure/scans/findings/cleanup-scanner-errors'),

  // ─── Activity Logs ──────────────────────────────────────────────────────────

  getActivityLogs: (params: AzureActivityLogsParams) => {
    const qs = new URLSearchParams({ subscriptionId: params.subscriptionId });
    if (params.startTime)   qs.set('startTime',   params.startTime);
    if (params.endTime)     qs.set('endTime',     params.endTime);
    if (params.maxResults)  qs.set('maxResults',  String(params.maxResults));
    return api.get<AzureActivityLogsResponse>(`/azure/activity-logs?${qs}`);
  },
};

import { api } from './client';
import type {
  GcpProject,
  GcpCredential,
  GcpScan,
  GcpFinding,
  GcpScanSummary,
  GcpAuthMethod,
  PaginatedResponse,
} from '../types';

export interface CreateGcpProjectPayload {
  name:        string;
  projectId:   string;
  description?: string;
}

export interface UpdateGcpProjectPayload {
  name?:        string;
  description?: string;
}

export interface GcpCredentialPayload {
  authMethod:          GcpAuthMethod;
  serviceAccountKey?:  string;   // full JSON string
  serviceAccountEmail?: string;
}

export interface GcpScanPayload {
  services?: string[];
}

export const gcpApi = {
  // ─── Projects ───────────────────────────────────────────────────────────────

  listProjects: (params?: { page?: number; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.page)  qs.set('page',  String(params.page));
    if (params?.limit) qs.set('limit', String(params.limit));
    return api.get<PaginatedResponse<GcpProject>>(
      `/gcp/projects${qs.toString() ? `?${qs}` : ''}`,
    );
  },

  getProject: (id: string) =>
    api.get<GcpProject>(`/gcp/projects/${id}`),

  createProject: (payload: CreateGcpProjectPayload) =>
    api.post<GcpProject>('/gcp/projects', payload),

  updateProject: (id: string, payload: UpdateGcpProjectPayload) =>
    api.put<GcpProject>(`/gcp/projects/${id}`, payload),

  deleteProject: (id: string) =>
    api.delete<void>(`/gcp/projects/${id}`),

  // ─── Credentials ────────────────────────────────────────────────────────────

  setCredentials: (projectId: string, payload: GcpCredentialPayload) =>
    api.post<GcpCredential>(`/gcp/projects/${projectId}/credentials`, payload),

  verifyCredentials: (projectId: string) =>
    api.post<{ valid: boolean; error?: string }>(
      `/gcp/projects/${projectId}/credentials/verify`,
    ),

  // ─── Scans ──────────────────────────────────────────────────────────────────

  triggerScan: (projectId: string, payload?: GcpScanPayload) =>
    api.post<{ scanId: string; jobId: string; status: string; services: string[] }>(
      `/gcp/projects/${projectId}/scan`,
      payload,
    ),

  listScans: (params?: { projectId?: string; status?: string; page?: number; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.projectId) qs.set('projectId', params.projectId);
    if (params?.status)    qs.set('status',    params.status);
    if (params?.page)      qs.set('page',      String(params.page));
    if (params?.limit)     qs.set('limit',     String(params.limit));
    return api.get<PaginatedResponse<GcpScan>>(
      `/gcp/scans${qs.toString() ? `?${qs}` : ''}`,
    );
  },

  getScan: (id: string) =>
    api.get<GcpScan>(`/gcp/scans/${id}`),

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
    return api.get<PaginatedResponse<GcpFinding>>(
      `/gcp/scans/${scanId}/findings${qs.toString() ? `?${qs}` : ''}`,
    );
  },

  exportFindings: (scanId: string) =>
    `/api/cspm/gcp/scans/${scanId}/findings/export`,
};

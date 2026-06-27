/**
 * API helpers for enterprise features:
 *   - Alert Configurations
 *   - Freeze Windows
 *   - Posture Scores
 *   - Baseline / Drift Detection
 *   - Scheduled Reports
 *   - Integrations (Webhook / ServiceNow / Jira)
 *   - IAM Privilege Escalation
 */

import { api } from './client';

// ─── Types ────────────────────────────────────────────────────────────────────

export type AlertChannel = 'SLACK' | 'EMAIL_SMTP' | 'EMAIL_O365' | 'EMAIL_GMAIL';

export interface AlertConfigSummary {
  id:          string;
  name:        string;
  isActive:    boolean;
  channel:     AlertChannel;
  minSeverity: string;
  categories:  string[];
  providers:   string[];
  targetIds:   string[];
  onFreezeOnly: boolean;
  createdAt:   string;
  updatedAt:   string;
}

export interface AlertConfigDetail extends AlertConfigSummary {
  config: Record<string, string>;
}

export interface AlertLog {
  id:           string;
  status:       string;
  subject:      string;
  errorMessage: string | null;
  sentAt:       string;
  config?: { id: string; name: string; channel: AlertChannel };
  change?: {
    id: string; severity: string; category: string;
    provider: string; resourceType: string; resourceName: string;
  };
}

export interface FreezeWindow {
  id:         string;
  name:       string;
  providers:  string[];
  targetIds:  string[];
  daysOfWeek: number[];
  startTime:  string;
  endTime:    string;
  timezone:   string;
  fixedStart: string | null;
  fixedEnd:   string | null;
  isActive:   boolean;
  createdAt:  string;
  updatedAt:  string;
}

export interface PostureScore {
  id:               string;
  provider:         string;
  targetId:         string;
  score:            number;
  grade:            'A' | 'B' | 'C' | 'D' | 'F';
  criticalOpen:     number;
  highOpen:         number;
  mediumOpen:       number;
  lowOpen:          number;
  freezeViolations: number;
  calculatedAt:     string;
}

export interface PostureHistoryPoint {
  score:            number;
  grade:            string;
  criticalOpen:     number;
  highOpen:         number;
  mediumOpen:       number;
  lowOpen:          number;
  freezeViolations: number;
  calculatedAt:     string;
}

export interface PostureSummary {
  total:      number;
  avgScore:   number | null;
  gradeCount: Record<string, number>;
  scores:     Array<{ provider: string; targetId: string; score: number; grade: string; calculatedAt: string }>;
}

// ─── Alert Config API ─────────────────────────────────────────────────────────

export const alertsApi = {
  list:   () => api.get<AlertConfigSummary[]>('/alerts'),
  get:    (id: string) => api.get<AlertConfigDetail>(`/alerts/${id}`),
  create: (data: Omit<AlertConfigDetail, 'id' | 'createdAt' | 'updatedAt'>) =>
    api.post<AlertConfigSummary>('/alerts', data),
  update: (id: string, data: Partial<AlertConfigDetail>) =>
    api.put<AlertConfigSummary>(`/alerts/${id}`, data),
  delete: (id: string) => api.delete<void>(`/alerts/${id}`),
  test:   (id: string) => api.post<{ success: boolean; message: string }>(`/alerts/${id}/test`),
  logs:   (id: string, page = 1, pageSize = 20) =>
    api.get<{ total: number; page: number; pageSize: number; logs: AlertLog[] }>(
      `/alerts/${id}/logs?page=${page}&pageSize=${pageSize}`
    ),
  recentLogs: (limit = 50) =>
    api.get<AlertLog[]>(`/alerts/logs/recent?limit=${limit}`),
};

// ─── Freeze Window API ────────────────────────────────────────────────────────

export const freezeWindowsApi = {
  list:   () => api.get<FreezeWindow[]>('/freeze-windows'),
  get:    (id: string) => api.get<FreezeWindow>(`/freeze-windows/${id}`),
  create: (data: Omit<FreezeWindow, 'id' | 'createdAt' | 'updatedAt'>) =>
    api.post<FreezeWindow>('/freeze-windows', data),
  update: (id: string, data: Partial<FreezeWindow>) =>
    api.put<FreezeWindow>(`/freeze-windows/${id}`, data),
  delete: (id: string) => api.delete<void>(`/freeze-windows/${id}`),
  toggle: (id: string) => api.patch<{ id: string; name: string; isActive: boolean }>(`/freeze-windows/${id}/toggle`),
};

// ─── Posture Score API ────────────────────────────────────────────────────────

export const postureApi = {
  current: (provider: string, targetId: string) =>
    api.get<PostureScore>(`/posture-score/current?provider=${provider}&targetId=${targetId}`),
  history: (provider: string, targetId: string, days = 30) =>
    api.get<{ provider: string; targetId: string; days: number; history: PostureHistoryPoint[] }>(
      `/posture-score/history?provider=${provider}&targetId=${targetId}&days=${days}`
    ),
  summary: () => api.get<PostureSummary>('/posture-score/summary'),
  compute: (provider: string, targetId: string) =>
    api.post<PostureScore>('/posture-score/compute', { provider, targetId }),
};

// ─── Baseline / Drift Types ───────────────────────────────────────────────────

export interface PendingApprovalRef {
  id:            string;
  action:        string;
  requestedBy:   string;
  requestedAt:   string;
  expiresAt:     string;
}

export interface BaselineSummary {
  id:              string;
  name:            string;
  description:     string | null;
  provider:        string;
  targetId:        string;
  resourceCount:   number;
  isActive:        boolean;
  capturedAt:      string;
  currentVersion:  number;
  openDrift:       number;
  criticalDrift:   number;
  highDrift:       number;
  pendingApprovals: PendingApprovalRef[];
}

export interface DriftResult {
  id:              string;
  driftType:       'ADDED' | 'MODIFIED' | 'DELETED';
  severity:        string;
  nativeId:        string;
  resourceType:    string;
  resourceName:    string | null;
  region:          string | null;
  driftedFields:   string[];
  status:          'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'REVERTED';
  firstDetectedAt: string;   // set once; never changes across re-scans
  detectedAt:      string;   // updated on every scan (last scan that saw this drift)
  acknowledgedAt:  string | null;
  resolvedAt:      string | null;
  pendingRevert:   { id: string; status: string; requestedBy: string } | null;
}

export interface DriftResultDetail extends DriftResult {
  baselineConfig:     unknown;
  currentConfig:      unknown;
  baselineCapturedAt: string | null;
  currentLastSeenAt:  string | null;   // DELETED: last seen in inventory; others: last sync time
  pendingRevert:      { id: string; status: string; requestedBy: string; expiresAt: string } | null;
}

// ─── Version History Types ────────────────────────────────────────────────────

export interface BaselineVersionSummary {
  id:            string;
  versionNumber: number;
  label:         string | null;
  resourceCount: number;
  capturedAt:    string;
  capturedBy:    string | null;
}

export interface BaselineVersionSnapshot {
  id:           string;
  versionId:    string;
  nativeId:     string;
  resourceType: string;
  resourceName: string | null;
  region:       string | null;
  configState:  unknown;
}

export interface BaselineVersionDetail extends BaselineVersionSummary {
  snapshots: BaselineVersionSnapshot[];
}

export interface VersionCompareResult {
  v1: BaselineVersionSummary;
  v2: BaselineVersionSummary;
  summary: { added: number; deleted: number; modified: number };
  added:    BaselineVersionSnapshot[];
  deleted:  BaselineVersionSnapshot[];
  modified: { nativeId: string; resourceType: string; resourceName: string | null; changedFields: string[] }[];
}

// ─── Approval Workflow Types ──────────────────────────────────────────────────

export type ApprovalAction = 'CAPTURE' | 'REFRESH' | 'REVERT';
export type ApprovalStatus =
  'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' |
  'CANCELLED' | 'EXECUTING' | 'COMPLETED' | 'FAILED';

export interface ApprovalRequest {
  id:              string;
  action:          ApprovalAction;
  baselineId:      string | null;
  driftId:         string | null;
  requestedBy:     string;
  requestedByName: string | null;
  status:          ApprovalStatus;
  notes:           string | null;
  reviewedBy:      string | null;
  reviewedByName:  string | null;
  reviewNotes:     string | null;
  requestedAt:     string;
  reviewedAt:      string | null;
  expiresAt:       string;
  executedAt:      string | null;
  executionError:  string | null;
  metadata:        Record<string, unknown> | null;
  // Enriched
  baseline?: { id: string; name: string; provider: string } | null;
  drift?:    { id: string; resourceType: string; resourceName: string | null; driftType: string; severity: string } | null;
}

// ─── Revert Plan Types ────────────────────────────────────────────────────────

export interface RevertPlan {
  canAutoRevert:      boolean;
  riskLevel:          'LOW' | 'MEDIUM' | 'HIGH';
  description:        string;
  steps:              string[];
  remediationScript?: string;
  warnings:           string[];
}

// ─── Report Schedule Types ────────────────────────────────────────────────────

export interface ReportSchedule {
  id:          string;
  name:        string;
  provider:    string | null;
  targetId:    string | null;
  frequency:   string;
  dayOfWeek:   number | null;
  dayOfMonth:  number | null;
  hour:        number;
  sections:    string[];
  recipients:  string[];
  isActive:    boolean;
  lastRunAt:   string | null;
  nextRunAt:   string | null;
  createdAt:   string;
  updatedAt:   string;
  _count?:     { runs: number };
}

export interface ReportRun {
  id:          string;
  scheduleId:  string;
  status:      string;
  startedAt:   string;
  completedAt: string | null;
  errorMessage: string | null;
}

// ─── Integration Types ────────────────────────────────────────────────────────

export type IntegrationType = 'WEBHOOK' | 'SERVICENOW' | 'JIRA';

export interface IntegrationSummary {
  id:              string;
  name:            string;
  integrationType: IntegrationType;
  isActive:        boolean;
  minSeverity:     string;
  providers:       string[];
  targetIds:       string[];
  onFreezeOnly:    boolean;
  createdAt:       string;
  updatedAt:       string;
  _count?:         { logs: number };
}

export interface IntegrationDetail extends IntegrationSummary {
  config: Record<string, string>;
}

export interface IntegrationLog {
  id:           string;
  status:       string;
  externalId:   string | null;
  errorMessage: string | null;
  sentAt:       string;
  config?:      { id: string; name: string; integrationType: IntegrationType };
  change?:      { id: string; severity: string; provider: string; eventName: string };
}

// ─── IAM Escalation Types ─────────────────────────────────────────────────────

export interface IamEscalationEvent {
  id:              string;
  provider:        string;
  targetId:        string;
  escalationType:  string;
  severity:        string;
  actor:           string | null;
  actorType:       string | null;
  targetPrincipal: string | null;
  resourceType:    string | null;
  resourceName:    string | null;
  eventName:       string;
  eventTime:       string;
  summary:         string;
  status:          string;
  createdAt:       string;
}

export interface IamEscalationStats {
  total:      number;
  byType:     Array<{ type: string; count: number }>;
  bySeverity: Record<string, number>;
  byStatus:   Record<string, number>;
}

// ─── Baseline API ─────────────────────────────────────────────────────────────

export const baselinesApi = {
  list:   (provider?: string, targetId?: string) => {
    const qs = new URLSearchParams();
    if (provider) qs.set('provider', provider);
    if (targetId) qs.set('targetId', targetId);
    return api.get<BaselineSummary[]>(`/baselines?${qs}`);
  },
  get:    (id: string) => api.get<BaselineSummary>(`/baselines/${id}`),

  // immediate=true skips approval gate (dev/single-user); otherwise creates ApprovalRequest
  create: (data: {
    provider: string; targetId: string; name: string; description?: string;
    resourceTypes?: string[]; nameSearch?: string;
    requestedBy?: string; requestedByName?: string; notes?: string; immediate?: boolean;
  }) => api.post<BaselineSummary | { approvalRequired: true; approvalId: string; message: string; expiresAt: string }>('/baselines', data),

  delete: (id: string) => api.delete<void>(`/baselines/${id}`),

  detect: (id: string) =>
    api.post<{ added: number; deleted: number; modified: number; reverted: number; total: number }>(`/baselines/${id}/detect`),

  refresh: (id: string, opts?: { requestedBy?: string; requestedByName?: string; notes?: string; immediate?: boolean }) =>
    api.post<BaselineSummary | { approvalRequired: true; approvalId: string; message: string; expiresAt: string }>(
      `/baselines/${id}/refresh`, opts ?? {}
    ),

  drift:  (id: string, page = 1, pageSize = 25, status = 'OPEN') =>
    api.get<{ total: number; page: number; pageSize: number; results: DriftResult[] }>(
      `/baselines/${id}/drift?page=${page}&pageSize=${pageSize}&status=${status}`
    ),

  driftDetail: (id: string, driftId: string) =>
    api.get<DriftResultDetail>(`/baselines/${id}/drift/${driftId}`),

  updateDrift: (id: string, driftId: string, status: string) =>
    api.patch<{ id: string; status: string }>(`/baselines/${id}/drift/${driftId}`, { status }),

  revertPlan: (id: string, driftId: string) =>
    api.post<RevertPlan>(`/baselines/${id}/drift/${driftId}/revert-plan`),

  requestRevert: (id: string, driftId: string, opts: { requestedBy: string; requestedByName?: string; notes?: string; immediate?: boolean }) =>
    api.post<{ approvalRequired?: boolean; approvalId?: string; message: string; success?: boolean } >(
      `/baselines/${id}/drift/${driftId}/revert`, opts
    ),

  // Version history
  versions:       (id: string) => api.get<BaselineVersionSummary[]>(`/baselines/${id}/versions`),
  versionDetail:  (id: string, vId: string) => api.get<BaselineVersionDetail>(`/baselines/${id}/versions/${vId}`),
  compareVersions:(id: string, vId1: string, vId2: string) =>
    api.get<VersionCompareResult>(`/baselines/${id}/versions/${vId1}/compare/${vId2}`),
};

// ─── Approvals API ────────────────────────────────────────────────────────────

export const approvalsApi = {
  list: (params?: { status?: string; action?: string; baselineId?: string; page?: number; pageSize?: number }) => {
    const qs = new URLSearchParams();
    if (params) Object.entries(params).forEach(([k, v]) => { if (v !== undefined) qs.set(k, String(v)); });
    return api.get<{ total: number; page: number; pageSize: number; items: ApprovalRequest[] }>(`/approvals?${qs}`);
  },
  pending: () => api.get<{ count: number }>('/approvals/pending'),
  get:     (id: string) => api.get<ApprovalRequest>(`/approvals/${id}`),
  approve: (id: string, data: { reviewedBy: string; reviewedByName?: string; reviewNotes?: string }) =>
    api.post<ApprovalRequest>(`/approvals/${id}/approve`, data),
  reject:  (id: string, data: { reviewedBy: string; reviewedByName?: string; reviewNotes?: string }) =>
    api.post<ApprovalRequest>(`/approvals/${id}/reject`, data),
  cancel:  (id: string, cancelledBy: string) =>
    api.post<ApprovalRequest>(`/approvals/${id}/cancel`, { cancelledBy }),
};

// ─── Report Schedule API ──────────────────────────────────────────────────────

export const reportSchedulesApi = {
  list:    () => api.get<ReportSchedule[]>('/report-schedules'),
  create:  (data: Omit<ReportSchedule, 'id' | 'createdAt' | 'updatedAt' | 'lastRunAt' | 'nextRunAt' | '_count'>) =>
    api.post<ReportSchedule>('/report-schedules', data),
  update:  (id: string, data: Partial<ReportSchedule>) =>
    api.put<ReportSchedule>(`/report-schedules/${id}`, data),
  delete:  (id: string) => api.delete<void>(`/report-schedules/${id}`),
  run:     (id: string) => api.post<{ message: string }>(`/report-schedules/${id}/run`),
  preview: (id: string) => `/api/report-schedules/${id}/preview`, // direct browser URL
  runs:    (id: string) => api.get<ReportRun[]>(`/report-schedules/${id}/runs`),
};

// ─── Integration API ──────────────────────────────────────────────────────────

export const integrationsApi = {
  list:   () => api.get<IntegrationSummary[]>('/integrations'),
  get:    (id: string) => api.get<IntegrationDetail>(`/integrations/${id}`),
  create: (data: Omit<IntegrationDetail, 'id' | 'createdAt' | 'updatedAt' | '_count'>) =>
    api.post<IntegrationSummary>('/integrations', data),
  update: (id: string, data: Partial<IntegrationDetail>) =>
    api.put<IntegrationSummary>(`/integrations/${id}`, data),
  delete: (id: string) => api.delete<void>(`/integrations/${id}`),
  test:   (id: string) => api.post<{ success: boolean; message: string }>(`/integrations/${id}/test`),
  logs:   (id: string, page = 1, pageSize = 20) =>
    api.get<{ total: number; page: number; pageSize: number; logs: IntegrationLog[] }>(
      `/integrations/${id}/logs?page=${page}&pageSize=${pageSize}`
    ),
  recentLogs: (limit = 50) => api.get<IntegrationLog[]>(`/integrations/logs/recent?limit=${limit}`),
};

// ─── IAM Escalation API ───────────────────────────────────────────────────────

export const iamEscalationApi = {
  stats: (provider?: string, targetId?: string) => {
    const qs = new URLSearchParams();
    if (provider) qs.set('provider', provider);
    if (targetId) qs.set('targetId', targetId);
    return api.get<IamEscalationStats>(`/iam-escalation/stats?${qs}`);
  },
  list: (params: { page?: number; pageSize?: number; provider?: string; targetId?: string; status?: string; severity?: string; escalationType?: string; days?: number } = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined) qs.set(k, String(v)); });
    return api.get<{ total: number; page: number; pageSize: number; events: IamEscalationEvent[] }>(
      `/iam-escalation?${qs}`
    );
  },
  get:      (id: string) => api.get<IamEscalationEvent>(`/iam-escalation/${id}`),
  patch:    (id: string, status: string, notes?: string) =>
    api.patch<{ id: string; status: string }>(`/iam-escalation/${id}`, { status, notes }),
  backfill: (provider: string, targetId: string) =>
    api.post<{ message: string }>('/iam-escalation/backfill', { provider, targetId }),
};

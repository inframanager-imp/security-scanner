import { api } from './client';

export type EvidenceStatus = 'COMPLIANT' | 'NON_COMPLIANT' | 'INSUFFICIENT';
export type EvidenceType   = 'AUTO_FINDING' | 'AUTO_SCAN' | 'MANUAL';

export interface ComplianceEvidence {
  id: string;
  frameworkId: string;
  controlId: string;
  provider: string;
  accountId: string | null;
  evidenceType: EvidenceType;
  status: EvidenceStatus;
  summary: string;
  detail: Record<string, unknown> | null;
  sourceType: string | null;
  sourceId: string | null;
  collectedAt: string;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface EvidenceSummaryItem {
  controlId: string;
  status: EvidenceStatus;
  collectedAt: string;
  expiresAt: string | null;
  summary: string;
}

export type FrameworkId = 'PCI_DSS' | 'SOC2' | 'ISO27001' | 'HIPAA' | 'CIS_AWS' | 'NIST_800_53' | 'GDPR' | 'FEDRAMP';
export type AzureFrameworkId = 'CIS_AZURE' | 'NIST' | 'ISO27001' | 'SOC2' | 'HIPAA';

export interface ControlResult {
  id: string;
  name: string;
  description: string;
  findingTitles: string[];
  status: 'PASS' | 'FAIL' | 'NOT_EVALUATED';
  failingFindings: number;
}

export interface FrameworkScore {
  frameworkId: FrameworkId;
  frameworkName: string;
  shortName: string;
  score: number;
  passingControls: number;
  failingControls: number;
  notEvaluatedControls: number;
  totalControls: number;
  controls: ControlResult[];
}

export interface AccountComplianceSummary {
  accountId: string;
  accountName: string;
  awsAccountId: string;
  scores: Omit<FrameworkScore, 'controls'>[];
}

export interface AzureControlResult {
  id: string;
  name: string;
  description: string;
  findingTitles: string[];
  status: 'PASS' | 'FAIL' | 'NOT_EVALUATED';
  failingFindings: number;
}

export interface AzureFrameworkScore {
  frameworkId: AzureFrameworkId;
  frameworkName: string;
  shortName: string;
  score: number;
  passingControls: number;
  failingControls: number;
  notEvaluatedControls: number;
  totalControls: number;
  controls: AzureControlResult[];
}

export interface AzureSubscriptionComplianceSummary {
  subscriptionId: string;
  subscriptionName: string;
  azureSubscriptionId: string;
  scores: Omit<AzureFrameworkScore, 'controls'>[];
}

export const complianceApi = {
  getAccountScores: (accountId: string) =>
    api.get<FrameworkScore[]>(`/compliance?accountId=${accountId}`),

  getAllAccountsScores: () =>
    api.get<AccountComplianceSummary[]>('/compliance/all'),

  getAzureSubscriptionScores: (subscriptionId: string) =>
    api.get<AzureFrameworkScore[]>(`/azure/compliance?subscriptionId=${subscriptionId}`),

  getAllAzureSubscriptionScores: () =>
    api.get<AzureSubscriptionComplianceSummary[]>('/azure/compliance/all'),

  collectEvidence: (accountId: string, provider: string, frameworkId?: string) =>
    api.post<{ created: number; updated: number }>('/compliance/evidence/collect', { accountId, provider, frameworkId }),

  getEvidence: (frameworkId: string, controlId: string, provider?: string, accountId?: string) => {
    const params = new URLSearchParams({ frameworkId, controlId });
    if (provider)  params.set('provider', provider);
    if (accountId) params.set('accountId', accountId);
    return api.get<ComplianceEvidence[]>(`/compliance/evidence?${params}`);
  },

  getEvidenceSummary: (frameworkId: string, provider?: string, accountId?: string) => {
    const params = new URLSearchParams({ frameworkId });
    if (provider)  params.set('provider', provider);
    if (accountId) params.set('accountId', accountId);
    return api.get<EvidenceSummaryItem[]>(`/compliance/evidence/summary?${params}`);
  },

  createManualEvidence: (data: {
    frameworkId: string; controlId: string; provider: string;
    accountId?: string; summary: string; status: EvidenceStatus; detail?: Record<string, unknown>;
  }) => api.post<ComplianceEvidence>('/compliance/evidence', data),

  deleteEvidence: (id: string) =>
    api.delete<{ deleted: boolean }>(`/compliance/evidence/${id}`),
};

import { api } from './client';

export interface WorkloadVulnerability {
  id: string;
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  resourceInventoryId: string;
  packageName: string;
  packageVersion: string;
  cveId: string;
  severity: string;
  cvssScore: number | null;
  fixedVersion: string | null;
  exploitAvailable: boolean;
  summary: string | null;
  reference: string | null;
  sourceFeed: string;
  observedAt: string;
  status: 'OPEN' | 'FIXED' | 'SUPPRESSED';
  resource: { id: string; nativeId: string; resourceType: string; region: string | null };
}

export interface CwppStats {
  bySeverity: { severity: string; count: number }[];
  hostsAffected: number;
  openTotal: number;
  infoMessage: string | null;
}

export const cwppApi = {
  scan: (provider: 'AWS' | 'AZURE' | 'GCP', accountId: string) =>
    api.post<{ jobId: string; status: string }>('/cwpp/scan', { provider, accountId }),

  list: (params: { provider?: string; accountId?: string; severity?: string; status?: string; page?: number; pageSize?: number }) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== '' && qs.set(k, String(v)));
    return api.get<{ data: WorkloadVulnerability[]; total: number; page: number; pageSize: number; totalPages: number }>(
      `/cwpp/vulnerabilities?${qs}`,
    );
  },

  host: (resourceInventoryId: string) =>
    api.get<WorkloadVulnerability[]>(`/cwpp/hosts/${resourceInventoryId}`),

  stats: (provider: 'AWS' | 'AZURE' | 'GCP', accountId: string) =>
    api.get<CwppStats>(`/cwpp/stats/${provider}/${accountId}`),

  update: (id: string, body: { status?: 'OPEN' | 'FIXED' | 'SUPPRESSED'; suppressedReason?: string }) =>
    api.patch<WorkloadVulnerability>(`/cwpp/vulnerabilities/${id}`, body),
};

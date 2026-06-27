import { api } from './client';

export type DataType = 'PII' | 'PHI' | 'PCI' | 'SECRETS' | 'FINANCIAL' | 'IP';
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW';

export interface DataClassification {
  id: string;
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  resourceInventoryId: string;
  dataType: DataType;
  confidence: Confidence;
  sampleCount: number;
  totalObjectsSampled: number;
  evidence: { labels?: string[]; examples?: string[]; samplePaths?: string[]; classifierVersion?: string };
  classifiedAt: string;
  expiresAt: string | null;
  resource: {
    id: string;
    nativeId: string;
    resourceType: string;
    region: string | null;
    dataSensitivity: string | null;
  };
}

export interface DspmStats {
  byDataType: { dataType: DataType; count: number }[];
  sensitiveAndPublic: number;
  classifiedResources: number;
}

export const dspmApi = {
  scan: (provider: 'AWS' | 'AZURE' | 'GCP', accountId: string) =>
    api.post<{ jobId: string; status: string }>('/dspm/scan', { provider, accountId }),

  list: (params: { provider?: string; accountId?: string; dataType?: DataType; minConfidence?: Confidence; page?: number; pageSize?: number }) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== '' && qs.set(k, String(v)));
    return api.get<{ data: DataClassification[]; total: number; page: number; pageSize: number; totalPages: number }>(
      `/dspm/classifications?${qs}`,
    );
  },

  resource: (resourceId: string) =>
    api.get<DataClassification[]>(`/dspm/resources/${resourceId}`),

  stats: (provider: 'AWS' | 'AZURE' | 'GCP', accountId: string) =>
    api.get<DspmStats>(`/dspm/stats/${provider}/${accountId}`),
};

import { api } from './client';

export type RiskStatus   = 'OPEN' | 'ACCEPTED' | 'MITIGATED' | 'CLOSED';
export type RiskCategory = 'CONFIGURATION' | 'VULNERABILITY' | 'ACCESS' | 'COMPLIANCE' | 'OPERATIONAL' | 'DATA';

export interface RiskItem {
  id: string;
  title: string;
  description: string;
  category: RiskCategory;
  likelihood: number;
  impact: number;
  riskScore: number;
  status: RiskStatus;
  owner: string | null;
  dueDate: string | null;
  provider: string | null;
  accountId: string | null;
  linkedFindingIds: string[];
  linkedControlIds: string[];
  mitigationPlan: string | null;
  acceptanceRationale: string | null;
  createdAt: string;
  updatedAt: string;
}

export type RiskItemCreate = Omit<RiskItem, 'id' | 'riskScore' | 'createdAt' | 'updatedAt'>;
export type RiskItemUpdate = Partial<RiskItemCreate>;

export const riskRegisterApi = {
  list: (params?: { provider?: string; accountId?: string; status?: RiskStatus; category?: RiskCategory }) => {
    const qs = new URLSearchParams();
    if (params?.provider)  qs.set('provider',  params.provider);
    if (params?.accountId) qs.set('accountId', params.accountId);
    if (params?.status)    qs.set('status',    params.status);
    if (params?.category)  qs.set('category',  params.category);
    const query = qs.toString();
    return api.get<RiskItem[]>(`/risk-register${query ? `?${query}` : ''}`);
  },

  get: (id: string) =>
    api.get<RiskItem>(`/risk-register/${id}`),

  create: (data: RiskItemCreate) =>
    api.post<RiskItem>('/risk-register', data),

  update: (id: string, data: RiskItemUpdate) =>
    api.patch<RiskItem>(`/risk-register/${id}`, data),

  delete: (id: string) =>
    api.delete<{ deleted: boolean }>(`/risk-register/${id}`),
};

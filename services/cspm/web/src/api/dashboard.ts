import { api } from './client';
import type { DashboardSummary, TrendPoint, AccountSummary, Finding } from '../types';

export const dashboardApi = {
  getSummary: () => api.get<DashboardSummary>('/dashboard/summary'),

  getTrends: (days: number = 30) =>
    api.get<TrendPoint[]>(`/dashboard/trends?days=${days}`),

  getAccounts: () => api.get<AccountSummary[]>('/dashboard/accounts'),

  getTopFindings: (limit: number = 10) =>
    api.get<Finding[]>(`/dashboard/top-findings?limit=${limit}`),
};

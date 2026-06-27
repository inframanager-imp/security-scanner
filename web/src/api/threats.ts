import { api } from './client';

export interface MonitorStatus {
  accountId:    string;
  name?:        string;
  awsAccountId?: string;
  monitoring:   boolean;
  lastCheck:    string | null;
}

export const threatsApi = {
  startMonitoring: (accountId: string) =>
    api.post<{ accountId: string; monitoring: boolean; message: string }>(
      `/threats/monitor/${accountId}/start`,
    ),

  stopMonitoring: (accountId: string) =>
    api.post<{ accountId: string; monitoring: boolean; message: string }>(
      `/threats/monitor/${accountId}/stop`,
    ),

  getStatus: (accountId: string) =>
    api.get<MonitorStatus>(`/threats/monitor/${accountId}/status`),

  getAllStatuses: () =>
    api.get<MonitorStatus[]>('/threats/monitor/all'),
};

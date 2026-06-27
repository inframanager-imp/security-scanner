import { api } from './client';
import type { Account, Credential, AuthMethod, PaginatedResponse } from '../types';

export interface CreateAccountPayload {
  name: string;
  awsAccountId: string;
  description?: string;
}

export interface UpdateAccountPayload {
  name?: string;
  description?: string;
}

export interface CreateCredentialPayload {
  authMethod: AuthMethod;
  accessKeyId?: string;
  secretAccessKey?: string;
  roleArn?: string;
  externalId?: string;
  region?: string;
}

export interface SetupAccountPayload {
  name: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}

export const accountsApi = {
  setup: (payload: SetupAccountPayload) =>
    api.post<Account>('/accounts/setup', payload),

  list: () => api.get<PaginatedResponse<Account>>('/accounts'),

  get: (id: string) => api.get<Account>(`/accounts/${id}`),

  create: (payload: CreateAccountPayload) =>
    api.post<Account>('/accounts', payload),

  update: (id: string, payload: UpdateAccountPayload) =>
    api.put<Account>(`/accounts/${id}`, payload),

  delete: (id: string) => api.delete<void>(`/accounts/${id}`),

  getCredentials: (accountId: string) =>
    api.get<Credential>(`/accounts/${accountId}/credentials`),

  setCredentials: (accountId: string, payload: CreateCredentialPayload) =>
    api.post<Credential>(`/accounts/${accountId}/credentials`, payload),

  updateCredentials: (accountId: string, payload: CreateCredentialPayload) =>
    api.post<Credential>(`/accounts/${accountId}/credentials`, payload),

  verifyCredentials: (accountId: string) =>
    api.post<{ valid: boolean; awsAccountId?: string; error?: string }>(
      `/accounts/${accountId}/credentials/verify`,
    ),

  deleteCredentials: (accountId: string) =>
    api.delete<void>(`/accounts/${accountId}/credentials`),
};

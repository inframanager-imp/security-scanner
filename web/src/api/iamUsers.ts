import { api } from './client';

export interface IamUserPolicyRef {
  name: string;
  type: 'managed' | 'inline';
  isAdminEquivalent: boolean;
}
export interface IamUserGroupPolicyRef {
  groupName: string;
  policyName: string;
  type: 'managed' | 'inline';
  isAdminEquivalent: boolean;
}
export interface IamUserAssumableRole {
  roleName: string;
  isAdminEquivalent: boolean;
  assumableBy: 'explicit' | 'wildcard';
}
export interface IamUserRow {
  userName: string;
  arn: string;
  groups: string[];
  directPolicies: IamUserPolicyRef[];
  groupPolicies: IamUserGroupPolicyRef[];
  assumableRoles: IamUserAssumableRole[];
  hasOpenEndedAccess: boolean;
  mfaEnabled: boolean;
  mfaMissing: boolean;
  passwordEnabled: boolean;
  passwordAgeDays: number | null;
  passwordStale: boolean;
  accessKeysActive: number;
  accessKeyAgeDays: number | null;
  keyStale: boolean;
  hasNeverUsedActiveKey: boolean;
  severity: string;
  discoveredAt: string;
}

export interface IamUsersResponse {
  data:        IamUserRow[];
  lastScanAt:  string | null;
}

export const iamUsersApi = {
  list: (accountId: string) =>
    api.get<IamUsersResponse>(`/iam-users?accountId=${accountId}`),
};

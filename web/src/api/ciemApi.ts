import { api } from './client';

export type AttackPathKind =
  | 'PRIVILEGE_ESCALATION'
  | 'LATERAL_MOVEMENT'
  | 'EXTERNAL_TO_ADMIN'
  | 'DATA_EXFILTRATION';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AttackPathStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface AttackPathHop {
  nodeId: string;
  label: string;
  edgeType: string;
  detail: string;
}

export interface AttackPath {
  id: string;
  provider: 'AWS' | 'AZURE' | 'GCP';
  accountId: string;
  kind: AttackPathKind;
  severity: Severity;
  sourceLabel: string;
  sinkLabel: string;
  pathJson: AttackPathHop[];
  summary: string;
  status: AttackPathStatus;
  firstSeenAt: string;
  lastSeenAt: string;
  notes: string | null;
}

export interface PrincipalPermission {
  id: string;
  principalArn: string;
  principalType: string;
  action: string;
  resourceArn: string;
  effect: 'ALLOW' | 'DENY';
  source: string;
}

export interface CiemStats {
  attackPathsByKind: { kind: string; count: number }[];
  attackPathsBySeverity: { severity: string; count: number }[];
  topPrincipalsByPermissionCount: { principalArn: string; permissionCount: number }[];
}

export const ciemApi = {
  listAttackPaths: (params: {
    provider?: string;
    accountId?: string;
    kind?: AttackPathKind;
    severity?: Severity;
    status?: AttackPathStatus;
    page?: number;
    pageSize?: number;
  }) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && qs.set(k, String(v)));
    return api.get<{ data: AttackPath[]; total: number; page: number; pageSize: number; totalPages: number }>(
      `/ciem/attack-paths?${qs}`,
    );
  },

  getAttackPath: (id: string) => api.get<AttackPath>(`/ciem/attack-paths/${id}`),

  updateAttackPath: (id: string, body: { status?: AttackPathStatus; notes?: string }) =>
    api.patch<AttackPath>(`/ciem/attack-paths/${id}`, body),

  getPrincipalPermissions: (arn: string, provider: string, accountId: string) =>
    api.get<PrincipalPermission[]>(
      `/ciem/principals/${encodeURIComponent(arn)}/permissions?provider=${provider}&accountId=${accountId}`,
    ),

  stats: (provider: 'AWS' | 'AZURE' | 'GCP', accountId: string) =>
    api.get<CiemStats>(`/ciem/stats/${provider}/${accountId}`),
};

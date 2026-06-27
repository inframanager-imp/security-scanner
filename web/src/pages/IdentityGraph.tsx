import { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Users, AlertTriangle, Eye, CheckCircle2, Network, Filter } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { accountsApi } from '../api/accounts';
import { azureApi } from '../api/azure';
import { gcpApi } from '../api/gcp';
import { ciemApi, type AttackPathKind, type AttackPathStatus, type Severity } from '../api/ciemApi';

type Provider = 'AWS' | 'AZURE' | 'GCP';

const SEVERITY_CLASSES: Record<Severity, string> = {
  CRITICAL: 'bg-red-100 text-red-800 ring-red-200',
  HIGH:     'bg-orange-100 text-orange-800 ring-orange-200',
  MEDIUM:   'bg-yellow-100 text-yellow-800 ring-yellow-200',
  LOW:      'bg-blue-50 text-blue-700 ring-blue-200',
};

const STATUS_CLASSES: Record<AttackPathStatus, string> = {
  OPEN:           'bg-red-50 text-red-700 ring-red-200',
  ACKNOWLEDGED:   'bg-amber-50 text-amber-700 ring-amber-200',
  RESOLVED:       'bg-emerald-50 text-emerald-700 ring-emerald-200',
  FALSE_POSITIVE: 'bg-gray-50 text-gray-700 ring-gray-200',
};

const KIND_LABELS: Record<AttackPathKind, string> = {
  PRIVILEGE_ESCALATION: 'Privilege Escalation',
  LATERAL_MOVEMENT:     'Lateral Movement',
  EXTERNAL_TO_ADMIN:    'External → Admin',
  DATA_EXFILTRATION:    'Data Exfiltration',
};

const KIND_COLORS: Record<AttackPathKind, string> = {
  PRIVILEGE_ESCALATION: 'bg-purple-50 text-purple-800 ring-purple-200',
  LATERAL_MOVEMENT:     'bg-blue-50 text-blue-800 ring-blue-200',
  EXTERNAL_TO_ADMIN:    'bg-red-50 text-red-800 ring-red-200',
  DATA_EXFILTRATION:    'bg-pink-50 text-pink-800 ring-pink-200',
};

export function IdentityGraph() {
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState<Provider>('AWS');
  const [accountId, setAccountId] = useState<string>('');
  const [kindFilter, setKindFilter] = useState<AttackPathKind | ''>('');
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('');
  const [statusFilter, setStatusFilter] = useState<AttackPathStatus | ''>('OPEN');

  const { data: awsAccounts = [] } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => accountsApi.list(),
    select: (d: any) => d?.data ?? [],
  });
  const { data: azureSubs = [] } = useQuery({
    queryKey: ['azure-subscriptions'],
    queryFn: () => azureApi.listSubscriptions({ limit: 200 }),
    select: (d: any) => d?.data ?? [],
  });
  const { data: gcpProjects = [] } = useQuery({
    queryKey: ['gcp-projects'],
    queryFn: () => gcpApi.listProjects({ limit: 200 }),
    select: (d: any) => d?.data ?? [],
  });

  const targets = useMemo(() => {
    if (provider === 'AWS')   return awsAccounts.map((a: any) => ({ id: a.id, label: `${a.name} (${a.awsAccountId})` }));
    if (provider === 'AZURE') return azureSubs.map((s: any) => ({ id: s.id, label: `${s.name} (${s.subscriptionId})` }));
    return gcpProjects.map((p: any) => ({ id: p.id, label: `${p.name} (${p.projectId})` }));
  }, [provider, awsAccounts, azureSubs, gcpProjects]);

  useEffect(() => {
    if (targets.length > 0 && !accountId) setAccountId(targets[0].id);
  }, [targets, accountId]);

  const { data: stats } = useQuery({
    queryKey: ['ciem-stats', provider, accountId],
    queryFn: () => ciemApi.stats(provider, accountId),
    enabled: Boolean(accountId),
    staleTime: 30_000,
  });

  const { data: paths } = useQuery({
    queryKey: ['ciem-paths', provider, accountId, kindFilter, severityFilter, statusFilter],
    queryFn: () =>
      ciemApi.listAttackPaths({
        provider,
        accountId,
        kind: kindFilter || undefined,
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        pageSize: 100,
      }),
    enabled: Boolean(accountId),
    staleTime: 15_000,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: AttackPathStatus }) =>
      ciemApi.updateAttackPath(id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ciem-paths'] });
      queryClient.invalidateQueries({ queryKey: ['ciem-stats'] });
    },
  });

  const rows = paths?.data ?? [];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Users className="text-purple-600" size={28} />
            Identity & Attack Paths
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            CIEM analysis: principal permissions and attack paths over the asset graph.
          </p>
        </div>
      </div>

      <Card>
        <div className="flex flex-wrap gap-4 items-end">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Provider</label>
            <select
              className="border rounded px-2 py-1 text-sm"
              value={provider}
              onChange={(e) => { setProvider(e.target.value as Provider); setAccountId(''); }}
            >
              <option value="AWS">AWS</option>
              <option value="AZURE">Azure</option>
              <option value="GCP">GCP</option>
            </select>
          </div>

          <div className="flex-1 min-w-[260px]">
            <label className="block text-xs font-medium text-gray-600 mb-1">Account</label>
            <select
              className="border rounded px-2 py-1 text-sm w-full"
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
            >
              {targets.length === 0 && <option>No accounts</option>}
              {targets.map((t: { id: string; label: string }) => (
                <option key={t.id} value={t.id}>{t.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1">
              <Filter size={12} /> Kind
            </label>
            <select
              className="border rounded px-2 py-1 text-sm"
              value={kindFilter}
              onChange={(e) => setKindFilter(e.target.value as AttackPathKind | '')}
            >
              <option value="">All</option>
              {(Object.keys(KIND_LABELS) as AttackPathKind[]).map((k) => (
                <option key={k} value={k}>{KIND_LABELS[k]}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Severity</label>
            <select
              className="border rounded px-2 py-1 text-sm"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as Severity | '')}
            >
              <option value="">All</option>
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Status</label>
            <select
              className="border rounded px-2 py-1 text-sm"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as AttackPathStatus | '')}
            >
              <option value="">All</option>
              {(['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'] as AttackPathStatus[]).map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* Stats tiles */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((sev) => {
          const found = stats?.attackPathsBySeverity.find((s) => s.severity === sev);
          return (
            <Card key={sev}>
              <div className="text-xs text-gray-500">{sev}</div>
              <div className={`text-2xl font-semibold ${SEVERITY_CLASSES[sev].split(' ')[1]}`}>
                {found?.count ?? 0}
              </div>
            </Card>
          );
        })}
      </div>

      {/* Top principals card */}
      {stats?.topPrincipalsByPermissionCount && stats.topPrincipalsByPermissionCount.length > 0 && (
        <Card title="Top principals by permission count">
          <div className="space-y-1">
            {stats.topPrincipalsByPermissionCount.slice(0, 10).map((p) => (
              <div key={p.principalArn} className="flex items-center justify-between text-sm">
                <span className="font-mono text-xs truncate max-w-[60%]">{p.principalArn}</span>
                <span className="text-gray-500">{p.permissionCount} permissions</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Attack paths table */}
      <Card title={`Attack paths (${rows.length})`}>
        {rows.length === 0 ? (
          <div className="text-center py-10 text-gray-500 text-sm">
            <Network size={28} className="mx-auto mb-2 text-gray-300" />
            <div>No attack paths matching the current filters.</div>
            <div className="text-xs mt-1">
              Run a scan or trigger a graph rebuild; CIEM analysis runs automatically after each.
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-gray-500 border-b">
                <tr>
                  <th className="py-2">Kind</th>
                  <th>Severity</th>
                  <th>Summary</th>
                  <th>Status</th>
                  <th>Last seen</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => (
                  <tr key={p.id} className="border-b last:border-0 hover:bg-gray-50">
                    <td className="py-2">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ring-1 ${KIND_COLORS[p.kind]}`}>
                        {KIND_LABELS[p.kind]}
                      </span>
                    </td>
                    <td>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold ring-1 ${SEVERITY_CLASSES[p.severity]}`}>
                        {p.severity}
                      </span>
                    </td>
                    <td className="text-sm max-w-[420px] truncate" title={p.summary}>{p.summary}</td>
                    <td>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs ring-1 ${STATUS_CLASSES[p.status]}`}>
                        {p.status}
                      </span>
                    </td>
                    <td className="text-xs text-gray-500">{new Date(p.lastSeenAt).toLocaleString()}</td>
                    <td>
                      <div className="flex items-center gap-1">
                        <Link
                          to={`/attack-paths/${p.id}`}
                          className="text-blue-600 hover:underline text-xs inline-flex items-center gap-1"
                        >
                          <Eye size={12} /> View
                        </Link>
                        {p.status === 'OPEN' && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => updateMutation.mutate({ id: p.id, status: 'ACKNOWLEDGED' })}
                          >
                            <AlertTriangle size={12} /> Ack
                          </Button>
                        )}
                        {p.status !== 'RESOLVED' && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => updateMutation.mutate({ id: p.id, status: 'RESOLVED' })}
                          >
                            <CheckCircle2 size={12} /> Resolve
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

export default IdentityGraph;

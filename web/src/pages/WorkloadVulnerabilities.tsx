import { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Server, RefreshCw, ExternalLink, Filter } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { accountsApi } from '../api/accounts';
import { azureApi } from '../api/azure';
import { gcpApi } from '../api/gcp';
import { cwppApi, type WorkloadVulnerability } from '../api/cwppApi';

type Provider = 'AWS' | 'AZURE' | 'GCP';

const SEVERITY_CLASSES: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 ring-red-200',
  HIGH:     'bg-orange-100 text-orange-800 ring-orange-200',
  MEDIUM:   'bg-yellow-100 text-yellow-800 ring-yellow-200',
  LOW:      'bg-blue-50 text-blue-700 ring-blue-200',
  UNKNOWN:  'bg-gray-50 text-gray-600 ring-gray-200',
};

const STATUS_CLASSES: Record<string, string> = {
  OPEN:       'bg-red-50 text-red-700 ring-red-200',
  FIXED:      'bg-emerald-50 text-emerald-700 ring-emerald-200',
  SUPPRESSED: 'bg-gray-50 text-gray-700 ring-gray-200',
};

function shortLabel(s: string, n = 32): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

export function WorkloadVulnerabilities() {
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState<Provider>('AWS');
  const [accountId, setAccountId] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('OPEN');

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
    queryKey: ['cwpp-stats', provider, accountId],
    queryFn: () => cwppApi.stats(provider, accountId),
    enabled: Boolean(accountId),
    staleTime: 30_000,
  });

  const { data: vulnsResp } = useQuery({
    queryKey: ['cwpp-vulns', provider, accountId, severityFilter, statusFilter],
    queryFn: () => cwppApi.list({ provider, accountId, severity: severityFilter || undefined, status: statusFilter || undefined, pageSize: 100 }),
    enabled: Boolean(accountId),
    staleTime: 15_000,
  });
  const rows = vulnsResp?.data ?? [];

  const [scanStatusMsg, setScanStatusMsg] = useState<string | null>(null);
  const scanMutation = useMutation({
    mutationFn: () => cwppApi.scan(provider, accountId),
    onSuccess: () => {
      setScanStatusMsg('Scan queued — waiting for results…');
      const MAX_ATTEMPTS = 10;
      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        await queryClient.invalidateQueries({ queryKey: ['cwpp-stats'] });
        await queryClient.invalidateQueries({ queryKey: ['cwpp-vulns'] });
        const fresh = await queryClient.fetchQuery({
          queryKey: ['cwpp-stats', provider, accountId],
          queryFn: () => cwppApi.stats(provider, accountId),
        }).catch(() => null);
        if (attempts >= MAX_ATTEMPTS) {
          clearInterval(poll);
          setScanStatusMsg(
            fresh
              ? `Scan complete — ${fresh.openTotal ?? 0} open vulnerabilit${(fresh.openTotal ?? 0) === 1 ? 'y' : 'ies'} found across ${fresh.hostsAffected ?? 0} host(s).`
              : 'Scan may still be running — refresh to check for results.'
          );
          setTimeout(() => setScanStatusMsg(null), 8000);
        }
      }, 2000);
    },
    onError: (err: any) => {
      setScanStatusMsg(`Scan failed: ${err?.message ?? 'unknown error'}`);
      setTimeout(() => setScanStatusMsg(null), 8000);
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'FIXED' | 'SUPPRESSED' }) =>
      cwppApi.update(id, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cwpp-vulns'] });
      queryClient.invalidateQueries({ queryKey: ['cwpp-stats'] });
    },
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Server className="text-amber-600" size={28} />
            Workload Vulnerabilities
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Agentless CWPP: OS packages and CVEs across VMs / instances.
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <Button variant="primary" onClick={() => scanMutation.mutate()} disabled={!accountId || scanMutation.isPending}>
            <RefreshCw size={14} className={scanMutation.isPending ? 'animate-spin' : ''} />
            {scanMutation.isPending ? 'Scanning…' : 'Run CWPP scan'}
          </Button>
          {scanStatusMsg && (
            <div className="text-xs text-gray-500 max-w-xs text-right">{scanStatusMsg}</div>
          )}
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
            <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1"><Filter size={12} /> Severity</label>
            <select className="border rounded px-2 py-1 text-sm" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
              <option value="">All</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Status</label>
            <select className="border rounded px-2 py-1 text-sm" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="">All</option>
              {['OPEN', 'FIXED', 'SUPPRESSED'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
      </Card>

      {stats?.infoMessage && (
        <div className="rounded border border-amber-200 bg-amber-50 text-amber-800 text-sm px-3 py-2">
          {stats.infoMessage}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
          const found = stats?.bySeverity.find((s) => s.severity === sev);
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

      <Card title={`Vulnerabilities (${rows.length})`}>
        {rows.length === 0 ? (
          <div className="text-center py-10 text-gray-500 text-sm">
            <Server size={28} className="mx-auto mb-2 text-gray-300" />
            <div>No workload vulnerabilities found.</div>
            <div className="text-xs mt-1">Run a CWPP scan to populate. Requires SSM Inventory (AWS) / Defender for Servers (Azure) / OS Config (GCP).</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-gray-500 border-b">
                <tr>
                  <th className="py-2">Severity</th>
                  <th>CVE</th>
                  <th>Package</th>
                  <th>Host</th>
                  <th>Status</th>
                  <th>Observed</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((v: WorkloadVulnerability) => (
                  <tr key={v.id} className="border-b last:border-0 hover:bg-gray-50">
                    <td className="py-2">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold ring-1 ${SEVERITY_CLASSES[v.severity] ?? SEVERITY_CLASSES.UNKNOWN}`}>
                        {v.severity}
                        {v.cvssScore != null && <span className="ml-1 opacity-70">{v.cvssScore}</span>}
                      </span>
                    </td>
                    <td>
                      <a className="font-mono text-xs text-blue-600 hover:underline" href={v.reference ?? `https://osv.dev/vulnerability/${v.cveId}`} target="_blank" rel="noreferrer">
                        {v.cveId} <ExternalLink size={10} className="inline" />
                      </a>
                    </td>
                    <td className="text-xs">
                      <div className="font-mono">{v.packageName}</div>
                      <div className="text-gray-500">{v.packageVersion}</div>
                    </td>
                    <td className="text-xs font-mono">{shortLabel(v.resource.nativeId, 28)}</td>
                    <td>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs ring-1 ${STATUS_CLASSES[v.status]}`}>{v.status}</span>
                    </td>
                    <td className="text-xs text-gray-500">{new Date(v.observedAt).toLocaleDateString()}</td>
                    <td>
                      <div className="flex items-center gap-1">
                        {v.status === 'OPEN' && (
                          <>
                            <Button size="sm" variant="ghost" onClick={() => updateMutation.mutate({ id: v.id, status: 'FIXED' })}>Mark fixed</Button>
                            <Button size="sm" variant="ghost" onClick={() => updateMutation.mutate({ id: v.id, status: 'SUPPRESSED' })}>Suppress</Button>
                          </>
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

export default WorkloadVulnerabilities;

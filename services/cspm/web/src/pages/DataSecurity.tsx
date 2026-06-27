import { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Database, RefreshCw, Globe, AlertTriangle } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { accountsApi } from '../api/accounts';
import { azureApi } from '../api/azure';
import { gcpApi } from '../api/gcp';
import { dspmApi, type DataClassification, type DataType, type Confidence } from '../api/dspmApi';

type Provider = 'AWS' | 'AZURE' | 'GCP';

const DATA_TYPE_COLORS: Record<DataType, string> = {
  PII:       'bg-blue-50 text-blue-700 ring-blue-200',
  PHI:       'bg-pink-50 text-pink-700 ring-pink-200',
  PCI:       'bg-red-50 text-red-700 ring-red-200',
  SECRETS:   'bg-orange-50 text-orange-700 ring-orange-200',
  FINANCIAL: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  IP:        'bg-violet-50 text-violet-700 ring-violet-200',
};

const CONFIDENCE_COLORS: Record<Confidence, string> = {
  HIGH:   'bg-red-100 text-red-800 ring-red-200',
  MEDIUM: 'bg-yellow-50 text-yellow-800 ring-yellow-200',
  LOW:    'bg-gray-50 text-gray-600 ring-gray-200',
};

const SENSITIVITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH:     'bg-orange-100 text-orange-800',
  MEDIUM:   'bg-yellow-100 text-yellow-800',
  LOW:      'bg-gray-50 text-gray-600',
};

function shortLabel(s: string, n = 32): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

export function DataSecurity() {
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState<Provider>('AWS');
  const [accountId, setAccountId] = useState<string>('');
  const [dataType, setDataType] = useState<DataType | ''>('');
  const [minConfidence, setMinConfidence] = useState<Confidence | ''>('');
  const [expanded, setExpanded] = useState<string | null>(null);

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
    queryKey: ['dspm-stats', provider, accountId],
    queryFn: () => dspmApi.stats(provider, accountId),
    enabled: Boolean(accountId),
    staleTime: 30_000,
  });

  const { data: classResp } = useQuery({
    queryKey: ['dspm-classifications', provider, accountId, dataType, minConfidence],
    queryFn: () => dspmApi.list({ provider, accountId, dataType: dataType || undefined, minConfidence: minConfidence || undefined, pageSize: 100 }),
    enabled: Boolean(accountId),
    staleTime: 15_000,
  });
  const rows = classResp?.data ?? [];

  const scanMutation = useMutation({
    mutationFn: () => dspmApi.scan(provider, accountId),
    onSuccess: () => {
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['dspm-classifications'] });
        queryClient.invalidateQueries({ queryKey: ['dspm-stats'] });
      }, 8000);
    },
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Database className="text-cyan-600" size={28} />
            Data Security (DSPM)
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Sensitive-data discovery: PII / PHI / PCI / secrets / financial / IP across storage resources.
          </p>
        </div>
        <Button variant="primary" onClick={() => scanMutation.mutate()} disabled={!accountId || scanMutation.isPending}>
          <RefreshCw size={14} className={scanMutation.isPending ? 'animate-spin' : ''} />
          {scanMutation.isPending ? 'Scanning…' : 'Run DSPM scan'}
        </Button>
      </div>

      <Card>
        <div className="flex flex-wrap gap-4 items-end">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Provider</label>
            <select className="border rounded px-2 py-1 text-sm" value={provider} onChange={(e) => { setProvider(e.target.value as Provider); setAccountId(''); }}>
              <option value="AWS">AWS</option>
              <option value="AZURE">Azure</option>
              <option value="GCP">GCP</option>
            </select>
          </div>
          <div className="flex-1 min-w-[260px]">
            <label className="block text-xs font-medium text-gray-600 mb-1">Account</label>
            <select className="border rounded px-2 py-1 text-sm w-full" value={accountId} onChange={(e) => setAccountId(e.target.value)}>
              {targets.length === 0 && <option>No accounts</option>}
              {targets.map((t: { id: string; label: string }) => (
                <option key={t.id} value={t.id}>{t.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Data type</label>
            <select className="border rounded px-2 py-1 text-sm" value={dataType} onChange={(e) => setDataType(e.target.value as DataType | '')}>
              <option value="">All</option>
              {(['PII', 'PHI', 'PCI', 'SECRETS', 'FINANCIAL', 'IP'] as DataType[]).map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Min confidence</label>
            <select className="border rounded px-2 py-1 text-sm" value={minConfidence} onChange={(e) => setMinConfidence(e.target.value as Confidence | '')}>
              <option value="">All</option>
              {(['HIGH', 'MEDIUM', 'LOW'] as Confidence[]).map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <div className="text-xs text-gray-500">Classified resources</div>
          <div className="text-2xl font-semibold">{stats?.classifiedResources ?? '—'}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-500 flex items-center gap-1">
            <Globe size={12} /> Sensitive AND publicly exposed
          </div>
          <div className={`text-2xl font-semibold ${stats?.sensitiveAndPublic ? 'text-red-600' : ''}`}>
            {stats?.sensitiveAndPublic ?? '—'}
          </div>
        </Card>
        <Card>
          <div className="text-xs text-gray-500">Most-found data type</div>
          <div className="text-2xl font-semibold">
            {stats?.byDataType[0]?.dataType ?? '—'}
          </div>
        </Card>
      </div>

      <Card title={`Classifications (${rows.length})`}>
        {rows.length === 0 ? (
          <div className="text-center py-10 text-gray-500 text-sm">
            <Database size={28} className="mx-auto mb-2 text-gray-300" />
            <div>No data classifications yet.</div>
            <div className="text-xs mt-1">Run a DSPM scan; it samples objects in each storage resource and looks for PII / PHI / PCI / secrets.</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-gray-500 border-b">
                <tr>
                  <th className="py-2">Resource</th>
                  <th>Data type</th>
                  <th>Confidence</th>
                  <th>Matches</th>
                  <th>Sampled</th>
                  <th>Sensitivity</th>
                  <th>Last seen</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c: DataClassification) => (
                  <>
                    <tr key={c.id} className="border-b last:border-0 hover:bg-gray-50 cursor-pointer" onClick={() => setExpanded(expanded === c.id ? null : c.id)}>
                      <td className="py-2 font-mono text-xs" title={c.resource.nativeId}>{shortLabel(c.resource.nativeId, 30)}</td>
                      <td>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ring-1 ${DATA_TYPE_COLORS[c.dataType]}`}>
                          {c.dataType}
                        </span>
                      </td>
                      <td>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold ring-1 ${CONFIDENCE_COLORS[c.confidence]}`}>
                          {c.confidence}
                        </span>
                      </td>
                      <td className="text-xs">{c.sampleCount}</td>
                      <td className="text-xs">{c.totalObjectsSampled}</td>
                      <td>
                        {c.resource.dataSensitivity && (
                          <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ${SENSITIVITY_COLORS[c.resource.dataSensitivity] ?? ''}`}>
                            {c.resource.dataSensitivity === 'CRITICAL' && <AlertTriangle size={10} className="mr-1" />}
                            {c.resource.dataSensitivity}
                          </span>
                        )}
                      </td>
                      <td className="text-xs text-gray-500">{new Date(c.classifiedAt).toLocaleDateString()}</td>
                      <td className="text-xs text-blue-600">{expanded === c.id ? '−' : '+'}</td>
                    </tr>
                    {expanded === c.id && (
                      <tr className="bg-gray-50">
                        <td colSpan={8} className="p-4">
                          <div className="text-xs space-y-2">
                            {c.evidence.labels && c.evidence.labels.length > 0 && (
                              <div>
                                <span className="font-medium">Classifier labels: </span>
                                {c.evidence.labels.join(', ')}
                              </div>
                            )}
                            {c.evidence.examples && c.evidence.examples.length > 0 && (
                              <div>
                                <span className="font-medium">Redacted examples: </span>
                                <span className="font-mono text-[11px]">{c.evidence.examples.join(' · ')}</span>
                                <div className="text-gray-500 text-[10px]">(prefix + length only; actual values are never stored)</div>
                              </div>
                            )}
                            {c.evidence.samplePaths && c.evidence.samplePaths.length > 0 && (
                              <div>
                                <span className="font-medium">Sample paths: </span>
                                <div className="font-mono text-[11px] space-y-0.5">
                                  {c.evidence.samplePaths.slice(0, 5).map((p) => <div key={p}>{shortLabel(p, 100)}</div>)}
                                </div>
                              </div>
                            )}
                            {c.evidence.classifierVersion && (
                              <div className="text-gray-500">Classifier version: {c.evidence.classifierVersion}</div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

export default DataSecurity;

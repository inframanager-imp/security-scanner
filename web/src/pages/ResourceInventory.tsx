import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Database, RefreshCw, Search, Filter, Server, Shield, Activity,
  HardDrive, Cloud, Box, ChevronRight, AlertTriangle, CheckCircle2,
  Trash2, GitBranch, GitCommit,
} from 'lucide-react';
import { resourceInventoryApi } from '../api/resourceInventory';
import { configChangesApi }      from '../api/configChanges';
import { accountsApi }           from '../api/accounts';
import { azureApi }              from '../api/azure';
import { gcpApi }                from '../api/gcp';
import { Card }    from '../components/ui/Card';
import { Button }  from '../components/ui/Button';
import { Select }  from '../components/ui/Select';
import { Input }   from '../components/ui/Input';
import { Pagination } from '../components/ui/Table';
import type { CloudProvider } from '../types';

// ─── Constants ────────────────────────────────────────────────────────────────

const PROVIDER_CONFIG = {
  AWS:   { label: 'AWS',   color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200', dot: 'bg-orange-500' },
  AZURE: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-50',   border: 'border-blue-200',   dot: 'bg-blue-500'   },
  GCP:   { label: 'GCP',   color: 'text-green-700',  bg: 'bg-green-50',  border: 'border-green-200',  dot: 'bg-green-500'  },
};

const RESOURCE_TYPE_ICONS: Record<string, typeof Server> = {
  'ec2':         Server,
  'vpc':         Activity,
  'subnet':      Activity,
  'securitygroup': Shield,
  's3':          HardDrive,
  'iam':         Shield,
  'rds':         Database,
  'lambda':      Box,
  'eks':         Box,
  'virtual':     Server,
  'storage':     HardDrive,
  'keyvault':    Shield,
  'sql':         Database,
  'network':     Activity,
  'compute':     Server,
  'container':   Box,
  'bucket':      HardDrive,
  'firewall':    Shield,
  'cluster':     Box,
  'serviceaccount': Shield,
};

function getResourceIcon(resourceType: string): typeof Server {
  const lower = resourceType.toLowerCase();
  for (const [key, Icon] of Object.entries(RESOURCE_TYPE_ICONS)) {
    if (lower.includes(key)) return Icon;
  }
  return Cloud;
}

function friendlyType(resourceType: string): string {
  // e.g. "AWS::EC2::Instance" → "EC2 Instance"
  // e.g. "Microsoft.Compute/virtualMachines" → "Virtual Machines"
  // e.g. "compute.googleapis.com/Instance" → "Compute Instance"
  return resourceType
    .replace(/^AWS::/, '').replace(/^Microsoft\./, '').replace(/\.googleapis\.com/, '')
    .replace(/\//g, ' ').replace(/::/g, ' ');
}

function fmtDate(d: string) {
  return new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ─── Summary cards for a single account target ────────────────────────────────

function TargetDiscoverCard({
  provider,
  targetId,
  name,
  nativeId,
}: {
  provider: CloudProvider;
  targetId: string;
  name:     string;
  nativeId: string;
}) {
  const qc = useQueryClient();
  const cfg = PROVIDER_CONFIG[provider];

  const { data: stats } = useQuery({
    queryKey:  ['resource-stats', provider, targetId],
    queryFn:   () => resourceInventoryApi.getStats(provider, targetId),
    staleTime: 60_000,
  });

  const discoverMutation = useMutation({
    mutationFn: () => resourceInventoryApi.discover(provider, targetId),
    onSuccess:  () => {
      setTimeout(() => qc.invalidateQueries({ queryKey: ['resource-stats', provider, targetId] }), 5000);
    },
  });

  const reconcileMutation = useMutation({
    mutationFn: () => configChangesApi.reconcileInventory(provider, targetId),
    onSuccess:  (data) => {
      qc.invalidateQueries({ queryKey: ['resource-stats', provider, targetId] });
      qc.invalidateQueries({ queryKey: ['resource-list'] });
      setReconcileMsg(`${data.message}`);
      setTimeout(() => setReconcileMsg(null), 6000);
    },
  });

  const [reconcileMsg, setReconcileMsg] = useState<string | null>(null);

  return (
    <div className={`bg-white border ${cfg.border} rounded-lg p-4`}>
      <div className="flex items-start justify-between mb-3">
        <div>
          <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.color} border ${cfg.border} mb-1`}>
            <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
            {cfg.label}
          </span>
          <p className="text-sm font-semibold text-gray-900">{name}</p>
          <p className="text-xs font-mono text-gray-400">{nativeId}</p>
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            leftIcon={<GitCommit size={12} className={reconcileMutation.isPending ? 'animate-spin' : ''} />}
            onClick={() => reconcileMutation.mutate()}
            disabled={reconcileMutation.isPending}
            title="Apply deletion events from Config Changes to inventory"
          >
            {reconcileMutation.isPending ? 'Reconciling…' : 'Reconcile'}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<RefreshCw size={12} className={discoverMutation.isPending ? 'animate-spin' : ''} />}
            onClick={() => discoverMutation.mutate()}
            disabled={discoverMutation.isPending}
          >
            {discoverMutation.isPending ? 'Discovering…' : 'Discover'}
          </Button>
        </div>
      </div>
      {reconcileMsg && (
        <div className="mb-2 text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded px-2 py-1">
          {reconcileMsg}
        </div>
      )}
      {stats ? (
        <div className="grid grid-cols-3 gap-2 text-center">
          <div className="bg-gray-50 rounded p-2">
            <p className="text-lg font-bold text-gray-900">{stats.byState?.ACTIVE ?? 0}</p>
            <p className="text-xs text-gray-500">Active</p>
          </div>
          <div className="bg-red-50 rounded p-2">
            <p className="text-lg font-bold text-red-600">{stats.byState?.DELETED ?? 0}</p>
            <p className="text-xs text-gray-500">Deleted</p>
          </div>
          <div className="bg-blue-50 rounded p-2">
            <p className="text-lg font-bold text-blue-600">{stats.byType?.length ?? 0}</p>
            <p className="text-xs text-gray-500">Types</p>
          </div>
        </div>
      ) : (
        <div className="h-12 flex items-center justify-center text-xs text-gray-400">
          {discoverMutation.isPending ? 'Running discovery…' : 'Click Discover to scan'}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function ResourceInventory() {
  const navigate = useNavigate();

  const [provFilter, setProvFilter]  = useState<'ALL' | CloudProvider>('ALL');
  const [typeFilter, setTypeFilter]  = useState('');
  const [stateFilter, setStateFilter] = useState('ACTIVE');
  const [search,     setSearch]      = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [page,        setPage]       = useState(1);

  const { data: awsPage }   = useQuery({ queryKey: ['accounts'],            queryFn: () => accountsApi.list() });
  const { data: azurePage } = useQuery({ queryKey: ['azure-subscriptions'], queryFn: () => azureApi.listSubscriptions({ limit: 100 }) });
  const { data: gcpPage }   = useQuery({ queryKey: ['gcp-projects'],        queryFn: () => gcpApi.listProjects({ limit: 100 }) });

  const { data: globalStats } = useQuery({
    queryKey:  ['resource-stats-global'],
    queryFn:   () => resourceInventoryApi.getStats(),
    staleTime: 60_000,
  });

  const listParams = useMemo(() => ({
    provider:     provFilter !== 'ALL' ? provFilter : undefined,
    resourceType: typeFilter || undefined,
    state:        stateFilter as 'ACTIVE' | 'DELETED' | '' || undefined,
    search:       search || undefined,
    page,
    pageSize:     50,
    sortBy:       'lastSeenAt' as const,
    sortOrder:    'desc' as const,
  }), [provFilter, typeFilter, stateFilter, search, page]);

  const { data: listData, isLoading } = useQuery({
    queryKey:  ['resource-list', listParams],
    queryFn:   () => resourceInventoryApi.list(listParams),
    staleTime: 30_000,
  });

  const resources  = listData?.data      ?? [];
  const totalPages = listData?.meta?.totalPages ?? 1;
  const totalCount = listData?.meta?.total      ?? 0;

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-0.5">
          <Database size={20} className="text-gray-600" />
          <h2 className="text-xl font-bold text-gray-900">Resource Inventory</h2>
        </div>
        <p className="text-sm text-gray-500">Auto-discovered cloud resources with versioned configuration history and dependency mapping</p>
      </div>

      {globalStats && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-gray-900">{globalStats.total}</p>
            <p className="text-xs text-gray-500 mt-0.5">Total Resources</p>
          </div>
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-green-700">{globalStats.byState?.ACTIVE ?? 0}</p>
            <p className="text-xs text-gray-500 mt-0.5">Active</p>
          </div>
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-red-600">{globalStats.byState?.DELETED ?? 0}</p>
            <p className="text-xs text-gray-500 mt-0.5">Deleted</p>
          </div>
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-center">
            <p className="text-3xl font-bold text-blue-700">{globalStats.byType?.length ?? 0}</p>
            <p className="text-xs text-gray-500 mt-0.5">Resource Types</p>
          </div>
        </div>
      )}

      <div>
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Discovery Controls</h3>
        <div className="grid grid-cols-3 gap-3">
          {(awsPage?.data ?? []).map((a) => (
            <TargetDiscoverCard key={a.id} provider="AWS" targetId={a.id} name={a.name} nativeId={a.awsAccountId} />
          ))}
          {(azurePage?.data ?? []).map((s) => (
            <TargetDiscoverCard key={s.id} provider="AZURE" targetId={s.id} name={s.name} nativeId={s.subscriptionId} />
          ))}
          {(gcpPage?.data ?? []).map((p) => (
            <TargetDiscoverCard key={p.id} provider="GCP" targetId={p.id} name={p.name} nativeId={p.projectId} />
          ))}
          {(awsPage?.data ?? []).length === 0 && (azurePage?.data ?? []).length === 0 && (gcpPage?.data ?? []).length === 0 && (
            <div className="col-span-3 text-center py-8 text-gray-400 text-sm border border-dashed border-gray-200 rounded-lg">
              No cloud accounts configured. Add an account in Cloud Subscriptions.
            </div>
          )}
        </div>
      </div>

      {globalStats && globalStats.byType.length > 0 && (
        <Card padding={false}>
          <div className="px-4 py-3 border-b border-gray-100">
            <p className="text-sm font-semibold text-gray-800">Resources by Type</p>
          </div>
          <div className="p-4 grid grid-cols-4 gap-3">
            {globalStats.byType.slice(0, 12).map(({ type, count }) => {
              const Icon = getResourceIcon(type);
              return (
                <button
                  key={type}
                  onClick={() => { setTypeFilter(type); setPage(1); }}
                  className="flex items-center gap-2 p-2 bg-gray-50 hover:bg-blue-50 rounded-lg transition-colors text-left"
                >
                  <Icon size={14} className="text-blue-500 shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-gray-800 truncate">{friendlyType(type)}</p>
                    <p className="text-xs text-gray-500">{count} resources</p>
                  </div>
                </button>
              );
            })}
          </div>
        </Card>
      )}

      <Card padding={false}>
        <div className="px-4 py-3 border-b border-gray-100 flex flex-wrap items-center gap-2">
          <Filter size={14} className="text-gray-400 shrink-0" />
          {(['ALL', 'AWS', 'AZURE', 'GCP'] as const).map((p) => (
            <button
              key={p}
              onClick={() => { setProvFilter(p); setPage(1); }}
              className={`px-3 py-1 text-xs font-medium rounded-full border transition-colors ${
                provFilter === p
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-500 border-gray-200 hover:border-gray-400'
              }`}
            >
              {p === 'ALL' ? 'All Clouds' : p}
            </button>
          ))}
          <div className="h-4 border-l border-gray-200" />
          <Select
            value={stateFilter}
            onChange={(e) => { setStateFilter(e.target.value); setPage(1); }}
            options={[
              { value: 'ACTIVE',  label: 'Active' },
              { value: 'DELETED', label: 'Deleted' },
              { value: '',        label: 'All States' },
            ]}
            className="w-28"
          />
          {typeFilter && (
            <span className="flex items-center gap-1 px-2 py-0.5 bg-blue-50 border border-blue-200 text-blue-700 rounded text-xs">
              {friendlyType(typeFilter)}
              <button onClick={() => setTypeFilter('')} className="ml-1 hover:text-blue-900">×</button>
            </span>
          )}
          <div className="flex items-center gap-1 ml-auto">
            <Input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter')  { setSearch(searchInput); setPage(1); }
                if (e.key === 'Escape') { setSearchInput(''); setSearch(''); setPage(1); }
              }}
              placeholder="Search resources…"
              className="w-52 h-8 text-sm"
            />
            <Button size="sm" variant="secondary" onClick={() => { setSearch(searchInput); setPage(1); }}>
              <Search size={13} />
            </Button>
            {search && (
              <Button size="sm" variant="ghost" onClick={() => { setSearch(''); setSearchInput(''); setPage(1); }}>×</Button>
            )}
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
          </div>
        ) : resources.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
            <Database className="h-12 w-12 text-gray-300" />
            <p className="text-gray-600 font-medium">No resources discovered yet</p>
            <p className="text-sm text-gray-400">Click "Discover" on any cloud account above to start scanning</p>
          </div>
        ) : (
          <>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50">
                  {['Cloud', 'Type', 'Name / ID', 'Region', 'Dependencies', 'State', 'Last Seen', ''].map((h) => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {resources.map((res) => {
                  const cfg  = PROVIDER_CONFIG[res.provider as CloudProvider];
                  const Icon = getResourceIcon(res.resourceType);
                  const isDeleted = res.state === 'DELETED';
                  return (
                    <tr
                      key={res.id}
                      className={`hover:bg-gray-50 cursor-pointer transition-colors ${isDeleted ? 'opacity-60' : ''}`}
                      onClick={() => navigate(`/resource-inventory/${res.id}`)}
                    >
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
                          {cfg.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1.5 text-xs text-gray-600 bg-gray-100 rounded px-2 py-0.5">
                          <Icon size={10} className="text-gray-400" />
                          {friendlyType(res.resourceType)}
                        </span>
                      </td>
                      <td className="px-4 py-3 max-w-xs">
                        <p className="text-sm font-medium text-gray-900 truncate">{res.resourceName ?? '—'}</p>
                        <p className="text-xs font-mono text-gray-400 truncate" title={res.nativeId}>{res.nativeId}</p>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-500">{res.region ?? '—'}</td>
                      <td className="px-4 py-3 text-xs text-gray-500">
                        {((res._count?.depsFrom ?? 0) + (res._count?.depsTo ?? 0)) > 0 ? (
                          <span className="flex items-center gap-1">
                            <GitBranch size={11} className="text-blue-400" />
                            {(res._count?.depsFrom ?? 0) + (res._count?.depsTo ?? 0)}
                          </span>
                        ) : '—'}
                      </td>
                      <td className="px-4 py-3">
                        {res.state === 'ACTIVE' ? (
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-green-700 bg-green-50 border border-green-200 rounded-full px-2 py-0.5">
                            <CheckCircle2 size={10} /> Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-full px-2 py-0.5">
                            <Trash2 size={10} /> Deleted
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">{fmtDate(res.lastSeenAt)}</td>
                      <td className="px-4 py-3">
                        <Button variant="ghost" size="sm" rightIcon={<ChevronRight size={13} />}
                          onClick={(e) => { e.stopPropagation(); navigate(`/resource-inventory/${res.id}`); }}>
                          View
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {totalPages > 1 && (
              <div className="px-4 py-3 border-t border-gray-100">
                <Pagination page={page} totalPages={totalPages} total={totalCount} pageSize={50} onPageChange={setPage} />
              </div>
            )}
          </>
        )}
      </Card>

      <div className="grid grid-cols-4 gap-4">
        {[
          { icon: Database, title: 'Auto-Discovery', desc: 'Continuously scans AWS Config, Azure ARM, and GCP APIs to build a complete resource inventory.' },
          { icon: GitBranch, title: 'Config Versioning', desc: 'Every configuration change creates a timestamped snapshot, enabling point-in-time reconstruction.' },
          { icon: AlertTriangle, title: 'Change Detection', desc: 'Property-level diffs highlight exactly what changed between any two snapshots.' },
          { icon: Activity, title: 'Dependency Mapping', desc: 'Automatic relationship detection across network, IAM, storage and compute resources.' },
        ].map(({ icon: Icon, title, desc }) => (
          <div key={title} className="bg-white border border-gray-200 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-2">
              <Icon size={16} className="text-blue-600" />
              <p className="text-sm font-semibold text-gray-800">{title}</p>
            </div>
            <p className="text-xs text-gray-500 leading-relaxed">{desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

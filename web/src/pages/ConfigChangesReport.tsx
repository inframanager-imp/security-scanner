import { useState, useMemo, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import {
  ArrowLeft, RefreshCw, Download, ChevronDown, ChevronUp,
  Shield, Activity, Server, Database, Lock, ScrollText, Cloud,
  AlertTriangle, CheckCircle2, User, MapPin, Tag, GitCompare,
  CheckSquare, Filter, Package, TrendingUp, TrendingDown, Zap, AlertCircle,
  Calendar, Share2, ExternalLink,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { configChangesApi } from '../api/configChanges';
import { useConfigSync }    from '../hooks/useConfigSync';
import { ConfigDiffView }   from '../components/ConfigDiffView';
import { resourceInventoryApi } from '../api/resourceInventory';
import { accountsApi }      from '../api/accounts';
import { azureApi }         from '../api/azure';
import { gcpApi }           from '../api/gcp';
import { Card }    from '../components/ui/Card';
import { Button }  from '../components/ui/Button';
import { Select }  from '../components/ui/Select';
import { Input }   from '../components/ui/Input';
import { Modal }   from '../components/ui/Modal';
import { Pagination } from '../components/ui/Table';
import type {
  CloudProvider, ChangeAction, ChangeCategory, ChangeStatus, ConfigChange, Severity,
  InventoryStatus, ResourceActivityLogEntry,
} from '../types';

// ─── Constants ────────────────────────────────────────────────────────────────

const CATEGORY_ICONS: Record<ChangeCategory, typeof Shield> = {
  IAM: Shield, NETWORK: Activity, STORAGE: Server,
  COMPUTE: Server, DATABASE: Database, ENCRYPTION: Lock,
  LOGGING: ScrollText, OTHER: Cloud,
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700 border-red-200',
  HIGH:     'bg-orange-100 text-orange-700 border-orange-200',
  MEDIUM:   'bg-yellow-100 text-yellow-700 border-yellow-200',
  LOW:      'bg-blue-100 text-blue-700 border-blue-200',
  INFO:     'bg-gray-100 text-gray-600 border-gray-200',
};

const STATUS_COLORS: Record<ChangeStatus, string> = {
  OPEN:           'bg-red-50 text-red-700 border-red-200',
  ACKNOWLEDGED:   'bg-green-50 text-green-700 border-green-200',
  RESOLVED:       'bg-gray-100 text-gray-600 border-gray-200',
  FALSE_POSITIVE: 'bg-purple-50 text-purple-700 border-purple-200',
};

const ACTION_COLORS: Record<ChangeAction, string> = {
  CREATED:  'bg-emerald-100 text-emerald-700 border-emerald-200',
  MODIFIED: 'bg-amber-100 text-amber-700 border-amber-200',
  DELETED:  'bg-red-100 text-red-700 border-red-200',
};

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
];

const CATEGORY_OPTIONS = [
  { value: '', label: 'All Categories' },
  { value: 'IAM', label: 'IAM' },
  { value: 'NETWORK', label: 'Network' },
  { value: 'STORAGE', label: 'Storage' },
  { value: 'COMPUTE', label: 'Compute' },
  { value: 'DATABASE', label: 'Database' },
  { value: 'ENCRYPTION', label: 'Encryption' },
  { value: 'LOGGING', label: 'Logging' },
  { value: 'OTHER', label: 'Other' },
];

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'OPEN', label: 'Open' },
  { value: 'ACKNOWLEDGED', label: 'Acknowledged' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'FALSE_POSITIVE', label: 'False Positive' },
];

const BULK_STATUS_OPTIONS = [
  { value: 'ACKNOWLEDGED', label: 'Acknowledged' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'FALSE_POSITIVE', label: 'False Positive' },
  { value: 'OPEN', label: 'Re-open' },
];

const SORT_OPTIONS = [
  { value: 'eventTime', label: 'Event Time' },
  { value: 'riskScore', label: 'Risk Score' },
  { value: 'severity',  label: 'Severity' },
];

// ─── Compliance Benchmark Mapping ─────────────────────────────────────────────

type BenchmarkId = 'CIS' | 'NIST-800-53' | 'SOC2' | 'PCI-DSS' | 'ISO-27001' | 'HIPAA';

const BENCHMARK_DESCRIPTIONS: Record<BenchmarkId, string> = {
  'CIS':        'Center for Internet Security Controls',
  'NIST-800-53':'NIST SP 800-53 Security Controls',
  'SOC2':       'SOC 2 Type II Trust Criteria',
  'PCI-DSS':    'Payment Card Industry DSS',
  'ISO-27001':  'ISO/IEC 27001 Information Security',
  'HIPAA':      'HIPAA Security Rule Safeguards',
};

const CATEGORY_TO_BENCHMARKS: Record<ChangeCategory, BenchmarkId[]> = {
  IAM:        ['CIS', 'NIST-800-53', 'SOC2', 'PCI-DSS', 'ISO-27001', 'HIPAA'],
  NETWORK:    ['CIS', 'NIST-800-53', 'SOC2', 'PCI-DSS'],
  STORAGE:    ['CIS', 'NIST-800-53', 'SOC2', 'PCI-DSS', 'ISO-27001', 'HIPAA'],
  DATABASE:   ['NIST-800-53', 'SOC2', 'PCI-DSS', 'HIPAA'],
  ENCRYPTION: ['CIS', 'NIST-800-53', 'SOC2', 'PCI-DSS', 'ISO-27001', 'HIPAA'],
  LOGGING:    ['CIS', 'NIST-800-53', 'SOC2', 'ISO-27001'],
  COMPUTE:    ['CIS', 'NIST-800-53'],
  OTHER:      [],
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmt(d?: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function fmtShort(d?: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function riskColor(score: number) {
  if (score >= 80) return 'text-red-600';
  if (score >= 60) return 'text-orange-500';
  if (score >= 40) return 'text-yellow-500';
  return 'text-blue-500';
}

// ─── Stats cards ──────────────────────────────────────────────────────────────

function StatCard({ label, value, color, sub }: { label: string; value: number | string; color: string; sub?: string }) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 text-center">
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-gray-500 mt-0.5">{label}</p>
      {sub && <p className="text-[10px] text-gray-400 mt-0.5">{sub}</p>}
    </div>
  );
}

// ─── Inventory lookup for graph link ─────────────────────────────────────────

function ResourceGraphLink({ resourceId, provider }: { resourceId: string; provider: string }) {
  const { data } = useQuery({
    queryKey: ['inv-lookup', resourceId, provider],
    queryFn:  () => resourceInventoryApi.list({
      provider: provider as 'AWS' | 'AZURE' | 'GCP',
      search:   resourceId,
      pageSize: 1,
    }),
    staleTime: 120_000,
    enabled:   !!resourceId,
  });

  const item = data?.data?.[0];
  if (!item) return null;

  return (
    <Link
      to={`/resource-inventory/${item.id}?tab=graph`}
      className="inline-flex items-center gap-1.5 mt-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-blue-50 border border-blue-200 text-blue-700 hover:bg-blue-100 transition-colors"
    >
      <Share2 size={11} /> View Relationship Graph
      <ExternalLink size={9} className="opacity-60" />
    </Link>
  );
}

// ─── Expanded row detail ───────────────────────────────────────────────────────

function ExpandedDetail({ change, colSpan }: { change: ConfigChange; colSpan: number }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-6 py-4 bg-gray-50 border-b border-gray-200">
        <div className="grid grid-cols-2 gap-6 text-sm">

          {/* Left column — event metadata */}
          <div className="space-y-4">
            <div>
              <h4 className="font-semibold text-gray-900 mb-1">Summary</h4>
              <p className="text-gray-600 leading-relaxed">{change.summary}</p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {change.actor && (
                <div>
                  <span className="text-xs text-gray-400 flex items-center gap-1 mb-0.5"><User size={10} /> Actor</span>
                  <p className="text-gray-700 font-medium text-xs break-all">{change.actor}</p>
                  {change.actorType && <p className="text-gray-400 text-xs">{change.actorType}</p>}
                </div>
              )}
              {change.sourceIp && (
                <div>
                  <span className="text-xs text-gray-400 flex items-center gap-1 mb-0.5"><MapPin size={10} /> Source IP</span>
                  <p className="text-gray-700 font-mono text-xs">{change.sourceIp}</p>
                </div>
              )}
              {change.region && (
                <div>
                  <span className="text-xs text-gray-400 flex items-center gap-1 mb-0.5"><MapPin size={10} /> Region</span>
                  <p className="text-gray-700 text-xs">{change.region}</p>
                </div>
              )}
              {change.resourceType && (
                <div>
                  <span className="text-xs text-gray-400 flex items-center gap-1 mb-0.5"><Tag size={10} /> Resource Type</span>
                  <p className="text-gray-700 text-xs break-all">{change.resourceType}</p>
                </div>
              )}
              {change.resourceId && (
                <div className="col-span-2">
                  <span className="text-xs text-gray-400 flex items-center gap-1 mb-0.5"><Tag size={10} /> Resource ID</span>
                  <p className="text-gray-700 font-mono text-xs break-all">{change.resourceId}</p>
                  <ResourceGraphLink resourceId={change.resourceId} provider={change.provider} />
                </div>
              )}
            </div>

            {change.notes && (
              <div>
                <span className="text-xs text-gray-400 mb-0.5 block">Notes</span>
                <p className="text-gray-700 text-xs bg-white border border-gray-200 rounded p-2">{change.notes}</p>
              </div>
            )}

            {change.acknowledgedBy && (
              <div className="flex items-center gap-1.5 text-xs text-green-700 bg-green-50 border border-green-200 rounded px-2 py-1">
                <CheckCircle2 size={12} />
                Acknowledged by <strong>{change.acknowledgedBy}</strong> on {fmt(change.acknowledgedAt)}
              </div>
            )}
          </div>

          {/* Right column — configuration diff */}
          <div>
            <h4 className="font-semibold text-gray-900 mb-2 flex items-center gap-1.5">
              <GitCompare size={14} className="text-blue-600" />
              Configuration Diff
              <span className="text-xs font-normal text-gray-400 ml-1">
                {change.changeAction === 'CREATED' ? '— new resource' :
                 change.changeAction === 'DELETED' ? '— resource removed' :
                 '— before → after'}
              </span>
            </h4>
            <ConfigDiffView
              before={change.previousValue as Record<string, unknown> | null}
              after={change.newValue       as Record<string, unknown> | null}
              changeAction={change.changeAction}
            />
          </div>

        </div>
      </td>
    </tr>
  );
}

// ─── Activity Log Row ──────────────────────────────────────────────────────────

function ActivityLogRow({ entry }: { entry: ResourceActivityLogEntry }) {
  return (
    <tr className="hover:bg-gray-50 transition-colors">
      <td className="px-4 py-3">
        <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
          entry.changeType === 'DELETED'
            ? 'bg-red-50 text-red-700 border-red-200'
            : 'bg-orange-50 text-orange-700 border-orange-200'
        }`}>
          {entry.changeType}
        </span>
      </td>
      <td className="px-4 py-3 max-w-[200px]">
        {entry.inventory.resourceName && (
          <p className="text-xs font-medium text-gray-800 truncate">{entry.inventory.resourceName}</p>
        )}
        <p className="font-mono text-xs text-blue-500 truncate" title={entry.inventory.nativeId}>
          {entry.inventory.nativeId}
        </p>
      </td>
      <td className="px-4 py-3 text-xs text-gray-600 max-w-[160px] truncate">
        {entry.inventory.resourceType}
      </td>
      <td className="px-4 py-3 text-xs text-gray-500">
        {entry.inventory.region ?? '—'}
      </td>
      <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">
        {fmt(entry.capturedAt)}
      </td>
    </tr>
  );
}

// ─── Compliance Benchmark Card ─────────────────────────────────────────────────

function BenchmarkCard({ id, count, criticalCount }: { id: BenchmarkId; count: number; criticalCount: number }) {
  const impacted = count > 0;
  const urgency  = criticalCount > 0 ? 'border-red-200 bg-red-50' :
                   impacted           ? 'border-orange-200 bg-orange-50' :
                                        'border-gray-100 bg-gray-50';
  const numColor = criticalCount > 0 ? 'text-red-600' :
                   impacted           ? 'text-orange-600' :
                                        'text-gray-300';

  return (
    <div className={`rounded-xl border p-4 flex flex-col gap-2 ${urgency}`}>
      <div className="flex items-start justify-between">
        <p className={`text-2xl font-bold ${numColor}`}>{count}</p>
        {criticalCount > 0 && (
          <span className="text-[10px] font-semibold text-red-600 bg-red-100 border border-red-200 rounded-full px-1.5 py-0.5">
            {criticalCount} CRIT
          </span>
        )}
      </div>
      <div>
        <p className="text-sm font-bold text-gray-700">{id}</p>
        <p className="text-[10px] text-gray-500 mt-0.5 leading-tight">{BENCHMARK_DESCRIPTIONS[id]}</p>
      </div>
      {impacted && (
        <p className="text-[10px] text-orange-600 font-medium">⚠ Compliance impact detected</p>
      )}
    </div>
  );
}

// ─── Main Report Page ─────────────────────────────────────────────────────────

type RouteProvider = 'aws' | 'azure' | 'gcp';
type ReportTab = 'changes' | 'activity';

export function ConfigChangesReport() {
  const navigate    = useNavigate();
  const { provider: rawProvider, id } = useParams<{ provider: RouteProvider; id: string }>();
  const provider = rawProvider?.toUpperCase() as CloudProvider;
  const qc = useQueryClient();

  const [activeTab, setActiveTab] = useState<ReportTab>('changes');

  const [changeAction, setChangeAction] = useState<ChangeAction | ''>('');
  const [severity,     setSeverity]     = useState('');
  const [category,     setCategory]     = useState('');
  const [changeStatus, setChangeStatus] = useState('');
  const [search,       setSearch]       = useState('');
  const [searchInput,  setSearchInput]  = useState('');
  const [dateFrom,     setDateFrom]     = useState('');
  const [dateTo,       setDateTo]       = useState('');
  const [sortBy,       setSortBy]       = useState<'eventTime' | 'riskScore' | 'severity'>('eventTime');
  const [sortOrder,    setSortOrder]    = useState<'asc' | 'desc'>('desc');
  const [page,         setPage]         = useState(1);

  const [activityPage, setActivityPage] = useState(1);

  useEffect(() => { setActivityPage(1); }, [provider, id]);

  const [selected,      setSelected]      = useState<Set<string>>(new Set());
  const [bulkModalOpen, setBulkModalOpen] = useState(false);
  const [bulkStatus,    setBulkStatus]    = useState<ChangeStatus>('ACKNOWLEDGED');
  const [bulkNotes,     setBulkNotes]     = useState('');

  const [expandedId, setExpandedId] = useState<string | null>(null);

  // ── Account / subscription info ──
  const { data: awsAccount } = useQuery({
    queryKey: ['account', id],
    queryFn:  () => accountsApi.get(id!),
    enabled:  provider === 'AWS' && !!id,
    refetchInterval: 65_000,
  });
  const { data: azureSub } = useQuery({
    queryKey: ['azure-sub', id],
    queryFn:  () => azureApi.getSubscription(id!),
    enabled:  provider === 'AZURE' && !!id,
    refetchInterval: 65_000,
  });
  const { data: gcpProj } = useQuery({
    queryKey: ['gcp-project', id],
    queryFn:  () => gcpApi.getProject(id!),
    enabled:  provider === 'GCP' && !!id,
    refetchInterval: 65_000,
  });

  const accountName =
    provider === 'AWS'   ? (awsAccount?.name ?? '…') :
    provider === 'AZURE' ? (azureSub?.name   ?? '…') :
                           (gcpProj?.name     ?? '…');

  const accountNativeId =
    provider === 'AWS'   ? (awsAccount?.awsAccountId  ?? '') :
    provider === 'AZURE' ? (azureSub?.subscriptionId   ?? '') :
                           (gcpProj?.projectId          ?? '');

  const inventoryStatus: InventoryStatus | undefined =
    provider === 'AWS'   ? awsAccount?.inventoryStatus  :
    provider === 'AZURE' ? azureSub?.inventoryStatus    :
                           gcpProj?.inventoryStatus;

  const isLiveMonitoring  = inventoryStatus === 'READY';
  const isInitializing    = inventoryStatus === 'INITIALIZING';

  // ── Stats ──
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['config-stats', provider, id],
    queryFn:  () => configChangesApi.getStats(provider, id!),
    enabled:  !!id && !!provider,
    staleTime: 30_000,
    refetchInterval: 35_000,
  });

  // ── Inventory stats (30-day window) ──
  const { data: invStats } = useQuery({
    queryKey: ['inv-stats', provider, id],
    queryFn:  () => resourceInventoryApi.getStats(provider, id!, 30),
    enabled:  !!id && !!provider,
    staleTime: 60_000,
    refetchInterval: 35_000,
  });

  // ── Activity log (MODIFIED + DELETED) ──
  const { data: activityData, isLoading: activityLoading } = useQuery({
    queryKey: ['inv-activity', provider, id, activityPage],
    queryFn:  () => resourceInventoryApi.getActivityLog(provider, id!, activityPage),
    enabled:  !!id && !!provider,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
    refetchInterval: 35_000,
  });

  const activityLog   = activityData?.data      ?? [];
  const activityTotal = activityData?.total      ?? 0;
  const activityPages = activityData?.totalPages ?? 1;

  // ── Sync runs ──
  const { data: runsData } = useQuery({
    queryKey: ['config-runs', provider, id],
    queryFn:  () => configChangesApi.getRuns(provider, id!),
    enabled:  !!id && !!provider,
    staleTime: 30_000,
    refetchInterval: 65_000,  // slightly longer than the 60s server sync so new run is already written
  });
  const lastSyncTime = runsData?.lastSuccessfulSyncAt ?? null;
  const lastChangesStored = runsData?.lastChangesStored ?? null;

  const { connected: syncConnected, lastSyncedAt: liveLastSyncedAt, secondsSinceSync } = useConfigSync({
    provider: provider as string,
    targetId: id,
  });

  // Prefer the live Socket.IO timestamp when available (more up-to-date than the polled API)
  const displaySyncTime = liveLastSyncedAt ?? lastSyncTime;

  // ── Changes list ──
  const listParams = useMemo(() => ({
    provider,
    targetId:      id!,
    changeAction:  changeAction as ChangeAction | undefined || undefined,
    severity:      severity     as Severity | undefined || undefined,
    category:      category     as ChangeCategory | undefined || undefined,
    changeStatus:  changeStatus as ChangeStatus | undefined || undefined,
    search:        search       || undefined,
    startTime:     dateFrom     ? new Date(dateFrom + 'T00:00:00.000Z').toISOString()  : undefined,
    endTime:       dateTo       ? new Date(dateTo   + 'T23:59:59.999Z').toISOString()  : undefined,
    page,
    pageSize:      20,
    sortBy,
    sortOrder,
  }), [provider, id, changeAction, severity, category, changeStatus, search, dateFrom, dateTo, page, sortBy, sortOrder]);

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ['config-changes', listParams],
    queryFn:  () => configChangesApi.list(listParams),
    enabled:  !!id && !!provider,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
    refetchInterval: 35_000,
  });

  const changes    = listData?.data      ?? [];
  const totalPages = listData?.totalPages ?? 1;
  const totalCount = listData?.total      ?? 0;

  // ── Compliance benchmark impact (computed from stats.byCategory) ──
  const benchmarkImpact = useMemo<Record<BenchmarkId, { total: number; critical: number }>>(() => {
    const init = { total: 0, critical: 0 };
    const counts: Record<BenchmarkId, { total: number; critical: number }> = {
      'CIS': { ...init }, 'NIST-800-53': { ...init }, 'SOC2': { ...init },
      'PCI-DSS': { ...init }, 'ISO-27001': { ...init }, 'HIPAA': { ...init },
    };
    if (!stats) return counts;

    for (const [cat, changeCount] of Object.entries(stats.byCategory) as [ChangeCategory, number][]) {
      const benchmarks = CATEGORY_TO_BENCHMARKS[cat] ?? [];
      for (const bm of benchmarks) {
        counts[bm].total += changeCount;
      }
    }
    // Add critical counts — IAM/NETWORK/ENCRYPTION critical changes are highest risk
    const criticalChanges = stats.bySeverity.CRITICAL ?? 0;
    if (criticalChanges > 0) {
      (['CIS', 'NIST-800-53', 'PCI-DSS'] as BenchmarkId[]).forEach((bm) => {
        counts[bm].critical += criticalChanges;
      });
    }
    return counts;
  }, [stats]);

  // ── Selection helpers ──
  const allPageSelected = changes.length > 0 && changes.every((c) => selected.has(c.id));

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (allPageSelected) {
      setSelected((prev) => { const next = new Set(prev); changes.forEach((c) => next.delete(c.id)); return next; });
    } else {
      setSelected((prev) => { const next = new Set(prev); changes.forEach((c) => next.add(c.id)); return next; });
    }
  }

  // ── Mutations ──
  const syncMutation = useMutation({
    mutationFn: () => configChangesApi.sync(provider, id!, 24),
    onSuccess: () => {
      setTimeout(() => {
        void qc.invalidateQueries({ queryKey: ['config-changes'] });
        void qc.invalidateQueries({ queryKey: ['config-stats', provider, id] });
        void qc.invalidateQueries({ queryKey: ['config-runs',  provider, id] });
        void qc.invalidateQueries({ queryKey: ['inv-stats',    provider, id] });
        void qc.invalidateQueries({ queryKey: ['inv-activity', provider, id] });
      }, 3000);
    },
  });

  const statusMutation = useMutation({
    mutationFn: ({ id: cid, status, notes }: { id: string; status: ChangeStatus; notes?: string }) =>
      configChangesApi.updateStatus(cid, status, notes),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config-changes'] }),
  });

  const bulkMutation = useMutation({
    mutationFn: () => configChangesApi.bulkUpdateStatus([...selected], bulkStatus, bulkNotes || undefined),
    onSuccess: () => {
      setSelected(new Set());
      setBulkModalOpen(false);
      setBulkNotes('');
      qc.invalidateQueries({ queryKey: ['config-changes'] });
      qc.invalidateQueries({ queryKey: ['config-stats', provider, id] });
    },
  });

  // ── CSV export ──
  function handleExport() {
    const url = configChangesApi.exportCsvUrl(provider, id!, {
      severity:     severity     as Severity | undefined     || undefined,
      category:     category     as ChangeCategory | undefined || undefined,
      changeStatus: changeStatus as ChangeStatus | undefined   || undefined,
    });
    window.open(url, '_blank');
  }

  const providerLabel = provider === 'AWS' ? 'AWS' : provider === 'AZURE' ? 'Azure' : 'GCP';

  const TABS: { id: ReportTab; label: string; count?: number }[] = [
    { id: 'changes',  label: 'Configuration Changes', count: totalCount },
    { id: 'activity', label: 'Resource Activity',     count: activityTotal },
  ];

  return (
    <div className="space-y-5">

      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div>
          <button
            onClick={() => navigate('/config-changes')}
            className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 mb-1.5 transition-colors"
          >
            <ArrowLeft size={14} /> Config Changes
          </button>
          <h2 className="text-xl font-bold text-gray-900">{accountName}</h2>
          <div className="flex items-center gap-3 mt-0.5 flex-wrap">
            <span className="text-sm text-gray-500">{providerLabel}</span>
            {accountNativeId && <span className="font-mono text-xs text-gray-400">{accountNativeId}</span>}
            {isLiveMonitoring && (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-full px-2.5 py-0.5">
                <Zap size={10} className="text-emerald-600" />
                Live Analysis Active
              </span>
            )}
            {isInitializing && (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-blue-700 bg-blue-50 border border-blue-200 rounded-full px-2.5 py-0.5 animate-pulse">
                <AlertCircle size={10} />
                Inventory Initializing
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            {syncConnected && (
              <span className="flex items-center gap-1 text-[10px] text-emerald-600 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Live
              </span>
            )}
            <button
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
              title="Sync now"
              className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-800 border border-gray-200 rounded px-2.5 py-1.5 transition-colors disabled:opacity-50"
            >
              <RefreshCw size={12} className={syncMutation.isPending ? 'animate-spin text-blue-500' : 'text-gray-400'} />
              {syncMutation.isPending
                ? 'Syncing…'
                : displaySyncTime
                  ? <>
                      Last synced: {fmtShort(displaySyncTime)}
                      {lastChangesStored != null ? ` · ${lastChangesStored} stored` : ''}
                      {secondsSinceSync !== null && secondsSinceSync < 10 ? ' · just now' : ''}
                    </>
                  : 'Sync now'
              }
            </button>
          </div>
          <Button variant="secondary" size="sm" leftIcon={<Download size={13} />} onClick={handleExport}>
            Export CSV
          </Button>
        </div>
      </div>


      {/* ── Config Change Stats ── */}
      {statsLoading ? (
        <div className="grid grid-cols-6 gap-3 animate-pulse">
          {Array.from({ length: 6 }).map((_, i) => <div key={i} className="h-16 bg-gray-100 rounded-lg" />)}
        </div>
      ) : stats ? (
        <div className="grid grid-cols-6 gap-3">
          <StatCard label="Total Changes" value={stats.total}               color="text-gray-800" />
          <StatCard label="Critical"      value={stats.bySeverity.CRITICAL} color="text-red-600"  />
          <StatCard label="High"          value={stats.bySeverity.HIGH}     color="text-orange-500" />
          <StatCard label="Medium"        value={stats.bySeverity.MEDIUM}   color="text-yellow-500" />
          <StatCard label="Low"           value={stats.bySeverity.LOW}      color="text-blue-500" />
          <StatCard label="Categories"    value={Object.keys(stats.byCategory).length} color="text-gray-700" />
        </div>
      ) : null}

      {/* ── Resource Inventory Summary ── */}
      {invStats && (
        <Card padding={false}>
          <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between">
            <p className="text-sm font-semibold text-gray-800 flex items-center gap-2">
              <Package size={14} className="text-blue-500" />
              Resource Inventory Summary
              <span className="text-xs font-normal text-gray-400 flex items-center gap-1">
                <Calendar size={10} /> last 30 days
              </span>
            </p>
            <span className="text-xs text-gray-400">{invStats.total} resources tracked</span>
          </div>
          <div className="grid grid-cols-5 divide-x divide-gray-100">
            {[
              {
                label: 'Total Resources',
                value: invStats.total,
                color: 'text-gray-800',
                sub: 'all time',
                Icon: null,
              },
              {
                label: 'Active',
                value: invStats.byState['ACTIVE'] ?? 0,
                color: 'text-emerald-600',
                sub: 'currently active',
                Icon: null,
              },
              {
                label: 'Deleted',
                value: invStats.byState['DELETED'] ?? 0,
                color: 'text-red-500',
                sub: 'removed from cloud',
                Icon: null,
              },
              {
                label: 'Created (30d)',
                value: invStats.created  ?? 0,
                color: 'text-blue-600',
                sub: 'new resources',
                Icon: TrendingUp,
              },
              {
                label: 'Modified (30d)',
                value: invStats.modified ?? 0,
                color: 'text-orange-500',
                sub: 'config changed',
                Icon: TrendingDown,
              },
            ].map(({ label, value, color, sub, Icon }) => (
              <div key={label} className="p-4 text-center">
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
                <p className="text-xs text-gray-600 mt-0.5 flex items-center justify-center gap-1 font-medium">
                  {Icon && <Icon size={10} className={color} />}
                  {label}
                </p>
                <p className="text-[10px] text-gray-400 mt-0.5">{sub}</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* ── Category breakdown + Top actors ── */}
      {stats && (
        <div className="grid grid-cols-3 gap-4">
          <Card className="col-span-2" padding={false}>
            <div className="px-4 py-3 border-b border-gray-100">
              <p className="text-sm font-semibold text-gray-800">Changes by Category</p>
            </div>
            <div className="p-4 space-y-2">
              {(Object.entries(stats.byCategory) as [ChangeCategory, number][])
                .sort(([, a], [, b]) => b - a)
                .map(([cat, cnt]) => {
                  const Icon = CATEGORY_ICONS[cat] ?? Cloud;
                  const pct  = stats.total > 0 ? Math.round((cnt / stats.total) * 100) : 0;
                  return (
                    <div key={cat} className="flex items-center gap-3">
                      <div className="flex items-center gap-1.5 w-28 shrink-0">
                        <Icon size={12} className="text-gray-400" />
                        <span className="text-xs text-gray-600">{cat}</span>
                      </div>
                      <div className="flex-1 bg-gray-100 rounded-full h-1.5">
                        <div className="bg-blue-500 h-1.5 rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-xs font-medium text-gray-700 w-6 text-right">{cnt}</span>
                    </div>
                  );
                })}
              {Object.keys(stats.byCategory).length === 0 && (
                <p className="text-sm text-gray-400 text-center py-4">No data yet — run a sync.</p>
              )}
            </div>
          </Card>

          <Card padding={false}>
            <div className="px-4 py-3 border-b border-gray-100">
              <p className="text-sm font-semibold text-gray-800">Top Actors</p>
            </div>
            <div className="p-4 space-y-2">
              {stats.topActors.slice(0, 6).map((a, i) => (
                <div key={i} className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <User size={11} className="text-gray-400 shrink-0" />
                    <span className="text-xs text-gray-700 truncate">{a.actor ?? 'Unknown'}</span>
                  </div>
                  <span className="text-xs font-semibold text-gray-600 shrink-0">{a.count}</span>
                </div>
              ))}
              {stats.topActors.length === 0 && (
                <p className="text-sm text-gray-400 text-center py-4">No actors recorded.</p>
              )}
            </div>
          </Card>
        </div>
      )}

      {/* ── Compliance Impact Numbers ── */}
      {stats && Object.values(benchmarkImpact).some((b) => b.total > 0) && (
        <div className="bg-white border border-gray-200 rounded-lg px-4 py-3">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3 flex items-center gap-1.5">
            <Shield size={12} className="text-purple-500" />
            Compliance Impact
          </p>
          <div className="flex flex-wrap gap-2">
            {(Object.entries(benchmarkImpact) as [BenchmarkId, { total: number; critical: number }][])
              .filter(([, b]) => b.total > 0)
              .sort(([, a], [, b]) => b.total - a.total)
              .map(([bm, { total, critical }]) => (
                <div
                  key={bm}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${
                    critical > 0 ? 'bg-red-50 border-red-200' : 'bg-orange-50 border-orange-200'
                  }`}
                >
                  <span className={`text-lg font-bold leading-none ${critical > 0 ? 'text-red-600' : 'text-orange-500'}`}>{total}</span>
                  <div>
                    <p className={`font-semibold leading-none ${critical > 0 ? 'text-red-700' : 'text-orange-700'}`}>{bm}</p>
                    {critical > 0 && (
                      <p className="text-[10px] text-red-500 mt-0.5">{critical} critical</p>
                    )}
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* ── Tabs: Config Changes | Resource Activity ── */}
      <div className="border-b border-gray-200">
        <div className="flex items-center gap-0">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-5 py-3 text-sm font-medium border-b-2 -mb-px transition-colors flex items-center gap-2 ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className={`text-xs rounded-full px-1.5 py-0.5 font-semibold ${
                  activeTab === tab.id ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-600'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ══ Tab: Configuration Changes ══ */}
      {activeTab === 'changes' && (
        <Card padding={false}>
          <div className="px-4 py-3 border-b border-gray-100 flex flex-wrap items-center gap-2">
            <Filter size={14} className="text-gray-400 shrink-0" />
            {(['', 'CREATED', 'MODIFIED', 'DELETED'] as const).map((a) => (
              <button
                key={a || 'ALL'}
                onClick={() => { setChangeAction(a); setPage(1); }}
                className={`text-xs font-semibold rounded-full px-3 py-1 border transition-colors ${
                  changeAction === a
                    ? a === ''        ? 'bg-gray-800 text-white border-gray-800'
                    : a === 'CREATED'  ? 'bg-emerald-600 text-white border-emerald-600'
                    : a === 'MODIFIED' ? 'bg-amber-500 text-white border-amber-500'
                    :                   'bg-red-600 text-white border-red-600'
                    : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                }`}
              >
                {a || 'All Actions'}
              </button>
            ))}
            <div className="w-px h-5 bg-gray-200 mx-1" />
            <Select value={severity}     onChange={(e) => { setSeverity(e.target.value);     setPage(1); }} options={SEVERITY_OPTIONS} className="w-36" />
            <Select value={category}     onChange={(e) => { setCategory(e.target.value);     setPage(1); }} options={CATEGORY_OPTIONS} className="w-36" />
            <Select value={changeStatus} onChange={(e) => { setChangeStatus(e.target.value); setPage(1); }} options={STATUS_OPTIONS}   className="w-36" />
            <Select value={sortBy}       onChange={(e) => { setSortBy(e.target.value as typeof sortBy); setPage(1); }} options={SORT_OPTIONS} className="w-36" />
            <button
              className="text-xs text-gray-500 hover:text-gray-800 border border-gray-200 rounded px-2 py-1.5 transition-colors"
              onClick={() => setSortOrder((o) => o === 'asc' ? 'desc' : 'asc')}
            >
              {sortOrder === 'desc' ? '↓ Newest' : '↑ Oldest'}
            </button>
            <div className="flex items-center gap-1 text-xs text-gray-500">
              <Calendar size={13} className="text-gray-400 shrink-0" />
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => { setDateFrom(e.target.value); setPage(1); }}
                className="border border-gray-200 rounded px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
              <span className="text-gray-400">–</span>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => { setDateTo(e.target.value); setPage(1); }}
                className="border border-gray-200 rounded px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
              {(dateFrom || dateTo) && (
                <button
                  onClick={() => { setDateFrom(''); setDateTo(''); setPage(1); }}
                  className="text-gray-400 hover:text-gray-600 font-bold"
                >×</button>
              )}
            </div>
            <div className="flex items-center gap-1 ml-auto">
              <Input
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter')  { setSearch(searchInput); setPage(1); }
                  if (e.key === 'Escape') { setSearchInput(''); setSearch(''); setPage(1); }
                }}
                placeholder="Search events…"
                className="w-52 h-8 text-sm"
              />
              <Button size="sm" variant="secondary" onClick={() => { setSearch(searchInput); setPage(1); }}>Search</Button>
              {search && (
                <Button size="sm" variant="ghost" onClick={() => { setSearch(''); setSearchInput(''); setPage(1); }}>×</Button>
              )}
            </div>

            {selected.size > 0 && (
              <Button size="sm" variant="primary" leftIcon={<CheckSquare size={13} />} onClick={() => setBulkModalOpen(true)}>
                Update {selected.size} Selected
              </Button>
            )}
          </div>

          {listLoading ? (
            <div className="flex items-center justify-center h-40">
              <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
            </div>
          ) : (
            <>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 bg-gray-50">
                    <th className="px-4 py-3 w-8">
                      <input type="checkbox" checked={allPageSelected} onChange={toggleSelectAll} className="rounded border-gray-300" />
                    </th>
                    <th className="px-2 py-3 w-6" />
                    {['Action', 'Severity', 'Risk', 'Category', 'Event', 'Resource', 'Actor', 'Time', 'Status', 'Actions'].map((h) => (
                      <th key={h} className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {changes.length === 0 ? (
                    <tr>
                      <td colSpan={12} className="text-center py-16 text-gray-400">
                        <AlertTriangle className="h-10 w-10 mx-auto mb-2 text-gray-300" />
                        <p>No changes found. Try adjusting filters or run a sync.</p>
                      </td>
                    </tr>
                  ) : changes.map((c) => {
                    const Icon = CATEGORY_ICONS[c.category] ?? Cloud;
                    const isExpanded = expandedId === c.id;
                    const isSelected = selected.has(c.id);
                    return (
                      <>
                        <tr
                          key={c.id}
                          className={`transition-colors ${isSelected ? 'bg-blue-50' : 'hover:bg-gray-50'}`}
                        >
                          <td className="px-4 py-3">
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => toggleSelect(c.id)}
                              onClick={(e) => e.stopPropagation()}
                              className="rounded border-gray-300"
                            />
                          </td>
                          <td className="px-2 py-3">
                            <button
                              onClick={() => setExpandedId(isExpanded ? null : c.id)}
                              className="text-gray-400 hover:text-gray-700 transition-colors"
                            >
                              {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                            </button>
                          </td>
                          <td className="px-3 py-3">
                            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${ACTION_COLORS[c.changeAction] ?? 'bg-gray-100 text-gray-600 border-gray-200'}`}>
                              {c.changeAction}
                            </span>
                          </td>
                          <td className="px-3 py-3">
                            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${SEVERITY_COLORS[c.severity] ?? ''}`}>
                              {c.severity}
                            </span>
                          </td>
                          <td className="px-3 py-3">
                            <span className={`text-sm font-bold ${riskColor(c.riskScore)}`}>{c.riskScore}</span>
                          </td>
                          <td className="px-3 py-3">
                            <span className="inline-flex items-center gap-1 text-xs text-gray-600 bg-gray-100 rounded px-1.5 py-0.5">
                              <Icon size={10} className="text-gray-400" />
                              {c.category}
                            </span>
                          </td>
                          <td className="px-3 py-3 max-w-xs">
                            <p className="text-xs font-medium text-gray-900 truncate" title={c.eventName}>{c.eventName}</p>
                            <p className="text-xs text-gray-400 truncate" title={c.summary}>{c.summary}</p>
                          </td>
                          <td className="px-3 py-3 max-w-[160px]">
                            {c.resourceName || c.resourceId ? (
                              <div>
                                {c.resourceName && <p className="text-xs text-gray-700 truncate">{c.resourceName}</p>}
                                {c.resourceId   && <p className="font-mono text-xs text-blue-500 truncate" title={c.resourceId}>{c.resourceId}</p>}
                              </div>
                            ) : <span className="text-gray-300">—</span>}
                          </td>
                          <td className="px-3 py-3 max-w-[120px]">
                            <p className="text-xs text-gray-700 truncate">{c.actor ?? '—'}</p>
                            {c.region && <p className="text-xs text-gray-400">{c.region}</p>}
                          </td>
                          <td className="px-3 py-3 whitespace-nowrap text-xs text-gray-500">{fmtShort(c.eventTime)}</td>
                          <td className="px-3 py-3">
                            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${STATUS_COLORS[c.changeStatus]}`}>
                              {c.changeStatus === 'ACKNOWLEDGED' ? 'Acked' :
                               c.changeStatus === 'FALSE_POSITIVE' ? 'FP' :
                               c.changeStatus}
                            </span>
                          </td>
                          <td className="px-3 py-3">
                            {c.changeStatus === 'OPEN' && (
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={(e) => { e.stopPropagation(); statusMutation.mutate({ id: c.id, status: 'ACKNOWLEDGED' }); }}
                                disabled={statusMutation.isPending}
                              >
                                Ack
                              </Button>
                            )}
                          </td>
                        </tr>
                        {isExpanded && <ExpandedDetail key={`exp-${c.id}`} change={c} colSpan={12} />}
                      </>
                    );
                  })}
                </tbody>
              </table>

              {totalPages > 1 && (
                <div className="px-4 py-3 border-t border-gray-100">
                  <Pagination page={page} totalPages={totalPages} total={totalCount} pageSize={20} onPageChange={setPage} />
                </div>
              )}
            </>
          )}
        </Card>
      )}

      {/* ══ Tab: Resource Activity (MODIFIED + DELETED only) ══ */}
      {activeTab === 'activity' && (
        <Card padding={false}>
          <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-gray-800 flex items-center gap-2">
                <Activity size={14} className="text-blue-500" />
                Resource Activity Log
              </p>
              <p className="text-xs text-gray-400 mt-0.5">
                Showing MODIFIED and DELETED events only — active resource lists excluded
              </p>
            </div>
            {activityTotal > 0 && (
              <span className="text-xs font-medium text-gray-500 bg-gray-100 rounded-full px-2.5 py-1">
                {activityTotal} events
              </span>
            )}
          </div>

          {activityLoading ? (
            <div className="flex items-center justify-center h-40">
              <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
            </div>
          ) : activityLog.length === 0 ? (
            <div className="text-center py-16 text-gray-400">
              <Activity className="h-10 w-10 mx-auto mb-2 text-gray-200" />
              <p className="text-sm">No modification or deletion events recorded yet.</p>
              <p className="text-xs mt-1">Run a sync or wait for real-time events to appear.</p>
            </div>
          ) : (
            <>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 bg-gray-50">
                    {['Event Type', 'Resource', 'Resource Type', 'Region', 'Detected At'].map((h) => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {activityLog.map((entry) => (
                    <ActivityLogRow key={entry.id} entry={entry} />
                  ))}
                </tbody>
              </table>
              {activityPages > 1 && (
                <div className="px-4 py-3 border-t border-gray-100">
                  <Pagination page={activityPage} totalPages={activityPages} total={activityTotal} pageSize={25} onPageChange={setActivityPage} />
                </div>
              )}
            </>
          )}
        </Card>
      )}


      {/* ── Bulk Update Modal ── */}
      <Modal
        open={bulkModalOpen}
        onClose={() => setBulkModalOpen(false)}
        title={`Update ${selected.size} Change${selected.size !== 1 ? 's' : ''}`}
      >
        <div className="space-y-4">
          <Select
            label="New Status"
            value={bulkStatus}
            onChange={(e) => setBulkStatus(e.target.value as ChangeStatus)}
            options={BULK_STATUS_OPTIONS}
          />
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Notes (optional)</label>
            <textarea
              value={bulkNotes}
              onChange={(e) => setBulkNotes(e.target.value)}
              placeholder="Add a note about this status change…"
              rows={3}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setBulkModalOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={() => bulkMutation.mutate()} disabled={bulkMutation.isPending}>
              {bulkMutation.isPending ? 'Updating…' : 'Update'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Cloud, Activity, AlertTriangle, Zap, CheckCircle, XCircle } from 'lucide-react';
import { dashboardApi } from '../api/dashboard';
import { StatCard, Card } from '../components/ui/Card';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { TrendLine } from '../components/charts/TrendLine';
import { ScanStatusBadge } from '../components/ui/Badge';

// ─── Types ────────────────────────────────────────────────────────────────────

type CloudProvider = 'AWS' | 'AZURE' | 'GCP';

interface CloudRow {
  id:             string;
  provider:       CloudProvider;
  name:           string;
  accountId:      string;
  lastScanAt?:    string | null;
  lastScanStatus?: string | null;
  summary?:       { critical: number; high: number; medium: number; low: number; info: number; total: number } | null;
  detailPath:     string;
}

// ─── Provider Config ──────────────────────────────────────────────────────────

const PROVIDER_CONFIG: Record<CloudProvider, { label: string; color: string; bg: string; border: string; dot: string }> = {
  AWS:   { label: 'AWS',   color: 'text-orange-700', bg: 'bg-orange-50',  border: 'border-orange-200', dot: 'bg-orange-500' },
  AZURE: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-50',    border: 'border-blue-200',   dot: 'bg-blue-500'   },
  GCP:   { label: 'GCP',   color: 'text-green-700',  bg: 'bg-green-50',   border: 'border-green-200',  dot: 'bg-green-500'  },
};

function ProviderBadge({ provider }: { provider: CloudProvider }) {
  const cfg = PROVIDER_CONFIG[provider];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

// ─── Severity Bar ─────────────────────────────────────────────────────────────

function SeverityBar({ summary }: { summary?: CloudRow['summary'] }) {
  if (!summary) return <span className="text-xs text-gray-400">No scan</span>;
  const t = summary.total || 0;
  if (t === 0) return <span className="text-xs text-green-600 font-medium">Clean</span>;
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-20 rounded-full overflow-hidden bg-gray-100">
        {summary.critical > 0 && <div style={{ width: `${(summary.critical / t) * 100}%` }} className="bg-red-600" />}
        {summary.high     > 0 && <div style={{ width: `${(summary.high     / t) * 100}%` }} className="bg-orange-500" />}
        {summary.medium   > 0 && <div style={{ width: `${(summary.medium   / t) * 100}%` }} className="bg-yellow-500" />}
        {summary.low      > 0 && <div style={{ width: `${(summary.low      / t) * 100}%` }} className="bg-blue-500" />}
        {summary.info     > 0 && <div style={{ width: `${(summary.info     / t) * 100}%` }} className="bg-gray-400" />}
      </div>
      <span className="text-xs text-gray-600 tabular-nums">{t}</span>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function computeRisk(s?: CloudRow['summary']): number {
  if (!s) return 0;
  return s.critical * 10 + s.high * 5 + s.medium * 2 + s.low;
}

function formatDate(dateStr?: string | null): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

export function Dashboard() {
  const navigate = useNavigate();

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['dashboard', 'summary'],
    queryFn:  () => dashboardApi.getSummary(),
  });

  const { data: trends = [], isLoading: trendsLoading } = useQuery({
    queryKey: ['dashboard', 'trends'],
    queryFn:  () => dashboardApi.getTrends(30),
  });

  const { data: allRows = [], isLoading: rowsLoading } = useQuery({
    queryKey: ['dashboard', 'accounts'],
    queryFn:  () => dashboardApi.getAccounts() as Promise<CloudRow[]>,
  });

  const emptySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

  const totalFindings =
    (summary?.findingsBySeverity?.critical ?? 0) +
    (summary?.findingsBySeverity?.high     ?? 0) +
    (summary?.findingsBySeverity?.medium   ?? 0) +
    (summary?.findingsBySeverity?.low      ?? 0) +
    (summary?.findingsBySeverity?.info     ?? 0);

  // Per-cloud pill counts
  const awsCount   = allRows.filter(r => r.provider === 'AWS').length;
  const azureCount = allRows.filter(r => r.provider === 'AZURE').length;
  const gcpCount   = allRows.filter(r => r.provider === 'GCP').length;

  return (
    <div className="space-y-6">

      {/* ── Stat Cards ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-6">
        <StatCard
          title="Total Subscriptions"
          value={summaryLoading ? '—' : (summary?.totalAccounts ?? 0)}
          icon={<Cloud size={22} />}
        />
        <StatCard
          title="Total Scans"
          value={summaryLoading ? '—' : (summary?.totalScans ?? 0)}
          icon={<Activity size={22} />}
        />
        <StatCard
          title="Active Scans"
          value={summaryLoading ? '—' : (summary?.activeScans ?? 0)}
          icon={<Zap size={22} />}
          valueClassName={summary?.activeScans ? 'text-blue-600' : undefined}
        />
        <StatCard
          title="Total Findings"
          value={summaryLoading ? '—' : totalFindings}
          icon={<AlertTriangle size={22} />}
          valueClassName={(summary?.findingsBySeverity?.critical ?? 0) > 0 ? 'text-red-600' : undefined}
        />
      </div>

      {/* ── Cloud Provider Summary Pills ────────────────────────────────────── */}
      {!summaryLoading && allRows.length > 0 && (
        <div className="flex items-center gap-3 flex-wrap">
          {([['AWS', awsCount], ['AZURE', azureCount], ['GCP', gcpCount]] as [CloudProvider, number][]).map(([p, count]) => {
            const cfg = PROVIDER_CONFIG[p];
            return (
              <button
                key={p}
                onClick={() => navigate('/cloud')}
                className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium ${cfg.bg} ${cfg.color} border ${cfg.border} hover:opacity-80 transition-opacity`}
              >
                <span className={`h-2 w-2 rounded-full ${cfg.dot}`} />
                {cfg.label}
                <span className="font-bold">{count}</span>
                <span className="font-normal opacity-70">account{count !== 1 ? 's' : ''}</span>
              </button>
            );
          })}
        </div>
      )}

      {/* ── Charts Row ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-5 gap-6">
        <Card title="Findings by Severity" className="col-span-2">
          {summaryLoading ? (
            <div className="h-48 flex items-center justify-center">
              <div className="animate-pulse text-gray-400 text-sm">Loading...</div>
            </div>
          ) : (
            <SeverityDonut summary={summary?.findingsBySeverity ?? emptySummary} />
          )}
        </Card>

        <Card title="30-Day Trend (All Clouds)" className="col-span-3">
          {trendsLoading ? (
            <div className="h-48 flex items-center justify-center">
              <div className="animate-pulse text-gray-400 text-sm">Loading...</div>
            </div>
          ) : (
            <TrendLine data={trends} />
          )}
        </Card>
      </div>

      {/* ── Cloud Subscriptions Overview Table ──────────────────────────────── */}
      <Card title="Cloud Subscriptions Overview" padding={false}>
        {rowsLoading ? (
          <div className="p-6 space-y-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-8 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        ) : allRows.length === 0 ? (
          <div className="p-12 text-center text-gray-500 text-sm">
            No cloud accounts found. <button onClick={() => navigate('/cloud')} className="text-blue-600 underline">Add an account</button> to get started.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {['Cloud', 'Account Name', 'Account / Project ID', 'Last Scan', 'Status', 'C', 'H', 'M', 'L', 'Findings', 'Risk'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {allRows.map(row => {
                  const risk = computeRisk(row.summary);
                  return (
                    <tr
                      key={`${row.provider}-${row.id}`}
                      className="hover:bg-gray-50 cursor-pointer transition-colors"
                      onClick={() => navigate(row.detailPath)}
                    >
                      <td className="px-4 py-3">
                        <ProviderBadge provider={row.provider} />
                      </td>
                      <td className="px-4 py-3 text-sm font-medium text-gray-900 whitespace-nowrap">
                        {row.name}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500 font-mono text-xs max-w-[160px] truncate">
                        {row.accountId}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">
                        {formatDate(row.lastScanAt)}
                      </td>
                      <td className="px-4 py-3">
                        {row.lastScanStatus
                          ? <ScanStatusBadge status={row.lastScanStatus as any} />
                          : <span className="text-gray-400 text-xs">—</span>}
                      </td>
                      <td className="px-4 py-3 text-sm font-bold text-red-600">
                        {row.summary?.critical ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-sm font-bold text-orange-500">
                        {row.summary?.high ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-sm font-bold text-yellow-500">
                        {row.summary?.medium ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-sm font-bold text-blue-500">
                        {row.summary?.low ?? '—'}
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBar summary={row.summary} />
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-sm font-bold ${risk > 50 ? 'text-red-600' : risk > 20 ? 'text-orange-500' : risk > 0 ? 'text-yellow-600' : 'text-green-600'}`}>
                          {row.summary ? risk : '—'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ── Critical & High Findings Summary ────────────────────────────────── */}
      {!summaryLoading && ((summary?.findingsBySeverity?.critical ?? 0) + (summary?.findingsBySeverity?.high ?? 0)) > 0 && (
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-4">
            <XCircle size={28} className="text-red-500 shrink-0" />
            <div>
              <p className="text-xs font-medium text-red-600 uppercase tracking-wide">Critical Findings</p>
              <p className="text-2xl font-bold text-red-700">{summary?.findingsBySeverity?.critical ?? 0}</p>
              <p className="text-xs text-red-500 mt-0.5">Require immediate attention</p>
            </div>
          </div>
          <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 flex items-center gap-4">
            <AlertTriangle size={28} className="text-orange-500 shrink-0" />
            <div>
              <p className="text-xs font-medium text-orange-600 uppercase tracking-wide">High Findings</p>
              <p className="text-2xl font-bold text-orange-700">{summary?.findingsBySeverity?.high ?? 0}</p>
              <p className="text-xs text-orange-500 mt-0.5">Should be addressed soon</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Clean state ──────────────────────────────────────────────────────── */}
      {!summaryLoading && totalFindings === 0 && allRows.length > 0 && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-6 flex items-center gap-4">
          <CheckCircle size={32} className="text-green-500 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-green-800">All clear across all cloud accounts</p>
            <p className="text-xs text-green-600 mt-0.5">No open findings detected. Keep up the good work!</p>
          </div>
        </div>
      )}
    </div>
  );
}

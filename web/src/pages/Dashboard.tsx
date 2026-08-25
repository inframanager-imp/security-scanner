import type { ReactNode } from 'react';
import clsx from 'clsx';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Cloud, Activity, AlertTriangle, Zap, CheckCircle, XCircle, Bug } from 'lucide-react';
import { dashboardApi } from '../api/dashboard';
import { aspmFetch } from '../aspm/aspmClient';
import { Card } from '../components/ui/Card';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { TrendLine } from '../components/charts/TrendLine';
import { ScanStatusBadge } from '../components/ui/Badge';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';

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
      <CloudProviderLogo provider={provider} className="h-3.5 w-3.5 shrink-0" />
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

// ─── Small presentation helpers ─────────────────────────────────────────────────

function MiniStat({ label, value, icon, accent }: { label: string; value: ReactNode; icon: ReactNode; accent?: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="h-10 w-10 rounded-lg bg-gray-50 flex items-center justify-center text-gray-400 shrink-0">{icon}</div>
      <div className="min-w-0">
        <p className="text-xs font-medium text-gray-500 truncate">{label}</p>
        <p className={clsx('text-xl font-bold leading-tight', accent ?? 'text-gray-900')}>{value}</p>
      </div>
    </div>
  );
}

const SEV_STYLE: Record<string, string> = {
  Critical: 'bg-red-50 text-red-700 ring-red-200',
  High:     'bg-orange-50 text-orange-700 ring-orange-200',
  Medium:   'bg-yellow-50 text-yellow-700 ring-yellow-200',
  Low:      'bg-blue-50 text-blue-700 ring-blue-200',
  Info:     'bg-gray-50 text-gray-600 ring-gray-200',
};

function SevChips({ counts }: { counts: { label: string; value: number }[] }) {
  return (
    <div className="flex flex-wrap gap-2">
      {counts.map(({ label, value }) => (
        <span
          key={label}
          className={clsx('inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-semibold ring-1 ring-inset', SEV_STYLE[label])}
        >
          {label}
          <span className="font-bold tabular-nums">{value}</span>
        </span>
      ))}
    </div>
  );
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

  // Application Security (ASPM) cross-product overview
  const { data: aspm, isLoading: aspmLoading } = useQuery({
    queryKey: ['dashboard', 'aspm-overview'],
    queryFn: async () => {
      const [tRes, vRes] = await Promise.all([
        aspmFetch('/api/aspm/targets'),
        aspmFetch('/api/aspm/vulnerabilities'),
      ]);
      const targets = await tRes.json();
      const vulns = await vRes.json();
      const list = Array.isArray(vulns) ? vulns : [];
      const open = list.filter((v: { status?: string }) => v.status !== 'Resolved');
      const bySev = (s: string) => open.filter((v: { severity?: string }) => v.severity === s).length;
      return {
        targets: Array.isArray(targets) ? targets.length : 0,
        open: open.length,
        critical: bySev('Critical'),
        high: bySev('High'),
        medium: bySev('Medium'),
        low: bySev('Low'),
      };
    },
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

      {/* ── Domain summary: Cloud Security + Application Security ──────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* Cloud Security (CSPM) */}
        <Card
          title="Cloud Security"
          action={
            <button onClick={() => navigate('/cloud')} className="text-sm font-medium text-blue-600 hover:underline">
              View cloud →
            </button>
          }
        >
          <div className="grid grid-cols-3 gap-4">
            <MiniStat label="Subscriptions" value={summaryLoading ? '—' : (summary?.totalAccounts ?? 0)} icon={<Cloud size={18} />} />
            <MiniStat label="Total Scans" value={summaryLoading ? '—' : (summary?.totalScans ?? 0)} icon={<Activity size={18} />} />
            <MiniStat label="Active Scans" value={summaryLoading ? '—' : (summary?.activeScans ?? 0)} icon={<Zap size={18} />} accent={summary?.activeScans ? 'text-blue-600' : undefined} />
          </div>
          <div className="mt-5 pt-4 border-t border-gray-100">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs font-medium text-gray-500">Findings by severity</p>
              <p className="text-xs text-gray-400">{totalFindings} total</p>
            </div>
            <SevChips counts={[
              { label: 'Critical', value: summary?.findingsBySeverity?.critical ?? 0 },
              { label: 'High',     value: summary?.findingsBySeverity?.high ?? 0 },
              { label: 'Medium',   value: summary?.findingsBySeverity?.medium ?? 0 },
              { label: 'Low',      value: summary?.findingsBySeverity?.low ?? 0 },
              { label: 'Info',     value: summary?.findingsBySeverity?.info ?? 0 },
            ]} />
          </div>
          {!summaryLoading && allRows.length > 0 && (
            <div className="mt-4 flex items-center gap-2 flex-wrap">
              {([['AWS', awsCount], ['AZURE', azureCount], ['GCP', gcpCount]] as [CloudProvider, number][]).map(([p, count]) => {
                const cfg = PROVIDER_CONFIG[p];
                return (
                  <span key={p} className={`inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
                    {cfg.label} <span className="font-bold">{count}</span>
                  </span>
                );
              })}
            </div>
          )}
        </Card>

        {/* Application Security (ASPM / VA-PT) */}
        <Card
          title="Application Security"
          action={
            <button onClick={() => navigate('/appsec/overview')} className="text-sm font-medium text-blue-600 hover:underline">
              App posture →
            </button>
          }
        >
          <div className="grid grid-cols-3 gap-4">
            <MiniStat label="Targets" value={aspmLoading ? '—' : (aspm?.targets ?? 0)} icon={<Bug size={18} />} />
            <MiniStat label="Open Vulns" value={aspmLoading ? '—' : (aspm?.open ?? 0)} icon={<AlertTriangle size={18} />} accent={(aspm?.open ?? 0) > 0 ? 'text-orange-600' : undefined} />
            <MiniStat label="Critical" value={aspmLoading ? '—' : (aspm?.critical ?? 0)} icon={<XCircle size={18} />} accent={(aspm?.critical ?? 0) > 0 ? 'text-red-600' : undefined} />
          </div>
          <div className="mt-5 pt-4 border-t border-gray-100">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs font-medium text-gray-500">Findings by severity</p>
              <p className="text-xs text-gray-400">{aspmLoading ? '' : `${aspm?.open ?? 0} open`}</p>
            </div>
            <SevChips counts={[
              { label: 'Critical', value: aspm?.critical ?? 0 },
              { label: 'High',     value: aspm?.high ?? 0 },
              { label: 'Medium',   value: aspm?.medium ?? 0 },
              { label: 'Low',      value: aspm?.low ?? 0 },
            ]} />
          </div>
          <div className="mt-4 flex items-center gap-2 flex-wrap">
            {[
              { label: 'Web (DAST)', to: '/appsec/web' },
              { label: 'API', to: '/appsec/api' },
              { label: 'Code (SAST/SCA)', to: '/appsec/code' },
              { label: 'Pentest', to: '/appsec/pentest' },
            ].map((q) => (
              <button key={q.to} onClick={() => navigate(q.to)} className="inline-flex items-center rounded-md px-2.5 py-1 text-xs font-medium bg-gray-50 text-gray-600 border border-gray-200 hover:bg-gray-100 transition-colors">
                {q.label}
              </button>
            ))}
          </div>
        </Card>
      </div>

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

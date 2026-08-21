import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Eye,
  FileText,
  Trash2,
  CheckCircle,
  AlertCircle,
  FileBarChart,
  Server,
  Bug,
  ShieldAlert,
  AlertTriangle,
} from 'lucide-react';
import { api } from '../api/client';
import { accountsApi } from '../api/accounts';
import { azureApi } from '../api/azure';
import { gcpApi } from '../api/gcp';
import { complianceApi } from '../api/compliance';
import { Button } from '../components/ui/Button';
import { Card, StatCard } from '../components/ui/Card';
import { Select } from '../components/ui/Select';
import { ScanStatusBadge } from '../components/ui/Badge';
import { FrameworkScoreOverview } from '../components/ui/FrameworkScoreOverview';
import { VaptReportModal } from '../components/ui/VaptReportModal';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';
import type { Account, AzureSubscription, GcpProject } from '../types';

// ─── Types ────────────────────────────────────────────────────────────────────

type CloudProvider = 'AWS' | 'AZURE' | 'GCP';
type ProviderFilter = 'ALL' | CloudProvider;

interface ReportRow {
  id:          string;
  provider:    CloudProvider;
  name:        string;
  accountId:   string;
  lastScanAt?: string | null;
  scanStatus?: string | null;
  summary?:    { critical: number; high: number; medium: number; low: number; info: number } | null;
  reportPath:  string;
}

interface DeduplicateResult {
  deleted: number;
  scanned: number;
  remaining: number;
  message: string;
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
    <div
      title={cfg.label}
      className={`inline-flex items-center justify-center rounded-xl p-1.5 ${cfg.bg} border ${cfg.border} shadow-2xs`}
    >
      <CloudProviderLogo provider={provider} className="h-4 w-4 shrink-0" />
    </div>
  );
}

// ─── Severity Bar ─────────────────────────────────────────────────────────────

function SeverityBar({ summary }: { summary?: ReportRow['summary'] }) {
  if (!summary) return <span className="text-xs text-gray-400 font-medium">No scan</span>;
  const total = (summary.critical + summary.high + summary.medium + summary.low + summary.info) || 0;
  if (total === 0) return <span className="text-xs text-emerald-600 font-semibold">Clean</span>;
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-24 rounded-full overflow-hidden bg-gray-100">
        {summary.critical > 0 && <div style={{ width: `${(summary.critical / total) * 100}%` }} className="bg-red-600" />}
        {summary.high     > 0 && <div style={{ width: `${(summary.high     / total) * 100}%` }} className="bg-orange-500" />}
        {summary.medium   > 0 && <div style={{ width: `${(summary.medium   / total) * 100}%` }} className="bg-yellow-500" />}
        {summary.low      > 0 && <div style={{ width: `${(summary.low      / total) * 100}%` }} className="bg-blue-500" />}
        {summary.info     > 0 && <div style={{ width: `${(summary.info     / total) * 100}%` }} className="bg-gray-400" />}
      </div>
      <span className="text-xs text-gray-600 font-medium tabular-nums">{total}</span>
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function computeRisk(critical = 0, high = 0, medium = 0, low = 0): number {
  return critical * 10 + high * 5 + medium * 2 + low;
}

function formatDate(dateStr?: string | null): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

// ─── Main Reports Page ────────────────────────────────────────────────────────

export function Reports() {
  const navigate     = useNavigate();
  const queryClient  = useQueryClient();
  const [provFilter, setProvFilter]   = useState<ProviderFilter>('ALL');
  const [dedupeResult, setDedupeResult] = useState<DeduplicateResult | null>(null);

  const dedupeMutation = useMutation({
    mutationFn: () => api.post<DeduplicateResult>('/findings/deduplicate', {}),
    onSuccess: (res) => {
      setDedupeResult(res);
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
    },
  });

  const { data: awsPage, isLoading: awsLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn:  () => accountsApi.list(),
  });
  const accounts = awsPage?.data ?? [];

  const { data: azurePage, isLoading: azureLoading } = useQuery({
    queryKey: ['azure-subscriptions', 'reports'],
    queryFn:  () => azureApi.listSubscriptions({ limit: 100 }),
  });

  const { data: gcpPage, isLoading: gcpLoading } = useQuery({
    queryKey: ['gcp-projects', 'reports'],
    queryFn:  () => gcpApi.listProjects({ limit: 100 }),
  });

  const { data: awsCompliance = [] } = useQuery({
    queryKey: ['compliance', 'all', 'aws'],
    queryFn:  () => complianceApi.getAllAccountsScores(),
  });

  const { data: azureCompliance = [] } = useQuery({
    queryKey: ['compliance', 'all', 'azure'],
    queryFn:  () => complianceApi.getAllAzureSubscriptionScores(),
  });

  const isLoading = awsLoading || azureLoading || gcpLoading;

  const [vaptModalRow, setVaptModalRow] = useState<ReportRow | null>(null);

  // Build unified rows
  const awsRows: ReportRow[] = (accounts as Account[]).map(a => ({
    id:         a.id,
    provider:   'AWS',
    name:       a.name,
    accountId:  a.awsAccountId,
    lastScanAt: a.latestScan?.startedAt ?? a.latestScan?.createdAt ?? null,
    scanStatus: a.latestScan?.status ?? null,
    summary:    a.latestScan?.summary ?? null,
    reportPath: `/reports/${a.id}`,
  }));

  const azureRows: ReportRow[] = (azurePage?.data ?? [] as AzureSubscription[]).map(s => ({
    id:         s.id,
    provider:   'AZURE',
    name:       s.name,
    accountId:  s.subscriptionId,
    lastScanAt: s.latestScan?.startedAt ?? s.latestScan?.createdAt ?? null,
    scanStatus: s.latestScan?.status ?? null,
    summary:    s.latestScan?.summary ?? null,
    reportPath: `/reports/azure/${s.id}`,
  }));

  const gcpRows: ReportRow[] = (gcpPage?.data ?? [] as GcpProject[]).map(p => ({
    id:         p.id,
    provider:   'GCP',
    name:       p.name,
    accountId:  p.projectId,
    lastScanAt: p.latestScan?.startedAt ?? p.latestScan?.createdAt ?? null,
    scanStatus: p.latestScan?.status ?? null,
    summary:    p.latestScan?.summary ?? null,
    reportPath: `/gcp/${p.id}`,
  }));

  const allRows = [...awsRows, ...azureRows, ...gcpRows].sort((a, b) => a.name.localeCompare(b.name));
  const rows    = provFilter === 'ALL' ? allRows : allRows.filter(r => r.provider === provFilter);

  // Summary stats
  const totalFindings = allRows.reduce((s, r) => s + (r.summary ? r.summary.critical + r.summary.high + r.summary.medium + r.summary.low + r.summary.info : 0), 0);
  const totalCritical = allRows.reduce((s, r) => s + (r.summary?.critical ?? 0), 0);
  const totalHigh     = allRows.reduce((s, r) => s + (r.summary?.high     ?? 0), 0);

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-1">
        <div className="space-y-0.5">
          <h1 className="text-xl sm:text-2xl font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
            Security Reports
          </h1>
          <p className="text-xs sm:text-sm text-gray-500 font-medium">
            Findings overview across all cloud accounts
          </p>
        </div>
        {provFilter === 'ALL' || provFilter === 'AWS' ? (
          <div className="flex flex-col items-end gap-1">
            <Button
              variant="secondary"
              size="sm"
              leftIcon={<Trash2 size={14} />}
              onClick={() => { setDedupeResult(null); dedupeMutation.mutate(); }}
              disabled={dedupeMutation.isPending}
              className="bg-white border-gray-300 shadow-2xs hover:bg-gray-50 text-gray-700 font-semibold"
            >
              {dedupeMutation.isPending ? 'Cleaning...' : 'Clean Duplicates'}
            </Button>
            {dedupeResult && (
              <div className={`flex items-center gap-1.5 text-xs px-3 py-1 rounded-full border shadow-2xs ${dedupeResult.deleted > 0 ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-gray-100 text-gray-600 border-gray-200'}`}>
                {dedupeResult.deleted > 0 ? <CheckCircle size={12} /> : <AlertCircle size={12} />}
                {dedupeResult.message}
              </div>
            )}
          </div>
        ) : null}
      </div>

      {/* Summary KPI cards */}
      {allRows.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total Accounts"
            value={allRows.length}
            icon={<Server size={20} className="text-blue-600" />}
          />
          <StatCard
            title="Total Findings"
            value={totalFindings}
            icon={<Bug size={20} className="text-violet-600" />}
          />
          <StatCard
            title="Critical"
            value={totalCritical}
            valueClassName={totalCritical > 0 ? 'text-red-600' : 'text-gray-400'}
            icon={<ShieldAlert size={20} className="text-red-600" />}
          />
          <StatCard
            title="High"
            value={totalHigh}
            valueClassName={totalHigh > 0 ? 'text-orange-500' : 'text-gray-400'}
            icon={<AlertTriangle size={20} className="text-orange-500" />}
          />
        </div>
      )}

      {/* Framework score overview chart */}
      <FrameworkScoreOverview awsAccounts={awsCompliance} azureSubs={azureCompliance} />

      {/* Cloud Filter (Right-aligned outside table) */}
      <div className="flex justify-end">
        <Select
          value={provFilter}
          onChange={(e) => setProvFilter(e.target.value as any)}
          options={[
            { value: 'ALL', label: 'All Clouds' },
            { value: 'AWS', label: 'AWS' },
            { value: 'AZURE', label: 'Azure' },
            { value: 'GCP', label: 'GCP' },
          ]}
          className="w-40"
        />
      </div>

      {/* Table Card */}
      <Card padding={false}>
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
          </div>
        ) : rows.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
            <FileText className="h-12 w-12 text-gray-300" />
            <p className="text-gray-600 font-medium">No accounts found</p>
            <p className="text-sm text-gray-400">Add a cloud account and run a scan to see reports here</p>
            <Button variant="primary" size="sm" onClick={() => navigate('/cloud')}>
              Go to Cloud Subscriptions
            </Button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50/80 border-b border-gray-200/80">
                <tr>
                  {['Cloud', 'Name', 'Account / Project ID', 'Last Scan', 'Status', 'Critical', 'High', 'Medium', 'Low', 'Risk Score', 'Findings', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-3.5 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {rows.map(row => {
                  const s    = row.summary;
                  const risk = computeRisk(s?.critical, s?.high, s?.medium, s?.low);
                  return (
                    <tr key={`${row.provider}-${row.id}`} className="hover:bg-slate-50/70 transition-colors">
                      <td className="px-4 py-3.5"><ProviderBadge provider={row.provider} /></td>
                      <td className="px-4 py-3.5 font-bold text-gray-900 whitespace-nowrap">{row.name}</td>
                      <td className="px-4 py-3.5">
                        <span className="font-mono text-xs font-semibold text-gray-700 bg-gray-100/90 border border-gray-200 px-2 py-0.5 rounded-md shadow-2xs max-w-[180px] inline-block truncate">
                          {row.accountId}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-xs font-medium text-gray-600 whitespace-nowrap">{formatDate(row.lastScanAt)}</td>
                      <td className="px-4 py-3.5">
                        {row.scanStatus
                          ? <ScanStatusBadge status={row.scanStatus as any} />
                          : <span className="text-gray-400 text-xs font-medium">—</span>}
                      </td>
                      <td className="px-4 py-3.5 text-sm font-bold text-red-600">{s?.critical ?? '—'}</td>
                      <td className="px-4 py-3.5 text-sm font-bold text-orange-500">{s?.high ?? '—'}</td>
                      <td className="px-4 py-3.5 text-sm font-bold text-yellow-500">{s?.medium ?? '—'}</td>
                      <td className="px-4 py-3.5 text-sm font-bold text-blue-500">{s?.low ?? '—'}</td>
                      <td className="px-4 py-3.5">
                        {s ? (
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-bold shadow-2xs ${
                            risk > 50
                              ? 'bg-red-50 text-red-700 border border-red-200/90'
                              : risk > 20
                              ? 'bg-amber-50 text-amber-700 border border-amber-200/90'
                              : risk > 0
                              ? 'bg-yellow-50 text-yellow-700 border border-yellow-200/90'
                              : 'bg-emerald-50 text-emerald-700 border border-emerald-200/90'
                          }`}>
                            {risk}
                          </span>
                        ) : (
                          <span className="text-gray-400 text-xs font-medium">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5"><SeverityBar summary={s} /></td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Button
                            variant="ghost"
                            size="sm"
                            leftIcon={<Eye size={13} />}
                            onClick={() => navigate(row.reportPath)}
                            disabled={!row.scanStatus}
                            className="hover:bg-blue-50 hover:text-blue-700 font-semibold"
                          >
                            View
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            leftIcon={<FileBarChart size={13} />}
                            onClick={() => setVaptModalRow(row)}
                            disabled={!row.scanStatus}
                            title="Generate a professional VAPT-style security report (view HTML, print to PDF)"
                            className="hover:bg-blue-50 hover:text-blue-700 font-semibold"
                          >
                            VAPT Report
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {vaptModalRow && (
        <VaptReportModal
          open={!!vaptModalRow}
          onClose={() => setVaptModalRow(null)}
          provider={vaptModalRow.provider}
          targetId={vaptModalRow.id}
          targetName={vaptModalRow.name}
        />
      )}
    </div>
  );
}

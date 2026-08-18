import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Eye, FileText, Trash2, CheckCircle2, AlertCircle, FileBarChart } from 'lucide-react';
import { api } from '../api/client';
import { accountsApi } from '../api/accounts';
import { azureApi } from '../api/azure';
import { gcpApi } from '../api/gcp';
import { complianceApi } from '../api/compliance';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
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
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
      <CloudProviderLogo provider={provider} className="h-3.5 w-3.5 shrink-0" />
      {cfg.label}
    </span>
  );
}

// ─── Severity Bar ─────────────────────────────────────────────────────────────

function SeverityBar({ summary }: { summary?: ReportRow['summary'] }) {
  if (!summary) return <span className="text-xs text-gray-400">No scan</span>;
  const total = (summary.critical + summary.high + summary.medium + summary.low + summary.info) || 0;
  if (total === 0) return <span className="text-xs text-green-600 font-medium">Clean</span>;
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-24 rounded-full overflow-hidden bg-gray-100">
        {summary.critical > 0 && <div style={{ width: `${(summary.critical / total) * 100}%` }} className="bg-red-600" />}
        {summary.high     > 0 && <div style={{ width: `${(summary.high     / total) * 100}%` }} className="bg-orange-500" />}
        {summary.medium   > 0 && <div style={{ width: `${(summary.medium   / total) * 100}%` }} className="bg-yellow-500" />}
        {summary.low      > 0 && <div style={{ width: `${(summary.low      / total) * 100}%` }} className="bg-blue-500" />}
        {summary.info     > 0 && <div style={{ width: `${(summary.info     / total) * 100}%` }} className="bg-gray-400" />}
      </div>
      <span className="text-xs text-gray-600 tabular-nums">{total}</span>
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
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Security Reports</h2>
          <p className="text-sm text-gray-500 mt-0.5">Findings overview across all cloud accounts</p>
        </div>
        {provFilter === 'ALL' || provFilter === 'AWS' ? (
          <div className="flex flex-col items-end gap-1">
            <Button
              variant="ghost"
              size="sm"
              leftIcon={<Trash2 size={14} />}
              onClick={() => { setDedupeResult(null); dedupeMutation.mutate(); }}
              disabled={dedupeMutation.isPending}
            >
              {dedupeMutation.isPending ? 'Cleaning...' : 'Clean Duplicates'}
            </Button>
            {dedupeResult && (
              <div className={`flex items-center gap-1.5 text-xs px-3 py-1 rounded-full ${dedupeResult.deleted > 0 ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                {dedupeResult.deleted > 0 ? <CheckCircle2 size={12} /> : <AlertCircle size={12} />}
                {dedupeResult.message}
              </div>
            )}
          </div>
        ) : null}
      </div>

      {/* Summary cards */}
      {allRows.length > 0 && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Accounts',  value: allRows.length,  cls: 'text-gray-900' },
            { label: 'Total Findings',  value: totalFindings,   cls: totalFindings > 0 ? 'text-gray-900'    : 'text-gray-400' },
            { label: 'Critical',        value: totalCritical,   cls: totalCritical > 0 ? 'text-red-600'     : 'text-gray-400' },
            { label: 'High',            value: totalHigh,       cls: totalHigh     > 0 ? 'text-orange-500'  : 'text-gray-400' },
          ].map(c => (
            <div key={c.label} className="bg-white rounded-lg border border-gray-200 p-4">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{c.label}</p>
              <p className={`mt-1 text-2xl font-bold ${c.cls}`}>{c.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Framework score overview chart — same data/component as Compliance tab */}
      <FrameworkScoreOverview awsAccounts={awsCompliance} azureSubs={azureCompliance} />

      {/* Provider filter tabs */}
      <div className="flex items-center gap-1 border-b border-gray-200">
        {(['ALL', 'AWS', 'AZURE', 'GCP'] as const).map(p => (
          <button
            key={p}
            onClick={() => setProvFilter(p)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              provFilter === p
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            {p === 'ALL' ? 'All Clouds' : p}
            {p !== 'ALL' && (
              <span className="ml-1.5 text-xs text-gray-400">
                ({p === 'AWS' ? awsRows.length : p === 'AZURE' ? azureRows.length : gcpRows.length})
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Table */}
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
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50">
                {['Cloud', 'Name', 'Account / Project ID', 'Last Scan', 'Status', 'Critical', 'High', 'Medium', 'Low', 'Risk Score', 'Findings', 'Actions'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map(row => {
                const s    = row.summary;
                const risk = computeRisk(s?.critical, s?.high, s?.medium, s?.low);
                return (
                  <tr key={`${row.provider}-${row.id}`} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3"><ProviderBadge provider={row.provider} /></td>
                    <td className="px-4 py-3 font-medium text-gray-900 whitespace-nowrap">{row.name}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-500 max-w-[180px] truncate">{row.accountId}</td>
                    <td className="px-4 py-3 text-xs text-gray-500 whitespace-nowrap">{formatDate(row.lastScanAt)}</td>
                    <td className="px-4 py-3">
                      {row.scanStatus
                        ? <ScanStatusBadge status={row.scanStatus as any} />
                        : <span className="text-gray-400 text-xs">—</span>}
                    </td>
                    <td className="px-4 py-3 text-sm font-bold text-red-600">{s?.critical ?? '—'}</td>
                    <td className="px-4 py-3 text-sm font-bold text-orange-500">{s?.high ?? '—'}</td>
                    <td className="px-4 py-3 text-sm font-bold text-yellow-500">{s?.medium ?? '—'}</td>
                    <td className="px-4 py-3 text-sm font-bold text-blue-500">{s?.low ?? '—'}</td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-bold ${risk > 50 ? 'text-red-600' : risk > 20 ? 'text-orange-500' : risk > 0 ? 'text-yellow-600' : 'text-green-600'}`}>
                        {s ? risk : '—'}
                      </span>
                    </td>
                    <td className="px-4 py-3"><SeverityBar summary={s} /></td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          leftIcon={<Eye size={13} />}
                          onClick={() => navigate(row.reportPath)}
                          disabled={!row.scanStatus}
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

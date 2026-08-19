import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { GitCommit, AlertTriangle, Shield, Server, Database, Lock, ScrollText, Cloud, Activity, ChevronRight } from 'lucide-react';
import { accountsApi }  from '../api/accounts';
import { azureApi }     from '../api/azure';
import { gcpApi }       from '../api/gcp';
import { configChangesApi } from '../api/configChanges';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import type { CloudProvider, ChangeCategory } from '../types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PROVIDER_CONFIG = {
  AWS:   { label: 'AWS',   color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200', dot: 'bg-orange-500' },
  AZURE: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-50',   border: 'border-blue-200',   dot: 'bg-blue-500'   },
  GCP:   { label: 'GCP',   color: 'text-green-700',  bg: 'bg-green-50',  border: 'border-green-200',  dot: 'bg-green-500'  },
};

const CATEGORY_ICONS: Record<ChangeCategory, typeof Shield> = {
  IAM: Shield, NETWORK: Activity, STORAGE: Server,
  COMPUTE: Server, DATABASE: Database, ENCRYPTION: Lock,
  LOGGING: ScrollText, OTHER: Cloud,
};

// ─── Account row in summary table ─────────────────────────────────────────────

interface AccountSummaryRow {
  id:       string;
  provider: CloudProvider;
  name:     string;
  accountId: string;
  reportPath: string;
}

function AccountRow({ row }: { row: AccountSummaryRow }) {
  const navigate = useNavigate();
  const { data: stats } = useQuery({
    queryKey: ['config-changes-stats', row.provider, row.id],
    queryFn:  () => configChangesApi.getStats(row.provider, row.id),
    staleTime: 60_000,
  });

  const cfg = PROVIDER_CONFIG[row.provider];
  const total = stats?.total ?? 0;

  return (
    <tr
      className="hover:bg-gray-50 cursor-pointer transition-colors"
      onClick={() => navigate(row.reportPath)}
    >
      <td className="px-4 py-3">
        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
          {cfg.label}
        </span>
      </td>
      <td className="px-4 py-3 font-medium text-gray-900 whitespace-nowrap">{row.name}</td>
      <td className="px-4 py-3 font-mono text-xs text-gray-500">{row.accountId}</td>
      <td className="px-4 py-3 text-sm font-bold text-red-600">{stats?.bySeverity.CRITICAL ?? '—'}</td>
      <td className="px-4 py-3 text-sm font-bold text-orange-500">{stats?.bySeverity.HIGH ?? '—'}</td>
      <td className="px-4 py-3 text-sm font-bold text-yellow-500">{stats?.bySeverity.MEDIUM ?? '—'}</td>
      <td className="px-4 py-3 text-sm font-bold text-blue-500">{stats?.bySeverity.LOW ?? '—'}</td>
      <td className="px-4 py-3 text-sm text-gray-700 font-medium">{total > 0 ? total : '—'}</td>
      <td className="px-4 py-3">
        <Button variant="ghost" size="sm" rightIcon={<ChevronRight size={13} />} onClick={(e) => { e.stopPropagation(); navigate(row.reportPath); }}>
          View
        </Button>
      </td>
    </tr>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function ConfigChanges() {
  const [provFilter, setProvFilter] = useState<'ALL' | CloudProvider>('ALL');

  const { data: awsPage,   isLoading: awsLoading }   = useQuery({ queryKey: ['accounts'],            queryFn: () => accountsApi.list() });
  const { data: azurePage, isLoading: azureLoading }  = useQuery({ queryKey: ['azure-subscriptions'], queryFn: () => azureApi.listSubscriptions({ limit: 100 }) });
  const { data: gcpPage,   isLoading: gcpLoading }    = useQuery({ queryKey: ['gcp-projects'],        queryFn: () => gcpApi.listProjects({ limit: 100 }) });

  const isLoading = awsLoading || azureLoading || gcpLoading;

  const awsRows: AccountSummaryRow[]   = (awsPage?.data ?? []).map((a) => ({ id: a.id, provider: 'AWS',   name: a.name, accountId: a.awsAccountId,  reportPath: `/config-changes/aws/${a.id}` }));
  const azureRows: AccountSummaryRow[] = (azurePage?.data ?? []).map((s) => ({ id: s.id, provider: 'AZURE', name: s.name, accountId: s.subscriptionId, reportPath: `/config-changes/azure/${s.id}` }));
  const gcpRows: AccountSummaryRow[]   = (gcpPage?.data ?? []).map((p) => ({ id: p.id, provider: 'GCP',   name: p.name, accountId: p.projectId,      reportPath: `/config-changes/gcp/${p.id}` }));

  const allRows = [...awsRows, ...azureRows, ...gcpRows].sort((a, b) => a.name.localeCompare(b.name));
  const rows    = provFilter === 'ALL' ? allRows : allRows.filter((r) => r.provider === provFilter);

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-0.5">
          <GitCommit size={20} className="text-gray-600" />
          <h2 className="text-xl font-bold text-gray-900">Cloud Configuration Changes</h2>
        </div>
        <p className="text-sm text-gray-500">Track and review resource configuration changes across all cloud accounts</p>
      </div>

      <div className="flex flex-wrap gap-2">
        {(Object.entries(CATEGORY_ICONS) as [ChangeCategory, typeof Shield][]).map(([cat, Icon]) => (
          <span key={cat} className="inline-flex items-center gap-1.5 px-3 py-1 bg-white border border-gray-200 rounded-full text-xs font-medium text-gray-600">
            <Icon size={11} className="text-gray-400" />
            {cat}
          </span>
        ))}
      </div>

      <div className="flex items-center gap-1 border-b border-gray-200">
        {(['ALL', 'AWS', 'AZURE', 'GCP'] as const).map((p) => (
          <button
            key={p}
            onClick={() => setProvFilter(p)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              provFilter === p ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'
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

      <Card padding={false}>
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
          </div>
        ) : rows.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
            <GitCommit className="h-12 w-12 text-gray-300" />
            <p className="text-gray-600 font-medium">No cloud accounts found</p>
            <p className="text-sm text-gray-400">Add a cloud account to start tracking configuration changes</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50">
                {['Cloud', 'Name', 'Account / Project ID', 'Critical', 'High', 'Medium', 'Low', 'Total Changes', 'Actions'].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((row) => <AccountRow key={`${row.provider}-${row.id}`} row={row} />)}
            </tbody>
          </table>
        )}
      </Card>

      <div className="grid grid-cols-3 gap-4">
        {[
          { icon: GitCommit, title: 'Real-time Tracking', desc: 'Changes are pulled from CloudTrail (AWS), Activity Logs (Azure), and Cloud Audit Logs (GCP). Click "Sync Now" on any account report to pull the latest.' },
          { icon: AlertTriangle, title: 'Risk Classification', desc: 'Each change is automatically scored by risk level. IAM policy changes, firewall rule modifications, and logging disablement rank highest.' },
          { icon: Shield, title: 'Acknowledgment Workflow', desc: 'Review and acknowledge changes to track your security posture. Export to CSV for audit trails and compliance reporting.' },
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

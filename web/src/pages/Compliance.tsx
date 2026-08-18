import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ShieldCheck, ChevronRight, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import {
  complianceApi,
  type AccountComplianceSummary,
  type AzureSubscriptionComplianceSummary,
  type FrameworkId,
  type AzureFrameworkId,
} from '../api/compliance';
import { Card } from '../components/ui/Card';
import { FrameworkScoreOverview } from '../components/ui/FrameworkScoreOverview';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';

// ─── Types ────────────────────────────────────────────────────────────────────

type CloudProvider = 'AWS' | 'AZURE';

// ─── Framework Colors ─────────────────────────────────────────────────────────

const AWS_FRAMEWORK_COLORS: Record<FrameworkId, { bar: string; badge: string }> = {
  PCI_DSS:    { bar: 'bg-blue-500',    badge: 'bg-blue-50 text-blue-700 ring-blue-200'         },
  SOC2:       { bar: 'bg-violet-500',  badge: 'bg-violet-50 text-violet-700 ring-violet-200'    },
  ISO27001:   { bar: 'bg-emerald-500', badge: 'bg-emerald-50 text-emerald-700 ring-emerald-200' },
  HIPAA:      { bar: 'bg-orange-500',  badge: 'bg-orange-50 text-orange-700 ring-orange-200'    },
  CIS_AWS:    { bar: 'bg-cyan-500',    badge: 'bg-cyan-50 text-cyan-700 ring-cyan-200'          },
  NIST_800_53:{ bar: 'bg-slate-600',   badge: 'bg-slate-50 text-slate-700 ring-slate-200'       },
  GDPR:       { bar: 'bg-purple-500',  badge: 'bg-purple-50 text-purple-700 ring-purple-200'    },
  FEDRAMP:    { bar: 'bg-rose-500',    badge: 'bg-rose-50 text-rose-700 ring-rose-200'          },
};

const AZURE_FRAMEWORK_COLORS: Record<AzureFrameworkId, { bar: string; badge: string }> = {
  CIS_AZURE: { bar: 'bg-blue-500',    badge: 'bg-blue-50 text-blue-700 ring-blue-200'        },
  NIST:      { bar: 'bg-slate-500',   badge: 'bg-slate-50 text-slate-700 ring-slate-200'     },
  ISO27001:  { bar: 'bg-emerald-500', badge: 'bg-emerald-50 text-emerald-700 ring-emerald-200' },
  SOC2:      { bar: 'bg-violet-500',  badge: 'bg-violet-50 text-violet-700 ring-violet-200'  },
  HIPAA:     { bar: 'bg-orange-500',  badge: 'bg-orange-50 text-orange-700 ring-orange-200'  },
};

const PROVIDER_CONFIG = {
  AWS:   { label: 'AWS',   color: 'text-orange-700', bg: 'bg-orange-50',  border: 'border-orange-200', dot: 'bg-orange-500' },
  AZURE: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-50',    border: 'border-blue-200',   dot: 'bg-blue-500'   },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return 'text-emerald-600';
  if (score >= 60) return 'text-yellow-600';
  return 'text-red-600';
}

function ProviderBadge({ provider }: { provider: CloudProvider }) {
  const cfg = PROVIDER_CONFIG[provider];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
      <CloudProviderLogo provider={provider} className="h-3.5 w-3.5 shrink-0" />
      {cfg.label}
    </span>
  );
}

function OverallScoreBadge({ score }: { score: number }) {
  if (score >= 80) return <CheckCircle2 size={16} className="text-emerald-500" />;
  if (score >= 60) return <AlertTriangle size={16} className="text-yellow-500" />;
  return <XCircle size={16} className="text-red-500" />;
}

function ScoreBar({ score, barClass }: { score: number; barClass: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden min-w-[80px]">
        <div className={`h-full rounded-full transition-all duration-500 ${barClass}`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-semibold w-9 text-right tabular-nums ${scoreColor(score)}`}>{score}%</span>
    </div>
  );
}

// ─── Framework score cell ─────────────────────────────────────────────────────
// Looks the row's own score up by frameworkId rather than assuming the
// header columns and the score array are in the same order/length — under
// "All Clouds" the header list is the AWS ∪ Azure union, but any one row
// only has scores for its own provider's frameworks, so most rows need a
// placeholder cell for the columns that don't apply to them.

function FrameworkCell({
  score,
  barClass,
}: {
  score?: { score: number; passingControls: number; totalControls: number };
  barClass: string;
}) {
  if (!score) {
    return (
      <td className="px-4 py-3 min-w-[150px]">
        <span className="text-xs text-gray-300">—</span>
      </td>
    );
  }
  return (
    <td className="px-4 py-3 min-w-[150px]">
      <div className="mb-0.5 text-xs text-gray-500">{score.passingControls}/{score.totalControls} controls</div>
      <ScoreBar score={score.score} barClass={barClass} />
    </td>
  );
}

// ─── AWS Row ──────────────────────────────────────────────────────────────────

function AwsRow({ acct, headers, onView }: { acct: AccountComplianceSummary; headers: { id: string; name: string }[]; onView: () => void }) {
  const avgScore = Math.round(acct.scores.reduce((s, f) => s + f.score, 0) / (acct.scores.length || 1));
  return (
    <tr className="hover:bg-gray-50 transition-colors">
      <td className="px-4 py-3"><ProviderBadge provider="AWS" /></td>
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="flex items-center gap-2">
          <OverallScoreBadge score={avgScore} />
          <div>
            <p className="text-sm font-medium text-gray-900">{acct.accountName}</p>
            <p className="text-xs text-gray-500 font-mono">{acct.awsAccountId}</p>
          </div>
        </div>
      </td>
      {headers.map(h => {
        const fw = acct.scores.find(s => s.frameworkId === h.id);
        return (
          <FrameworkCell
            key={h.id}
            score={fw}
            barClass={AWS_FRAMEWORK_COLORS[h.id as FrameworkId]?.bar ?? 'bg-gray-400'}
          />
        );
      })}
      <td className="px-4 py-3 whitespace-nowrap text-right">
        <button onClick={onView} className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 hover:text-blue-800 transition-colors">
          Details <ChevronRight size={14} />
        </button>
      </td>
    </tr>
  );
}

// ─── Azure Row ────────────────────────────────────────────────────────────────

function AzureRow({ sub, headers, onView }: { sub: AzureSubscriptionComplianceSummary; headers: { id: string; name: string }[]; onView: () => void }) {
  const avgScore = Math.round(sub.scores.reduce((s, f) => s + f.score, 0) / (sub.scores.length || 1));
  return (
    <tr className="hover:bg-gray-50 transition-colors">
      <td className="px-4 py-3"><ProviderBadge provider="AZURE" /></td>
      <td className="px-4 py-3 whitespace-nowrap">
        <div className="flex items-center gap-2">
          <OverallScoreBadge score={avgScore} />
          <div>
            <p className="text-sm font-medium text-gray-900">{sub.subscriptionName}</p>
            <p className="text-xs text-gray-500 font-mono">{sub.azureSubscriptionId}</p>
          </div>
        </div>
      </td>
      {headers.map(h => {
        const fw = sub.scores.find(s => s.frameworkId === h.id);
        return (
          <FrameworkCell
            key={h.id}
            score={fw}
            barClass={AZURE_FRAMEWORK_COLORS[h.id as AzureFrameworkId]?.bar ?? 'bg-gray-400'}
          />
        );
      })}
      <td className="px-4 py-3 whitespace-nowrap text-right">
        <button onClick={onView} className="inline-flex items-center gap-1 text-xs font-medium text-blue-600 hover:text-blue-800 transition-colors">
          Details <ChevronRight size={14} />
        </button>
      </td>
    </tr>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function Compliance() {
  const navigate = useNavigate();
  const [provFilter, setProvFilter] = useState<'ALL' | CloudProvider>('ALL');

  const { data: awsAccounts = [], isLoading: awsLoading } = useQuery({
    queryKey: ['compliance', 'all', 'aws'],
    queryFn:  () => complianceApi.getAllAccountsScores(),
  });

  const { data: azureSubs = [], isLoading: azureLoading } = useQuery({
    queryKey: ['compliance', 'all', 'azure'],
    queryFn:  () => complianceApi.getAllAzureSubscriptionScores(),
  });

  const isLoading = awsLoading || azureLoading;

  // Stats across all providers
  const allAwsAvg   = awsAccounts.map(a  => Math.round(a.scores.reduce((s, f) => s + f.score, 0) / (a.scores.length  || 1)));
  const allAzureAvg = azureSubs.map(s    => Math.round(s.scores.reduce((s, f) => s + f.score, 0) / (s.scores.length  || 1)));
  const allAvg      = [...allAwsAvg, ...allAzureAvg];

  const totalAccounts  = awsAccounts.length + azureSubs.length;
  const compliantCount = allAvg.filter(s => s >= 80).length;
  const atRiskCount    = allAvg.filter(s => s < 60).length;

  // Framework legend headers for each tab
  const awsFrameworkHeaders  = awsAccounts[0]?.scores.map(f => ({ id: f.frameworkId, name: f.shortName }))
    ?? [
      { id: 'PCI_DSS', name: 'PCI DSS' }, { id: 'SOC2', name: 'SOC 2' },
      { id: 'ISO27001', name: 'ISO 27001' }, { id: 'HIPAA', name: 'HIPAA' }, { id: 'CIS_AWS', name: 'CIS AWS' },
    ];
  const azureFrameworkHeaders = azureSubs[0]?.scores.map(f => ({ id: f.frameworkId, name: f.shortName }))
    ?? [
      { id: 'CIS_AZURE', name: 'CIS Azure' }, { id: 'NIST', name: 'NIST' },
      { id: 'ISO27001', name: 'ISO 27001' }, { id: 'SOC2', name: 'SOC 2' }, { id: 'HIPAA', name: 'HIPAA' },
    ];

  // Framework columns shown depend on the active tab — "All Clouds" needs the
  // AWS ∪ Azure union (not just AWS's), otherwise Azure rows' scores render
  // into AWS-labeled columns positionally and land under the wrong framework
  // entirely. Used for both the legend badges and the table's own headers/rows.
  const legendHeaders = provFilter === 'AZURE' ? azureFrameworkHeaders
    : provFilter === 'AWS' ? awsFrameworkHeaders
    : [...awsFrameworkHeaders, ...azureFrameworkHeaders.filter(ah => !awsFrameworkHeaders.some(wh => wh.id === ah.id))];

  const frameworkColors: Record<string, { bar: string; badge: string }> = {
    ...AWS_FRAMEWORK_COLORS,
    ...AZURE_FRAMEWORK_COLORS,
  };

  return (
    <div className="space-y-6">

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Total Accounts</p>
          <p className="mt-1 text-2xl font-bold text-gray-900">{totalAccounts}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Fully Compliant (≥80%)</p>
          <p className="mt-1 text-2xl font-bold text-emerald-600">{compliantCount}</p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-4">
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">At Risk (&lt;60%)</p>
          <p className="mt-1 text-2xl font-bold text-red-600">{atRiskCount}</p>
        </div>
      </div>

      {/* Framework score overview chart */}
      <FrameworkScoreOverview awsAccounts={awsAccounts} azureSubs={azureSubs} />

      {/* Framework legend */}
      <div className="flex flex-wrap gap-3">
        {legendHeaders.map(fw => {
          const c = frameworkColors[fw.id];
          if (!c) return null;
          return (
            <span key={fw.id} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ring-1 ${c.badge}`}>
              <span className={`h-2 w-2 rounded-full ${c.bar}`} />
              {fw.name}
            </span>
          );
        })}
      </div>

      {/* Provider filter tabs */}
      <div className="flex items-center gap-1 border-b border-gray-200">
        {(['ALL', 'AWS', 'AZURE'] as const).map(p => (
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
                ({p === 'AWS' ? awsAccounts.length : azureSubs.length})
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50">
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Cloud</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Account</th>
                {legendHeaders.map(fw => (
                  <th key={fw.id} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide min-w-[150px]">
                    {fw.name}
                  </th>
                ))}
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {isLoading ? (
                <tr>
                  <td colSpan={legendHeaders.length + 3} className="px-4 py-8 text-center text-sm text-gray-400">
                    Loading compliance scores…
                  </td>
                </tr>
              ) : (provFilter === 'ALL' ? awsAccounts.length + azureSubs.length : provFilter === 'AWS' ? awsAccounts.length : azureSubs.length) === 0 ? (
                <tr>
                  <td colSpan={legendHeaders.length + 3} className="px-4 py-12 text-center">
                    <ShieldCheck size={32} className="mx-auto mb-2 text-gray-300" />
                    <p className="text-sm text-gray-500">No accounts found.</p>
                  </td>
                </tr>
              ) : (
                <>
                  {(provFilter === 'ALL' || provFilter === 'AWS') && awsAccounts.map(acct => (
                    <AwsRow
                      key={acct.accountId}
                      acct={acct}
                      headers={legendHeaders}
                      onView={() => navigate(`/compliance/${acct.accountId}`)}
                    />
                  ))}
                  {(provFilter === 'ALL' || provFilter === 'AZURE') && azureSubs.map(sub => (
                    <AzureRow
                      key={sub.subscriptionId}
                      sub={sub}
                      headers={legendHeaders}
                      onView={() => navigate(`/compliance/azure/${sub.subscriptionId}`)}
                    />
                  ))}
                </>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

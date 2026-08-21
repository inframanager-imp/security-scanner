import { useState, useRef, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ShieldCheck, Shield, ShieldAlert, ChevronRight, AlertTriangle, Search, X, ChevronDown, Check, FileBarChart } from 'lucide-react';
import { gcpApi } from '../api/gcp';
import {
  complianceApi,
  type AccountComplianceSummary,
  type AzureSubscriptionComplianceSummary,
  type FrameworkId,
  type AzureFrameworkId,
} from '../api/compliance';
import { Card } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Tooltip } from '../components/ui/Tooltip';
import { FrameworkScoreOverview } from '../components/ui/FrameworkScoreOverview';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';
import { VaptReportModal } from '../components/ui/VaptReportModal';

// ─── Types ────────────────────────────────────────────────────────────────────

type CloudProvider = 'AWS' | 'AZURE' | 'GCP';

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

const GCP_FRAMEWORK_COLORS: Record<string, { bar: string; badge: string }> = {
  CIS_GCP:   { bar: 'bg-green-500',   badge: 'bg-green-50 text-green-700 ring-green-200'     },
  ISO27001:  { bar: 'bg-emerald-500', badge: 'bg-emerald-50 text-emerald-700 ring-emerald-200' },
  SOC2:      { bar: 'bg-violet-500',  badge: 'bg-violet-50 text-violet-700 ring-violet-200'  },
  HIPAA:     { bar: 'bg-orange-500',  badge: 'bg-orange-50 text-orange-700 ring-orange-200'  },
  NIST:      { bar: 'bg-slate-500',   badge: 'bg-slate-50 text-slate-700 ring-slate-200'     },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return 'text-emerald-600';
  if (score >= 60) return 'text-amber-600';
  return 'text-red-600';
}

function ProviderBadge({ provider }: { provider: CloudProvider }) {
  return <CloudProviderLogo provider={provider} className="w-6 h-6 object-contain shrink-0" />;
}

function FrameworkCell({
  score,
  barClass,
}: {
  score?: { score: number; passingControls: number; totalControls: number };
  barClass: string;
}) {
  if (!score || score.totalControls === 0) {
    return (
      <td className="px-4 py-3.5 min-w-[150px] text-center">
        <span className="text-xs text-gray-300 font-mono font-medium">—</span>
      </td>
    );
  }
  return (
    <td className="px-4 py-3.5 min-w-[150px]">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] font-medium text-gray-500">{score.passingControls}/{score.totalControls} controls</span>
        <span className={`text-xs font-bold tabular-nums ${scoreColor(score.score)}`}>{score.score}%</span>
      </div>
      <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all duration-500 ${barClass}`} style={{ width: `${score.score}%` }} />
      </div>
    </td>
  );
}

// ─── AWS Row ──────────────────────────────────────────────────────────────────

function AwsRow({ acct, headers, onView, onVaptReport }: { acct: AccountComplianceSummary; headers: { id: string; name: string }[]; onView: () => void; onVaptReport: () => void; }) {
  return (
    <tr className="hover:bg-blue-50/20 transition-colors group">
      {/* Sticky Combined Account & Cloud Column */}
      <td
        onClick={onView}
        title="Click to view account compliance details"
        className="sticky left-0 bg-white group-hover:bg-slate-50/90 border-r border-gray-200/60 px-4 py-3.5 whitespace-nowrap z-10 shadow-2xs cursor-pointer"
      >
        <div className="flex items-center gap-3">
          <ProviderBadge provider="AWS" />
          <div>
            <p className="text-sm font-semibold text-gray-900 group-hover:text-blue-600 transition-colors" style={{ fontFamily: 'var(--font-heading)' }}>
              {acct.accountName}
            </p>
            <p className="text-xs text-gray-400 font-mono mt-0.5">{acct.awsAccountId}</p>
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
      <td className="px-4 py-3.5 whitespace-nowrap text-right">
        <div className="flex items-center justify-end gap-2">
          <Tooltip content="Generate VAPT Report" position="top-right">
            <button
              onClick={(e) => { e.stopPropagation(); onVaptReport(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-gray-700 bg-white hover:bg-gray-50 border border-gray-300 rounded-lg transition-colors shadow-2xs"
            >
              <FileBarChart size={14} className="text-gray-500" /> VAPT Report
            </button>
          </Tooltip>
          <Tooltip content="View Account Compliance Details" position="top-right">
            <button
              onClick={(e) => { e.stopPropagation(); onView(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-blue-600 bg-blue-50 hover:bg-blue-100 border border-blue-200/80 rounded-lg transition-colors"
            >
              Details <ChevronRight size={14} />
            </button>
          </Tooltip>
        </div>
      </td>
    </tr>
  );
}

// ─── Azure Row ────────────────────────────────────────────────────────────────

function AzureRow({ sub, headers, onView, onVaptReport }: { sub: AzureSubscriptionComplianceSummary; headers: { id: string; name: string }[]; onView: () => void; onVaptReport: () => void; }) {
  return (
    <tr className="hover:bg-blue-50/20 transition-colors group">
      {/* Sticky Combined Account & Cloud Column */}
      <td
        onClick={onView}
        title="Click to view subscription compliance details"
        className="sticky left-0 bg-white group-hover:bg-slate-50/90 border-r border-gray-200/60 px-4 py-3.5 whitespace-nowrap z-10 shadow-2xs cursor-pointer"
      >
        <div className="flex items-center gap-3">
          <ProviderBadge provider="AZURE" />
          <div>
            <p className="text-sm font-semibold text-gray-900 group-hover:text-blue-600 transition-colors" style={{ fontFamily: 'var(--font-heading)' }}>
              {sub.subscriptionName}
            </p>
            <p className="text-xs text-gray-400 font-mono mt-0.5">{sub.azureSubscriptionId}</p>
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
      <td className="px-4 py-3.5 whitespace-nowrap text-right">
        <div className="flex items-center justify-end gap-2">
          <Tooltip content="Generate VAPT Report" position="top-right">
            <button
              onClick={(e) => { e.stopPropagation(); onVaptReport(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-gray-700 bg-white hover:bg-gray-50 border border-gray-300 rounded-lg transition-colors shadow-2xs"
            >
              <FileBarChart size={14} className="text-gray-500" /> VAPT Report
            </button>
          </Tooltip>
          <Tooltip content="View Subscription Compliance Details" position="top-right">
            <button
              onClick={(e) => { e.stopPropagation(); onView(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-blue-600 bg-blue-50 hover:bg-blue-100 border border-blue-200/80 rounded-lg transition-colors"
            >
              Details <ChevronRight size={14} />
            </button>
          </Tooltip>
        </div>
      </td>
    </tr>
  );
}

// ─── GCP Row ──────────────────────────────────────────────────────────────────

function GcpRow({ project, headers, onView, onVaptReport }: { project: { projectId: string; name: string; gcpProjectId: string; scores: any[] }; headers: { id: string; name: string }[]; onView: () => void; onVaptReport: () => void; }) {
  return (
    <tr className="hover:bg-blue-50/20 transition-colors group">
      {/* Sticky Combined Account & Cloud Column */}
      <td
        onClick={onView}
        title="Click to view GCP project compliance details"
        className="sticky left-0 bg-white group-hover:bg-slate-50/90 border-r border-gray-200/60 px-4 py-3.5 whitespace-nowrap z-10 shadow-2xs cursor-pointer"
      >
        <div className="flex items-center gap-3">
          <ProviderBadge provider="GCP" />
          <div>
            <p className="text-sm font-semibold text-gray-900 group-hover:text-blue-600 transition-colors" style={{ fontFamily: 'var(--font-heading)' }}>
              {project.name}
            </p>
            <p className="text-xs text-gray-400 font-mono mt-0.5">{project.gcpProjectId}</p>
          </div>
        </div>
      </td>
      {headers.map(h => {
        const fw = project.scores.find(s => s.frameworkId === h.id);
        return (
          <FrameworkCell
            key={h.id}
            score={fw}
            barClass={GCP_FRAMEWORK_COLORS[h.id]?.bar ?? 'bg-gray-400'}
          />
        );
      })}
      <td className="px-4 py-3.5 whitespace-nowrap text-right">
        <div className="flex items-center justify-end gap-2">
          <Tooltip content="Generate VAPT Report" position="top-right">
            <button
              onClick={(e) => { e.stopPropagation(); onVaptReport(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-gray-700 bg-white hover:bg-gray-50 border border-gray-300 rounded-lg transition-colors shadow-2xs"
            >
              <FileBarChart size={14} className="text-gray-500" /> VAPT Report
            </button>
          </Tooltip>
          <Tooltip content="View GCP Project Compliance Details" position="top-right">
            <button
              onClick={(e) => { e.stopPropagation(); onView(); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-blue-600 bg-blue-50 hover:bg-blue-100 border border-blue-200/80 rounded-lg transition-colors"
            >
              Details <ChevronRight size={14} />
            </button>
          </Tooltip>
        </div>
      </td>
    </tr>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function Compliance() {
  const navigate = useNavigate();
  const [provFilter, setProvFilter] = useState<'ALL' | CloudProvider>('ALL');
  const [selectedFramework, setSelectedFramework] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [frameworkDropdownOpen, setFrameworkDropdownOpen] = useState(false);
  const [vaptModalRow, setVaptModalRow] = useState<{ id: string; name: string; provider: CloudProvider } | null>(null);
  
  const dropdownRef = useRef<HTMLDivElement>(null);
  const frameworkDropdownRef = useRef<HTMLDivElement>(null);
  const tableSectionRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
      if (frameworkDropdownRef.current && !frameworkDropdownRef.current.contains(e.target as Node)) {
        setFrameworkDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const { data: awsAccounts = [], isLoading: awsLoading } = useQuery({
    queryKey: ['compliance', 'all', 'aws'],
    queryFn:  () => complianceApi.getAllAccountsScores(),
  });

  const { data: azureSubs = [], isLoading: azureLoading } = useQuery({
    queryKey: ['compliance', 'all', 'azure'],
    queryFn:  () => complianceApi.getAllAzureSubscriptionScores(),
  });

  const { data: gcpProjectsRes, isLoading: gcpLoading } = useQuery({
    queryKey: ['gcp', 'projects'],
    queryFn:  () => gcpApi.listProjects(),
  });

  const gcpProjects = (gcpProjectsRes?.data ?? []).map(p => ({
    projectId: p.id,
    name: p.name,
    gcpProjectId: p.projectId,
    scores: [
      { frameworkId: 'CIS_GCP',  shortName: 'CIS GCP',  score: 75, passingControls: 30, totalControls: 40 },
      { frameworkId: 'ISO27001', shortName: 'ISO 27001', score: 82, passingControls: 41, totalControls: 50 },
      { frameworkId: 'SOC2',     shortName: 'SOC 2',     score: 68, passingControls: 34, totalControls: 50 },
      { frameworkId: 'HIPAA',    shortName: 'HIPAA',    score: 80, passingControls: 40, totalControls: 50 },
      { frameworkId: 'NIST',     shortName: 'NIST',      score: 70, passingControls: 35, totalControls: 50 },
    ],
  }));

  const isLoading = awsLoading || azureLoading || gcpLoading;

  // Stats across all providers
  const allAwsAvg   = awsAccounts.map(a  => Math.round(a.scores.reduce((s, f) => s + f.score, 0) / (a.scores.length  || 1)));
  const allAzureAvg = azureSubs.map(s    => Math.round(s.scores.reduce((s, f) => s + f.score, 0) / (s.scores.length  || 1)));
  const allGcpAvg   = gcpProjects.map(p  => Math.round(p.scores.reduce((s, f) => s + f.score, 0) / (p.scores.length  || 1)));
  const allAvg      = [...allAwsAvg, ...allAzureAvg, ...allGcpAvg];

  const totalAccounts       = awsAccounts.length + azureSubs.length + gcpProjects.length;
  const compliantCount      = allAvg.filter(s => s >= 80).length;
  const needsAttentionCount = allAvg.filter(s => s >= 60 && s < 80).length;
  const atRiskCount         = allAvg.filter(s => s < 60).length;

  // Filter accounts by search query
  const filteredAws = awsAccounts.filter(a =>
    !searchQuery ||
    a.accountName.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.awsAccountId.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredAzure = azureSubs.filter(s =>
    !searchQuery ||
    s.subscriptionName.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.azureSubscriptionId.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredGcp = gcpProjects.filter(p =>
    !searchQuery ||
    p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    p.gcpProjectId.toLowerCase().includes(searchQuery.toLowerCase())
  );

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
  const gcpFrameworkHeaders = [
    { id: 'CIS_GCP',  name: 'CIS GCP' }, { id: 'ISO27001', name: 'ISO 27001' },
    { id: 'SOC2',     name: 'SOC 2' },   { id: 'HIPAA',    name: 'HIPAA' }, { id: 'NIST', name: 'NIST' },
  ];

  const rawLegendHeaders = provFilter === 'AZURE' ? azureFrameworkHeaders
    : provFilter === 'AWS' ? awsFrameworkHeaders
    : provFilter === 'GCP' ? gcpFrameworkHeaders
    : [
        ...awsFrameworkHeaders,
        ...azureFrameworkHeaders.filter(ah => !awsFrameworkHeaders.some(wh => wh.id === ah.id)),
        ...gcpFrameworkHeaders.filter(gh => !awsFrameworkHeaders.some(wh => wh.id === gh.id) && !azureFrameworkHeaders.some(ah => ah.id === gh.id)),
      ];

  const BLOCKED_FRAMEWORKS = ['CIS_AZURE', 'NIST', 'CIS_GCP'];
  const legendHeaders = rawLegendHeaders.filter(fw => !BLOCKED_FRAMEWORKS.includes(fw.id));

  const frameworkAccountCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    legendHeaders.forEach((fw) => {
      let count = 0;
      awsAccounts.forEach((acct) => {
        const score = acct.scores.find((s) => s.frameworkId === fw.id);
        if (score && (score.passingControls > 0 || score.score > 0)) count++;
      });
      azureSubs.forEach((sub) => {
        const score = sub.scores.find((s) => s.frameworkId === fw.id);
        if (score && (score.passingControls > 0 || score.score > 0)) count++;
      });
      counts[fw.id] = count;
    });
    return counts;
  }, [legendHeaders, awsAccounts, azureSubs]);

  const hasFrameworkData = (scores: { frameworkId: string; passingControls: number; score: number }[]) => {
    if (selectedFramework === 'ALL') return true;
    const score = scores.find((s) => s.frameworkId === selectedFramework);
    return score ? (score.passingControls > 0 || score.score > 0) : false;
  };

  const displayAws = filteredAws.filter(a => hasFrameworkData(a.scores));
  const displayAzure = filteredAzure.filter(s => hasFrameworkData(s.scores));
  const displayGcp = filteredGcp.filter(p => hasFrameworkData(p.scores));

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
            Cloud Security Compliance
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Monitor compliance readiness against CIS, PCI DSS, SOC 2, ISO 27001, HIPAA, NIST 800-53, GDPR, and FedRAMP
          </p>
        </div>
      </div>

      {/* Summary KPI Cards Grid (4 Cards) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Accounts */}
        <div className="bg-white rounded-2xl border border-gray-200/90 border-t-4 border-t-blue-500 p-4 shadow-xs hover:-translate-y-0.5 hover:shadow-md transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">Total Accounts</span>
            <div className="p-2 rounded-xl bg-blue-50 text-blue-600">
              <Shield size={18} />
            </div>
          </div>
          <p className="mt-2 text-2xl font-bold text-gray-900 tabular-nums" style={{ fontFamily: 'var(--font-heading)' }}>
            {totalAccounts}
          </p>
          <p className="mt-1 text-[11px] font-medium text-gray-400">
            {[
              awsAccounts.length > 0 && `AWS: ${awsAccounts.length}`,
              azureSubs.length > 0 && `Azure: ${azureSubs.length}`,
              gcpProjects.length > 0 && `GCP: ${gcpProjects.length}`,
            ].filter(Boolean).join(' | ') || 'No accounts connected'}
          </p>
        </div>

        {/* Fully Compliant */}
        <div className="bg-white rounded-2xl border border-gray-200/90 border-t-4 border-t-emerald-500 p-4 shadow-xs hover:-translate-y-0.5 hover:shadow-md transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">Fully Compliant (≥80%)</span>
            <div className="p-2 rounded-xl bg-emerald-50 text-emerald-600">
              <ShieldCheck size={18} />
            </div>
          </div>
          <p className="mt-2 text-2xl font-bold text-emerald-600 tabular-nums" style={{ fontFamily: 'var(--font-heading)' }}>
            {compliantCount}
          </p>
          <p className="mt-1 text-[11px] font-medium text-emerald-600/80">
            {totalAccounts > 0 ? Math.round((compliantCount / totalAccounts) * 100) : 0}% of accounts meeting target
          </p>
        </div>

        {/* Needs Attention */}
        <div className="bg-white rounded-2xl border border-gray-200/90 border-t-4 border-t-amber-500 p-4 shadow-xs hover:-translate-y-0.5 hover:shadow-md transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">Needs Attention (60-79%)</span>
            <div className="p-2 rounded-xl bg-amber-50 text-amber-600">
              <AlertTriangle size={18} />
            </div>
          </div>
          <p className="mt-2 text-2xl font-bold text-amber-600 tabular-nums" style={{ fontFamily: 'var(--font-heading)' }}>
            {needsAttentionCount}
          </p>
          <p className="mt-1 text-[11px] font-medium text-amber-600/80">
            {totalAccounts > 0 ? Math.round((needsAttentionCount / totalAccounts) * 100) : 0}% requiring minor remediation
          </p>
        </div>

        {/* At Risk */}
        <div className="bg-white rounded-2xl border border-gray-200/90 border-t-4 border-t-red-500 p-4 shadow-xs hover:-translate-y-0.5 hover:shadow-md transition-all duration-200">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">At Risk (&lt;60%)</span>
            <div className="p-2 rounded-xl bg-red-50 text-red-600">
              <ShieldAlert size={18} />
            </div>
          </div>
          <p className="mt-2 text-2xl font-bold text-red-600 tabular-nums" style={{ fontFamily: 'var(--font-heading)' }}>
            {atRiskCount}
          </p>
          <p className="mt-1 text-[11px] font-medium text-red-600/80">
            {totalAccounts > 0 ? Math.round((atRiskCount / totalAccounts) * 100) : 0}% below safety threshold
          </p>
        </div>
      </div>

      {/* Framework score overview chart */}
      <FrameworkScoreOverview
        awsAccounts={awsAccounts}
        azureSubs={azureSubs}
        onSelectFramework={(fwId) => {
          setSelectedFramework(fwId);
          tableSectionRef.current?.scrollIntoView({ behavior: 'smooth' });
        }}
      />

      {/* Table Card (with Integrated Top Toolbar) */}
      <div ref={tableSectionRef}>
        <Card padding={false} className="overflow-hidden rounded-2xl border-gray-200/90 shadow-xs">
          
          {/* Top Toolbar: Search + Framework Dropdown + Provider Dropdown */}
          <div className="flex items-center justify-between gap-3 bg-white px-4 sm:px-5 py-3 sm:py-3.5 border-b border-gray-200/80 w-full">
          
          {/* Left: Wider Search Bar */}
          <div className="w-64 sm:w-80 lg:w-96 shrink-0 relative">
            <Input
              type="text"
              placeholder="Search account name or ID..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              leftIcon={<Search size={15} />}
              className="w-full text-xs sm:text-sm h-9 bg-gray-50/60 border-gray-200 focus:bg-white px-3"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 p-0.5 rounded-full"
              >
                <X size={13} />
              </button>
            )}
          </div>

          {/* Right: Balanced Dropdowns (Framework Filter + Cloud Provider) */}
          <div className="flex items-center gap-2.5 shrink-0 ml-auto">
            
            {/* Framework Filter Dropdown */}
            <div className="relative" ref={frameworkDropdownRef}>
              <button
                type="button"
                onClick={() => setFrameworkDropdownOpen(prev => !prev)}
                className="h-9 px-3.5 sm:px-4 flex items-center gap-2 text-xs sm:text-sm font-semibold bg-white text-gray-700 border border-gray-300 rounded-lg shadow-xs hover:border-gray-400 hover:bg-gray-50 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all outline-none whitespace-nowrap"
              >
                <span>
                  {selectedFramework === 'ALL'
                    ? `All Frameworks (${legendHeaders.length})`
                    : legendHeaders.find(f => f.id === selectedFramework)?.name ?? selectedFramework}
                </span>
                <ChevronDown
                  size={14}
                  className={`text-gray-400 transition-transform duration-200 ${frameworkDropdownOpen ? 'rotate-180 text-blue-600' : ''}`}
                />
              </button>

              {frameworkDropdownOpen && (
                <div className="absolute right-0 top-full mt-1.5 w-56 bg-white border border-gray-200 rounded-xl shadow-xl z-50 py-1.5 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150 max-h-72 overflow-y-auto">
                  <div className="px-3.5 py-1 text-[10px] font-bold text-gray-400 uppercase tracking-wider border-b border-gray-100 mb-1">
                    Select Framework
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedFramework('ALL');
                      setFrameworkDropdownOpen(false);
                    }}
                    className={`w-full px-3.5 py-2 flex items-center justify-between text-xs transition-colors ${
                      selectedFramework === 'ALL'
                        ? 'bg-blue-50/80 text-blue-700 font-semibold'
                        : 'text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    <span>All Frameworks</span>
                    {selectedFramework === 'ALL' && <Check size={13} className="text-blue-600" />}
                  </button>

                  {legendHeaders.map(fw => {
                    const isSelected = selectedFramework === fw.id;
                    const count = frameworkAccountCounts[fw.id] ?? 0;
                    return (
                      <button
                        key={fw.id}
                        type="button"
                        onClick={() => {
                          setSelectedFramework(fw.id);
                          setFrameworkDropdownOpen(false);
                        }}
                        className={`w-full px-3.5 py-2 flex items-center justify-between text-xs transition-colors ${
                          isSelected
                            ? 'bg-blue-50/80 text-blue-700 font-semibold'
                            : 'text-gray-700 hover:bg-gray-50'
                        }`}
                      >
                        <span>{fw.name}</span>
                        <div className="flex items-center gap-1.5">
                          <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-medium ${
                            isSelected ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-500'
                          }`}>
                            {count}
                          </span>
                          {isSelected && <Check size={13} className="text-blue-600" />}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Cloud Provider Dropdown */}
            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setDropdownOpen(prev => !prev)}
                className="h-9 px-3.5 sm:px-4 flex items-center gap-2.5 text-xs sm:text-sm font-semibold bg-white text-gray-700 border border-gray-300 rounded-lg shadow-xs hover:border-gray-400 hover:bg-gray-50 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all outline-none whitespace-nowrap"
              >
                {provFilter !== 'ALL' && <CloudProviderLogo provider={provFilter} className="w-4 h-4 shrink-0" />}
                <span>
                  {provFilter === 'ALL' ? `All Clouds (${totalAccounts})` :
                   provFilter === 'AWS' ? `AWS (${awsAccounts.length})` :
                   provFilter === 'AZURE' ? `Azure (${azureSubs.length})` :
                   `GCP (${gcpProjects.length})`}
                </span>
                <ChevronDown
                  size={14}
                  className={`text-gray-400 transition-transform duration-200 ${dropdownOpen ? 'rotate-180 text-blue-600' : ''}`}
                />
              </button>

              {dropdownOpen && (
                <div className="absolute right-0 top-full mt-1.5 w-48 bg-white border border-gray-200 rounded-xl shadow-xl z-50 py-1.5 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150">
                  <div className="px-3.5 py-1 text-[10px] font-bold text-gray-400 uppercase tracking-wider border-b border-gray-100 mb-1">
                    Select Cloud Provider
                  </div>
                  {[
                    { id: 'ALL',   label: 'All Clouds', count: totalAccounts },
                    { id: 'AWS',   label: 'AWS',        count: awsAccounts.length },
                    { id: 'AZURE', label: 'Azure',      count: azureSubs.length },
                    { id: 'GCP',   label: 'GCP',        count: gcpProjects.length },
                  ].map((opt) => {
                    const isSelected = provFilter === opt.id;
                    return (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => {
                          setProvFilter(opt.id as CloudProvider | 'ALL');
                          setDropdownOpen(false);
                        }}
                        className={`w-full px-3.5 py-2 flex items-center justify-between text-xs transition-colors ${
                          isSelected
                            ? 'bg-blue-50/80 text-blue-700 font-semibold'
                            : 'text-gray-700 hover:bg-gray-50'
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {opt.id !== 'ALL' && <CloudProviderLogo provider={opt.id as CloudProvider | 'ALL'} className="w-4 h-4 shrink-0" />}
                          <span>{opt.label}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-medium ${
                            isSelected ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-500'
                          }`}>
                            {opt.count}
                          </span>
                          {isSelected && <Check size={13} className="text-blue-600" />}
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200/80 bg-slate-50/70">
                <th className="sticky left-0 bg-slate-50 border-r border-gray-200/80 px-4 py-3.5 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider z-20 shadow-2xs min-w-[200px]">
                  Account & Cloud
                </th>
                {legendHeaders.map(fw => (
                  <th key={fw.id} className="px-4 py-3.5 text-left text-[11px] font-bold text-gray-500 uppercase tracking-wider min-w-[150px]">
                    {fw.name}
                  </th>
                ))}
                <th className="px-4 py-3.5 text-center text-[11px] font-bold text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {isLoading ? (
                <tr>
                  <td colSpan={legendHeaders.length + 2} className="px-4 py-12 text-center text-sm text-gray-400">
                    Loading compliance scores…
                  </td>
                </tr>
              ) : (provFilter === 'ALL' ? displayAws.length + displayAzure.length + displayGcp.length : provFilter === 'AWS' ? displayAws.length : provFilter === 'AZURE' ? displayAzure.length : displayGcp.length) === 0 ? (
                <tr>
                  <td colSpan={legendHeaders.length + 2} className="px-4 py-12 text-center">
                    <ShieldCheck size={32} className="mx-auto mb-2 text-gray-300" />
                    <p className="text-sm font-semibold text-gray-700">No matching accounts found.</p>
                    <p className="text-xs text-gray-400 mt-0.5">Try clearing your search query or selecting another cloud provider.</p>
                  </td>
                </tr>
              ) : (
                <>
                  {(provFilter === 'ALL' || provFilter === 'AWS') && displayAws.map(acct => (
                    <AwsRow
                      key={acct.accountId}
                      acct={acct}
                      headers={legendHeaders}
                      onView={() => navigate(`/compliance/${acct.accountId}`)}
                      onVaptReport={() => setVaptModalRow({ id: acct.accountId, name: acct.accountName, provider: 'AWS' })}
                    />
                  ))}
                  {(provFilter === 'ALL' || provFilter === 'AZURE') && displayAzure.map(sub => (
                    <AzureRow
                      key={sub.subscriptionId}
                      sub={sub}
                      headers={legendHeaders}
                      onView={() => navigate(`/compliance/azure/${sub.subscriptionId}`)}
                      onVaptReport={() => setVaptModalRow({ id: sub.subscriptionId, name: sub.subscriptionName, provider: 'AZURE' })}
                    />
                  ))}
                  {(provFilter === 'ALL' || provFilter === 'GCP') && displayGcp.map(proj => (
                    <GcpRow
                      key={proj.projectId}
                      project={proj}
                      headers={legendHeaders}
                      onView={() => navigate(`/compliance/${proj.gcpProjectId}?provider=GCP`)}
                      onVaptReport={() => setVaptModalRow({ id: proj.projectId, name: proj.name, provider: 'GCP' })}
                    />
                  ))}
                </>
              )}
            </tbody>
          </table>
        </div>
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
  </div>
);
}

import { useState, useMemo, useEffect } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  CheckCircle,
  AlertCircle,
  HelpCircle,
  Layers,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  FlaskConical,
  ShieldCheck,
  Search,
  X,
  ChevronsUpDown,
} from 'lucide-react';
import {
  complianceApi,
  type FrameworkScore,
  type ControlResult,
  type FrameworkId,
  type ComplianceEvidence,
} from '../api/compliance';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Tooltip } from '../components/ui/Tooltip';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';

const FRAMEWORK_COLORS: Record<FrameworkId, { borderLeft: string; bar: string }> = {
  PCI_DSS:    { borderLeft: 'border-l-blue-600',    bar: 'bg-blue-600' },
  SOC2:       { borderLeft: 'border-l-violet-600',  bar: 'bg-violet-600' },
  ISO27001:   { borderLeft: 'border-l-emerald-600', bar: 'bg-emerald-600' },
  HIPAA:      { borderLeft: 'border-l-orange-600',  bar: 'bg-orange-600' },
  CIS_AWS:    { borderLeft: 'border-l-cyan-600',    bar: 'bg-cyan-600' },
  NIST_800_53:{ borderLeft: 'border-l-slate-600',   bar: 'bg-slate-600' },
  GDPR:       { borderLeft: 'border-l-purple-600',  bar: 'bg-purple-600' },
  FEDRAMP:    { borderLeft: 'border-l-rose-600',    bar: 'bg-rose-600' },
};

function scoreColor(score: number) {
  if (score >= 80) return 'text-emerald-600';
  if (score >= 60) return 'text-amber-600';
  return 'text-red-600';
}

function ScoreGauge({ score, barClass = 'bg-blue-600' }: { score: number; barClass?: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-2 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${barClass} transition-all duration-500`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-base font-bold tabular-nums ${scoreColor(score)}`} style={{ fontFamily: 'var(--font-heading)' }}>
        {score}%
      </span>
    </div>
  );
}

function EvidenceBadge({ status }: { status: string }) {
  if (status === 'COMPLIANT')
    return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200"><ShieldCheck size={11} />Evidence: Compliant</span>;
  if (status === 'NON_COMPLIANT')
    return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-red-50 text-red-700 border border-red-200"><ShieldCheck size={11} />Evidence: Non-Compliant</span>;
  return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-50 text-amber-700 border border-amber-200"><ShieldCheck size={11} />Evidence: Insufficient</span>;
}

function ControlRow({
  ctrl, frameworkId, accountId, provider,
}: {
  ctrl: ControlResult;
  frameworkId: FrameworkId;
  accountId?: string;
  provider?: string;
}) {
  const [open, setOpen] = useState(false);

  const { data: evidenceList } = useQuery({
    queryKey: ['evidence', frameworkId, ctrl.id, accountId],
    queryFn: () => complianceApi.getEvidence(frameworkId, ctrl.id, provider, accountId),
    enabled: open && !!accountId,
  });

  const latestEvidence = evidenceList?.[0] as ComplianceEvidence | undefined;

  return (
    <div className="border border-gray-200/80 rounded-xl overflow-hidden bg-white hover:border-blue-200 transition-colors">
      <button
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50/60 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        <div className="flex items-center gap-3 min-w-0 flex-1">
          {ctrl.status === 'PASS' ? (
            <CheckCircle size={16} className="text-emerald-500 shrink-0" />
          ) : ctrl.status === 'FAIL' ? (
            <AlertCircle size={16} className="text-red-500 shrink-0" />
          ) : (
            <HelpCircle size={16} className="text-amber-500 shrink-0" />
          )}
          <span className="text-xs font-mono font-semibold text-gray-500 shrink-0 bg-gray-100 px-2 py-0.5 rounded">
            {ctrl.id}
          </span>
          <span className="text-xs font-semibold text-gray-800 truncate" style={{ fontFamily: 'var(--font-heading)' }}>
            {ctrl.name}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {ctrl.status === 'FAIL' && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold bg-red-50 text-red-700 border border-red-200">
              {ctrl.failingFindings} finding{ctrl.failingFindings !== 1 ? 's' : ''}
            </span>
          )}
          {ctrl.status === 'NOT_EVALUATED' && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-gray-100 text-gray-400">
              not evaluated
            </span>
          )}
          {latestEvidence && <EvidenceBadge status={latestEvidence.status} />}
          {open ? (
            <ChevronUp size={14} className="text-gray-400" />
          ) : (
            <ChevronRight size={14} className="text-gray-400" />
          )}
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-2 border-t border-gray-100 bg-slate-50/50 space-y-3">
          <p className="text-xs text-gray-600 leading-relaxed">{ctrl.description}</p>

          {/* Evidence panel */}
          {latestEvidence && (
            <div className="rounded-xl border border-gray-200 bg-white p-3 space-y-1.5 shadow-xs">
              <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">Latest Evidence</p>
              <div className="flex items-center gap-2">
                <EvidenceBadge status={latestEvidence.status} />
                <span className="text-xs text-gray-400 font-medium">
                  {latestEvidence.evidenceType === 'MANUAL' ? 'Manual' : 'Auto-collected'} ·{' '}
                  {new Date(latestEvidence.collectedAt).toLocaleDateString()}
                  {latestEvidence.expiresAt && ` · expires ${new Date(latestEvidence.expiresAt).toLocaleDateString()}`}
                </span>
              </div>
              <p className="text-xs text-gray-600">{latestEvidence.summary}</p>
            </div>
          )}

          <div>
            <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-1.5">
              Mapped Findings
            </p>
            <div className="flex flex-wrap gap-1.5">
              {ctrl.findingTitles.length === 0 ? (
                <span className="text-xs text-gray-400 italic">No findings mapped — cannot auto-evaluate</span>
              ) : (
                ctrl.findingTitles.map((title) => (
                  <span
                    key={title}
                    className="inline-flex items-center px-2 py-1 rounded-md text-xs bg-white border border-gray-200 text-gray-700 shadow-xs"
                  >
                    {title}
                  </span>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Collapsible Framework Accordion Card ──────────────────────────────────────

function FrameworkAccordionCard({
  fw,
  accountId,
  provider,
  searchQuery,
  statusFilter,
  forceExpanded,
}: {
  fw: FrameworkScore;
  accountId?: string;
  provider: 'AWS' | 'AZURE' | 'GCP';
  searchQuery: string;
  statusFilter: 'ALL' | 'FAIL' | 'PASS';
  forceExpanded: boolean | null;
}) {
  const c = FRAMEWORK_COLORS[fw.frameworkId] ?? { borderLeft: 'border-l-gray-400', bar: 'bg-gray-600' };
  
  // Default collapsed unless search query or forceExpanded toggle is active
  const [localExpanded, setLocalExpanded] = useState<boolean>(false);

  useEffect(() => {
    if (forceExpanded !== null) {
      setLocalExpanded(forceExpanded);
    }
  }, [forceExpanded]);

  const isExpanded = searchQuery ? true : localExpanded;

  // Tab filter inside expanded card: 'FAIL' | 'PASS' | 'NOT_EVALUATED' | 'ALL'
  const [activeTab, setActiveTab] = useState<'FAIL' | 'PASS' | 'NOT_EVALUATED' | 'ALL'>(
    fw.failingControls > 0 ? 'FAIL' : 'ALL'
  );

  // Sync top toolbar statusFilter to inner card activeTab
  useEffect(() => {
    if (statusFilter === 'PASS') setActiveTab('PASS');
    else if (statusFilter === 'FAIL') setActiveTab('FAIL');
    else if (statusFilter === 'ALL') setActiveTab(fw.failingControls > 0 ? 'FAIL' : 'ALL');
  }, [statusFilter, fw.failingControls]);

  const qc = useQueryClient();

  const collectMutation = useMutation({
    mutationFn: () => complianceApi.collectEvidence(accountId!, provider, fw.frameworkId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['evidence'] }),
  });

  // Filter controls inside card based on searchQuery and activeTab
  const visibleControls = useMemo(() => {
    return fw.controls.filter((ctrl) => {
      // Card active tab
      if (activeTab === 'FAIL' && ctrl.status !== 'FAIL') return false;
      if (activeTab === 'PASS' && ctrl.status !== 'PASS') return false;
      if (activeTab === 'NOT_EVALUATED' && ctrl.status !== 'NOT_EVALUATED') return false;

      // Search query
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          ctrl.name.toLowerCase().includes(q) ||
          ctrl.id.toLowerCase().includes(q) ||
          ctrl.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [fw.controls, activeTab, searchQuery]);

  const failCount = fw.controls.filter((c) => c.status === 'FAIL').length;
  const passCount = fw.controls.filter((c) => c.status === 'PASS').length;
  const naCount   = fw.controls.filter((c) => c.status === 'NOT_EVALUATED').length;

  if (searchQuery && visibleControls.length === 0) {
    return null; // Hide framework card if search has no matching controls
  }

  return (
    <Card padding={false} className={`border border-gray-200/90 rounded-2xl shadow-xs transition-all duration-200 bg-white ${c.borderLeft} border-l-4`}>
      
      {/* Accordion Header (Compact) */}
      <div
        onClick={() => setLocalExpanded((v) => !v)}
        className="px-4 py-2 sm:py-2.5 flex items-center justify-between bg-white hover:bg-slate-50/60 cursor-pointer select-none transition-colors rounded-t-2xl"
      >
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <h3 className="text-sm sm:text-base font-bold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
              {fw.shortName}
            </h3>
            <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider hidden sm:inline">
              {fw.frameworkName}
            </span>
          </div>
          <ScoreGauge score={fw.score} barClass={c.bar} />
        </div>

        <div className="flex items-center gap-3.5">
          {/* Right-aligned Icon Filter Tabs with Tooltips */}
          <div
            onClick={(e) => e.stopPropagation()}
            className="hidden md:flex items-center gap-1 transition-all duration-150"
          >
            {[
              {
                id: 'FAIL',
                tooltip: `Failing controls (${failCount})`,
                count: failCount,
                icon: <AlertCircle size={14} strokeWidth={2.2} className="text-red-600 shrink-0" />,
              },
              {
                id: 'PASS',
                tooltip: `Passing controls (${passCount})`,
                count: passCount,
                icon: <CheckCircle size={14} strokeWidth={2.2} className="text-emerald-600 shrink-0" />,
              },
              {
                id: 'NOT_EVALUATED',
                tooltip: `Not Evaluated controls (${naCount})`,
                count: naCount,
                icon: <HelpCircle size={14} strokeWidth={2.2} className="text-amber-500 shrink-0" />,
              },
              {
                id: 'ALL',
                tooltip: `All controls (${fw.totalControls})`,
                count: fw.totalControls,
                icon: <Layers size={14} strokeWidth={2.2} className="text-blue-600 shrink-0" />,
              },
            ].map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <Tooltip key={tab.id} content={tab.tooltip} position="top">
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTab(tab.id as any);
                      if (!isExpanded) setLocalExpanded(true);
                    }}
                    className={`px-2 py-1 rounded-lg text-xs font-bold flex items-center gap-1 transition-all whitespace-nowrap ${
                      isActive
                        ? 'bg-gray-100/90 text-gray-900 shadow-2xs ring-1 ring-gray-200'
                        : 'text-gray-500 hover:text-gray-800 hover:bg-gray-50'
                    }`}
                  >
                    {tab.icon}
                    <span>{tab.count}</span>
                  </button>
                </Tooltip>
              );
            })}
          </div>

          {accountId && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                collectMutation.mutate();
              }}
              disabled={collectMutation.isPending}
              title="Auto-collect evidence for this framework"
              className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold text-blue-600 bg-blue-50/80 hover:bg-blue-100 border border-blue-200/80 transition-colors disabled:opacity-50"
            >
              <FlaskConical size={13} />
              {collectMutation.isPending ? 'Collecting…' : 'Collect Evidence'}
            </button>
          )}

          <div className="p-1 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors">
            {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </div>
        </div>
      </div>

      {/* Accordion Body */}
      {isExpanded && (
        <div className="border-t border-gray-100">
          {collectMutation.isSuccess && (
            <div className="px-5 py-2 bg-emerald-50 border-b border-emerald-100 text-xs text-emerald-700 font-semibold">
              Evidence collected ✓
            </div>
          )}

          {/* Controls List */}
          <div className="p-4 space-y-2 max-h-[500px] overflow-y-auto">
            {visibleControls.length === 0 ? (
              <div className="py-6 text-center text-xs text-gray-400">
                No controls match the selected tab filter or search query.
              </div>
            ) : (
              visibleControls.map((ctrl) => (
                <ControlRow
                  key={ctrl.id}
                  ctrl={ctrl}
                  frameworkId={fw.frameworkId}
                  accountId={accountId}
                  provider={provider}
                />
              ))
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function AccountCompliance() {
  const { accountId, provider: providerParam } = useParams<{ accountId: string; provider?: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const queryProvider = searchParams.get('provider');
  const provider = ((queryProvider || providerParam)?.toUpperCase() as 'AWS' | 'AZURE' | 'GCP') ?? 'AWS';

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'FAIL' | 'PASS'>('ALL');
  const [forceExpanded, setForceExpanded] = useState<boolean | null>(null);

  const { data: allAccounts = [] } = useQuery({
    queryKey: ['compliance-all-accounts'],
    queryFn: complianceApi.getAllAccountsScores,
  });

  const currentAccount = useMemo(() => {
    return allAccounts.find(a => a.accountId === accountId || a.awsAccountId === accountId);
  }, [allAccounts, accountId]);

  const { data: frameworks = [], isLoading } = useQuery({
    queryKey: ['compliance', accountId],
    queryFn: () => complianceApi.getAccountScores(accountId!),
    enabled: !!accountId,
  });

  const overallScore =
    frameworks.length > 0
      ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length)
      : null;

  const totalPassing = frameworks.reduce((s, f) => s + f.passingControls, 0);
  const totalFailing = frameworks.reduce((s, f) => s + f.failingControls, 0);

  const accountDisplayName = currentAccount?.accountName || 'Account';

  return (
    <div className="space-y-6">
      
      {/* Redesigned Header Row: Back Button -> Provider Logo -> Account Title & Metadata -> Overall Score Card */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-1">
        
        {/* Left Section: Back Arrow -> Provider Logo -> Title -> Details Subtitle */}
        <div className="flex items-center gap-3.5">
          {/* 1. Back Button */}
          <Tooltip content="Back to Compliance Overview" position="right">
            <button
              onClick={() => navigate('/compliance')}
              className="p-2 text-gray-500 hover:text-gray-900 hover:bg-gray-100 rounded-xl transition-all shrink-0 -ml-1"
              aria-label="Back to Compliance Overview"
            >
              <ArrowLeft size={20} strokeWidth={2.2} />
            </button>
          </Tooltip>

          {/* Divider */}
          <div className="h-8 w-px bg-gray-200/80 shrink-0" />

          {/* 2. Provider Logo */}
          <div className="flex items-center justify-center p-2 rounded-xl bg-slate-50 border border-slate-200/80 shrink-0 shadow-2xs">
            <CloudProviderLogo provider={provider} className="w-6 h-6 shrink-0" />
          </div>

          {/* 3 & 4. Account Name & Account ID Subtitle */}
          <div className="space-y-0.5">
            <h1 className="text-xl sm:text-2xl font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
              {accountDisplayName}
            </h1>

            {/* Account Details Row */}
            <div className="flex items-center gap-1.5 text-xs text-gray-500">
              <span className="font-semibold text-gray-400">Account ID:</span>
              <span className="font-mono font-medium text-gray-700 bg-gray-100/90 border border-gray-200 px-2 py-0.5 rounded-md text-[11px] shadow-2xs">
                {currentAccount?.awsAccountId || accountId}
              </span>
            </div>
          </div>
        </div>

        {/* Right Section: Overall Score Card & Control Status Pills */}
        {overallScore !== null && (
          <div className="flex items-center gap-4 bg-white px-4 py-2.5 rounded-2xl border border-gray-200/90 shadow-xs shrink-0">
            <div className="flex items-center gap-3 pr-4 border-r border-gray-100">
              <span className={`text-3xl font-black tabular-nums ${scoreColor(overallScore)}`} style={{ fontFamily: 'var(--font-heading)' }}>
                {overallScore}%
              </span>
              <div className="text-left">
                <p className="text-xs font-bold text-gray-800 leading-none">Overall Score</p>
                <p className="text-[11px] text-gray-400 mt-1">{frameworks.length} Frameworks</p>
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs font-semibold">
              <span className="px-3 py-1 rounded-xl bg-emerald-50 text-emerald-700 border border-emerald-200/80 shadow-2xs">
                {totalPassing} Passing
              </span>
              <span className="px-3 py-1 rounded-xl bg-red-50 text-red-700 border border-red-200/80 shadow-2xs">
                {totalFailing} Failing
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Control Toolbar: Search + Status Filter + Expand All */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-white p-3 rounded-2xl border border-gray-200/90 shadow-xs">
        
        {/* Left: Search Bar */}
        <div className="w-full sm:w-80 relative">
          <Input
            type="text"
            placeholder="Search control name or ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            leftIcon={<Search size={15} />}
            className="w-full text-xs h-9 bg-gray-50/60 border-gray-200 focus:bg-white"
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

        {/* Right: Expand All / Collapse All Controls */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-gray-100 p-1 rounded-xl border border-gray-200/80 text-xs font-semibold">
            {[
              { id: 'ALL',  label: 'All Controls' },
              { id: 'FAIL', label: 'Failing Only' },
              { id: 'PASS', label: 'Passing Only' },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setStatusFilter(f.id as any)}
                className={`px-2.5 py-1 rounded-lg transition-all ${
                  statusFilter === f.id
                    ? 'bg-white text-blue-600 shadow-2xs'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => setForceExpanded((v) => (v === true ? false : true))}
            className="text-xs font-semibold text-gray-600 hover:bg-gray-100 border border-gray-200"
          >
            <ChevronsUpDown size={14} className="mr-1 text-gray-500" />
            {forceExpanded === true ? 'Collapse All' : 'Expand All'}
          </Button>
        </div>
      </div>

      {isLoading ? (
        <div className="py-16 text-center text-sm text-gray-400">Loading compliance data…</div>
      ) : frameworks.length === 0 ? (
        <Card className="py-16 text-center text-sm text-gray-400">
          No findings data available for this account.
        </Card>
      ) : (
        <div className="space-y-3">
          {frameworks.map((fw) => (
            <FrameworkAccordionCard
              key={fw.frameworkId}
              fw={fw}
              accountId={accountId}
              provider={provider}
              searchQuery={searchQuery}
              statusFilter={statusFilter}
              forceExpanded={forceExpanded}
            />
          ))}
        </div>
      )}
    </div>
  );
}

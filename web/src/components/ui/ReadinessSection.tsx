import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CheckCircle, AlertCircle, HelpCircle, ChevronDown, ChevronRight, X, ShieldCheck } from 'lucide-react';
import clsx from 'clsx';
import {
  complianceApi,
  type FrameworkScore,
  type AzureFrameworkScore,
  type FrameworkId,
  type AzureFrameworkId,
  type ControlResult,
  type AzureControlResult,
} from '../../api/compliance';

// ─── Circular SVG gauge ───────────────────────────────────────────────────────

const SIZE   = 68;
const RADIUS = 26;
const CIRC   = 2 * Math.PI * RADIUS;

function gaugeColor(score: number): string {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  return '#ef4444';
}

function CircularGauge({ score }: { score: number }) {
  const color  = gaugeColor(score);
  const offset = CIRC * (1 - score / 100);
  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`}>
        {/* track */}
        <circle cx={SIZE/2} cy={SIZE/2} r={RADIUS} fill="none" stroke="#f1f5f9" strokeWidth={6} />
        {/* progress */}
        <circle
          cx={SIZE/2} cy={SIZE/2} r={RADIUS} fill="none"
          stroke={color} strokeWidth={6}
          strokeDasharray={CIRC} strokeDashoffset={offset}
          strokeLinecap="round" transform={`rotate(-90 ${SIZE/2} ${SIZE/2})`}
          className="transition-all duration-500 ease-out"
        />
      </svg>
      <span className="absolute text-xs font-extrabold tabular-nums tracking-tight" style={{ color }}>
        {score}%
      </span>
    </div>
  );
}

// ─── Expandable control row ───────────────────────────────────────────────────

function ControlRow({ ctrl }: { ctrl: ControlResult | AzureControlResult }) {
  const [open, setOpen] = useState(false);
  const isPass = ctrl.status === 'PASS';
  const isFail = ctrl.status === 'FAIL';

  return (
    <div className="border border-gray-200/80 rounded-xl overflow-hidden bg-white hover:border-gray-300 transition-all shadow-2xs">
      <button
        className="w-full flex items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50/70 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        {/* Left: Icon + ID Badge + Control Name */}
        <div className="flex items-start gap-2.5 min-w-0 flex-1">
          {isPass ? (
            <CheckCircle size={16} className="text-emerald-500 mt-0.5 shrink-0" />
          ) : isFail ? (
            <AlertCircle size={16} className="text-red-500 mt-0.5 shrink-0" />
          ) : (
            <HelpCircle size={16} className="text-amber-500 mt-0.5 shrink-0" />
          )}

          <div className="flex items-center gap-2 flex-wrap min-w-0">
            <span className="font-mono text-xs font-semibold text-gray-600 bg-gray-100 border border-gray-200 px-1.5 py-0.5 rounded shrink-0">
              {ctrl.id}
            </span>
            <span className="text-xs sm:text-sm font-semibold text-gray-900 leading-snug">
              {ctrl.name}
            </span>
          </div>
        </div>

        {/* Right: Findings Badge & Chevron */}
        <div className="flex items-center gap-2 shrink-0 ml-2">
          {isFail && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold bg-red-50 text-red-700 border border-red-200/80 shadow-2xs whitespace-nowrap">
              {ctrl.failingFindings} finding{ctrl.failingFindings !== 1 ? 's' : ''}
            </span>
          )}
          {ctrl.status === 'NOT_EVALUATED' && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-gray-100 text-gray-500 border border-gray-200/80 whitespace-nowrap">
              not evaluated
            </span>
          )}
          <div className="p-1 rounded-lg text-gray-400 hover:text-gray-600">
            {open ? (
              <ChevronDown size={14} className="text-blue-600" />
            ) : (
              <ChevronRight size={14} />
            )}
          </div>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-3 border-t border-gray-100 bg-slate-50/70 space-y-3">
          <p className="text-xs text-gray-700 leading-relaxed font-normal">{ctrl.description}</p>
          {ctrl.findingTitles.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                Mapped Findings
              </p>
              <div className="flex flex-wrap gap-1.5">
                {ctrl.findingTitles.map((t) => (
                  <span
                    key={t}
                    className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-white border border-gray-200 text-gray-800 shadow-2xs"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Framework detail modal ───────────────────────────────────────────────────

function FrameworkModal({
  fw,
  onClose,
}: {
  fw: FrameworkScore | AzureFrameworkScore;
  onClose: () => void;
}) {
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'PASS' | 'FAIL' | 'NOT_EVALUATED'>('ALL');

  const fail = fw.controls.filter((x) => x.status === 'FAIL');
  const pass = fw.controls.filter((x) => x.status === 'PASS');
  const na   = fw.controls.filter((x) => x.status === 'NOT_EVALUATED');

  const showFail = (filterStatus === 'ALL' || filterStatus === 'FAIL') && fail.length > 0;
  const showPass = (filterStatus === 'ALL' || filterStatus === 'PASS') && pass.length > 0;
  const showNa   = (filterStatus === 'ALL' || filterStatus === 'NOT_EVALUATED') && na.length > 0;

  const toggleFilter = (status: 'PASS' | 'FAIL' | 'NOT_EVALUATED') => {
    setFilterStatus((prev) => (prev === status ? 'ALL' : status));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop with blur */}
      <div className="absolute inset-0 bg-slate-900/40 backdrop-blur-xs transition-opacity" onClick={onClose} />

      <div className="relative bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[85vh] flex flex-col overflow-hidden border border-gray-200/90 animate-in fade-in-50 zoom-in-95 duration-150">

        {/* Clean White Header */}
        <div className="px-6 py-4 border-b border-gray-200/80 flex items-center justify-between bg-white shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-50 border border-blue-200/80 text-blue-600 shadow-2xs">
              <ShieldCheck size={20} />
            </div>
            <div>
              <h2 className="text-lg font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
                {fw.shortName}
              </h2>
              <p className="text-xs text-gray-500 font-medium">
                {fw.frameworkName}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 bg-slate-50 border border-slate-200/80 px-3 py-1.5 rounded-xl shadow-2xs">
              <span className="text-xs font-semibold text-gray-500">Readiness Score:</span>
              <span className={`text-base font-extrabold tabular-nums ${
                fw.score >= 80 ? 'text-emerald-600' : fw.score >= 60 ? 'text-amber-500' : 'text-red-600'
              }`}>
                {fw.score}%
              </span>
            </div>

            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-gray-900 hover:bg-gray-100 rounded-xl transition-all"
              aria-label="Close modal"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Interactive Stats Pill Strip */}
        <div className="px-6 py-2.5 border-b border-gray-100 flex items-center gap-2 text-xs bg-slate-50/80 shrink-0 flex-wrap select-none">
          <button
            type="button"
            onClick={() => toggleFilter('PASS')}
            className={clsx(
              'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer shadow-2xs',
              filterStatus === 'PASS'
                ? 'bg-emerald-600 text-white ring-2 ring-emerald-500/40 shadow-sm scale-[1.02]'
                : 'bg-emerald-50 text-emerald-700 border border-emerald-200/80 hover:bg-emerald-100/80'
            )}
          >
            <CheckCircle size={13} className={filterStatus === 'PASS' ? 'text-white' : 'text-emerald-500'} />
            {fw.passingControls} Passing
          </button>

          <button
            type="button"
            onClick={() => toggleFilter('FAIL')}
            className={clsx(
              'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold transition-all cursor-pointer shadow-2xs',
              filterStatus === 'FAIL'
                ? 'bg-red-600 text-white ring-2 ring-red-500/40 shadow-sm scale-[1.02]'
                : 'bg-red-50 text-red-700 border border-red-200/80 hover:bg-red-100/80'
            )}
          >
            <AlertCircle size={13} className={filterStatus === 'FAIL' ? 'text-white' : 'text-red-500'} />
            {fw.failingControls} Failing
          </button>

          {fw.notEvaluatedControls > 0 && (
            <button
              type="button"
              onClick={() => toggleFilter('NOT_EVALUATED')}
              className={clsx(
                'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium transition-all cursor-pointer shadow-2xs',
                filterStatus === 'NOT_EVALUATED'
                  ? 'bg-gray-700 text-white ring-2 ring-gray-400/40 shadow-sm scale-[1.02]'
                  : 'bg-gray-100 text-gray-600 border border-gray-200/80 hover:bg-gray-200/80'
              )}
            >
              <HelpCircle size={13} className={filterStatus === 'NOT_EVALUATED' ? 'text-white' : 'text-gray-400'} />
              {fw.notEvaluatedControls} Not Evaluated
            </button>
          )}

          <button
            type="button"
            onClick={() => setFilterStatus('ALL')}
            className={clsx(
              'ml-auto text-xs font-semibold px-2.5 py-1 rounded-lg transition-all cursor-pointer',
              filterStatus === 'ALL'
                ? 'text-blue-700 font-bold bg-blue-50 border border-blue-200/80'
                : 'text-gray-500 hover:text-gray-800 hover:bg-gray-200/60'
            )}
          >
            {filterStatus !== 'ALL' ? 'Show All Controls' : `${fw.totalControls} Total Controls`}
          </button>
        </div>

        {/* Controls Scrollable List */}
        <div className="overflow-y-auto flex-1 p-5 space-y-4 bg-gray-50/30">
          {!showFail && !showPass && !showNa && (
            <div className="text-center py-8 text-xs text-gray-400">
              No controls match the selected status filter.
            </div>
          )}

          {showFail && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-extrabold text-red-600 uppercase tracking-wider px-1">
                <AlertCircle size={13} />
                <span>Failing Controls ({fail.length})</span>
              </div>
              <div className="space-y-2">
                {fail.map((ctrl) => <ControlRow key={ctrl.id} ctrl={ctrl} />)}
              </div>
            </div>
          )}

          {showPass && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-extrabold text-emerald-600 uppercase tracking-wider px-1 pt-2">
                <CheckCircle size={13} />
                <span>Passing Controls ({pass.length})</span>
              </div>
              <div className="space-y-2">
                {pass.map((ctrl) => <ControlRow key={ctrl.id} ctrl={ctrl} />)}
              </div>
            </div>
          )}

          {showNa && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-extrabold text-gray-400 uppercase tracking-wider px-1 pt-2">
                <HelpCircle size={13} />
                <span>Not Evaluated ({na.length})</span>
              </div>
              <div className="space-y-2">
                {na.map((ctrl) => <ControlRow key={ctrl.id} ctrl={ctrl} />)}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Gauge card ───────────────────────────────────────────────────────────────

function GaugeCard({
  fw,
  onClick,
}: {
  fw: FrameworkScore | AzureFrameworkScore;
  onClick: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className="bg-white rounded-xl border border-gray-200/90 p-3.5 flex flex-col items-center justify-between text-center hover:border-blue-400 hover:shadow-md hover:bg-blue-50/20 transition-all duration-200 cursor-pointer group space-y-2.5 h-full"
    >
      <CircularGauge score={fw.score} />

      <div className="space-y-0.5 w-full">
        <p className="text-xs font-bold text-gray-900 truncate tracking-tight group-hover:text-blue-600 transition-colors">
          {fw.shortName}
        </p>
        <p className="text-[10px] text-gray-400 font-medium whitespace-nowrap">
          {fw.passingControls}/{fw.totalControls} passed
        </p>
      </div>

      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          onClick();
        }}
        className="w-full inline-flex items-center justify-center gap-0.5 text-[11px] font-semibold text-blue-600 group-hover:text-blue-700 bg-blue-50/80 group-hover:bg-blue-100/90 border border-blue-200/80 rounded-md py-1 transition-all shadow-2xs mt-auto"
      >
        <span>View</span>
        <ChevronRight size={11} className="transition-transform duration-200 group-hover:translate-x-0.5" />
      </button>
    </div>
  );
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function ReadinessSkeleton({ count = 8 }: { count?: number }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200/90 p-4 space-y-4 shadow-2xs">
      <div className="h-5 w-56 bg-gray-100 rounded animate-pulse" />
      <div className="grid grid-cols-4 sm:grid-cols-8 gap-2.5">
        {[...Array(count)].map((_, i) => (
          <div key={i} className="h-40 bg-gray-100/80 rounded-xl animate-pulse" />
        ))}
      </div>
    </div>
  );
}

// ─── AWS Readiness Section ────────────────────────────────────────────────────

const AWS_ORDER: FrameworkId[] = ['CIS_AWS', 'PCI_DSS', 'SOC2', 'ISO27001', 'HIPAA', 'NIST_800_53', 'GDPR', 'FEDRAMP'];

export function AwsReadinessSection({ accountId }: { accountId: string }) {
  const [active, setActive] = useState<FrameworkScore | null>(null);

  const { data: frameworks, isLoading, isError } = useQuery({
    queryKey: ['compliance', accountId],
    queryFn:  () => complianceApi.getAccountScores(accountId),
    enabled:  !!accountId,
  });

  if (isLoading) return <ReadinessSkeleton count={8} />;

  if (isError || !frameworks || frameworks.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200/90 p-6 text-center shadow-2xs">
        <p className="text-sm font-semibold text-gray-700 mb-1">Readiness for Other Audits</p>
        <p className="text-xs text-gray-400">Run a scan to generate compliance readiness scores.</p>
      </div>
    );
  }

  const ordered = AWS_ORDER
    .map((id) => frameworks.find((f) => f.frameworkId === id))
    .filter(Boolean) as FrameworkScore[];

  return (
    <>
      <div className="bg-white rounded-xl border border-gray-200/90 p-4 space-y-3.5 shadow-2xs">
        <div className="flex items-center justify-between pb-2 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-blue-50 border border-blue-200/80 text-blue-600 shadow-2xs">
              <ShieldCheck size={16} />
            </div>
            <div>
              <h3 className="text-sm font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
                Readiness for Other Audits
              </h3>
            </div>
          </div>
          <span className="text-xs text-gray-400 font-medium">
            {ordered.length} Frameworks Mapped
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2.5">
          {ordered.map((fw) => (
            <GaugeCard key={fw.frameworkId} fw={fw} onClick={() => setActive(fw)} />
          ))}
        </div>
      </div>
      {active && <FrameworkModal fw={active} onClose={() => setActive(null)} />}
    </>
  );
}

// ─── Azure Readiness Section ──────────────────────────────────────────────────

const AZURE_ORDER: AzureFrameworkId[] = ['CIS_AZURE', 'NIST', 'ISO27001', 'SOC2', 'HIPAA'];

export function AzureReadinessSection({ subscriptionId }: { subscriptionId: string }) {
  const [active, setActive] = useState<AzureFrameworkScore | null>(null);

  const { data: frameworks, isLoading, isError } = useQuery({
    queryKey: ['azure-compliance', subscriptionId],
    queryFn:  () => complianceApi.getAzureSubscriptionScores(subscriptionId),
    enabled:  !!subscriptionId,
  });

  if (isLoading) return <ReadinessSkeleton count={5} />;

  if (isError || !frameworks || frameworks.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200/90 p-6 text-center shadow-2xs">
        <p className="text-sm font-semibold text-gray-700 mb-1">Readiness for Other Audits</p>
        <p className="text-xs text-gray-400">Run a scan to generate compliance readiness scores.</p>
      </div>
    );
  }

  const ordered = AZURE_ORDER
    .map((id) => frameworks.find((f) => f.frameworkId === id))
    .filter(Boolean) as AzureFrameworkScore[];

  return (
    <>
      <div className="bg-white rounded-xl border border-gray-200/90 p-4 space-y-3.5 shadow-2xs">
        <div className="flex items-center justify-between pb-2 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-blue-50 border border-blue-200/80 text-blue-600 shadow-2xs">
              <ShieldCheck size={16} />
            </div>
            <div>
              <h3 className="text-sm font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
                Readiness for Other Audits
              </h3>
            </div>
          </div>
          <span className="text-xs text-gray-400 font-medium">
            {ordered.length} Frameworks Mapped
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          {ordered.map((fw) => (
            <GaugeCard key={fw.frameworkId} fw={fw} onClick={() => setActive(fw)} />
          ))}
        </div>
      </div>
      {active && <FrameworkModal fw={active} onClose={() => setActive(null)} />}
    </>
  );
}

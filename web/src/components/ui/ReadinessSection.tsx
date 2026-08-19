import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CheckCircle, AlertCircle, HelpCircle, ChevronDown, ChevronRight, X } from 'lucide-react';
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

const SIZE   = 110;
const RADIUS = 44;
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
        <circle cx={SIZE/2} cy={SIZE/2} r={RADIUS} fill="none" stroke="#e5e7eb" strokeWidth={9} />
        {/* progress */}
        <circle
          cx={SIZE/2} cy={SIZE/2} r={RADIUS} fill="none"
          stroke={color} strokeWidth={9}
          strokeDasharray={CIRC} strokeDashoffset={offset}
          strokeLinecap="round" transform={`rotate(-90 ${SIZE/2} ${SIZE/2})`}
        />
      </svg>
      <span className="absolute text-base font-bold tabular-nums" style={{ color }}>
        {score}%
      </span>
    </div>
  );
}

// ─── Expandable control row ───────────────────────────────────────────────────

function ControlRow({ ctrl }: { ctrl: ControlResult | AzureControlResult }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        {ctrl.status === 'PASS'
          ? <CheckCircle size={15} className="text-emerald-500 mt-0.5 shrink-0" />
          : ctrl.status === 'FAIL'
          ? <AlertCircle size={15} className="text-red-500 mt-0.5 shrink-0" />
          : <HelpCircle  size={15} className="text-amber-500 mt-0.5 shrink-0" />
        }
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-gray-400">{ctrl.id}</span>
            <span className="text-sm font-medium text-gray-800">{ctrl.name}</span>
            {ctrl.status === 'FAIL' && (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700 ring-1 ring-red-200">
                {ctrl.failingFindings} finding{ctrl.failingFindings !== 1 ? 's' : ''}
              </span>
            )}
            {ctrl.status === 'NOT_EVALUATED' && (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-50 text-gray-400 ring-1 ring-gray-200">
                not evaluated
              </span>
            )}
          </div>
        </div>
        {open
          ? <ChevronDown  size={13} className="text-gray-400 shrink-0 mt-0.5" />
          : <ChevronRight size={13} className="text-gray-400 shrink-0 mt-0.5" />
        }
      </button>
      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-100 bg-gray-50/60 space-y-2">
          <p className="text-xs text-gray-600">{ctrl.description}</p>
          {ctrl.findingTitles.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
                Mapped Findings
              </p>
              <div className="flex flex-wrap gap-1.5">
                {ctrl.findingTitles.map((t) => (
                  <span
                    key={t}
                    className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-white ring-1 ring-gray-200 text-gray-700"
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

const FW_COLORS: Record<string, { bar: string; header: string }> = {
  PCI_DSS:     { bar: 'bg-blue-500',    header: 'bg-blue-600'    },
  SOC2:        { bar: 'bg-violet-500',  header: 'bg-violet-600'  },
  ISO27001:    { bar: 'bg-emerald-500', header: 'bg-emerald-600' },
  HIPAA:       { bar: 'bg-orange-500',  header: 'bg-orange-600'  },
  CIS_AWS:     { bar: 'bg-cyan-500',    header: 'bg-cyan-600'    },
  CIS_AZURE:   { bar: 'bg-blue-500',    header: 'bg-blue-600'    },
  NIST:        { bar: 'bg-slate-500',   header: 'bg-slate-600'   },
  NIST_800_53: { bar: 'bg-slate-600',   header: 'bg-slate-700'   },
  GDPR:        { bar: 'bg-purple-500',  header: 'bg-purple-600'  },
  FEDRAMP:     { bar: 'bg-rose-500',    header: 'bg-rose-600'    },
};

function FrameworkModal({
  fw,
  onClose,
}: {
  fw: FrameworkScore | AzureFrameworkScore;
  onClose: () => void;
}) {
  const c    = FW_COLORS[fw.frameworkId] ?? { bar: 'bg-gray-500', header: 'bg-gray-600' };
  const fail = fw.controls.filter((x) => x.status === 'FAIL');
  const pass = fw.controls.filter((x) => x.status === 'PASS');
  const na   = fw.controls.filter((x) => x.status === 'NOT_EVALUATED');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative bg-white rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden">

        {/* header */}
        <div className={`${c.header} px-6 py-4 flex items-center justify-between shrink-0`}>
          <div>
            <p className="text-white text-xs font-medium opacity-75">{fw.frameworkName}</p>
            <p className="text-white text-xl font-bold">{fw.shortName}</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-white text-3xl font-bold">{fw.score}%</p>
              <div className="mt-1 w-24 h-1.5 bg-white/30 rounded-full overflow-hidden">
                <div className={`h-full ${c.bar} rounded-full`} style={{ width: `${fw.score}%` }} />
              </div>
            </div>
            <button onClick={onClose} className="text-white/80 hover:text-white transition-colors ml-2">
              <X size={20} />
            </button>
          </div>
        </div>

        {/* stats strip */}
        <div className="px-6 py-3 border-b border-gray-100 flex gap-6 text-xs bg-gray-50 shrink-0">
          <span><strong className="text-emerald-600">{fw.passingControls}</strong><span className="text-gray-500"> passing</span></span>
          <span><strong className="text-red-500">{fw.failingControls}</strong><span className="text-gray-500"> failing</span></span>
          {fw.notEvaluatedControls > 0 && (
            <span><strong className="text-gray-400">{fw.notEvaluatedControls}</strong><span className="text-gray-400"> not evaluated</span></span>
          )}
          <span><strong className="text-gray-700">{fw.totalControls}</strong><span className="text-gray-500"> total</span></span>
        </div>

        {/* controls */}
        <div className="overflow-y-auto flex-1 p-4 space-y-2">
          {fail.length > 0 && (
            <p className="text-xs font-semibold text-red-500 uppercase tracking-wide mb-1">Failing Controls</p>
          )}
          {fail.map((ctrl) => <ControlRow key={ctrl.id} ctrl={ctrl} />)}

          {pass.length > 0 && (
            <p className="text-xs font-semibold text-emerald-600 uppercase tracking-wide mt-4 mb-1">Passing Controls</p>
          )}
          {pass.map((ctrl) => <ControlRow key={ctrl.id} ctrl={ctrl} />)}

          {na.length > 0 && (
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mt-4 mb-1">Not Evaluated</p>
          )}
          {na.map((ctrl) => <ControlRow key={ctrl.id} ctrl={ctrl} />)}
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
    <div className="flex flex-col items-center gap-2 w-36">
      <CircularGauge score={fw.score} />
      <p className="text-sm text-gray-500 text-center font-medium tracking-wide">
        {fw.shortName}
      </p>
      <p className="text-xl font-bold text-gray-900">{fw.score}%</p>
      <button
        onClick={onClick}
        className="text-xs text-blue-600 border border-blue-300 rounded-full px-4 py-1 hover:bg-blue-50 transition-colors whitespace-nowrap"
      >
        View Readiness
      </button>
    </div>
  );
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function ReadinessSkeleton({ count = 5 }: { count?: number }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-8">
      <div className="h-4 w-52 bg-gray-100 rounded animate-pulse mb-8 mx-auto" />
      <div className="flex justify-center gap-10 flex-wrap">
        {[...Array(count)].map((_, i) => (
          <div key={i} className="flex flex-col items-center gap-2 w-36">
            <div className="rounded-full bg-gray-100 animate-pulse" style={{ width: SIZE, height: SIZE }} />
            <div className="h-3 w-16 bg-gray-100 rounded animate-pulse" />
            <div className="h-6 w-12 bg-gray-100 rounded animate-pulse" />
            <div className="h-6 w-28 bg-gray-100 rounded-full animate-pulse" />
          </div>
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

  if (isLoading) return <ReadinessSkeleton count={5} />;

  if (isError || !frameworks || frameworks.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200 p-8 text-center">
        <p className="text-sm font-semibold text-gray-700 mb-2">Readiness for Other Audits</p>
        <p className="text-sm text-gray-400">Run a scan to generate compliance readiness scores.</p>
      </div>
    );
  }

  const ordered = AWS_ORDER
    .map((id) => frameworks.find((f) => f.frameworkId === id))
    .filter(Boolean) as FrameworkScore[];

  return (
    <>
      <div className="bg-white rounded-xl border border-gray-200 p-8">
        <p className="text-base font-semibold text-gray-800 mb-8 text-center">Readiness for Other Audits</p>
        <div className="flex justify-center flex-wrap gap-10">
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
      <div className="bg-white rounded-xl border border-gray-200 p-8 text-center">
        <p className="text-sm font-semibold text-gray-700 mb-2">Readiness for Other Audits</p>
        <p className="text-sm text-gray-400">Run a scan to generate compliance readiness scores.</p>
      </div>
    );
  }

  const ordered = AZURE_ORDER
    .map((id) => frameworks.find((f) => f.frameworkId === id))
    .filter(Boolean) as AzureFrameworkScore[];

  return (
    <>
      <div className="bg-white rounded-xl border border-gray-200 p-8">
        <p className="text-base font-semibold text-gray-800 mb-8 text-center">Readiness for Other Audits</p>
        <div className="flex justify-center flex-wrap gap-10">
          {ordered.map((fw) => (
            <GaugeCard key={fw.frameworkId} fw={fw} onClick={() => setActive(fw)} />
          ))}
        </div>
      </div>
      {active && <FrameworkModal fw={active} onClose={() => setActive(null)} />}
    </>
  );
}

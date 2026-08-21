import { useMemo } from 'react';
import type { AccountComplianceSummary, AzureSubscriptionComplianceSummary } from '../../api/compliance';

// ─── Framework Gauge Chart ────────────────────────────────────────────────────
// Shared by the Compliance tab (Cloud Security) and the Reports tab (Operations)
// so both surfaces show the exact same "Framework Score Overview" — same data,
// same math, same visual, one component.

const G_SIZE = 84;
const G_R    = 32;
const G_CIRC = 2 * Math.PI * G_R;

function gaugeStroke(score: number): { stroke: string; bg: string; text: string; status: string; cardBorder: string } {
  if (score >= 80) {
    return { stroke: '#10b981', bg: 'bg-emerald-50', text: 'text-emerald-700', status: 'Good', cardBorder: 'border-emerald-200/80 hover:border-emerald-300' };
  }
  if (score >= 60) {
    return { stroke: '#f59e0b', bg: 'bg-amber-50', text: 'text-amber-700', status: 'Fair', cardBorder: 'border-amber-200/80 hover:border-amber-300' };
  }
  return { stroke: '#ef4444', bg: 'bg-red-50', text: 'text-red-700', status: 'At Risk', cardBorder: 'border-red-200/90 hover:border-red-300' };
}

const FRAMEWORK_NAME_TO_ID: Record<string, string> = {
  'PCI DSS': 'PCI_DSS',
  'SOC 2': 'SOC2',
  'ISO 27001': 'ISO27001',
  'HIPAA': 'HIPAA',
  'CIS AWS': 'CIS_AWS',
  'NIST 800-53': 'NIST_800_53',
  'GDPR': 'GDPR',
  'FedRAMP': 'FEDRAMP',
  'CIS Azure': 'CIS_AZURE',
  'NIST': 'NIST',
  'CIS GCP': 'CIS_GCP',
};

function FrameworkGauge({
  name,
  avg,
  count,
  onClick,
}: {
  name: string;
  avg: number;
  count: number;
  onClick?: () => void;
}) {
  const cfg = gaugeStroke(avg);
  const offset = G_CIRC * (1 - avg / 100);
  return (
    <div
      onClick={onClick}
      className={`bg-slate-50/60 hover:bg-white border ${cfg.cardBorder} rounded-xl p-3.5 flex flex-col items-center hover:-translate-y-1 hover:shadow-md transition-all duration-200 group cursor-pointer min-w-[124px] flex-1`}
    >
      <div className="relative inline-flex items-center justify-center mb-2">
        <svg width={G_SIZE} height={G_SIZE} viewBox={`0 0 ${G_SIZE} ${G_SIZE}`} className="transform -rotate-90">
          <circle cx={G_SIZE / 2} cy={G_SIZE / 2} r={G_R} fill="none" stroke="#f1f5f9" strokeWidth={7} />
          <circle
            cx={G_SIZE / 2} cy={G_SIZE / 2} r={G_R} fill="none"
            stroke={cfg.stroke} strokeWidth={7}
            strokeDasharray={G_CIRC} strokeDashoffset={offset}
            strokeLinecap="round" className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className="text-base font-bold tabular-nums text-gray-900 leading-none" style={{ fontFamily: 'var(--font-heading)' }}>
            {avg}%
          </span>
        </div>
      </div>
      <p className="text-xs font-bold text-gray-800 text-center leading-tight mb-1 group-hover:text-blue-600 transition-colors" style={{ fontFamily: 'var(--font-heading)' }}>
        {name}
      </p>
      <div className="flex items-center gap-1.5 mt-0.5">
        <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${cfg.bg} ${cfg.text}`}>
          {cfg.status}
        </span>
        <span className="text-[10px] text-gray-400 font-medium">
          ({count})
        </span>
      </div>
    </div>
  );
}

export interface FrameworkGaugeDatum {
  name:  string;
  avg:   number;
  count: number;
}

/** Per-framework average score across every AWS account + Azure subscription. */
export function computeFrameworkGauges(
  awsAccounts: AccountComplianceSummary[],
  azureSubs:   AzureSubscriptionComplianceSummary[],
): FrameworkGaugeDatum[] {
  const map = new Map<string, { total: number; count: number }>();
  for (const acct of awsAccounts) {
    for (const f of acct.scores) {
      if (f.passingControls > 0 || f.score > 0) {
        const key = f.shortName;
        const prev = map.get(key) ?? { total: 0, count: 0 };
        map.set(key, { total: prev.total + f.score, count: prev.count + 1 });
      }
    }
  }
  for (const sub of azureSubs) {
    for (const f of sub.scores) {
      if (f.passingControls > 0 || f.score > 0) {
        const key = f.shortName;
        const prev = map.get(key) ?? { total: 0, count: 0 };
        map.set(key, { total: prev.total + f.score, count: prev.count + 1 });
      }
    }
  }
  return Array.from(map.entries())
    .filter(([name]) => !['CIS Azure', 'NIST', 'CIS GCP'].includes(name))
    .map(([name, { total, count }]) => ({ name, avg: Math.round(total / count), count }))
    .sort((a, b) => b.avg - a.avg);
}

interface FrameworkScoreOverviewProps {
  awsAccounts: AccountComplianceSummary[];
  azureSubs:   AzureSubscriptionComplianceSummary[];
  onSelectFramework?: (frameworkId: string) => void;
  /** Optional — pass through className to adjust spacing in the host page. */
  className?: string;
}

/**
 * "Framework Score Overview" card — average compliance score per framework
 * (CIS, PCI DSS, SOC 2, ISO 27001, HIPAA, NIST, GDPR, FedRAMP) across every
 * scanned AWS account and Azure subscription. Renders nothing when there's no
 * compliance data yet (matches the empty-state behavior both host pages want).
 */
export function FrameworkScoreOverview({ awsAccounts, azureSubs, onSelectFramework, className }: FrameworkScoreOverviewProps) {
  const frameworkGauges = useMemo(
    () => computeFrameworkGauges(awsAccounts, azureSubs),
    [awsAccounts, azureSubs],
  );

  if (frameworkGauges.length === 0) return null;

  return (
    <div className={`bg-white border border-gray-200/90 rounded-2xl p-5 shadow-xs ${className ?? ''}`}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-bold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
            Framework Score Overview
          </h3>
          <p className="text-xs text-gray-500 mt-0.5">Average compliance posture across all accounts & subscriptions</p>
        </div>
        <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-gray-100 text-gray-600 border border-gray-200">
          {frameworkGauges.length} Frameworks
        </span>
      </div>
      <div className="flex w-full overflow-x-auto gap-3 pb-2 snap-x">
        {frameworkGauges.map(({ name, avg, count }) => {
          const fwId = FRAMEWORK_NAME_TO_ID[name] ?? name;
          return (
            <FrameworkGauge
              key={name}
              name={name}
              avg={avg}
              count={count}
              onClick={() => onSelectFramework?.(fwId)}
            />
          );
        })}
      </div>
    </div>
  );
}

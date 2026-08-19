import { useMemo } from 'react';
import type { AccountComplianceSummary, AzureSubscriptionComplianceSummary } from '../../api/compliance';

// ─── Framework Gauge Chart ────────────────────────────────────────────────────
// Shared by the Compliance tab (Cloud Security) and the Reports tab (Operations)
// so both surfaces show the exact same "Framework Score Overview" — same data,
// same math, same visual, one component.

const G_SIZE = 96;
const G_R    = 36;
const G_CIRC = 2 * Math.PI * G_R;

function gaugeStroke(score: number): string {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  return '#ef4444';
}

function FrameworkGauge({ name, avg, count }: { name: string; avg: number; count: number }) {
  const color  = gaugeStroke(avg);
  const offset = G_CIRC * (1 - avg / 100);
  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative inline-flex items-center justify-center">
        <svg width={G_SIZE} height={G_SIZE} viewBox={`0 0 ${G_SIZE} ${G_SIZE}`}>
          <circle cx={G_SIZE / 2} cy={G_SIZE / 2} r={G_R} fill="none" stroke="#e5e7eb" strokeWidth={8} />
          <circle
            cx={G_SIZE / 2} cy={G_SIZE / 2} r={G_R} fill="none"
            stroke={color} strokeWidth={8}
            strokeDasharray={G_CIRC} strokeDashoffset={offset}
            strokeLinecap="round" transform={`rotate(-90 ${G_SIZE / 2} ${G_SIZE / 2})`}
          />
        </svg>
        <span className="absolute text-sm font-bold tabular-nums" style={{ color }}>{avg}%</span>
      </div>
      <p className="text-xs font-semibold text-gray-700 text-center leading-tight">{name}</p>
      <p className="text-[10px] text-gray-400">{count} account{count !== 1 ? 's' : ''}</p>
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
      const key = f.shortName;
      const prev = map.get(key) ?? { total: 0, count: 0 };
      map.set(key, { total: prev.total + f.score, count: prev.count + 1 });
    }
  }
  for (const sub of azureSubs) {
    for (const f of sub.scores) {
      const key = f.shortName;
      const prev = map.get(key) ?? { total: 0, count: 0 };
      map.set(key, { total: prev.total + f.score, count: prev.count + 1 });
    }
  }
  return Array.from(map.entries())
    .map(([name, { total, count }]) => ({ name, avg: Math.round(total / count), count }))
    .sort((a, b) => b.avg - a.avg);
}

interface FrameworkScoreOverviewProps {
  awsAccounts: AccountComplianceSummary[];
  azureSubs:   AzureSubscriptionComplianceSummary[];
  /** Optional — pass through className to adjust spacing in the host page. */
  className?: string;
}

export function FrameworkScoreOverview({ awsAccounts, azureSubs, className }: FrameworkScoreOverviewProps) {
  const frameworkGauges = useMemo(
    () => computeFrameworkGauges(awsAccounts, azureSubs),
    [awsAccounts, azureSubs],
  );

  if (frameworkGauges.length === 0) return null;

  return (
    <div className={`bg-white border border-gray-200 rounded-lg px-6 py-4 ${className ?? ''}`}>
      <p className="text-sm font-semibold text-gray-800 mb-4">
        Framework Score Overview
        <span className="ml-2 text-xs font-normal text-gray-400">average across all accounts</span>
      </p>
      <div className="flex flex-wrap gap-6 justify-start">
        {frameworkGauges.map(({ name, avg, count }) => (
          <FrameworkGauge key={name} name={name} avg={avg} count={count} />
        ))}
      </div>
    </div>
  );
}

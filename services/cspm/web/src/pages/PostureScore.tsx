import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, RefreshCw, TrendingUp, TrendingDown, Minus, AlertTriangle } from 'lucide-react';
import { postureApi, type PostureScore as PostureScoreType, type PostureHistoryPoint } from '../api/enterprise';

// ─── Grade ring ───────────────────────────────────────────────────────────────

const GRADE_COLORS: Record<string, { ring: string; text: string; bg: string; label: string }> = {
  A: { ring: '#22c55e', text: 'text-green-700',  bg: 'bg-green-50',  label: 'Excellent' },
  B: { ring: '#3b82f6', text: 'text-blue-700',   bg: 'bg-blue-50',   label: 'Good' },
  C: { ring: '#f59e0b', text: 'text-yellow-700', bg: 'bg-yellow-50', label: 'Fair' },
  D: { ring: '#f97316', text: 'text-orange-700', bg: 'bg-orange-50', label: 'Poor' },
  F: { ring: '#ef4444', text: 'text-red-700',    bg: 'bg-red-50',    label: 'Critical' },
};

function ScoreGauge({ score, grade }: { score: number; grade: string }) {
  const color  = GRADE_COLORS[grade] ?? GRADE_COLORS['F'];
  const radius = 52;
  const circ   = 2 * Math.PI * radius;
  const dash   = (score / 100) * circ;

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="140" className="-rotate-90">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="12" />
        <circle
          cx="70" cy="70" r={radius} fill="none"
          stroke={color.ring} strokeWidth="12"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
      <div className="mt-[-100px] text-center mb-[60px]">
        <span className="text-3xl font-bold text-gray-900">{score}</span>
        <span className={`ml-1 text-xl font-bold ${color.text}`}>{grade}</span>
      </div>
      <span className={`text-xs font-semibold px-3 py-1 rounded-full ${color.bg} ${color.text}`}>
        {color.label}
      </span>
    </div>
  );
}

// ─── Penalty breakdown bars ───────────────────────────────────────────────────

function PenaltyBar({ label, count, penalty, maxPenalty, color }: {
  label: string; count: number; penalty: number; maxPenalty: number; color: string;
}) {
  const pct = maxPenalty > 0 ? (penalty / maxPenalty) * 100 : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs text-gray-600">
        <span>{label} <span className="text-gray-400">({count})</span></span>
        <span className="font-medium text-gray-700">−{penalty} pts</span>
      </div>
      <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%`, transition: 'width 0.5s ease' }} />
      </div>
    </div>
  );
}

// ─── Mini sparkline ───────────────────────────────────────────────────────────

function Sparkline({ points }: { points: PostureHistoryPoint[] }) {
  if (points.length < 2) return null;

  const scores = points.map((p) => p.score);
  const min    = Math.min(...scores);
  const max    = Math.max(...scores);
  const range  = max - min || 1;
  const W = 200; const H = 50;

  const pts = scores.map((s, i) => {
    const x = (i / (scores.length - 1)) * W;
    const y = H - ((s - min) / range) * (H - 8) - 4;
    return `${x},${y}`;
  }).join(' ');

  const last  = scores[scores.length - 1];
  const prev  = scores[scores.length - 2];
  const trend = last > prev ? 'up' : last < prev ? 'down' : 'flat';

  return (
    <div className="flex items-center gap-3">
      <svg width={W} height={H} className="overflow-visible">
        <polyline points={pts} fill="none" stroke="#6366f1" strokeWidth="2" strokeLinejoin="round" />
      </svg>
      {trend === 'up'   && <TrendingUp   className="w-4 h-4 text-green-500" />}
      {trend === 'down' && <TrendingDown  className="w-4 h-4 text-red-500" />}
      {trend === 'flat' && <Minus         className="w-4 h-4 text-gray-400" />}
    </div>
  );
}

// ─── Score detail card ────────────────────────────────────────────────────────

function ScoreCard({ entry }: { entry: PostureScoreType }) {
  const [showHistory, setShowHistory] = useState(false);
  const qc = useQueryClient();

  const { data: hist } = useQuery({
    queryKey: ['posture-history', entry.provider, entry.targetId],
    queryFn:  () => postureApi.history(entry.provider, entry.targetId, 30),
    enabled:  showHistory,
  });

  const recomputeMut = useMutation({
    mutationFn: () => postureApi.compute(entry.provider, entry.targetId),
    onSuccess:  () => {
      void qc.invalidateQueries({ queryKey: ['posture-summary'] });
      void qc.invalidateQueries({ queryKey: ['posture-history', entry.provider, entry.targetId] });
    },
  });

  const maxPenalty = 132; // theoretical max
  const critPenalty  = Math.min(entry.criticalOpen,    3) * 15;
  const highPenalty  = Math.min(entry.highOpen,        4) * 8;
  const medPenalty   = Math.min(entry.mediumOpen,      5) * 3;
  const lowPenalty   = Math.min(entry.lowOpen,         5) * 1;
  const freezePenalty = Math.min(entry.freezeViolations, 2) * 10;

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <div className="p-5">
        {/* Header */}
        <div className="flex items-start justify-between gap-3 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                entry.provider === 'AWS'   ? 'bg-orange-100 text-orange-700' :
                entry.provider === 'AZURE' ? 'bg-blue-100 text-blue-700' :
                'bg-green-100 text-green-700'
              }`}>{entry.provider}</span>
            </div>
            <p className="text-xs text-gray-500 mt-1 font-mono">{entry.targetId.slice(0, 24)}…</p>
          </div>
          <button
            onClick={() => recomputeMut.mutate()}
            disabled={recomputeMut.isPending}
            className="p-1.5 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
            title="Recompute now"
          >
            <RefreshCw className={`w-4 h-4 ${recomputeMut.isPending ? 'animate-spin' : ''}`} />
          </button>
        </div>

        {/* Gauge */}
        <div className="flex justify-center mb-5">
          <ScoreGauge score={entry.score} grade={entry.grade} />
        </div>

        {/* Penalty breakdown */}
        <div className="space-y-2">
          <PenaltyBar label="Critical open" count={entry.criticalOpen}    penalty={critPenalty}   maxPenalty={maxPenalty} color="bg-red-500" />
          <PenaltyBar label="High open"     count={entry.highOpen}        penalty={highPenalty}   maxPenalty={maxPenalty} color="bg-orange-400" />
          <PenaltyBar label="Medium open"   count={entry.mediumOpen}      penalty={medPenalty}    maxPenalty={maxPenalty} color="bg-yellow-400" />
          <PenaltyBar label="Low open"      count={entry.lowOpen}         penalty={lowPenalty}    maxPenalty={maxPenalty} color="bg-blue-300" />
          {freezePenalty > 0 && (
            <PenaltyBar label="Freeze violations (30d)" count={entry.freezeViolations} penalty={freezePenalty} maxPenalty={maxPenalty} color="bg-indigo-500" />
          )}
        </div>

        {/* History toggle */}
        <button
          onClick={() => setShowHistory((v) => !v)}
          className="mt-4 w-full text-xs text-indigo-600 hover:text-indigo-800 flex items-center justify-center gap-1 transition-colors"
        >
          <TrendingUp className="w-3 h-3" />
          {showHistory ? 'Hide trend' : 'Show 30-day trend'}
        </button>

        {showHistory && hist && (
          <div className="mt-3 border-t pt-3">
            <Sparkline points={hist.history} />
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-gray-500">
              {hist.history.length > 0 && (
                <>
                  <span>Min: <strong>{Math.min(...hist.history.map((p) => p.score))}</strong></span>
                  <span>Max: <strong>{Math.max(...hist.history.map((p) => p.score))}</strong></span>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="border-t border-gray-100 px-5 py-2 bg-gray-50 text-xs text-gray-400">
        Last calculated: {new Date(entry.calculatedAt).toLocaleString()}
      </div>
    </div>
  );
}

// ─── Grade distribution bar ───────────────────────────────────────────────────

function GradeDistribution({ gradeCount }: { gradeCount: Record<string, number> }) {
  const total = Object.values(gradeCount).reduce((s, n) => s + n, 0);
  if (total === 0) return null;

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <h2 className="text-sm font-semibold text-gray-700 mb-4">Grade Distribution</h2>
      <div className="flex gap-1 h-6 rounded-full overflow-hidden">
        {(['A', 'B', 'C', 'D', 'F'] as const).map((g) => {
          const count = gradeCount[g] ?? 0;
          const pct   = (count / total) * 100;
          if (pct === 0) return null;
          const bg = g === 'A' ? 'bg-green-500' : g === 'B' ? 'bg-blue-500' : g === 'C' ? 'bg-yellow-400'
            : g === 'D' ? 'bg-orange-500' : 'bg-red-500';
          return <div key={g} className={`${bg} flex items-center justify-center text-white text-xs font-bold`} style={{ width: `${pct}%` }}>{count > 0 ? g : ''}</div>;
        })}
      </div>
      <div className="mt-3 flex gap-4 text-xs text-gray-600">
        {(['A', 'B', 'C', 'D', 'F'] as const).map((g) => {
          const count = gradeCount[g] ?? 0;
          const colors: Record<string, string> = { A: 'text-green-600', B: 'text-blue-600', C: 'text-yellow-600', D: 'text-orange-600', F: 'text-red-600' };
          return (
            <span key={g} className={`font-semibold ${colors[g]}`}>
              {g}: {count}
            </span>
          );
        })}
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function PostureScore() {
  const [filterGrade, setFilterGrade] = useState<string | null>(null);
  const [filterProvider, setFilterProvider] = useState<string | null>(null);

  const { data: summary, isLoading, refetch } = useQuery({
    queryKey:      ['posture-summary'],
    queryFn:       postureApi.summary,
    refetchInterval: 5 * 60 * 1000, // auto-refresh every 5 min
  });

  const filtered = (summary?.scores ?? []).filter((s) => {
    if (filterGrade    && s.grade    !== filterGrade)    return false;
    if (filterProvider && s.provider !== filterProvider) return false;
    return true;
  });

  // To render ScoreCard we need full PostureScore records — fetch current for each filtered target
  const targetKeys = filtered.map((s) => `${s.provider}:${s.targetId}`);

  const { data: detailedScores = [] } = useQuery({
    queryKey: ['posture-current-batch', targetKeys.join(',')],
    queryFn:  async () => {
      const results = await Promise.allSettled(
        filtered.map((s) => postureApi.current(s.provider, s.targetId))
      );
      return results
        .filter((r): r is PromiseFulfilledResult<PostureScoreType> => r.status === 'fulfilled')
        .map((r) => r.value);
    },
    enabled: filtered.length > 0,
  });

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-violet-50 rounded-xl">
            <Shield className="w-6 h-6 text-violet-600" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">Risk Posture Score</h1>
            <p className="text-sm text-gray-500">0–100 security posture per cloud subscription · recalculated every 5 min</p>
          </div>
        </div>
        <button
          onClick={() => void refetch()}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Scoring legend */}
      <div className="bg-violet-50 border border-violet-100 rounded-lg p-4 mb-6">
        <h2 className="text-xs font-semibold text-violet-800 uppercase tracking-wider mb-2">Scoring Formula</h2>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-x-8 gap-y-1 text-xs text-violet-900">
          <span>Critical open change: <strong>−15 pts</strong> (cap 3)</span>
          <span>High open change: <strong>−8 pts</strong> (cap 4)</span>
          <span>Medium open change: <strong>−3 pts</strong> (cap 5)</span>
          <span>Low open change: <strong>−1 pt</strong> (cap 5)</span>
          <span>Unacked Critical &gt;24h: <strong>−5 pts</strong> (cap 3)</span>
          <span>Freeze violation 30d: <strong>−10 pts</strong> (cap 2)</span>
        </div>
        <div className="flex gap-6 mt-3 text-xs">
          {[['A', '85–100', 'bg-green-500'], ['B', '70–84', 'bg-blue-500'], ['C', '55–69', 'bg-yellow-400'],
            ['D', '40–54', 'bg-orange-500'], ['F', '0–39', 'bg-red-500']].map(([g, r, c]) => (
            <span key={g} className="flex items-center gap-1">
              <span className={`w-5 h-5 rounded flex items-center justify-center ${c} text-white text-xs font-bold`}>{g}</span>
              <span className="text-gray-600">{r}</span>
            </span>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading posture scores…</div>
      ) : !summary || summary.total === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <Shield className="w-10 h-10 mx-auto text-gray-300 mb-3" />
          <p className="font-medium text-gray-600">No posture scores yet</p>
          <p className="text-sm mt-1">Scores are calculated every 5 minutes for READY subscriptions.</p>
        </div>
      ) : (
        <>
          {/* Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-white rounded-xl border border-gray-200 p-4 text-center">
              <p className="text-3xl font-bold text-violet-700">{summary.avgScore ?? '–'}</p>
              <p className="text-xs text-gray-500 mt-1">Avg Score</p>
            </div>
            <div className="bg-white rounded-xl border border-gray-200 p-4 text-center">
              <p className="text-3xl font-bold text-gray-800">{summary.total}</p>
              <p className="text-xs text-gray-500 mt-1">Total Subscriptions</p>
            </div>
            <div className="bg-white rounded-xl border border-green-200 p-4 text-center">
              <p className="text-3xl font-bold text-green-700">
                {(summary.gradeCount['A'] ?? 0) + (summary.gradeCount['B'] ?? 0)}
              </p>
              <p className="text-xs text-gray-500 mt-1">Grade A or B</p>
            </div>
            <div className="bg-white rounded-xl border border-red-200 p-4 text-center">
              <p className="text-3xl font-bold text-red-700">
                {(summary.gradeCount['D'] ?? 0) + (summary.gradeCount['F'] ?? 0)}
              </p>
              <p className="text-xs text-gray-500 mt-1">Grade D or F</p>
            </div>
          </div>

          <GradeDistribution gradeCount={summary.gradeCount} />

          {/* Filters */}
          <div className="flex gap-3 mt-6 mb-4">
            <div className="flex gap-1">
              {[null, 'A', 'B', 'C', 'D', 'F'].map((g) => (
                <button
                  key={g ?? 'all'}
                  onClick={() => setFilterGrade(g)}
                  className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${
                    filterGrade === g
                      ? 'bg-violet-600 text-white border-violet-600'
                      : 'bg-white text-gray-600 border-gray-300 hover:border-violet-400'
                  }`}
                >
                  {g ?? 'All Grades'}
                </button>
              ))}
            </div>
            <div className="flex gap-1">
              {[null, 'AWS', 'AZURE', 'GCP'].map((p) => (
                <button
                  key={p ?? 'all'}
                  onClick={() => setFilterProvider(p)}
                  className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${
                    filterProvider === p
                      ? 'bg-blue-600 text-white border-blue-600'
                      : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
                  }`}
                >
                  {p ?? 'All Providers'}
                </button>
              ))}
            </div>
          </div>

          {/* Score cards */}
          {detailedScores.length === 0 ? (
            <div className="text-center py-8 text-gray-500 text-sm">
              <AlertTriangle className="w-8 h-8 mx-auto text-gray-300 mb-2" />
              No subscriptions match the selected filters.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
              {detailedScores.map((s) => (
                <ScoreCard key={`${s.provider}:${s.targetId}`} entry={s} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

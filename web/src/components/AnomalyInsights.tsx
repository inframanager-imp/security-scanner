/**
 * AnomalyInsights — ML Anomaly Detection dashboard panel
 *
 * Shows:
 *  - Summary cards (total / CRITICAL / HIGH / open)
 *  - 7-day trend sparkline (using CSS bars)
 *  - Anomaly type breakdown
 *  - Top anomalous actors
 *  - Event list with detail expand
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Brain, TrendingUp, AlertOctagon, Globe, Clock, ShieldOff,
  GitBranch, Database, BarChart2, ChevronDown, ChevronRight,
  RefreshCw, CheckCircle, XCircle, Flag,
} from 'lucide-react';
import { anomalyApi, type AnomalyEvent, type AnomalyType, type AnomalySeverity, type AnomalyStatus } from '../api/anomaly';
import { Card } from './ui/Card';

// ─── Constants ────────────────────────────────────────────────────────────────

const TYPE_CONFIG: Record<AnomalyType, { label: string; icon: React.ReactNode; color: string }> = {
  FREQUENCY:         { label: 'Frequency Spike',    icon: <TrendingUp size={14} />,  color: 'text-orange-600 bg-orange-50 ring-orange-200'  },
  GEOGRAPHIC:        { label: 'New Location',        icon: <Globe size={14} />,       color: 'text-blue-600 bg-blue-50 ring-blue-200'        },
  TEMPORAL:          { label: 'Off-Hours Activity',  icon: <Clock size={14} />,       color: 'text-violet-600 bg-violet-50 ring-violet-200'  },
  ACCESS_DENIED:     { label: 'Auth Failure Spike',  icon: <ShieldOff size={14} />,   color: 'text-red-600 bg-red-50 ring-red-200'           },
  IMPOSSIBLE_TRAVEL: { label: 'Impossible Travel',   icon: <Globe size={14} />,       color: 'text-pink-600 bg-pink-50 ring-pink-200'        },
  RARE_EVENT:        { label: 'Rare API Call',        icon: <AlertOctagon size={14}/>, color: 'text-yellow-600 bg-yellow-50 ring-yellow-200'  },
  LATERAL_MOVEMENT:  { label: 'Lateral Movement',    icon: <GitBranch size={14} />,   color: 'text-cyan-600 bg-cyan-50 ring-cyan-200'        },
  DATA_EXFIL:        { label: 'Data Exfiltration',   icon: <Database size={14} />,    color: 'text-rose-600 bg-rose-50 ring-rose-200'        },
};

const SEV_COLOR: Record<AnomalySeverity, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH:     'bg-orange-500 text-white',
  MEDIUM:   'bg-yellow-500 text-white',
  LOW:      'bg-gray-400 text-white',
};

const STATUS_CONFIG: Record<AnomalyStatus, { label: string; cls: string }> = {
  OPEN:          { label: 'Open',          cls: 'bg-red-50 text-red-700 ring-red-200'          },
  ACKNOWLEDGED:  { label: 'Acknowledged',  cls: 'bg-yellow-50 text-yellow-700 ring-yellow-200' },
  RESOLVED:      { label: 'Resolved',      cls: 'bg-emerald-50 text-emerald-700 ring-emerald-200' },
  FALSE_POSITIVE:{ label: 'False Positive',cls: 'bg-gray-50 text-gray-500 ring-gray-200'       },
};

// ─── Score ring ───────────────────────────────────────────────────────────────

function ScoreRing({ score }: { score: number }) {
  const color = score >= 85 ? '#dc2626' : score >= 65 ? '#f97316' : score >= 40 ? '#eab308' : '#6b7280';
  return (
    <span
      className="inline-flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold text-white shrink-0"
      style={{ background: color }}
    >
      {Math.round(score)}
    </span>
  );
}

// ─── Sparkline (CSS bar chart) ────────────────────────────────────────────────

function Sparkline({ data }: { data: Array<{ day: string; count: number }> }) {
  if (!data.length) return <div className="text-xs text-gray-400 italic">No trend data</div>;
  const max = Math.max(...data.map((d) => d.count), 1);
  return (
    <div className="flex items-end gap-0.5 h-10">
      {data.map((d) => (
        <div
          key={d.day}
          title={`${d.day}: ${d.count}`}
          className="flex-1 rounded-sm bg-orange-400 min-h-[2px] transition-all"
          style={{ height: `${Math.max(4, (d.count / max) * 40)}px` }}
        />
      ))}
    </div>
  );
}

// ─── Anomaly event row ────────────────────────────────────────────────────────

function AnomalyRow({ event, onStatusChange }: {
  event: AnomalyEvent;
  onStatusChange: (id: string, status: AnomalyStatus) => void;
}) {
  const [open, setOpen] = useState(false);
  const tc = TYPE_CONFIG[event.anomalyType] ?? { label: event.anomalyType, icon: null, color: 'text-gray-600 bg-gray-50 ring-gray-200' };
  const sc = STATUS_CONFIG[event.status];

  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden">
      <button
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        <ScoreRing score={event.score} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {/* Type badge */}
            <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium ring-1 ${tc.color}`}>
              {tc.icon}{tc.label}
            </span>
            {/* Severity */}
            <span className={`inline-flex px-1.5 py-0.5 rounded text-xs font-bold ${SEV_COLOR[event.severity]}`}>
              {event.severity}
            </span>
            {/* Provider */}
            <span className="text-xs text-gray-500 font-mono">{event.provider}</span>
            {/* Status */}
            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ring-1 ${sc.cls}`}>
              {sc.label}
            </span>
          </div>

          <p className="text-xs text-gray-700 mt-1 line-clamp-2">{event.description}</p>

          <div className="flex gap-3 mt-1 text-xs text-gray-400">
            <span>Actor: <span className="text-gray-600 font-mono">{event.actorId}</span></span>
            {event.sourceIp && <span>IP: <span className="text-gray-600">{event.sourceIp}</span></span>}
            <span>{new Date(event.detectedAt).toLocaleString()}</span>
          </div>
        </div>

        {open ? <ChevronDown size={14} className="text-gray-400 shrink-0 mt-0.5" />
               : <ChevronRight size={14} className="text-gray-400 shrink-0 mt-0.5" />}
      </button>

      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-100 bg-gray-50/60 space-y-3">
          {/* Detail key-values */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
            {Object.entries(event.detail ?? {}).filter(([, v]) => v !== null && v !== undefined && typeof v !== 'object').map(([k, v]) => (
              <div key={k} className="flex gap-1">
                <span className="text-gray-400 font-medium capitalize shrink-0">{k.replace(/([A-Z])/g, ' $1').trim()}:</span>
                <span className="text-gray-700 font-mono truncate">{String(v)}</span>
              </div>
            ))}
          </div>

          {event.eventName && (
            <div className="text-xs">
              <span className="text-gray-500">API call: </span>
              <span className="font-mono text-gray-800">{event.eventName}</span>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex gap-2 pt-1">
            {event.status === 'OPEN' && (
              <>
                <button
                  onClick={() => onStatusChange(event.id, 'ACKNOWLEDGED')}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-yellow-50 text-yellow-700 ring-1 ring-yellow-200 hover:bg-yellow-100 transition-colors"
                >
                  <Flag size={10} /> Acknowledge
                </button>
                <button
                  onClick={() => onStatusChange(event.id, 'FALSE_POSITIVE')}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-gray-50 text-gray-600 ring-1 ring-gray-200 hover:bg-gray-100 transition-colors"
                >
                  <XCircle size={10} /> False Positive
                </button>
              </>
            )}
            {(event.status === 'OPEN' || event.status === 'ACKNOWLEDGED') && (
              <button
                onClick={() => onStatusChange(event.id, 'RESOLVED')}
                className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200 hover:bg-emerald-100 transition-colors"
              >
                <CheckCircle size={10} /> Resolve
              </button>
            )}
          </div>

          {event.notes && (
            <p className="text-xs text-gray-500 italic">{event.notes}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export function AnomalyInsights({
  provider,
  accountId,
}: {
  provider?: string;
  accountId?: string;
}) {
  const qc = useQueryClient();
  const [filterType,     setFilterType]     = useState<AnomalyType | ''>('');
  const [filterSeverity, setFilterSeverity] = useState<AnomalySeverity | ''>('');
  const [filterStatus,   setFilterStatus]   = useState<AnomalyStatus | 'OPEN'>('OPEN');
  const [showSeedPanel,  setShowSeedPanel]  = useState(false);

  const summaryQuery = useQuery({
    queryKey: ['anomaly-summary', provider, accountId],
    queryFn:  () => anomalyApi.getSummary({ provider, accountId, days: 7 }),
    refetchInterval: 60_000,
  });

  const eventsQuery = useQuery({
    queryKey: ['anomaly-events', provider, accountId, filterType, filterSeverity, filterStatus],
    queryFn:  () => anomalyApi.listEvents({
      provider, accountId,
      ...(filterType     ? { type:     filterType     } : {}),
      ...(filterSeverity ? { severity: filterSeverity } : {}),
      ...(filterStatus   ? { status:   filterStatus   } : {}),
      limit: 100,
    }),
    refetchInterval: 30_000,
  });

  const actorsQuery = useQuery({
    queryKey: ['anomaly-actors', provider, accountId],
    queryFn:  () => anomalyApi.getActors({ provider, accountId }),
    refetchInterval: 60_000,
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: AnomalyStatus }) =>
      anomalyApi.updateEvent(id, { status }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['anomaly-events'] });
      qc.invalidateQueries({ queryKey: ['anomaly-summary'] });
    },
  });

  const seedMutation = useMutation({
    mutationFn: () => anomalyApi.seedBaselines(provider ?? 'AWS', accountId ?? '', 30),
  });

  const summary = summaryQuery.data;
  const events  = eventsQuery.data?.data ?? [];
  const actors  = actorsQuery.data ?? [];

  const totalOpen     = summary?.byStatus?.['OPEN']     ?? 0;
  const totalCritical = summary?.bySeverity?.['CRITICAL'] ?? 0;
  const totalHigh     = summary?.bySeverity?.['HIGH']     ?? 0;
  const total         = summary?.total ?? 0;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Brain size={18} className="text-violet-600" />
          <h3 className="text-base font-semibold text-gray-900">ML Anomaly Detection</h3>
          <span className="text-xs text-gray-400 font-normal">— EWMA · Z-score · Geo · Temporal</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { qc.invalidateQueries({ queryKey: ['anomaly-events'] }); qc.invalidateQueries({ queryKey: ['anomaly-summary'] }); }}
            className="p-1.5 rounded hover:bg-gray-100 text-gray-400"
            title="Refresh"
          >
            <RefreshCw size={14} />
          </button>
          <button
            onClick={() => setShowSeedPanel((v) => !v)}
            className="text-xs px-2 py-1 rounded border border-gray-200 text-gray-600 hover:bg-gray-50"
          >
            Seed Baselines
          </button>
        </div>
      </div>

      {/* Baseline seed panel */}
      {showSeedPanel && (
        <Card className="p-4 bg-violet-50 border border-violet-200">
          <p className="text-xs text-violet-700 mb-3">
            Replay 30 days of historical cloud events to train per-actor baselines.
            Runs in background — anomaly detection improves immediately.
          </p>
          <button
            onClick={() => { seedMutation.mutate(); setShowSeedPanel(false); }}
            disabled={!accountId || seedMutation.isPending}
            className="px-3 py-1.5 rounded text-xs font-medium bg-violet-600 text-white hover:bg-violet-700 disabled:opacity-50 transition-colors"
          >
            {seedMutation.isPending ? 'Starting…' : '▶ Start Baseline Seeding'}
          </button>
          {seedMutation.isSuccess && <span className="ml-2 text-xs text-emerald-600">Seeding started ✓</span>}
        </Card>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: '7-Day Anomalies', value: total,         cls: 'text-gray-800'    },
          { label: 'Critical',         value: totalCritical, cls: 'text-red-600'    },
          { label: 'High',             value: totalHigh,     cls: 'text-orange-500' },
          { label: 'Open',             value: totalOpen,     cls: 'text-red-600'    },
        ].map(({ label, value, cls }) => (
          <Card key={label} className="px-4 py-3 text-center">
            <p className={`text-2xl font-bold tabular-nums ${cls}`}>{value}</p>
            <p className="text-xs text-gray-400 mt-0.5">{label}</p>
          </Card>
        ))}
      </div>

      {/* Trend + Type breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* 7-day trend */}
        <Card className="p-4">
          <div className="flex items-center gap-2 mb-3">
            <BarChart2 size={14} className="text-orange-500" />
            <p className="text-xs font-semibold text-gray-700">7-Day Trend</p>
          </div>
          <Sparkline data={summary?.trend ?? []} />
          <p className="text-xs text-gray-400 mt-1 text-right">anomalies / day</p>
        </Card>

        {/* By type */}
        <Card className="p-4">
          <p className="text-xs font-semibold text-gray-700 mb-3">By Anomaly Type</p>
          <div className="space-y-1.5">
            {Object.entries(summary?.byType ?? {}).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
              const tc = TYPE_CONFIG[type as AnomalyType];
              if (!tc || !count) return null;
              return (
                <div key={type} className="flex items-center gap-2">
                  <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium ring-1 w-40 ${tc.color}`}>
                    {tc.icon}{tc.label}
                  </span>
                  <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-orange-400 rounded-full"
                      style={{ width: `${Math.min(100, (count / Math.max(total, 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="text-xs font-medium text-gray-600 w-6 text-right">{count}</span>
                </div>
              );
            })}
            {!summary?.byType || Object.keys(summary.byType).length === 0 && (
              <p className="text-xs text-gray-400 italic">No anomalies in last 7 days</p>
            )}
          </div>
        </Card>
      </div>

      {/* Top anomalous actors */}
      {actors.length > 0 && (
        <Card className="p-4">
          <p className="text-xs font-semibold text-gray-700 mb-3">Most Anomalous Actors</p>
          <div className="divide-y divide-gray-50">
            {actors.slice(0, 5).map((actor) => (
              <div key={actor.actorId} className="flex items-center gap-3 py-2">
                <div
                  className="shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white"
                  style={{ background: (actor.maxScore ?? 0) >= 80 ? '#dc2626' : (actor.maxScore ?? 0) >= 60 ? '#f97316' : '#6b7280' }}
                >
                  {actor.anomalyCount}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-mono text-gray-800 truncate">{actor.actorId}</p>
                  <p className="text-xs text-gray-400">
                    Max score: {actor.maxScore?.toFixed(0) ?? '—'} ·
                    Last: {actor.lastSeen ? new Date(actor.lastSeen).toLocaleDateString() : '—'}
                  </p>
                </div>
                <button
                  onClick={() => setFilterType('')}
                  className="text-xs px-2 py-0.5 rounded border border-gray-200 text-gray-500 hover:bg-gray-50"
                >
                  Filter
                </button>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <span className="text-xs text-gray-500 font-medium">Filter:</span>

        {/* Status */}
        {(['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE', ''] as (AnomalyStatus | '')[]).map((s) => (
          <button
            key={s}
            onClick={() => setFilterStatus(s as AnomalyStatus | 'OPEN')}
            className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
              filterStatus === s ? 'bg-gray-800 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {s || 'All'}
          </button>
        ))}

        <span className="text-gray-200">|</span>

        {/* Severity */}
        <select
          className="rounded border border-gray-300 px-2 py-0.5 text-xs focus:outline-none"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value as AnomalySeverity | '')}
        >
          <option value="">All Severities</option>
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as AnomalySeverity[]).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        {/* Type */}
        <select
          className="rounded border border-gray-300 px-2 py-0.5 text-xs focus:outline-none"
          value={filterType}
          onChange={(e) => setFilterType(e.target.value as AnomalyType | '')}
        >
          <option value="">All Types</option>
          {Object.entries(TYPE_CONFIG).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>

        <span className="ml-auto text-xs text-gray-400">{events.length} event{events.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Event list */}
      {eventsQuery.isLoading ? (
        <div className="py-8 text-center text-sm text-gray-400">Loading anomaly events…</div>
      ) : events.length === 0 ? (
        <Card className="py-10 text-center">
          <Brain size={28} className="text-gray-300 mx-auto mb-2" />
          <p className="text-sm text-gray-500">No anomaly events match the current filter.</p>
          <p className="text-xs text-gray-400 mt-1">Anomalies are detected in real-time as cloud events arrive.</p>
        </Card>
      ) : (
        <div className="space-y-2">
          {events.map((event) => (
            <AnomalyRow
              key={event.id}
              event={event}
              onStatusChange={(id, status) => updateMutation.mutate({ id, status })}
            />
          ))}
        </div>
      )}
    </div>
  );
}

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ShieldAlert, RefreshCw, CheckCircle, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react';
import { iamEscalationApi, type IamEscalationEvent, type IamEscalationStats } from '../api/enterprise';

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700',
  HIGH:     'bg-orange-100 text-orange-700',
  MEDIUM:   'bg-yellow-100 text-yellow-700',
  LOW:      'bg-blue-100 text-blue-700',
};

const TYPE_ICONS: Record<string, string> = {
  POLICY_ATTACH:              '📎',
  INLINE_POLICY:              '📝',
  TRUST_POLICY:               '🔗',
  PERMISSION_BOUNDARY_DELETE: '🚫',
  CREDENTIAL_CREATION:        '🔑',
  ACCESS_KEY_CREATION:        '🗝',
  ADMIN_GROUP:                '👑',
  ROLE_CREATION:              '🎭',
  ROOT_ACTIVITY:              '⚠️',
  STS_ASSUME_ROLE:            '↔️',
  POLICY_CREATION:            '📋',
};

const TYPE_LABELS: Record<string, string> = {
  POLICY_ATTACH:              'Policy Attachment',
  INLINE_POLICY:              'Inline Policy Write',
  TRUST_POLICY:               'Trust Policy Change',
  PERMISSION_BOUNDARY_DELETE: 'Permission Boundary Deleted',
  CREDENTIAL_CREATION:        'Console Credential Created',
  ACCESS_KEY_CREATION:        'Access Key Created',
  ADMIN_GROUP:                'Added to Admin Group',
  ROLE_CREATION:              'IAM Role Created',
  ROOT_ACTIVITY:              'Root Account Activity',
  STS_ASSUME_ROLE:            'Role Assumed via STS',
  POLICY_CREATION:            'IAM Policy Created',
};

function SevBadge({ sev }: { sev: string }) {
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEV_CLASS[sev] ?? 'bg-gray-100 text-gray-600'}`}>{sev}</span>;
}

// ─── Stats bar ────────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: IamEscalationStats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
      <div className="bg-white rounded-xl border border-gray-200 p-4 text-center">
        <p className="text-2xl font-bold text-gray-900">{stats.total}</p>
        <p className="text-xs text-gray-500 mt-1">Events (30d)</p>
      </div>
      <div className={`bg-white rounded-xl border p-4 text-center ${(stats.bySeverity['CRITICAL'] ?? 0) > 0 ? 'border-red-200' : 'border-gray-200'}`}>
        <p className={`text-2xl font-bold ${(stats.bySeverity['CRITICAL'] ?? 0) > 0 ? 'text-red-600' : 'text-gray-900'}`}>
          {stats.bySeverity['CRITICAL'] ?? 0}
        </p>
        <p className="text-xs text-gray-500 mt-1">Critical</p>
      </div>
      <div className={`bg-white rounded-xl border p-4 text-center ${(stats.byStatus['OPEN'] ?? 0) > 0 ? 'border-orange-200' : 'border-gray-200'}`}>
        <p className={`text-2xl font-bold ${(stats.byStatus['OPEN'] ?? 0) > 0 ? 'text-orange-600' : 'text-gray-900'}`}>
          {stats.byStatus['OPEN'] ?? 0}
        </p>
        <p className="text-xs text-gray-500 mt-1">Open</p>
      </div>
      <div className="bg-white rounded-xl border border-green-200 p-4 text-center">
        <p className="text-2xl font-bold text-green-600">{stats.byStatus['RESOLVED'] ?? 0}</p>
        <p className="text-xs text-gray-500 mt-1">Resolved</p>
      </div>
    </div>
  );
}

// ─── Type breakdown ───────────────────────────────────────────────────────────

function TypeBreakdown({ stats }: { stats: IamEscalationStats }) {
  if (stats.byType.length === 0) return null;
  const max = Math.max(...stats.byType.map((t) => t.count));

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 mb-6">
      <h2 className="text-sm font-semibold text-gray-700 mb-4">Escalation Type Breakdown</h2>
      <div className="space-y-2">
        {stats.byType.map((t) => (
          <div key={t.type} className="flex items-center gap-3">
            <span className="text-base w-6 shrink-0">{TYPE_ICONS[t.type] ?? '⚡'}</span>
            <span className="text-xs text-gray-700 w-48 shrink-0">{TYPE_LABELS[t.type] ?? t.type.replace(/_/g, ' ')}</span>
            <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
              <div
                className="h-full bg-red-400 rounded-full transition-all"
                style={{ width: `${(t.count / max) * 100}%` }}
              />
            </div>
            <span className="text-xs font-semibold text-gray-600 w-6 text-right">{t.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Event row ────────────────────────────────────────────────────────────────

function EventRow({ event, onAck, onResolve }: {
  event: IamEscalationEvent;
  onAck:     () => void;
  onResolve: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <div
        className="flex items-start gap-3 p-4 cursor-pointer hover:bg-gray-50 transition-colors"
        onClick={() => setExpanded((v) => !v)}
      >
        <span className="text-xl mt-0.5 shrink-0">{TYPE_ICONS[event.escalationType] ?? '⚡'}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SevBadge sev={event.severity} />
            <span className="text-sm font-medium text-gray-800">
              {TYPE_LABELS[event.escalationType] ?? event.escalationType.replace(/_/g, ' ')}
            </span>
            <span className={`px-2 py-0.5 rounded text-xs font-bold ${
              event.provider === 'AWS'   ? 'bg-orange-100 text-orange-700' :
              event.provider === 'AZURE' ? 'bg-blue-100 text-blue-700' :
              'bg-green-100 text-green-700'
            }`}>{event.provider}</span>
            <span className={`ml-auto px-2 py-0.5 rounded-full text-xs font-medium ${
              event.status === 'OPEN'         ? 'bg-red-100 text-red-700' :
              event.status === 'ACKNOWLEDGED' ? 'bg-yellow-100 text-yellow-700' :
              'bg-green-100 text-green-700'
            }`}>{event.status}</span>
          </div>
          <p className="text-xs text-gray-600 mt-1 truncate">{event.summary}</p>
          <div className="flex gap-3 mt-1 text-xs text-gray-400">
            {event.actor && <span>Actor: <strong className="text-gray-600">{event.actor}</strong></span>}
            <span>{new Date(event.eventTime).toLocaleString()}</span>
          </div>
        </div>
        <div className="shrink-0">
          {expanded ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-100 px-4 pb-4 pt-3 space-y-3">
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div><span className="text-gray-500">Event Name:</span> <span className="font-mono text-gray-800">{event.eventName}</span></div>
            <div><span className="text-gray-500">Actor Type:</span> <span className="text-gray-800">{event.actorType ?? '—'}</span></div>
            {event.targetPrincipal && (
              <div className="col-span-2"><span className="text-gray-500">Target Principal:</span> <span className="font-mono text-gray-800">{event.targetPrincipal}</span></div>
            )}
            {event.resourceName && (
              <div><span className="text-gray-500">Resource:</span> <span className="text-gray-800">{event.resourceType} / {event.resourceName}</span></div>
            )}
            <div><span className="text-gray-500">Target ID:</span> <span className="font-mono text-gray-700">{event.targetId.slice(0, 24)}…</span></div>
          </div>

          <div className="flex gap-2 pt-1">
            {event.status === 'OPEN' && (
              <button
                onClick={(e) => { e.stopPropagation(); onAck(); }}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-yellow-50 text-yellow-700 border border-yellow-200 rounded-lg hover:bg-yellow-100 transition-colors"
              >
                <AlertTriangle className="w-3 h-3" /> Acknowledge
              </button>
            )}
            {(event.status === 'OPEN' || event.status === 'ACKNOWLEDGED') && (
              <button
                onClick={(e) => { e.stopPropagation(); onResolve(); }}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 bg-green-50 text-green-700 border border-green-200 rounded-lg hover:bg-green-100 transition-colors"
              >
                <CheckCircle className="w-3 h-3" /> Resolve
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function IamEscalation() {
  const qc = useQueryClient();
  const [filters, setFilters] = useState({
    status: 'OPEN', severity: '', escalationType: '', provider: '', days: 30,
  });
  const [page, setPage] = useState(1);

  const { data: stats }  = useQuery({
    queryKey: ['iam-stats', filters.provider],
    queryFn:  () => iamEscalationApi.stats(filters.provider || undefined),
    refetchInterval: 60_000,
  });

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['iam-events', filters, page],
    queryFn:  () => iamEscalationApi.list({ ...filters, page, pageSize: 20 }),
  });

  const patchMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      iamEscalationApi.patch(id, status),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['iam-events'] });
      void qc.invalidateQueries({ queryKey: ['iam-stats'] });
    },
  });

  const setFilter = (key: string, val: string | number) => {
    setFilters((f) => ({ ...f, [key]: val }));
    setPage(1);
  };

  return (
    <div className="p-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-red-50 rounded-xl">
            <ShieldAlert className="w-6 h-6 text-red-600" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">IAM Privilege Escalation</h1>
            <p className="text-sm text-gray-500">Real-time detection of IAM policy changes, role assumptions, and credential creation</p>
          </div>
        </div>
        <button
          onClick={() => void refetch()}
          disabled={isLoading}
          className="flex items-center gap-2 px-3 py-2 bg-white border border-gray-300 text-gray-700 rounded-lg text-sm hover:bg-gray-50 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Stats */}
      {stats && <StatsBar stats={stats} />}

      {/* Type breakdown */}
      {stats && stats.byType.length > 0 && <TypeBreakdown stats={stats} />}

      {/* Filters */}
      <div className="bg-white rounded-xl border border-gray-200 p-4 mb-4 flex flex-wrap gap-3">
        {/* Status */}
        <div className="flex gap-1">
          {['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'ALL'].map((s) => (
            <button
              key={s}
              onClick={() => setFilter('status', s === 'ALL' ? '' : s)}
              className={`px-2 py-1 rounded text-xs font-medium border transition-colors ${
                (filters.status || 'ALL') === (s === 'ALL' ? '' : s) || (s === 'ALL' && !filters.status)
                  ? 'bg-red-600 text-white border-red-600'
                  : 'bg-white text-gray-600 border-gray-300'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        {/* Severity */}
        <select
          className="border rounded px-2 py-1 text-xs focus:ring-2 focus:ring-red-500 focus:outline-none"
          value={filters.severity}
          onChange={(e) => setFilter('severity', e.target.value)}
        >
          <option value="">All Severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => <option key={s}>{s}</option>)}
        </select>

        {/* Provider */}
        <select
          className="border rounded px-2 py-1 text-xs focus:ring-2 focus:ring-red-500 focus:outline-none"
          value={filters.provider}
          onChange={(e) => setFilter('provider', e.target.value)}
        >
          <option value="">All Providers</option>
          {['AWS', 'AZURE', 'GCP'].map((p) => <option key={p}>{p}</option>)}
        </select>

        {/* Escalation type */}
        <select
          className="border rounded px-2 py-1 text-xs focus:ring-2 focus:ring-red-500 focus:outline-none"
          value={filters.escalationType}
          onChange={(e) => setFilter('escalationType', e.target.value)}
        >
          <option value="">All Types</option>
          {Object.keys(TYPE_LABELS).map((t) => (
            <option key={t} value={t}>{TYPE_LABELS[t]}</option>
          ))}
        </select>

        {/* Days */}
        <select
          className="border rounded px-2 py-1 text-xs focus:ring-2 focus:ring-red-500 focus:outline-none"
          value={filters.days}
          onChange={(e) => setFilter('days', parseInt(e.target.value))}
        >
          {[7, 14, 30, 60, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}
        </select>

        {data && (
          <span className="ml-auto text-xs text-gray-500 self-center">{data.total} events</span>
        )}
      </div>

      {/* Event list */}
      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading events…</div>
      ) : !data || data.events.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <ShieldAlert className="w-10 h-10 mx-auto text-gray-300 mb-3" />
          <p className="font-medium text-gray-600">No escalation events found</p>
          <p className="text-sm mt-1">Events are detected automatically as new changes are synced.</p>
        </div>
      ) : (
        <>
          <div className="space-y-3">
            {data.events.map((event: IamEscalationEvent) => (
              <EventRow
                key={event.id}
                event={event}
                onAck={()     => patchMut.mutate({ id: event.id, status: 'ACKNOWLEDGED' })}
                onResolve={()  => patchMut.mutate({ id: event.id, status: 'RESOLVED' })}
              />
            ))}
          </div>

          {/* Pagination */}
          {data.total > 20 && (
            <div className="flex gap-2 pt-4 justify-center">
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="text-sm text-red-600 disabled:text-gray-400">← Prev</button>
              <span className="text-sm text-gray-500">{page} / {Math.ceil(data.total / 20)}</span>
              <button onClick={() => setPage((p) => p + 1)} disabled={page >= Math.ceil(data.total / 20)} className="text-sm text-red-600 disabled:text-gray-400">Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

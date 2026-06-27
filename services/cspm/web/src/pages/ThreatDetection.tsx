import { useState, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  XCircle,
  Clock,
  User,
  Globe,
  Terminal,
  Search,
  Info,
  Radio,
  RadioTower,
  Bell,
  Activity,
  Wifi,
  WifiOff,
  Timer,
  CalendarClock,
  Zap,
} from 'lucide-react';
import { findingsApi } from '../api/findings';
import { accountsApi } from '../api/accounts';
import { threatsApi, type MonitorStatus } from '../api/threats';
import { useThreatMonitor, type HeartbeatPayload } from '../hooks/useThreatMonitor';
import { Card } from '../components/ui/Card';
import { Select } from '../components/ui/Select';
import { Input } from '../components/ui/Input';
import { SeverityBadge } from '../components/ui/Badge';
import { AnomalyInsights } from '../components/AnomalyInsights';
import type { Finding, FindingStatus } from '../types';

// ─── Constants ───────────────────────────────────────────────────────────────

const CHECK_INTERVAL_S = 120; // 2 minutes

const CATEGORY_LABELS: Record<string, string> = {
  DefenseEvasion:     'Defense Evasion',
  UnauthorizedAccess: 'Unauthorized Access',
  Persistence:        'Persistence',
  PrivilegeEscalation:'Privilege Escalation',
  Reconnaissance:     'Reconnaissance',
  Exfiltration:       'Exfiltration',
  Impact:             'Impact',
};

const CATEGORY_COLORS: Record<string, string> = {
  DefenseEvasion:     'bg-purple-100 text-purple-700 ring-purple-200',
  UnauthorizedAccess: 'bg-red-100 text-red-700 ring-red-200',
  Persistence:        'bg-orange-100 text-orange-700 ring-orange-200',
  PrivilegeEscalation:'bg-rose-100 text-rose-700 ring-rose-200',
  Reconnaissance:     'bg-yellow-100 text-yellow-700 ring-yellow-200',
  Exfiltration:       'bg-pink-100 text-pink-700 ring-pink-200',
  Impact:             'bg-red-100 text-red-700 ring-red-200',
};

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

const TIME_WINDOWS = [
  { value: '1',  label: 'Last 24 hours' },
  { value: '7',  label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: '',   label: 'All time' },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDate(d?: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function timeAgo(isoString: string): string {
  const secs = Math.round((Date.now() - new Date(isoString).getTime()) / 1000);
  if (secs < 10)  return 'just now';
  if (secs < 60)  return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

function nextCheckIn(lastCheck: string | null): string {
  if (!lastCheck) return '—';
  const elapsed = Math.round((Date.now() - new Date(lastCheck).getTime()) / 1000);
  const remaining = CHECK_INTERVAL_S - elapsed;
  if (remaining <= 0) return 'any moment';
  return `${remaining}s`;
}

function categoryBadge(category: string) {
  const label = CATEGORY_LABELS[category] ?? category;
  const color = CATEGORY_COLORS[category] ?? 'bg-gray-100 text-gray-600 ring-gray-200';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ring-1 ${color}`}>
      {label}
    </span>
  );
}

function summarise(findings: Finding[]) {
  return findings.reduce(
    (acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc; },
    {} as Record<string, number>,
  );
}

// ─── Activity Log ─────────────────────────────────────────────────────────────

interface ActivityEntry {
  id:        string;
  type:      'heartbeat' | 'threat';
  accountId: string;
  accountName?: string;
  time:      string;        // ISO
  newThreats?: number;
  threatTitle?: string;
  severity?:   string;
}

function ActivityLog({ entries, accounts }: { entries: ActivityEntry[]; accounts: any[] }) {
  const accountName = (id: string) =>
    accounts.find((a: any) => a.id === id)?.name ?? id.slice(0, 8) + '…';

  if (entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-32 text-gray-400 text-xs gap-2">
        <Activity size={20} className="text-gray-300" />
        <span>Waiting for monitoring activity…</span>
      </div>
    );
  }

  return (
    <div className="divide-y divide-gray-100 max-h-52 overflow-y-auto">
      {entries.map(e => (
        <div key={e.id} className="flex items-start gap-3 px-4 py-2.5 hover:bg-gray-50">
          <div className="mt-0.5 shrink-0">
            {e.type === 'threat'
              ? <Zap size={13} className="text-red-500" />
              : <Activity size={13} className="text-green-500" />}
          </div>
          <div className="flex-1 min-w-0">
            {e.type === 'threat' ? (
              <p className="text-xs text-gray-800 font-medium truncate">
                <span className={`inline-block mr-1.5 px-1.5 py-0.5 rounded text-white text-[10px] font-bold ${
                  e.severity === 'CRITICAL' ? 'bg-red-600' :
                  e.severity === 'HIGH' ? 'bg-orange-500' : 'bg-yellow-500'
                }`}>{e.severity}</span>
                {e.threatTitle}
              </p>
            ) : (
              <p className="text-xs text-gray-700">
                Checked <span className="font-medium">{accountName(e.accountId)}</span>
                {(e.newThreats ?? 0) > 0
                  ? <span className="ml-1 text-red-600 font-semibold">— {e.newThreats} new threat{e.newThreats! > 1 ? 's' : ''} found</span>
                  : <span className="ml-1 text-gray-400">— no new threats</span>}
              </p>
            )}
          </div>
          <span className="text-[10px] text-gray-400 shrink-0 mt-0.5">{timeAgo(e.time)}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Monitoring Status Panel ──────────────────────────────────────────────────

interface StatusPanelProps {
  statuses:     MonitorStatus[];
  connected:    boolean;
  liveHeartbeats: Record<string, HeartbeatPayload>;
  tick:         number; // incremented every second to force re-render
  onToggle:     (accountId: string, currentlyMonitoring: boolean) => void;
  toggling:     string | null;
}

function MonitoringStatusPanel({ statuses, connected, liveHeartbeats, tick: _tick, onToggle, toggling }: StatusPanelProps) {

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-100 text-sm">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-4 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase">Account</th>
            <th className="px-4 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
            <th className="px-4 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase">Last Checked</th>
            <th className="px-4 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase">Next Check</th>
            <th className="px-4 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase">Socket</th>
            <th className="px-4 py-2.5 text-right text-xs font-semibold text-gray-500 uppercase">Action</th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-100">
          {statuses.map(s => {
            // Prefer live heartbeat data over REST poll data
            const live      = liveHeartbeats[s.accountId];
            const lastCheck = live?.checkedAt ?? s.lastCheck;
            const isActive  = s.monitoring;

            return (
              <tr key={s.accountId} className={isActive ? 'bg-green-50/30' : ''}>
                <td className="px-4 py-3">
                  <div className="font-medium text-gray-900 text-sm">{s.name}</div>
                  <div className="text-xs text-gray-400 font-mono">{s.awsAccountId}</div>
                </td>
                <td className="px-4 py-3">
                  {isActive ? (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-green-100 text-green-700 text-xs font-semibold">
                      <span className="relative flex h-1.5 w-1.5">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
                      </span>
                      Active
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-gray-100 text-gray-500 text-xs font-semibold">
                      <span className="h-1.5 w-1.5 rounded-full bg-gray-400" />
                      Inactive
                    </span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {lastCheck ? (
                    <div>
                      <div className="text-xs font-medium text-gray-800">{formatDate(lastCheck)}</div>
                      <div className="text-[11px] text-gray-400 mt-0.5">{timeAgo(lastCheck)}</div>
                    </div>
                  ) : (
                    <span className="text-xs text-gray-400">Not yet checked</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {isActive && lastCheck ? (
                    <div className="flex items-center gap-1.5 text-xs text-indigo-600 font-mono font-medium">
                      <Timer size={11} />
                      {nextCheckIn(lastCheck)}
                    </div>
                  ) : (
                    <span className="text-xs text-gray-400">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {isActive ? (
                    connected
                      ? <span className="inline-flex items-center gap-1 text-xs text-green-600"><Wifi size={11} /> Connected</span>
                      : <span className="inline-flex items-center gap-1 text-xs text-red-500"><WifiOff size={11} /> Offline</span>
                  ) : (
                    <span className="text-xs text-gray-400">—</span>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => onToggle(s.accountId, isActive)}
                    disabled={toggling === s.accountId}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all
                      ${isActive
                        ? 'bg-red-50 text-red-700 border-red-200 hover:bg-red-100'
                        : 'bg-green-50 text-green-700 border-green-200 hover:bg-green-100'}
                      ${toggling === s.accountId ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    {isActive ? <><RadioTower size={12} /> Stop</> : <><Radio size={12} /> Start</>}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {statuses.length === 0 && (
        <div className="py-8 text-center text-gray-400 text-sm">No accounts configured.</div>
      )}
    </div>
  );
}

// ─── Toast ───────────────────────────────────────────────────────────────────

interface ToastItem {
  id:       string;
  title:    string;
  severity: string;
  actor?:   string;
  time:     string;
}

function ThreatToast({ toasts, onDismiss }: { toasts: ToastItem[]; onDismiss: (id: string) => void }) {
  if (toasts.length === 0) return null;
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map(t => (
        <div
          key={t.id}
          className="flex items-start gap-3 bg-gray-900 text-white rounded-lg shadow-xl border border-red-500/40 px-4 py-3"
        >
          <Bell size={14} className="text-red-400 mt-0.5 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${
                t.severity === 'CRITICAL' ? 'bg-red-600' :
                t.severity === 'HIGH'     ? 'bg-orange-500' : 'bg-yellow-500'
              }`}>{t.severity}</span>
              <span className="text-xs text-gray-300">{t.time}</span>
            </div>
            <p className="text-sm font-semibold text-white mt-0.5 leading-tight">{t.title}</p>
            {t.actor && <p className="text-xs text-gray-400 font-mono truncate mt-0.5">{t.actor}</p>}
          </div>
          <button
            onClick={() => onDismiss(t.id)}
            className="text-gray-500 hover:text-gray-300 text-lg leading-none mt-0.5"
          >×</button>
        </div>
      ))}
    </div>
  );
}

// ─── Finding Row ─────────────────────────────────────────────────────────────

interface RowProps {
  finding:        Finding;
  onStatusChange: (id: string, status: FindingStatus) => void;
  updating:       boolean;
}

function ThreatRow({ finding, onStatusChange, updating }: RowProps) {
  const [expanded, setExpanded] = useState(false);
  const ev           = finding.evidence ?? {};
  const category     = String(ev.threatCategory   ?? '');
  const actor        = String(ev.actor             ?? '—');
  const sourceIP     = String(ev.sourceIP          ?? '');
  const eventTime    = String(ev.eventTime         ?? '');
  const resource     = String(ev.affectedResource  ?? ev.instanceType ?? ev.snapshotId ?? '—');
  const eventCount   = Number(ev.eventCount ?? 1);
  const rawEvents: unknown[] = Array.isArray(ev.rawEvents) ? ev.rawEvents : [];

  return (
    <>
      <tr className="hover:bg-gray-50 cursor-pointer" onClick={() => setExpanded(v => !v)}>
        <td className="px-3 py-3 w-8">
          {expanded
            ? <ChevronDown size={14} className="text-gray-400" />
            : <ChevronRight size={14} className="text-gray-400" />}
        </td>
        <td className="px-3 py-3"><SeverityBadge severity={finding.severity} /></td>
        <td className="px-3 py-3 text-sm font-semibold text-gray-900 max-w-xs">
          {finding.title.replace('Threat: ', '')}
        </td>
        <td className="px-3 py-3">{category ? categoryBadge(category) : '—'}</td>
        <td className="px-3 py-3 text-xs font-mono text-gray-600 max-w-[180px] truncate" title={actor}>{actor}</td>
        <td className="px-3 py-3 text-xs text-gray-500 font-mono">{sourceIP || '—'}</td>
        <td className="px-3 py-3 text-xs text-gray-500 max-w-[150px] truncate" title={resource}>{resource}</td>
        <td className="px-3 py-3 text-xs text-gray-400">{formatDate(eventTime || finding.discoveredAt)}</td>
        <td className="px-3 py-3">
          {eventCount > 1 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-gray-100 text-gray-600">
              ×{eventCount}
            </span>
          )}
        </td>
        <td className="px-3 py-3" onClick={e => e.stopPropagation()}>
          <select
            value={finding.findingStatus}
            onChange={e => onStatusChange(finding.id, e.target.value as FindingStatus)}
            disabled={updating}
            className="text-xs border border-gray-200 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-indigo-400"
          >
            <option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={10} className="px-6 py-5 bg-gray-50 border-b border-gray-200">
            <div className="grid grid-cols-2 gap-6 text-sm">
              <div>
                <h4 className="font-semibold text-gray-900 mb-1 flex items-center gap-1">
                  <AlertTriangle size={13} className="text-orange-500" /> Threat Details
                </h4>
                <p className="text-gray-600 leading-relaxed">{finding.description}</p>
              </div>
              <div>
                <h4 className="font-semibold text-gray-900 mb-1 flex items-center gap-1">
                  <Terminal size={13} className="text-green-600" /> Remediation
                </h4>
                <p className="text-gray-600 leading-relaxed font-mono text-xs whitespace-pre-wrap">{finding.remediation}</p>
              </div>
              {rawEvents.length > 0 && (
                <div className="col-span-2">
                  <h4 className="font-semibold text-gray-900 mb-1 flex items-center gap-1">
                    <Info size={13} className="text-indigo-500" /> CloudTrail Evidence ({rawEvents.length} event{rawEvents.length > 1 ? 's' : ''})
                  </h4>
                  <pre className="text-xs bg-gray-900 text-green-400 rounded-lg p-4 overflow-auto max-h-64 leading-relaxed">
                    {JSON.stringify(rawEvents[0], null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export function ThreatDetection() {
  const queryClient = useQueryClient();
  const [accountId,    setAccountId]    = useState('');
  const [severity,     setSeverity]     = useState('');
  const [category,     setCategory]     = useState('');
  const [statusFilter, setStatusFilter] = useState('OPEN');
  const [timeWindow,   setTimeWindow]   = useState('7');
  const [search,       setSearch]       = useState('');
  const [updatingId,   setUpdatingId]   = useState<string | null>(null);
  const [toasts,       setToasts]       = useState<ToastItem[]>([]);
  const [activityLog,  setActivityLog]  = useState<ActivityEntry[]>([]);
  const [liveHeartbeats, setLiveHeartbeats] = useState<Record<string, HeartbeatPayload>>({});
  const [tick,         setTick]         = useState(0);   // 1-second ticker for countdowns
  const [toggling,     setToggling]     = useState<string | null>(null);
  const [activeTab,    setActiveTab]    = useState<'rule-based' | 'ml-anomaly'>('rule-based');
  const toastCounter = useRef(0);
  const activityCounter = useRef(0);

  // 1-second ticker for next-check countdown
  useEffect(() => {
    const t = setInterval(() => setTick(n => n + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const { data: accountsData = [] } = useQuery({
    queryKey: ['accounts-list'],
    queryFn:  () => accountsApi.list(),
  });
  const accounts: any[] = Array.isArray(accountsData)
    ? accountsData
    : (accountsData as any)?.data ?? [];

  // All-accounts monitoring statuses (poll every 30s; live data supplements)
  const { data: allStatuses = [], refetch: refetchStatuses } = useQuery({
    queryKey: ['monitor-status-all'],
    queryFn:  () => threatsApi.getAllStatuses(),
    refetchInterval: 30_000,
  });
  const statuses: MonitorStatus[] = Array.isArray(allStatuses) ? allStatuses : [];
  const activeCount = statuses.filter(s => s.monitoring).length;

  // ── Real-time socket subscriptions (global room = receives all accounts) ──
  const { connected } = useThreatMonitor({
    all: true,
    onHeartbeat: (payload) => {
      // Update live heartbeat map
      setLiveHeartbeats(prev => ({ ...prev, [payload.accountId]: payload }));

      // Add to activity log
      const entry: ActivityEntry = {
        id:        String(++activityCounter.current),
        type:      'heartbeat',
        accountId: payload.accountId,
        time:      payload.checkedAt,
        newThreats: payload.newThreats,
      };
      setActivityLog(prev => [entry, ...prev].slice(0, 50));

      if (payload.newThreats > 0) {
        queryClient.invalidateQueries({ queryKey: ['threat-findings'] });
      }
    },
    onThreatDetected: (payload) => {
      if (!payload.finding) return;

      // Add to activity log
      const entry: ActivityEntry = {
        id:           String(++activityCounter.current),
        type:         'threat',
        accountId:    payload.accountId,
        time:         payload.detectedAt,
        threatTitle:  payload.finding.title,
        severity:     payload.finding.severity,
      };
      setActivityLog(prev => [entry, ...prev].slice(0, 50));

      // Show toast
      const id = String(++toastCounter.current);
      const toast: ToastItem = {
        id,
        title:    payload.finding.title,
        severity: payload.finding.severity,
        actor:    payload.finding.actor,
        time:     new Date(payload.detectedAt).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
      };
      setToasts(prev => [toast, ...prev].slice(0, 5));
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 8000);
      queryClient.invalidateQueries({ queryKey: ['threat-findings'] });
    },
  });

  // Toggle monitoring for an account
  const handleToggle = async (aid: string, currentlyActive: boolean) => {
    setToggling(aid);
    try {
      if (currentlyActive) {
        await threatsApi.stopMonitoring(aid);
      } else {
        await threatsApi.startMonitoring(aid);
      }
      await refetchStatuses();
    } finally {
      setToggling(null);
    }
  };

  // ── Findings query ─────────────────────────────────────────────────────────
  const { data, isLoading } = useQuery({
    queryKey: ['threat-findings', accountId, severity, statusFilter, timeWindow],
    queryFn: () =>
      findingsApi.list({
        service:       'THREAT',
        accountId:     accountId || undefined,
        severity:      (severity as any) || undefined,
        findingStatus: (statusFilter as any) || undefined,
        pageSize:      500,
      }),
  });

  const allFindings: Finding[] = (data as any)?.data ?? [];

  const windowFiltered = timeWindow
    ? allFindings.filter(f => {
        const t = f.evidence?.eventTime ?? f.discoveredAt;
        if (!t) return true;
        return Date.now() - new Date(t as string).getTime() <= parseInt(timeWindow) * 86400_000;
      })
    : allFindings;

  const filtered = windowFiltered.filter(f => {
    if (category && f.evidence?.threatCategory !== category) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        String(f.evidence?.actor ?? '').toLowerCase().includes(q) ||
        String(f.evidence?.affectedResource ?? '').toLowerCase().includes(q) ||
        String(f.evidence?.sourceIP ?? '').includes(q)
      );
    }
    return true;
  });

  const sorted = [...filtered].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
  );

  const counts = summarise(filtered);

  const categoryGroups = filtered.reduce((acc, f) => {
    const cat = String(f.evidence?.threatCategory ?? 'Unknown');
    acc[cat] = (acc[cat] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      findingsApi.updateStatus(id, status),
    onMutate: ({ id }) => setUpdatingId(id),
    onSettled: () => {
      setUpdatingId(null);
      queryClient.invalidateQueries({ queryKey: ['threat-findings'] });
    },
  });

  return (
    <div className="space-y-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
            <ShieldAlert size={20} className="text-red-600" />
            Threat Detection
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            CloudTrail-based real-time threat detection — GuardDuty-equivalent, no license required
          </p>
        </div>
        {/* Tab switcher */}
        <div className="flex items-center gap-1 bg-gray-100 rounded-lg p-1">
          <button
            onClick={() => setActiveTab('rule-based')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'rule-based'
                ? 'bg-white text-gray-900 shadow-sm'
                : 'text-gray-600 hover:text-gray-800'
            }`}
          >
            Rule-Based Detection
          </button>
          <button
            onClick={() => setActiveTab('ml-anomaly')}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1 ${
              activeTab === 'ml-anomaly'
                ? 'bg-white text-violet-700 shadow-sm'
                : 'text-gray-600 hover:text-gray-800'
            }`}
          >
            <span>🧠</span> ML Anomaly
          </button>
        </div>

        {!isLoading && activeTab === 'rule-based' && (
          <div className="flex items-center gap-5">
            {(counts.CRITICAL ?? 0) > 0 && (
              <div className="text-center">
                <div className="text-xl font-bold text-red-600">{counts.CRITICAL}</div>
                <div className="text-xs text-gray-500">Critical</div>
              </div>
            )}
            {(counts.HIGH ?? 0) > 0 && (
              <div className="text-center">
                <div className="text-xl font-bold text-orange-500">{counts.HIGH}</div>
                <div className="text-xs text-gray-500">High</div>
              </div>
            )}
            {(counts.MEDIUM ?? 0) > 0 && (
              <div className="text-center">
                <div className="text-xl font-bold text-yellow-500">{counts.MEDIUM}</div>
                <div className="text-xs text-gray-500">Medium</div>
              </div>
            )}
            <div className="text-center">
              <div className="text-xl font-bold text-gray-700">{filtered.length}</div>
              <div className="text-xs text-gray-500">Total</div>
            </div>
          </div>
        )}
      </div>

      {/* ── Rule-based panels (hidden when ML tab active) ───────────────────── */}
      {activeTab === 'rule-based' && <>

      {/* ── Monitoring Status Panel + Activity Log ─────────────────────────── */}
      <div className="grid grid-cols-3 gap-4">

        {/* Status table (2/3 width) */}
        <Card className="col-span-2 p-0 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
            <div className="flex items-center gap-2">
              <CalendarClock size={15} className="text-indigo-500" />
              <span className="font-semibold text-gray-900 text-sm">Monitoring Status</span>
            </div>
            <div className="flex items-center gap-3">
              {activeCount > 0 && (
                <span className="inline-flex items-center gap-1.5 text-xs font-medium text-green-700 bg-green-100 px-2.5 py-1 rounded-full">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
                  </span>
                  {activeCount} account{activeCount > 1 ? 's' : ''} monitored
                </span>
              )}
              <span className={`inline-flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-full ${
                connected ? 'text-green-600 bg-green-50' : 'text-red-500 bg-red-50'
              }`}>
                {connected ? <Wifi size={11} /> : <WifiOff size={11} />}
                {connected ? 'Socket connected' : 'Socket offline'}
              </span>
            </div>
          </div>
          <MonitoringStatusPanel
            statuses={statuses}
            connected={connected}
            liveHeartbeats={liveHeartbeats}
            tick={tick}
            onToggle={handleToggle}
            toggling={toggling}
          />
        </Card>

        {/* Activity log (1/3 width) */}
        <Card className="p-0 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-100">
            <Activity size={15} className="text-indigo-500" />
            <span className="font-semibold text-gray-900 text-sm">Live Activity</span>
            {activityLog.length > 0 && (
              <span className="ml-auto text-[10px] text-gray-400">{activityLog.length} events</span>
            )}
          </div>
          <ActivityLog entries={activityLog} accounts={accounts} />
        </Card>
      </div>

      {/* ── Critical alert banner ───────────────────────────────────────────── */}
      {(counts.CRITICAL ?? 0) > 0 && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 flex items-start gap-3">
          <XCircle size={16} className="text-red-600 mt-0.5 shrink-0" />
          <div className="text-sm">
            <span className="font-bold text-red-800">
              {counts.CRITICAL} CRITICAL threat{(counts.CRITICAL ?? 0) > 1 ? 's' : ''} require immediate attention.
            </span>
            <span className="text-red-700 ml-1">Review findings below and take remediation action immediately.</span>
          </div>
        </div>
      )}

      {/* ── Category pills ──────────────────────────────────────────────────── */}
      {Object.keys(categoryGroups).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(categoryGroups)
            .sort(([, a], [, b]) => b - a)
            .map(([cat, count]) => (
              <button
                key={cat}
                onClick={() => setCategory(category === cat ? '' : cat)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold border transition-all
                  ${category === cat
                    ? 'ring-2 ring-offset-1 ring-indigo-400 ' + (CATEGORY_COLORS[cat] ?? 'bg-gray-100 text-gray-700')
                    : (CATEGORY_COLORS[cat] ?? 'bg-gray-100 text-gray-700') + ' border-transparent'}`}
              >
                {CATEGORY_LABELS[cat] ?? cat}
                <span className="bg-white/60 rounded-full px-1.5 py-0.5 font-bold">{count}</span>
              </button>
            ))}
        </div>
      )}

      {/* ── Filters ─────────────────────────────────────────────────────────── */}
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <Select
            value={accountId}
            onChange={e => setAccountId(e.target.value)}
            options={[
              { value: '', label: 'All Accounts' },
              ...accounts.map((a: any) => ({ value: a.id, label: `${a.name} (${a.awsAccountId})` })),
            ]}
          />
          <Select
            value={timeWindow}
            onChange={e => setTimeWindow(e.target.value)}
            options={TIME_WINDOWS}
          />
          <Select
            value={severity}
            onChange={e => setSeverity(e.target.value)}
            options={[
              { value: '',         label: 'All Severities' },
              { value: 'CRITICAL', label: 'Critical' },
              { value: 'HIGH',     label: 'High' },
              { value: 'MEDIUM',   label: 'Medium' },
              { value: 'LOW',      label: 'Low' },
            ]}
          />
          <Select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            options={[
              { value: '',               label: 'All Statuses' },
              { value: 'OPEN',           label: 'Open' },
              { value: 'ACKNOWLEDGED',   label: 'Acknowledged' },
              { value: 'RESOLVED',       label: 'Resolved' },
              { value: 'FALSE_POSITIVE', label: 'False Positive' },
            ]}
          />
          <div className="flex-1 min-w-48">
            <Input
              placeholder="Search actor, IP, resource, threat type…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              leftIcon={<Search size={14} />}
            />
          </div>
        </div>
      </Card>

      {/* ── Findings Table ──────────────────────────────────────────────────── */}
      {isLoading ? (
        <Card>
          <div className="space-y-3 p-2">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-12 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        </Card>
      ) : sorted.length === 0 ? (
        <Card>
          <div className="py-16 text-center">
            <ShieldAlert className="mx-auto h-12 w-12 text-gray-300 mb-4" />
            <p className="text-gray-500 text-sm font-medium">No threat indicators found</p>
            <p className="text-gray-400 text-xs mt-1">
              {allFindings.length === 0
                ? 'Run a scan with Threat Detection enabled, or start live monitoring to continuously analyze CloudTrail events.'
                : 'No threats match the current filters.'}
            </p>
          </div>
        </Card>
      ) : (
        <Card className="overflow-x-auto p-0">
          <table className="min-w-full divide-y divide-gray-100">
            <thead className="bg-gray-50">
              <tr>
                <th className="w-8" />
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Severity</th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Threat</th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Category</th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">
                  <span className="flex items-center gap-1"><User size={11} />Actor</span>
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">
                  <span className="flex items-center gap-1"><Globe size={11} />Source IP</span>
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Resource</th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">
                  <span className="flex items-center gap-1"><Clock size={11} />Event Time</span>
                </th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Count</th>
                <th className="px-3 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {sorted.map(f => (
                <ThreatRow
                  key={f.id}
                  finding={f}
                  onStatusChange={(id, status) => updateStatus.mutate({ id, status })}
                  updating={updatingId === f.id}
                />
              ))}
            </tbody>
          </table>
        </Card>
      )}

      </> /* end rule-based panels */}

      {/* ── ML Anomaly tab ────────────────────────────────────────────────────── */}
      {activeTab === 'ml-anomaly' && (
        <AnomalyInsights
          provider={accountId ? 'AWS' : undefined}
          accountId={accountId || undefined}
        />
      )}

      {/* ── Toast notifications ─────────────────────────────────────────────── */}
      <ThreatToast toasts={toasts} onDismiss={id => setToasts(prev => prev.filter(t => t.id !== id))} />
    </div>
  );
}

export default ThreatDetection;

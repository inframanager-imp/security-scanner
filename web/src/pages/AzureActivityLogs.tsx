import { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  RefreshCw,
  Activity,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Clock,
  Calendar,
} from 'lucide-react';
import { azureApi } from '../api/azure';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Select } from '../components/ui/Select';
import { Input } from '../components/ui/Input';
import { SeverityBadge } from '../components/ui/Badge';
import type { AzureSubscription, AzureActivityEvent, Severity } from '../types';

// ─── Severity Dashboard ───────────────────────────────────────────────────────

interface SeverityCountProps {
  label:     string;
  count:     number;
  color:     string;
  bg:        string;
  icon:      React.ReactNode;
  active:    boolean;
  onClick:   () => void;
}

function SeverityCount({ label, count, color, bg, icon, active, onClick }: SeverityCountProps) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 flex items-center gap-3 px-4 py-3 rounded-lg border-2 transition-all ${
        active
          ? `border-current ${bg} ${color}`
          : 'border-transparent bg-gray-50 text-gray-600 hover:bg-gray-100'
      }`}
    >
      <div className={`h-9 w-9 rounded-full flex items-center justify-center ${bg} ${color}`}>
        {icon}
      </div>
      <div className="text-left">
        <p className="text-xl font-bold leading-none">{count}</p>
        <p className="text-xs font-medium mt-0.5 opacity-80">{label}</p>
      </div>
    </button>
  );
}

// ─── Event Row ────────────────────────────────────────────────────────────────

function EventRow({ event }: { event: AzureActivityEvent }) {
  const [expanded, setExpanded] = useState(false);

  const ts = event.eventTimestamp ? new Date(event.eventTimestamp).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  }) : '—';

  return (
    <div className="border-b border-gray-100 last:border-0">
      <button
        className="w-full text-left px-4 py-3 hover:bg-gray-50 transition-colors flex items-start gap-3"
        onClick={() => setExpanded(e => !e)}
      >
        <SeverityBadge severity={event.severity} />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-gray-900 truncate">
            {event.operationName ?? '(unknown operation)'}
          </p>
          <p className="text-xs text-gray-500 mt-0.5">
            {ts}
            {event.caller    ? ` · ${event.caller}`    : ''}
            {event.category  ? ` · ${event.category}`  : ''}
          </p>
        </div>
        <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${
          event.status === 'Succeeded'
            ? 'bg-green-100 text-green-700'
            : event.status === 'Failed'
              ? 'bg-red-100 text-red-700'
              : 'bg-gray-100 text-gray-600'
        }`}>
          {event.status ?? '—'}
        </span>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 bg-gray-50 border-t border-gray-100">
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 pt-3 text-xs">
            {[
              { label: 'Resource Group',  value: event.resourceGroup },
              { label: 'Resource ID',     value: event.resourceId    },
              { label: 'Category',        value: event.category      },
              { label: 'Level',           value: event.level         },
              { label: 'Caller',          value: event.caller        },
              { label: 'Event ID',        value: event.id            },
            ].map(({ label, value }) =>
              value ? (
                <div key={label}>
                  <span className="font-medium text-gray-500">{label}: </span>
                  <span className="text-gray-800 break-all">{value}</span>
                </div>
              ) : null,
            )}
          </div>
          {event.description && (
            <div className="text-xs text-gray-700 bg-white rounded border border-gray-200 px-3 py-2">
              {event.description}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Preset time ranges ───────────────────────────────────────────────────────

const PRESETS = [
  { label: '1h',  ms: 1  * 60 * 60 * 1_000 },
  { label: '6h',  ms: 6  * 60 * 60 * 1_000 },
  { label: '24h', ms: 24 * 60 * 60 * 1_000 },
  { label: '7d',  ms: 7  * 24 * 60 * 60 * 1_000 },
];

// ─── Main Component ───────────────────────────────────────────────────────────

export function AzureActivityLogs() {
  const [subscriptionId,    setSubscriptionId]    = useState<string>('');
  const [selectedPreset,    setSelectedPreset]    = useState<number>(1); // index into PRESETS
  const [isCustomRange,     setIsCustomRange]     = useState(false);
  const [customStart,       setCustomStart]       = useState('');
  const [customEnd,         setCustomEnd]         = useState('');
  const [severityFilter,    setSeverityFilter]    = useState<Severity | 'ALL'>('ALL');
  const [isLive,            setIsLive]            = useState(true);
  const [lastRefreshed,     setLastRefreshed]     = useState<Date | null>(null);
  const [page,              setPage]              = useState(1);
  const PAGE_SIZE = 50;

  const { data: subsPage } = useQuery({
    queryKey: ['azure-subscriptions'],
    queryFn:  () => azureApi.listSubscriptions({ limit: 100 }),
  });
  const subscriptions: AzureSubscription[] = [...(subsPage?.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));

  useEffect(() => {
    if (subscriptions.length > 0 && !subscriptionId) {
      setSubscriptionId(subscriptions[0].id);
    }
  }, [subscriptions, subscriptionId]);

  const now      = new Date();
  const presetMs = PRESETS[selectedPreset].ms;
  const endTime  = isCustomRange && customEnd   ? customEnd   : now.toISOString();
  const startTime = isCustomRange && customStart ? customStart : new Date(now.getTime() - presetMs).toISOString();

  const queryEnabled = !!subscriptionId;

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ['azure-activity-logs', subscriptionId, isLive ? 'live' : selectedPreset, isCustomRange ? customStart : null, isCustomRange ? customEnd : null],
    queryFn: async () => {
      const result = await azureApi.getActivityLogs({
        subscriptionId,
        startTime,
        endTime,
        maxResults: 500,
      });
      setLastRefreshed(new Date());
      return result;
    },
    enabled:                    queryEnabled,
    refetchInterval:             isLive ? 30_000 : false,
    refetchIntervalInBackground: true,
    staleTime:                   isLive ? 0 : 30_000,
  });

  const allEvents   = data?.events ?? [];
  const summary     = data?.summary ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };

  const filtered = severityFilter === 'ALL'
    ? allEvents
    : allEvents.filter(e => e.severity === severityFilter);
  const totalPages  = Math.ceil(filtered.length / PAGE_SIZE);
  const pageEvents  = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  function handleSeverityFilter(sev: Severity | 'ALL') {
    setSeverityFilter(sev);
    setPage(1);
  }

  const subOptions = subscriptions.map(s => ({ value: s.id, label: s.name }));
  if (subOptions.length === 0) subOptions.push({ value: '', label: 'No subscriptions' });

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Azure Activity Logs</h2>
          <p className="text-sm text-gray-500 mt-0.5">Real-time Azure Monitor activity log viewer</p>
        </div>
        <button
          onClick={() => setIsLive(l => !l)}
          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border transition-all ${
            isLive
              ? 'bg-green-50 border-green-300 text-green-700'
              : 'bg-gray-100 border-gray-300 text-gray-500'
          }`}
        >
          <span className={`h-2 w-2 rounded-full ${isLive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
          {isLive ? (
            <>LIVE{lastRefreshed && <span className="font-normal opacity-70"> · {lastRefreshed.toLocaleTimeString()}</span>}</>
          ) : (
            'Paused'
          )}
        </button>
      </div>

      <div className="flex gap-3">
        <SeverityCount
          label="Critical"   count={summary.critical} color="text-red-700"    bg="bg-red-100"
          icon={<ShieldAlert size={18} />}
          active={severityFilter === 'CRITICAL'}
          onClick={() => handleSeverityFilter(severityFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
        />
        <SeverityCount
          label="High"       count={summary.high}     color="text-orange-700" bg="bg-orange-100"
          icon={<AlertTriangle size={18} />}
          active={severityFilter === 'HIGH'}
          onClick={() => handleSeverityFilter(severityFilter === 'HIGH' ? 'ALL' : 'HIGH')}
        />
        <SeverityCount
          label="Medium"     count={summary.medium}   color="text-yellow-700" bg="bg-yellow-100"
          icon={<AlertTriangle size={18} />}
          active={severityFilter === 'MEDIUM'}
          onClick={() => handleSeverityFilter(severityFilter === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
        />
        <SeverityCount
          label="Low"        count={summary.low}      color="text-blue-700"   bg="bg-blue-100"
          icon={<ShieldCheck size={18} />}
          active={severityFilter === 'LOW'}
          onClick={() => handleSeverityFilter(severityFilter === 'LOW' ? 'ALL' : 'LOW')}
        />
        <SeverityCount
          label="Info"       count={summary.info}     color="text-gray-600"   bg="bg-gray-100"
          icon={<Info size={18} />}
          active={severityFilter === 'INFO'}
          onClick={() => handleSeverityFilter(severityFilter === 'INFO' ? 'ALL' : 'INFO')}
        />
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <div className="w-64">
          <Select
            label="Subscription"
            value={subscriptionId}
            onChange={e => setSubscriptionId(e.target.value)}
            options={subOptions}
          />
        </div>

        <div>
          <p className="text-xs font-medium text-gray-500 mb-1.5">Time Range</p>
          <div className="flex gap-1">
            {PRESETS.map((p, i) => (
              <button
                key={p.label}
                onClick={() => { setSelectedPreset(i); setIsCustomRange(false); }}
                disabled={isCustomRange}
                className={`px-3 py-1.5 rounded text-xs font-medium border transition-all ${
                  !isCustomRange && selectedPreset === i
                    ? 'bg-blue-600 border-blue-600 text-white'
                    : 'bg-white border-gray-300 text-gray-600 hover:border-gray-400 disabled:opacity-40'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div>
          <p className="text-xs font-medium text-gray-500 mb-1.5">
            <button
              onClick={() => setIsCustomRange(c => !c)}
              disabled={isLive}
              title={isLive ? 'Disable live mode to use custom range' : undefined}
              className={`flex items-center gap-1 ${isLive ? 'opacity-40 cursor-not-allowed' : 'hover:text-gray-700'}`}
            >
              <Calendar size={13} />
              Custom Range
            </button>
          </p>
          {isCustomRange && !isLive && (
            <div className="flex items-center gap-2">
              <Input
                type="datetime-local"
                value={customStart}
                onChange={e => setCustomStart(e.target.value)}
                className="text-xs"
              />
              <span className="text-gray-400 text-xs">to</span>
              <Input
                type="datetime-local"
                value={customEnd}
                onChange={e => setCustomEnd(e.target.value)}
                className="text-xs"
              />
            </div>
          )}
        </div>

        <div className="ml-auto flex items-end gap-2">
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />}
            onClick={() => void refetch()}
            disabled={!queryEnabled}
          >
            Refresh
          </Button>
        </div>
      </div>

      <Card
        padding={false}
        title={`Events${filtered.length > 0 ? ` (${filtered.length} matching)` : ''}`}
        action={
          allEvents.length > 0 ? (
            <span className="text-xs text-gray-400 flex items-center gap-1">
              <Activity size={12} />
              {allEvents.length} total
            </span>
          ) : undefined
        }
      >
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
          </div>
        ) : !subscriptionId ? (
          <div className="py-16 text-center text-sm text-gray-400">
            Select an Azure subscription to view activity logs.
          </div>
        ) : error ? (
          <div className="py-10 px-4 text-center text-sm text-red-600">
            {(error as Error).message}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-16 text-center text-sm text-gray-400 flex flex-col items-center gap-2">
            <Clock size={32} className="text-gray-300" />
            No events found for the selected time range{severityFilter !== 'ALL' ? ` at ${severityFilter} severity` : ''}.
          </div>
        ) : (
          <>
            <div className="divide-y divide-gray-100">
              {pageEvents.map(event => (
                <EventRow key={event.id} event={event} />
              ))}
            </div>

            {!isLive && totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
                <p className="text-xs text-gray-500">
                  Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}
                </p>
                <div className="flex gap-2">
                  <Button variant="secondary" size="sm" onClick={() => setPage(p => p - 1)} disabled={page === 1}>
                    Previous
                  </Button>
                  <Button variant="secondary" size="sm" onClick={() => setPage(p => p + 1)} disabled={page === totalPages}>
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}

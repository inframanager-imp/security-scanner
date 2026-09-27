import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ScrollText, RefreshCw, ShieldAlert, ShieldCheck, ShieldX, Search } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Modal } from '../components/ui/Modal';
import { Table, Pagination, type Column } from '../components/ui/Table';
import { auditLogsApi, type AuditLogEntry, type AuditLogFilters, type AuditOutcome } from '../api/auditLogs';
import { useAuth } from '../hooks/useAuth';

const PAGE_SIZE = 50;

const OUTCOME_STYLE: Record<AuditOutcome, { cls: string; icon: React.ReactNode }> = {
  SUCCESS: { cls: 'bg-emerald-50 text-emerald-700 border-emerald-200', icon: <ShieldCheck size={12} /> },
  FAILED:  { cls: 'bg-amber-50 text-amber-700 border-amber-200',       icon: <ShieldAlert size={12} /> },
  DENIED:  { cls: 'bg-red-50 text-red-700 border-red-200',             icon: <ShieldX size={12} /> },
};

const METHOD_STYLE: Record<string, string> = {
  GET: 'text-gray-600 bg-gray-100',
  POST: 'text-blue-700 bg-blue-50',
  PUT: 'text-indigo-700 bg-indigo-50',
  PATCH: 'text-violet-700 bg-violet-50',
  DELETE: 'text-red-700 bg-red-50',
};

function OutcomeBadge({ outcome }: { outcome: AuditOutcome }) {
  const s = OUTCOME_STYLE[outcome] ?? OUTCOME_STYLE.FAILED;
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${s.cls}`}>
      {s.icon}
      {outcome}
    </span>
  );
}

function fmt(ts: string): string {
  return new Date(ts).toLocaleString('en-US', {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function prettyJson(raw: string | null): string {
  if (!raw) return '—';
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

export default function AuditLogs() {
  const { user } = useAuth();
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<AuditLogFilters>({});
  const [draft, setDraft] = useState<AuditLogFilters>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['audit-logs', page, filters],
    queryFn: () => auditLogsApi.list({ ...filters, page, limit: PAGE_SIZE }),
    enabled: user?.role === 'ADMIN',
    refetchInterval: 30_000,
  });

  const { data: actions } = useQuery({
    queryKey: ['audit-logs', 'actions'],
    queryFn: () => auditLogsApi.actions(),
    enabled: user?.role === 'ADMIN',
    staleTime: 5 * 60_000,
  });

  const { data: detail } = useQuery({
    queryKey: ['audit-logs', 'detail', selectedId],
    queryFn: () => auditLogsApi.get(selectedId as string),
    enabled: !!selectedId,
  });

  if (user && user.role !== 'ADMIN') {
    return (
      <Card>
        <div className="flex flex-col items-center gap-2 py-12 text-center">
          <ShieldX className="h-10 w-10 text-gray-300" />
          <p className="font-semibold text-gray-700">Admin access required</p>
          <p className="text-sm text-gray-500">The audit log is only visible to administrators.</p>
        </div>
      </Card>
    );
  }

  const columns: Column<AuditLogEntry>[] = [
    { key: 'createdAt', header: 'Time', render: (r) => <span className="whitespace-nowrap text-xs text-gray-600">{fmt(r.createdAt)}</span> },
    {
      key: 'user', header: 'User',
      render: (r) => (
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-gray-900">{r.userEmail ?? <span className="text-gray-400">anonymous</span>}</p>
          {r.userRole && <p className="text-[11px] text-gray-500">{r.userRole}</p>}
        </div>
      ),
    },
    { key: 'action', header: 'Action', render: (r) => <span className="font-mono text-xs text-gray-800">{r.action}</span> },
    {
      key: 'request', header: 'Request',
      render: (r) => (
        <div className="flex items-center gap-2">
          <span className={`rounded px-1.5 py-0.5 font-mono text-[11px] font-bold ${METHOD_STYLE[r.method] ?? ''}`}>{r.method}</span>
          <span className="max-w-[320px] truncate font-mono text-xs text-gray-600" title={r.path}>{r.path}</span>
        </div>
      ),
    },
    {
      key: 'outcome', header: 'Outcome',
      render: (r) => (
        <div className="flex items-center gap-2">
          <OutcomeBadge outcome={r.outcome} />
          <span className="text-xs tabular-nums text-gray-500">{r.statusCode}</span>
        </div>
      ),
    },
    { key: 'ip', header: 'IP', render: (r) => <span className="font-mono text-xs text-gray-500">{r.ip ?? '—'}</span> },
  ];

  const applyFilters = () => {
    setPage(1);
    setFilters(draft);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-extrabold tracking-tight text-gray-900 sm:text-2xl" style={{ fontFamily: 'var(--font-heading)' }}>
            <ScrollText className="text-[#4b9cd3]" size={22} />
            Audit Log
          </h1>
          <p className="text-xs font-medium text-gray-500 sm:text-sm">
            Every state-changing and denied request, with who did it and from where.
          </p>
        </div>
        <Button variant="secondary" size="sm" leftIcon={<RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />} onClick={() => refetch()}>
          Refresh
        </Button>
      </div>

      <Card>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-6">
          <Input label="User email" placeholder="contains…" value={draft.email ?? ''} onChange={(e) => setDraft({ ...draft, email: e.target.value })} />
          <Select
            label="Action"
            value={draft.action ?? ''}
            onChange={(e) => setDraft({ ...draft, action: e.target.value })}
            options={[{ value: '', label: 'All actions' }, ...(actions?.data ?? []).map((a) => ({ value: a, label: a }))]}
          />
          <Select
            label="Method"
            value={draft.method ?? ''}
            onChange={(e) => setDraft({ ...draft, method: e.target.value as AuditLogFilters['method'] })}
            options={['', 'POST', 'PUT', 'PATCH', 'DELETE', 'GET'].map((m) => ({ value: m, label: m || 'Any method' }))}
          />
          <Select
            label="Outcome"
            value={draft.outcome ?? ''}
            onChange={(e) => setDraft({ ...draft, outcome: e.target.value as AuditLogFilters['outcome'] })}
            options={[
              { value: '', label: 'Any outcome' },
              { value: 'SUCCESS', label: 'Success' },
              { value: 'FAILED', label: 'Failed' },
              { value: 'DENIED', label: 'Denied' },
            ]}
          />
          <Input label="From" type="datetime-local" value={draft.from ?? ''} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
          <Input label="To" type="datetime-local" value={draft.to ?? ''} onChange={(e) => setDraft({ ...draft, to: e.target.value })} />
        </div>
        <div className="mt-3 flex items-center gap-2">
          <Button variant="primary" size="sm" leftIcon={<Search size={14} />} onClick={applyFilters}>Apply</Button>
          <Button variant="ghost" size="sm" onClick={() => { setDraft({}); setFilters({}); setPage(1); }}>Clear</Button>
          {data && <span className="ml-auto text-xs text-gray-500">{data.total.toLocaleString()} entries</span>}
        </div>
      </Card>

      <Card padding={false}>
        {isError ? (
          <div className="p-6 text-sm text-red-600">{error instanceof Error ? error.message : 'Failed to load audit log'}</div>
        ) : (
          <>
            <Table
              columns={columns}
              data={data?.data ?? []}
              loading={isLoading}
              keyExtractor={(r) => r.id}
              emptyMessage="No audit entries match these filters."
              onRowClick={(r) => setSelectedId(r.id)}
            />
            {data && data.totalPages > 1 && (
              <Pagination page={data.page} totalPages={data.totalPages} total={data.total} pageSize={data.limit} onPageChange={setPage} />
            )}
          </>
        )}
      </Card>

      <Modal open={!!selectedId} onClose={() => setSelectedId(null)} title="Audit entry" size="lg">
        {detail?.data ? (
          <div className="space-y-4 text-sm">
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
              {[
                ['Time', fmt(detail.data.createdAt)],
                ['User', detail.data.userEmail ?? 'anonymous'],
                ['Role', detail.data.userRole ?? '—'],
                ['Action', detail.data.action],
                ['Request', `${detail.data.method} ${detail.data.path}`],
                ['Status', `${detail.data.statusCode} · ${detail.data.outcome}`],
                ['IP', detail.data.ip ?? '—'],
                ['Duration', detail.data.durationMs != null ? `${detail.data.durationMs} ms` : '—'],
                ['User agent', detail.data.userAgent ?? '—'],
              ].map(([k, v]) => (
                <div key={k} className="min-w-0">
                  <dt className="text-[11px] font-semibold uppercase tracking-wide text-gray-500">{k}</dt>
                  <dd className="truncate text-gray-900" title={v}>{v}</dd>
                </div>
              ))}
            </dl>
            {detail.data.query && (
              <div>
                <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-500">Query</p>
                <pre className="max-h-40 overflow-auto rounded-lg bg-gray-50 p-3 font-mono text-xs text-gray-800">{prettyJson(detail.data.query)}</pre>
              </div>
            )}
            <div>
              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-500">Request body (secrets redacted)</p>
              <pre className="max-h-72 overflow-auto rounded-lg bg-gray-50 p-3 font-mono text-xs text-gray-800">{prettyJson(detail.data.requestBody)}</pre>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-500">Loading…</p>
        )}
      </Modal>
    </div>
  );
}

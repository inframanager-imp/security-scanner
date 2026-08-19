import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Bell, Plus, Trash2, Edit2, Send, CheckCircle, XCircle,
  Mail, MessageSquare, ChevronDown, ChevronUp, Info,
} from 'lucide-react';
import { alertsApi, type AlertConfigDetail, type AlertChannel, type AlertLog } from '../api/enterprise';

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const PROVIDERS  = ['AWS', 'AZURE', 'GCP'];
const CATEGORIES = [
  'IDENTITY_ACCESS', 'NETWORK_SECURITY', 'DATA_STORAGE', 'COMPUTE',
  'LOGGING_MONITORING', 'ENCRYPTION', 'SERVERLESS', 'CONTAINER', 'COMPLIANCE', 'OTHER',
];

const CHANNEL_LABELS: Record<AlertChannel, string> = {
  SLACK:       'Slack Webhook',
  EMAIL_SMTP:  'Email (SMTP)',
  EMAIL_O365:  'Email (Office 365)',
  EMAIL_GMAIL: 'Email (Google Workspace)',
};

const CHANNEL_ICONS: Record<AlertChannel, React.ReactNode> = {
  SLACK:       <MessageSquare className="w-4 h-4" />,
  EMAIL_SMTP:  <Mail className="w-4 h-4" />,
  EMAIL_O365:  <Mail className="w-4 h-4" />,
  EMAIL_GMAIL: <Mail className="w-4 h-4" />,
};

// ─── Channel config field definitions ────────────────────────────────────────

const CHANNEL_FIELDS: Record<AlertChannel, Array<{ key: string; label: string; type?: string; placeholder?: string }>> = {
  SLACK: [
    { key: 'webhookUrl', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/...' },
  ],
  EMAIL_SMTP: [
    { key: 'host',     label: 'SMTP Host',     placeholder: 'smtp.example.com' },
    { key: 'port',     label: 'SMTP Port',     placeholder: '587' },
    { key: 'user',     label: 'Username',      placeholder: 'alerts@example.com' },
    { key: 'pass',     label: 'Password',      type: 'password', placeholder: '••••••••' },
    { key: 'from',     label: 'From Address',  placeholder: 'alerts@example.com' },
    { key: 'to',       label: 'To Address(es)',placeholder: 'team@example.com' },
    { key: 'secure',   label: 'Use TLS',       placeholder: 'true' },
  ],
  EMAIL_O365: [
    { key: 'tenantId',     label: 'Tenant ID',     placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    { key: 'clientId',     label: 'Client ID',     placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' },
    { key: 'clientSecret', label: 'Client Secret', type: 'password', placeholder: '••••••••' },
    { key: 'fromEmail',    label: 'From Email',    placeholder: 'alerts@yourdomain.onmicrosoft.com' },
    { key: 'toEmail',      label: 'To Email(s)',   placeholder: 'team@yourdomain.com' },
  ],
  EMAIL_GMAIL: [
    { key: 'serviceAccountJson', label: 'Service Account JSON', placeholder: '{ "type": "service_account", ... }' },
    { key: 'fromEmail',          label: 'From Email (delegated)', placeholder: 'alerts@yourdomain.com' },
    { key: 'toEmail',            label: 'To Email(s)',           placeholder: 'team@yourdomain.com' },
  ],
};

// ─── Severity badge ───────────────────────────────────────────────────────────

function SevBadge({ sev }: { sev: string }) {
  const cls = sev === 'CRITICAL' ? 'bg-red-100 text-red-700'
    : sev === 'HIGH'   ? 'bg-orange-100 text-orange-700'
    : sev === 'MEDIUM' ? 'bg-yellow-100 text-yellow-700'
    : 'bg-blue-100 text-blue-700';
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls}`}>{sev}</span>;
}

// ─── Alert Config Form ────────────────────────────────────────────────────────

interface FormState {
  name:         string;
  isActive:     boolean;
  channel:      AlertChannel;
  minSeverity:  string;
  categories:   string[];
  providers:    string[];
  targetIds:    string;
  onFreezeOnly: boolean;
  config:       Record<string, string>;
}

const defaultForm = (): FormState => ({
  name:         '',
  isActive:     true,
  channel:      'SLACK',
  minSeverity:  'HIGH',
  categories:   [],
  providers:    [],
  targetIds:    '',
  onFreezeOnly: false,
  config:       {},
});

function AlertForm({
  initial,
  onSave,
  onCancel,
  isSaving,
}: {
  initial?: FormState;
  onSave: (form: FormState) => void;
  onCancel: () => void;
  isSaving: boolean;
}) {
  const [form, setForm] = useState<FormState>(initial ?? defaultForm());

  const toggleArr = (arr: string[], val: string) =>
    arr.includes(val) ? arr.filter((x) => x !== val) : [...arr, val];

  const setConfig = (key: string, val: string) =>
    setForm((f) => ({ ...f, config: { ...f.config, [key]: val } }));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
          <input
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. Critical AWS Alerts → Slack"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Channel</label>
          <select
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
            value={form.channel}
            onChange={(e) => setForm((f) => ({ ...f, channel: e.target.value as AlertChannel, config: {} }))}
          >
            {(Object.keys(CHANNEL_LABELS) as AlertChannel[]).map((ch) => (
              <option key={ch} value={ch}>{CHANNEL_LABELS[ch]}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Min Severity</label>
          <select
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
            value={form.minSeverity}
            onChange={(e) => setForm((f) => ({ ...f, minSeverity: e.target.value }))}
          >
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">
          {CHANNEL_LABELS[form.channel]} Configuration
        </label>
        <div className="bg-gray-50 rounded-lg p-4 space-y-3 border">
          {CHANNEL_FIELDS[form.channel].map((f) => (
            <div key={f.key}>
              <label className="block text-xs font-medium text-gray-600 mb-1">{f.label}</label>
              <input
                className="w-full border rounded px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none bg-white"
                type={f.type ?? 'text'}
                placeholder={f.placeholder}
                value={form.config[f.key] ?? ''}
                onChange={(e) => setConfig(f.key, e.target.value)}
              />
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">Providers (empty = all)</label>
          <div className="flex gap-2">
            {PROVIDERS.map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setForm((f) => ({ ...f, providers: toggleArr(f.providers, p) }))}
                className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${
                  form.providers.includes(p)
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Target IDs (empty = all)</label>
          <input
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
            value={form.targetIds}
            onChange={(e) => setForm((f) => ({ ...f, targetIds: e.target.value }))}
            placeholder="account-id-1, sub-id-2 (comma separated)"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Categories (empty = all)</label>
        <div className="flex flex-wrap gap-2">
          {CATEGORIES.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setForm((f) => ({ ...f, categories: toggleArr(f.categories, c) }))}
              className={`px-2 py-1 rounded text-xs font-medium border transition-colors ${
                form.categories.includes(c)
                  ? 'bg-purple-600 text-white border-purple-600'
                  : 'bg-white text-gray-600 border-gray-300 hover:border-purple-400'
              }`}
            >
              {c.replace(/_/g, ' ')}
            </button>
          ))}
        </div>
      </div>

      <div className="flex gap-6">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={form.isActive}
            onChange={(e) => setForm((f) => ({ ...f, isActive: e.target.checked }))}
            className="rounded border-gray-300 text-blue-600"
          />
          <span className="text-sm text-gray-700">Active</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={form.onFreezeOnly}
            onChange={(e) => setForm((f) => ({ ...f, onFreezeOnly: e.target.checked }))}
            className="rounded border-gray-300 text-blue-600"
          />
          <span className="text-sm text-gray-700">Only alert on freeze violations</span>
        </label>
      </div>

      <div className="flex gap-3 pt-2">
        <button
          type="button"
          onClick={() => onSave(form)}
          disabled={isSaving || !form.name}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {isSaving ? 'Saving…' : 'Save Configuration'}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-white text-gray-700 border border-gray-300 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ─── Log history panel ────────────────────────────────────────────────────────

function LogsPanel({ configId }: { configId: string }) {
  const [page, setPage] = useState(1);
  const { data } = useQuery({
    queryKey: ['alert-logs', configId, page],
    queryFn:  () => alertsApi.logs(configId, page, 10),
  });

  if (!data) return <div className="text-sm text-gray-500 py-4">Loading logs…</div>;
  if (data.logs.length === 0) return <div className="text-sm text-gray-500 py-4">No alerts sent yet.</div>;

  return (
    <div className="space-y-2">
      {data.logs.map((log: AlertLog) => (
        <div key={log.id} className="flex items-start gap-3 py-2 border-b last:border-b-0">
          {log.status === 'SENT'
            ? <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
            : <XCircle    className="w-4 h-4 text-red-500   mt-0.5 shrink-0" />
          }
          <div className="flex-1 min-w-0">
            <p className="text-sm text-gray-800 truncate">{log.subject}</p>
            {log.errorMessage && (
              <p className="text-xs text-red-600 mt-0.5 truncate">{log.errorMessage}</p>
            )}
            {log.change && (
              <p className="text-xs text-gray-500 mt-0.5">
                {log.change.severity} · {log.change.category.replace(/_/g, ' ')} · {log.change.resourceName}
              </p>
            )}
          </div>
          <span className="text-xs text-gray-400 shrink-0">
            {new Date(log.sentAt).toLocaleString()}
          </span>
        </div>
      ))}
      {data.total > 10 && (
        <div className="flex gap-2 pt-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="text-xs text-blue-600 disabled:text-gray-400"
          >Prev</button>
          <span className="text-xs text-gray-500">{page} / {Math.ceil(data.total / 10)}</span>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={page >= Math.ceil(data.total / 10)}
            className="text-xs text-blue-600 disabled:text-gray-400"
          >Next</button>
        </div>
      )}
    </div>
  );
}

// ─── Config card ──────────────────────────────────────────────────────────────

function ConfigCard({
  cfg,
  onEdit,
  onDelete,
  onTest,
  isTesting,
  testResult,
}: {
  cfg: import('../api/enterprise').AlertConfigSummary;
  onEdit: () => void;
  onDelete: () => void;
  onTest: () => void;
  isTesting: boolean;
  testResult?: string;
}) {
  const [showLogs, setShowLogs] = useState(false);

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className={`p-1.5 rounded-lg ${cfg.isActive ? 'bg-blue-50 text-blue-600' : 'bg-gray-100 text-gray-400'}`}>
              {CHANNEL_ICONS[cfg.channel]}
            </div>
            <div>
              <h3 className="font-medium text-gray-900 text-sm">{cfg.name}</h3>
              <p className="text-xs text-gray-500">{CHANNEL_LABELS[cfg.channel]}</p>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
              cfg.isActive ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
            }`}>
              {cfg.isActive ? 'Active' : 'Disabled'}
            </span>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2 items-center text-xs text-gray-600">
          <SevBadge sev={cfg.minSeverity} />
          {cfg.providers.length > 0 && (
            <span className="bg-gray-100 rounded px-2 py-0.5">{cfg.providers.join(', ')}</span>
          )}
          {cfg.onFreezeOnly && (
            <span className="bg-amber-100 text-amber-700 rounded px-2 py-0.5">Freeze violations only</span>
          )}
          {cfg.categories.length > 0 && (
            <span className="text-gray-400">{cfg.categories.length} categories</span>
          )}
        </div>

        {testResult && (
          <div className={`mt-2 text-xs px-3 py-1.5 rounded ${
            testResult.startsWith('Error')
              ? 'bg-red-50 text-red-700'
              : 'bg-green-50 text-green-700'
          }`}>
            {testResult}
          </div>
        )}
      </div>

      <div className="border-t border-gray-100 px-4 py-2 flex gap-3 bg-gray-50">
        <button
          onClick={onTest}
          disabled={isTesting}
          className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-800 disabled:opacity-50 transition-colors"
        >
          <Send className="w-3 h-3" />
          {isTesting ? 'Sending…' : 'Test'}
        </button>
        <button
          onClick={onEdit}
          className="flex items-center gap-1.5 text-xs text-gray-600 hover:text-gray-800 transition-colors"
        >
          <Edit2 className="w-3 h-3" /> Edit
        </button>
        <button
          onClick={() => setShowLogs((v) => !v)}
          className="flex items-center gap-1.5 text-xs text-gray-600 hover:text-gray-800 transition-colors"
        >
          {showLogs ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          Logs
        </button>
        <button
          onClick={onDelete}
          className="flex items-center gap-1.5 text-xs text-red-500 hover:text-red-700 ml-auto transition-colors"
        >
          <Trash2 className="w-3 h-3" /> Delete
        </button>
      </div>

      {showLogs && (
        <div className="px-4 pb-4 pt-2 border-t border-gray-100">
          <LogsPanel configId={cfg.id} />
        </div>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AlertConfiguration() {
  const qc = useQueryClient();
  const [showForm, setShowForm]       = useState(false);
  const [editingId, setEditingId]     = useState<string | null>(null);
  const [editInitial, setEditInitial] = useState<FormState | null>(null);
  const [testResults, setTestResults] = useState<Record<string, string>>({});
  const [testingId, setTestingId]     = useState<string | null>(null);

  const { data: configs = [], isLoading } = useQuery({
    queryKey: ['alert-configs'],
    queryFn:  alertsApi.list,
  });

  const createMut = useMutation({
    mutationFn: (form: FormState) => alertsApi.create({
      ...form,
      targetIds: form.targetIds ? form.targetIds.split(',').map((s) => s.trim()) : [],
    } as Parameters<typeof alertsApi.create>[0]),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['alert-configs'] }); setShowForm(false); },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, form }: { id: string; form: FormState }) => alertsApi.update(id, {
      ...form,
      targetIds: form.targetIds ? form.targetIds.split(',').map((s) => s.trim()) : [],
    }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['alert-configs'] }); setEditingId(null); setEditInitial(null); },
  });

  const deleteMut = useMutation({
    mutationFn: alertsApi.delete,
    onSuccess:  () => { void qc.invalidateQueries({ queryKey: ['alert-configs'] }); },
  });

  const handleTest = async (id: string) => {
    setTestingId(id);
    try {
      const r = await alertsApi.test(id);
      setTestResults((prev) => ({ ...prev, [id]: r.message }));
    } catch (err) {
      setTestResults((prev) => ({ ...prev, [id]: `Error: ${(err as Error).message}` }));
    } finally {
      setTestingId(null);
    }
  };

  const handleEdit = async (id: string) => {
    const detail = await alertsApi.get(id);
    setEditInitial({
      name:         detail.name,
      isActive:     detail.isActive,
      channel:      detail.channel,
      minSeverity:  detail.minSeverity,
      categories:   detail.categories,
      providers:    detail.providers,
      targetIds:    detail.targetIds.join(', '),
      onFreezeOnly: detail.onFreezeOnly,
      config:       detail.config,
    });
    setEditingId(id);
  };

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-50 rounded-xl">
            <Bell className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">Alert Configuration</h1>
            <p className="text-sm text-gray-500">Route security change notifications to Slack or email</p>
          </div>
        </div>
        <button
          onClick={() => { setShowForm(true); setEditingId(null); setEditInitial(null); }}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-4 h-4" /> New Alert Config
        </button>
      </div>

      <div className="flex items-start gap-2 bg-blue-50 border border-blue-100 rounded-lg p-3 mb-6 text-sm text-blue-800">
        <Info className="w-4 h-4 mt-0.5 shrink-0" />
        <p>
          Alerts fire in real-time when config changes match your filters.
          Use <strong>Min Severity</strong> to avoid noise, and <strong>Freeze violations only</strong>
          for change-freeze enforcement notifications.
        </p>
      </div>

      {showForm && !editingId && (
        <div className="bg-white rounded-xl border border-blue-200 shadow-sm p-6 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">New Alert Configuration</h2>
          <AlertForm
            onSave={(form) => createMut.mutate(form)}
            onCancel={() => setShowForm(false)}
            isSaving={createMut.isPending}
          />
        </div>
      )}

      {editingId && editInitial && (
        <div className="bg-white rounded-xl border border-amber-200 shadow-sm p-6 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">Edit Alert Configuration</h2>
          <AlertForm
            initial={editInitial}
            onSave={(form) => updateMut.mutate({ id: editingId, form })}
            onCancel={() => { setEditingId(null); setEditInitial(null); }}
            isSaving={updateMut.isPending}
          />
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading configurations…</div>
      ) : configs.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <Bell className="w-10 h-10 mx-auto text-gray-300 mb-3" />
          <p className="font-medium text-gray-600">No alert configurations yet</p>
          <p className="text-sm mt-1">Create your first to start receiving notifications.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {configs.map((cfg) => (
            <ConfigCard
              key={cfg.id}
              cfg={cfg}
              onEdit={() => void handleEdit(cfg.id)}
              onDelete={() => { if (confirm(`Delete "${cfg.name}"?`)) deleteMut.mutate(cfg.id); }}
              onTest={() => void handleTest(cfg.id)}
              isTesting={testingId === cfg.id}
              testResult={testResults[cfg.id]}
            />
          ))}
        </div>
      )}
    </div>
  );
}

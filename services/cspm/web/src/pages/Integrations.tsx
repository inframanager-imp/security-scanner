import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link2, Plus, Trash2, Edit2, Send, CheckCircle, XCircle } from 'lucide-react';
import {
  integrationsApi, type IntegrationSummary, type IntegrationDetail,
  type IntegrationType, type IntegrationLog,
} from '../api/enterprise';

// ─── Integration type metadata ────────────────────────────────────────────────

const TYPE_META: Record<IntegrationType, { label: string; color: string; fields: Array<{ key: string; label: string; type?: string; placeholder?: string }> }> = {
  WEBHOOK: {
    label: 'Webhook',
    color: 'bg-green-100 text-green-700',
    fields: [
      { key: 'url',        label: 'Webhook URL',          placeholder: 'https://your-endpoint.example.com/hook' },
      { key: 'secret',     label: 'Signing Secret (optional)', placeholder: 'hmac-secret for X-Scanner-Signature' },
      { key: 'authHeader', label: 'Authorization Header (optional)', placeholder: 'Bearer token123' },
    ],
  },
  SERVICENOW: {
    label: 'ServiceNow',
    color: 'bg-sky-100 text-sky-700',
    fields: [
      { key: 'instanceUrl', label: 'Instance URL',    placeholder: 'https://yourinstance.service-now.com' },
      { key: 'username',    label: 'Username',        placeholder: 'integration-user' },
      { key: 'password',    label: 'Password',        type: 'password', placeholder: '••••••••' },
      { key: 'callerId',    label: 'Caller ID (optional)', placeholder: 'aws-scanner' },
    ],
  },
  JIRA: {
    label: 'Jira',
    color: 'bg-blue-100 text-blue-700',
    fields: [
      { key: 'baseUrl',    label: 'Jira Base URL',    placeholder: 'https://yourorg.atlassian.net' },
      { key: 'email',      label: 'Email',            placeholder: 'api-user@yourorg.com' },
      { key: 'apiToken',   label: 'API Token',        type: 'password', placeholder: '••••••••' },
      { key: 'projectKey', label: 'Project Key',      placeholder: 'SEC' },
      { key: 'issueType',  label: 'Issue Type',       placeholder: 'Bug' },
    ],
  },
};

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

// ─── Form state ───────────────────────────────────────────────────────────────

interface FormState {
  name:            string;
  integrationType: IntegrationType;
  isActive:        boolean;
  minSeverity:     string;
  providers:       string[];
  targetIds:       string;
  onFreezeOnly:    boolean;
  config:          Record<string, string>;
}

const defaultForm = (): FormState => ({
  name:            '',
  integrationType: 'WEBHOOK',
  isActive:        true,
  minSeverity:     'HIGH',
  providers:       [],
  targetIds:       '',
  onFreezeOnly:    false,
  config:          {},
});

function detailToForm(d: IntegrationDetail): FormState {
  return {
    name:            d.name,
    integrationType: d.integrationType,
    isActive:        d.isActive,
    minSeverity:     d.minSeverity,
    providers:       d.providers,
    targetIds:       d.targetIds.join(', '),
    onFreezeOnly:    d.onFreezeOnly,
    config:          d.config,
  };
}

// ─── Form component ───────────────────────────────────────────────────────────

function IntegrationForm({
  initial,
  onSave,
  onCancel,
  isSaving,
}: {
  initial?: FormState;
  onSave: (f: FormState) => void;
  onCancel: () => void;
  isSaving: boolean;
}) {
  const [form, setForm] = useState<FormState>(initial ?? defaultForm());
  const meta = TYPE_META[form.integrationType];

  const toggleProvider = (p: string) =>
    setForm((f) => ({
      ...f,
      providers: f.providers.includes(p) ? f.providers.filter((x) => x !== p) : [...f.providers, p],
    }));

  const setConfig = (key: string, val: string) =>
    setForm((f) => ({ ...f, config: { ...f.config, [key]: val } }));

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
          <input
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-green-500 focus:outline-none"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. Production AWS → Jira SEC project"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Integration Type</label>
          <div className="flex gap-2">
            {(Object.keys(TYPE_META) as IntegrationType[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setForm((f) => ({ ...f, integrationType: t, config: {} }))}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  form.integrationType === t
                    ? 'bg-green-600 text-white border-green-600'
                    : 'bg-white text-gray-600 border-gray-300 hover:border-green-400'
                }`}
              >
                {TYPE_META[t].label}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Min Severity</label>
          <select
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-green-500 focus:outline-none"
            value={form.minSeverity}
            onChange={(e) => setForm((f) => ({ ...f, minSeverity: e.target.value }))}
          >
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {/* Channel config */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-2">{meta.label} Configuration</label>
        <div className="bg-gray-50 rounded-lg p-4 space-y-3 border">
          {meta.fields.map((f) => (
            <div key={f.key}>
              <label className="block text-xs font-medium text-gray-600 mb-1">{f.label}</label>
              <input
                className="w-full border rounded px-3 py-1.5 text-sm bg-white focus:ring-2 focus:ring-green-500 focus:outline-none"
                type={f.type ?? 'text'}
                placeholder={f.placeholder}
                value={form.config[f.key] ?? ''}
                onChange={(e) => setConfig(f.key, e.target.value)}
              />
            </div>
          ))}
        </div>
      </div>

      {/* Scope */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-2">Providers (empty = all)</label>
          <div className="flex gap-2">
            {['AWS', 'AZURE', 'GCP'].map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => toggleProvider(p)}
                className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${
                  form.providers.includes(p)
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Target IDs (empty = all)</label>
          <input
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-green-500 focus:outline-none"
            value={form.targetIds}
            onChange={(e) => setForm((f) => ({ ...f, targetIds: e.target.value }))}
            placeholder="account-id-1, sub-id-2"
          />
        </div>
      </div>

      <div className="flex gap-6">
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={form.isActive} onChange={(e) => setForm((f) => ({ ...f, isActive: e.target.checked }))} className="rounded" />
          <span className="text-sm text-gray-700">Active</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={form.onFreezeOnly} onChange={(e) => setForm((f) => ({ ...f, onFreezeOnly: e.target.checked }))} className="rounded" />
          <span className="text-sm text-gray-700">Freeze violations only</span>
        </label>
      </div>

      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => onSave(form)}
          disabled={isSaving || !form.name}
          className="px-4 py-2 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 disabled:opacity-50 transition-colors"
        >
          {isSaving ? 'Saving…' : 'Save Integration'}
        </button>
        <button type="button" onClick={onCancel} className="px-4 py-2 bg-white border border-gray-300 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors">Cancel</button>
      </div>
    </div>
  );
}

// ─── Integration card ─────────────────────────────────────────────────────────

function IntegrationCard({
  cfg,
  onEdit,
  onDelete,
}: {
  cfg: IntegrationSummary;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const [testing, setTesting]     = useState(false);
  const [testResult, setTestResult] = useState<string>();

  const handleTest = async () => {
    setTesting(true);
    try {
      const r = await integrationsApi.test(cfg.id);
      setTestResult(r.message);
    } catch (err) {
      setTestResult(`Error: ${(err as Error).message}`);
    } finally {
      setTesting(false);
    }
  };

  const meta = TYPE_META[cfg.integrationType];

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-xs font-bold ${meta.color}`}>{meta.label}</span>
              <h3 className="font-medium text-gray-900 text-sm">{cfg.name}</h3>
            </div>
            <div className="flex flex-wrap gap-1.5 mt-2 text-xs text-gray-600">
              <span className="bg-gray-100 rounded px-2 py-0.5">Min: {cfg.minSeverity}</span>
              {cfg.providers.length > 0 && (
                <span className="bg-blue-50 text-blue-700 rounded px-2 py-0.5">{cfg.providers.join(', ')}</span>
              )}
              {cfg.onFreezeOnly && (
                <span className="bg-amber-100 text-amber-700 rounded px-2 py-0.5">❄ Freeze only</span>
              )}
              <span className="text-gray-400">{(cfg._count?.logs ?? 0)} deliveries</span>
            </div>
          </div>
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
            cfg.isActive ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
          }`}>
            {cfg.isActive ? 'Active' : 'Off'}
          </span>
        </div>

        {testResult && (
          <div className={`mt-2 text-xs px-3 py-1.5 rounded ${testResult.startsWith('Error') ? 'bg-red-50 text-red-700' : 'bg-green-50 text-green-700'}`}>
            {testResult}
          </div>
        )}
      </div>

      <div className="border-t border-gray-100 px-4 py-2 flex gap-3 bg-gray-50">
        <button
          onClick={() => void handleTest()}
          disabled={testing}
          className="flex items-center gap-1.5 text-xs text-green-600 hover:text-green-800 disabled:opacity-50 transition-colors"
        >
          <Send className="w-3 h-3" /> {testing ? 'Testing…' : 'Test'}
        </button>
        <button onClick={onEdit} className="flex items-center gap-1.5 text-xs text-gray-600 hover:text-gray-800 transition-colors">
          <Edit2 className="w-3 h-3" /> Edit
        </button>
        <button onClick={onDelete} className="flex items-center gap-1.5 text-xs text-red-500 hover:text-red-700 ml-auto transition-colors">
          <Trash2 className="w-3 h-3" /> Delete
        </button>
      </div>
    </div>
  );
}

// ─── Recent log panel ─────────────────────────────────────────────────────────

function RecentLogs() {
  const { data: logs = [] } = useQuery({
    queryKey:      ['integration-logs-recent'],
    queryFn:       () => integrationsApi.recentLogs(30),
    refetchInterval: 30_000,
  });

  if (logs.length === 0) return null;

  return (
    <div className="mt-8">
      <h2 className="text-sm font-semibold text-gray-700 mb-3">Recent Delivery Log</h2>
      <div className="bg-white rounded-xl border border-gray-200 divide-y divide-gray-100">
        {logs.map((log: IntegrationLog) => (
          <div key={log.id} className="flex items-center gap-3 px-4 py-2.5">
            {log.status === 'SENT'
              ? <CheckCircle className="w-4 h-4 text-green-500 shrink-0" />
              : <XCircle    className="w-4 h-4 text-red-500 shrink-0" />
            }
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 text-xs">
                {log.config && <span className="font-medium text-gray-800">{log.config.name}</span>}
                {log.config && <span className={`px-1.5 rounded ${TYPE_META[log.config.integrationType]?.color ?? ''}`}>{log.config.integrationType}</span>}
                {log.externalId && <span className="text-gray-500">→ {log.externalId}</span>}
              </div>
              {log.errorMessage && (
                <p className="text-xs text-red-600 truncate mt-0.5">{log.errorMessage}</p>
              )}
            </div>
            <span className="text-xs text-gray-400 shrink-0">
              {new Date(log.sentAt).toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Integrations() {
  const qc = useQueryClient();
  const [showForm, setShowForm]       = useState(false);
  const [editingId, setEditingId]     = useState<string | null>(null);
  const [editInitial, setEditInitial] = useState<FormState | null>(null);

  const { data: configs = [], isLoading } = useQuery({
    queryKey: ['integrations'],
    queryFn:  integrationsApi.list,
  });

  const createMut = useMutation({
    mutationFn: (f: FormState) => integrationsApi.create({
      ...f,
      targetIds: f.targetIds ? f.targetIds.split(',').map((s) => s.trim()) : [],
    } as Parameters<typeof integrationsApi.create>[0]),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['integrations'] }); setShowForm(false); },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, f }: { id: string; f: FormState }) => integrationsApi.update(id, {
      ...f,
      targetIds: f.targetIds ? f.targetIds.split(',').map((s) => s.trim()) : [],
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['integrations'] });
      setEditingId(null); setEditInitial(null);
    },
  });

  const deleteMut = useMutation({
    mutationFn: integrationsApi.delete,
    onSuccess:  () => void qc.invalidateQueries({ queryKey: ['integrations'] }),
  });

  const handleEdit = async (id: string) => {
    const detail = await integrationsApi.get(id);
    setEditInitial(detailToForm(detail));
    setEditingId(id);
    setShowForm(false);
  };

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-green-50 rounded-xl">
            <Link2 className="w-6 h-6 text-green-600" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">Integrations</h1>
            <p className="text-sm text-gray-500">Route change events to Webhook endpoints, ServiceNow, or Jira</p>
          </div>
        </div>
        <button
          onClick={() => { setShowForm(true); setEditingId(null); setEditInitial(null); }}
          className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg text-sm font-medium hover:bg-green-700 transition-colors"
        >
          <Plus className="w-4 h-4" /> New Integration
        </button>
      </div>

      {showForm && !editingId && (
        <div className="bg-white rounded-xl border border-green-200 shadow-sm p-5 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">New Integration</h2>
          <IntegrationForm
            onSave={(f) => createMut.mutate(f)}
            onCancel={() => setShowForm(false)}
            isSaving={createMut.isPending}
          />
        </div>
      )}

      {editingId && editInitial && (
        <div className="bg-white rounded-xl border border-amber-200 shadow-sm p-5 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">Edit Integration</h2>
          <IntegrationForm
            initial={editInitial}
            onSave={(f) => updateMut.mutate({ id: editingId, f })}
            onCancel={() => { setEditingId(null); setEditInitial(null); }}
            isSaving={updateMut.isPending}
          />
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading integrations…</div>
      ) : configs.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <Link2 className="w-10 h-10 mx-auto text-gray-300 mb-3" />
          <p className="font-medium text-gray-600">No integrations configured</p>
          <p className="text-sm mt-1">Connect to Webhook, ServiceNow, or Jira to auto-create tickets.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {configs.map((cfg) => (
            <IntegrationCard
              key={cfg.id}
              cfg={cfg}
              onEdit={() => void handleEdit(cfg.id)}
              onDelete={() => { if (confirm(`Delete "${cfg.name}"?`)) deleteMut.mutate(cfg.id); }}
            />
          ))}
        </div>
      )}

      <RecentLogs />
    </div>
  );
}

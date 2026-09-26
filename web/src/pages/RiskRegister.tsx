import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle, Plus, X, ChevronDown, ChevronUp,
  ShieldAlert, CheckCircle, Clock, XCircle, Edit2, Trash2,
} from 'lucide-react';
import { riskRegisterApi, type RiskItem, type RiskStatus, type RiskCategory } from '../api/riskRegister';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';

// ─── Constants ─────────────────────────────────────────────────────────────────

const CATEGORIES: RiskCategory[] = ['CONFIGURATION', 'VULNERABILITY', 'ACCESS', 'COMPLIANCE', 'OPERATIONAL', 'DATA'];
const STATUSES: RiskStatus[]     = ['OPEN', 'ACCEPTED', 'MITIGATED', 'CLOSED'];

const STATUS_CONFIG: Record<RiskStatus, { label: string; icon: React.ReactNode; classes: string }> = {
  OPEN:      { label: 'Open',      icon: <AlertTriangle size={12} />, classes: 'bg-red-50 text-red-700 ring-red-200'       },
  ACCEPTED:  { label: 'Accepted',  icon: <Clock size={12} />,         classes: 'bg-yellow-50 text-yellow-700 ring-yellow-200' },
  MITIGATED: { label: 'Mitigated', icon: <CheckCircle size={12} />,   classes: 'bg-emerald-50 text-emerald-700 ring-emerald-200' },
  CLOSED:    { label: 'Closed',    icon: <XCircle size={12} />,       classes: 'bg-gray-50 text-gray-500 ring-gray-200'     },
};

const CATEGORY_COLORS: Record<RiskCategory, string> = {
  CONFIGURATION: 'bg-cyan-50 text-cyan-700 ring-cyan-200',
  VULNERABILITY: 'bg-red-50 text-red-700 ring-red-200',
  ACCESS:        'bg-orange-50 text-orange-700 ring-orange-200',
  COMPLIANCE:    'bg-blue-50 text-blue-700 ring-blue-200',
  OPERATIONAL:   'bg-violet-50 text-violet-700 ring-violet-200',
  DATA:          'bg-emerald-50 text-emerald-700 ring-emerald-200',
};

function riskColor(score: number) {
  if (score >= 16) return 'text-red-600 bg-red-50';
  if (score >= 9)  return 'text-orange-600 bg-orange-50';
  if (score >= 4)  return 'text-yellow-600 bg-yellow-50';
  return 'text-emerald-600 bg-emerald-50';
}

function riskLabel(score: number) {
  if (score >= 16) return 'Critical';
  if (score >= 9)  return 'High';
  if (score >= 4)  return 'Medium';
  return 'Low';
}

// ─── Risk Score Matrix display ─────────────────────────────────────────────────

function RiskScoreBadge({ likelihood, impact }: { likelihood: number; impact: number }) {
  const score = likelihood * impact;
  const cls = riskColor(score);
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-bold ring-1 ${cls}`}>
      {score} <span className="font-normal opacity-70">({riskLabel(score)})</span>
    </span>
  );
}

// ─── Form ──────────────────────────────────────────────────────────────────────

interface FormState {
  title: string;
  description: string;
  category: RiskCategory;
  likelihood: number;
  impact: number;
  status: RiskStatus;
  owner: string;
  dueDate: string;
  provider: string;
  mitigationPlan: string;
  acceptanceRationale: string;
}

const EMPTY_FORM: FormState = {
  title: '', description: '', category: 'COMPLIANCE', likelihood: 3, impact: 3,
  status: 'OPEN', owner: '', dueDate: '', provider: '', mitigationPlan: '', acceptanceRationale: '',
};

function RiskForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial: FormState;
  onSave: (data: FormState) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const [form, setForm] = useState<FormState>(initial);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setForm((f) => ({ ...f, [k]: v }));
  const score = form.likelihood * form.impact;

  return (
    <div className="space-y-4">
      {/* Title */}
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Title *</label>
        <input
          className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={form.title}
          onChange={(e) => set('title', e.target.value)}
          placeholder="e.g. S3 bucket publicly accessible"
        />
      </div>

      {/* Description */}
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Description *</label>
        <textarea
          className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 min-h-[72px]"
          value={form.description}
          onChange={(e) => set('description', e.target.value)}
          placeholder="Describe the risk and its potential impact…"
        />
      </div>

      {/* Category + Status */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Category *</label>
          <select
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={form.category}
            onChange={(e) => set('category', e.target.value as RiskCategory)}
          >
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Status</label>
          <select
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={form.status}
            onChange={(e) => set('status', e.target.value as RiskStatus)}
          >
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {/* Likelihood + Impact */}
      <div className="grid grid-cols-3 gap-3 items-end">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Likelihood (1–5)</label>
          <input
            type="number" min={1} max={5}
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={form.likelihood}
            onChange={(e) => set('likelihood', Math.min(5, Math.max(1, +e.target.value)))}
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Impact (1–5)</label>
          <input
            type="number" min={1} max={5}
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={form.impact}
            onChange={(e) => set('impact', Math.min(5, Math.max(1, +e.target.value)))}
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Risk Score</label>
          <div className="px-3 py-1.5">
            <RiskScoreBadge likelihood={form.likelihood} impact={form.impact} />
          </div>
        </div>
      </div>

      {/* Owner + Due Date */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Owner</label>
          <input
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={form.owner}
            onChange={(e) => set('owner', e.target.value)}
            placeholder="e.g. security-team@company.com"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Due Date</label>
          <input
            type="date"
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={form.dueDate}
            onChange={(e) => set('dueDate', e.target.value)}
          />
        </div>
      </div>

      {/* Provider */}
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Cloud Provider</label>
        <select
          className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={form.provider}
          onChange={(e) => set('provider', e.target.value)}
        >
          <option value="">All / Unknown</option>
          <option value="AWS">AWS</option>
          <option value="AZURE">Azure</option>
          <option value="GCP">GCP</option>
        </select>
      </div>

      {/* Mitigation plan */}
      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Mitigation Plan</label>
        <textarea
          className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 min-h-[60px]"
          value={form.mitigationPlan}
          onChange={(e) => set('mitigationPlan', e.target.value)}
          placeholder="Steps to mitigate or remediate this risk…"
        />
      </div>

      {/* Acceptance rationale — only shown for ACCEPTED status */}
      {form.status === 'ACCEPTED' && (
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Acceptance Rationale *</label>
          <textarea
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 min-h-[60px]"
            value={form.acceptanceRationale}
            onChange={(e) => set('acceptanceRationale', e.target.value)}
            placeholder="Why is this risk being accepted instead of mitigated?"
          />
        </div>
      )}

      <div className="flex justify-end gap-2 pt-2">
        <Button variant="secondary" size="sm" onClick={onCancel}>Cancel</Button>
        <Button
          size="sm"
          onClick={() => onSave(form)}
          disabled={saving || !form.title || !form.description}
        >
          {saving ? 'Saving…' : 'Save Risk'}
        </Button>
      </div>
    </div>
  );
}

// ─── Risk Item Row ─────────────────────────────────────────────────────────────

function RiskRow({
  item,
  onEdit,
  onDelete,
}: {
  item: RiskItem;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const [open, setOpen] = useState(false);
  const sc = STATUS_CONFIG[item.status];

  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden">
      <div className="flex items-start gap-3 px-4 py-3">
        {/* Score */}
        <div className={`shrink-0 mt-0.5 flex items-center justify-center w-9 h-9 rounded-lg text-sm font-bold ${riskColor(item.riskScore)}`}>
          {item.riskScore}
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-gray-800">{item.title}</span>
            <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium ring-1 ${sc.classes}`}>
              {sc.icon}{sc.label}
            </span>
            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ring-1 ${CATEGORY_COLORS[item.category]}`}>
              {item.category}
            </span>
            {item.provider && (
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-50 text-gray-600 ring-1 ring-gray-200">
                {item.provider}
              </span>
            )}
            <span className="text-xs text-gray-400 ml-auto tabular-nums">
              L:{item.likelihood} × I:{item.impact} = {item.riskScore} ({riskLabel(item.riskScore)})
            </span>
          </div>

          <p className="text-xs text-gray-500 mt-0.5 line-clamp-1">{item.description}</p>

          {(item.owner || item.dueDate) && (
            <div className="flex gap-3 mt-1 text-xs text-gray-400">
              {item.owner    && <span>Owner: <span className="text-gray-600">{item.owner}</span></span>}
              {item.dueDate  && <span>Due: <span className="text-gray-600">{new Date(item.dueDate).toLocaleDateString()}</span></span>}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="shrink-0 flex items-center gap-1">
          <button
            onClick={() => setOpen((v) => !v)}
            className="p-1.5 rounded hover:bg-gray-100 text-gray-400"
            title="Toggle details"
          >
            {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
          <button onClick={onEdit}   className="p-1.5 rounded hover:bg-gray-100 text-gray-400" title="Edit"><Edit2 size={14} /></button>
          <button onClick={onDelete} className="p-1.5 rounded hover:bg-red-50 text-red-400"    title="Delete"><Trash2 size={14} /></button>
        </div>
      </div>

      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-100 bg-gray-50/60 space-y-3">
          <p className="text-xs text-gray-700">{item.description}</p>

          {item.mitigationPlan && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Mitigation Plan</p>
              <p className="text-xs text-gray-700 whitespace-pre-wrap">{item.mitigationPlan}</p>
            </div>
          )}

          {item.acceptanceRationale && (
            <div>
              <p className="text-xs font-semibold text-yellow-600 uppercase tracking-wide mb-1">Acceptance Rationale</p>
              <p className="text-xs text-gray-700 whitespace-pre-wrap">{item.acceptanceRationale}</p>
            </div>
          )}

          {(item.linkedControlIds as string[]).length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1">Linked Controls</p>
              <div className="flex flex-wrap gap-1">
                {(item.linkedControlIds as string[]).map((c) => (
                  <span key={c} className="px-2 py-0.5 rounded text-xs bg-blue-50 text-blue-700 ring-1 ring-blue-200">{c}</span>
                ))}
              </div>
            </div>
          )}

          <p className="text-xs text-gray-400">
            Created: {new Date(item.createdAt).toLocaleDateString()} ·
            Updated: {new Date(item.updatedAt).toLocaleDateString()}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export function RiskRegister() {
  const qc = useQueryClient();
  const [filterStatus,   setFilterStatus]   = useState<RiskStatus | ''>('');
  const [filterCategory, setFilterCategory] = useState<RiskCategory | ''>('');
  const [filterProvider, setFilterProvider] = useState('');
  const [showForm,       setShowForm]       = useState(false);
  const [editingItem,    setEditingItem]     = useState<RiskItem | null>(null);

  const { data: items = [], isLoading } = useQuery({
    queryKey: ['risk-register', filterStatus, filterCategory, filterProvider],
    queryFn: () => riskRegisterApi.list({
      ...(filterStatus   ? { status:   filterStatus   } : {}),
      ...(filterCategory ? { category: filterCategory } : {}),
      ...(filterProvider ? { provider: filterProvider } : {}),
    }),
  });

  const createMutation = useMutation({
    mutationFn: (data: FormState) => riskRegisterApi.create({
      title: data.title,
      description: data.description,
      category: data.category,
      likelihood: data.likelihood,
      impact: data.impact,
      status: data.status,
      owner:    data.owner    || null,
      dueDate:  data.dueDate  || null,
      provider: data.provider || null,
      accountId: null,
      linkedFindingIds: [],
      linkedControlIds: [],
      mitigationPlan:      data.mitigationPlan      || null,
      acceptanceRationale: data.acceptanceRationale || null,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['risk-register'] }); setShowForm(false); },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: FormState }) => riskRegisterApi.update(id, {
      title: data.title,
      description: data.description,
      category: data.category,
      likelihood: data.likelihood,
      impact: data.impact,
      status: data.status,
      owner:    data.owner    || null,
      dueDate:  data.dueDate  || null,
      provider: data.provider || null,
      mitigationPlan:      data.mitigationPlan      || null,
      acceptanceRationale: data.acceptanceRationale || null,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['risk-register'] }); setEditingItem(null); },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => riskRegisterApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['risk-register'] }),
  });

  // Summary stats
  const open      = items.filter((i) => i.status === 'OPEN').length;
  const critical  = items.filter((i) => i.riskScore >= 16).length;
  const high      = items.filter((i) => i.riskScore >= 9 && i.riskScore < 16).length;
  const mitigated = items.filter((i) => i.status === 'MITIGATED').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-red-50">
            <ShieldAlert size={18} className="text-red-600" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-gray-900">Risk Register</h2>
            <p className="text-sm text-gray-500">Track, assess, and manage compliance and security risks</p>
          </div>
        </div>
        <Button size="sm" onClick={() => { setEditingItem(null); setShowForm(true); }}>
          <Plus size={14} className="mr-1" />
          Add Risk
        </Button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Open Risks',     value: open,      cls: 'text-red-600'    },
          { label: 'Critical',       value: critical,  cls: 'text-red-700'    },
          { label: 'High',           value: high,      cls: 'text-orange-600' },
          { label: 'Mitigated',      value: mitigated, cls: 'text-emerald-600'},
        ].map(({ label, value, cls }) => (
          <Card key={label} className="px-5 py-4 text-center">
            <p className={`text-2xl font-bold tabular-nums ${cls}`}>{value}</p>
            <p className="text-xs text-gray-500 mt-0.5">{label}</p>
          </Card>
        ))}
      </div>

      {/* Create form */}
      {showForm && !editingItem && (
        <Card className="p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-900">New Risk Item</h3>
            <button onClick={() => setShowForm(false)} className="text-gray-400 hover:text-gray-600"><X size={16} /></button>
          </div>
          <RiskForm
            initial={EMPTY_FORM}
            onSave={(data) => createMutation.mutate(data)}
            onCancel={() => setShowForm(false)}
            saving={createMutation.isPending}
          />
        </Card>
      )}

      {/* Edit form */}
      {editingItem && (
        <Card className="p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-900">Edit Risk Item</h3>
            <button onClick={() => setEditingItem(null)} className="text-gray-400 hover:text-gray-600"><X size={16} /></button>
          </div>
          <RiskForm
            initial={{
              title: editingItem.title,
              description: editingItem.description,
              category: editingItem.category,
              likelihood: editingItem.likelihood,
              impact: editingItem.impact,
              status: editingItem.status,
              owner: editingItem.owner ?? '',
              dueDate: editingItem.dueDate ? editingItem.dueDate.split('T')[0] : '',
              provider: editingItem.provider ?? '',
              mitigationPlan: editingItem.mitigationPlan ?? '',
              acceptanceRationale: editingItem.acceptanceRationale ?? '',
            }}
            onSave={(data) => updateMutation.mutate({ id: editingItem.id, data })}
            onCancel={() => setEditingItem(null)}
            saving={updateMutation.isPending}
          />
        </Card>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <span className="text-xs text-gray-500 font-medium">Filter:</span>

        {/* Status */}
        <div className="flex gap-1">
          {(['', ...STATUSES] as (RiskStatus | '')[]).map((s) => (
            <button
              key={s}
              onClick={() => setFilterStatus(s)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                filterStatus === s
                  ? 'bg-gray-800 text-white'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {s || 'All Status'}
            </button>
          ))}
        </div>

        <span className="text-gray-200">|</span>

        {/* Category */}
        <select
          className="rounded border border-gray-300 px-2 py-1 text-xs text-gray-700 focus:outline-none"
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value as RiskCategory | '')}
        >
          <option value="">All Categories</option>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>

        {/* Provider */}
        <select
          className="rounded border border-gray-300 px-2 py-1 text-xs text-gray-700 focus:outline-none"
          value={filterProvider}
          onChange={(e) => setFilterProvider(e.target.value)}
        >
          <option value="">All Providers</option>
          <option value="AWS">AWS</option>
          <option value="AZURE">Azure</option>
          <option value="GCP">GCP</option>
        </select>

        <span className="ml-auto text-xs text-gray-400">{items.length} risk{items.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Risk list */}
      {isLoading ? (
        <div className="py-16 text-center text-sm text-gray-400">Loading risk register…</div>
      ) : items.length === 0 ? (
        <Card className="py-16 text-center">
          <ShieldAlert size={32} className="text-gray-300 mx-auto mb-3" />
          <p className="text-sm text-gray-500">No risks recorded yet.</p>
          <p className="text-xs text-gray-400 mt-1">Click "Add Risk" to create the first entry.</p>
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((item) => (
            <RiskRow
              key={item.id}
              item={item}
              onEdit={() => { setShowForm(false); setEditingItem(item); }}
              onDelete={() => {
                if (confirm(`Delete risk "${item.title}"?`)) deleteMutation.mutate(item.id);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

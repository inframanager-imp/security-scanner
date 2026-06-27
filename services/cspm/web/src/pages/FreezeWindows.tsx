import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { SnowflakeIcon, Plus, Trash2, Edit2, Clock, Power, PowerOff, Calendar, Info } from 'lucide-react';
import { freezeWindowsApi, type FreezeWindow } from '../api/enterprise';

// ─── Constants ────────────────────────────────────────────────────────────────

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const PROVIDERS = ['AWS', 'AZURE', 'GCP'];

const TIMEZONES = [
  'UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
  'America/Sao_Paulo', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow',
  'Asia/Dubai', 'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney',
];

// ─── Form state ───────────────────────────────────────────────────────────────

interface FreezeForm {
  name:       string;
  mode:       'recurring' | 'fixed';
  providers:  string[];
  targetIds:  string;
  daysOfWeek: number[];
  startTime:  string;
  endTime:    string;
  timezone:   string;
  fixedStart: string;
  fixedEnd:   string;
  isActive:   boolean;
}

const defaultForm = (): FreezeForm => ({
  name:       '',
  mode:       'recurring',
  providers:  [],
  targetIds:  '',
  daysOfWeek: [],
  startTime:  '22:00',
  endTime:    '06:00',
  timezone:   'UTC',
  fixedStart: '',
  fixedEnd:   '',
  isActive:   true,
});

function formToApi(form: FreezeForm): Omit<FreezeWindow, 'id' | 'createdAt' | 'updatedAt'> {
  return {
    name:       form.name,
    providers:  form.providers,
    targetIds:  form.targetIds ? form.targetIds.split(',').map((s) => s.trim()) : [],
    daysOfWeek: form.mode === 'recurring' ? form.daysOfWeek : [],
    startTime:  form.startTime,
    endTime:    form.endTime,
    timezone:   form.timezone,
    fixedStart: form.mode === 'fixed' && form.fixedStart ? form.fixedStart : null,
    fixedEnd:   form.mode === 'fixed' && form.fixedEnd   ? form.fixedEnd   : null,
    isActive:   form.isActive,
  };
}

function windowToForm(w: FreezeWindow): FreezeForm {
  return {
    name:       w.name,
    mode:       w.fixedStart ? 'fixed' : 'recurring',
    providers:  w.providers,
    targetIds:  w.targetIds.join(', '),
    daysOfWeek: w.daysOfWeek,
    startTime:  w.startTime,
    endTime:    w.endTime,
    timezone:   w.timezone,
    fixedStart: w.fixedStart ? new Date(w.fixedStart).toISOString().slice(0, 16) : '',
    fixedEnd:   w.fixedEnd   ? new Date(w.fixedEnd).toISOString().slice(0, 16)   : '',
    isActive:   w.isActive,
  };
}

// ─── Schedule display helpers ─────────────────────────────────────────────────

function scheduleLabel(w: FreezeWindow): string {
  if (w.fixedStart && w.fixedEnd) {
    return `${new Date(w.fixedStart).toLocaleString()} → ${new Date(w.fixedEnd).toLocaleString()}`;
  }
  const days = w.daysOfWeek.length === 0
    ? 'Every day'
    : w.daysOfWeek.map((d) => DAY_NAMES[d]).join(', ');
  const isOvernight = w.startTime > w.endTime;
  return `${days} · ${w.startTime}–${w.endTime}${isOvernight ? ' (overnight)' : ''} ${w.timezone}`;
}

// ─── Form component ───────────────────────────────────────────────────────────

function FreezeForm({
  initial,
  onSave,
  onCancel,
  isSaving,
}: {
  initial?: FreezeForm;
  onSave: (form: FreezeForm) => void;
  onCancel: () => void;
  isSaving: boolean;
}) {
  const [form, setForm] = useState<FreezeForm>(initial ?? defaultForm());

  const toggleArr = <T,>(arr: T[], val: T) =>
    arr.includes(val) ? arr.filter((x) => x !== val) : [...arr, val];

  return (
    <div className="space-y-5">
      {/* Name */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Name</label>
        <input
          className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
          value={form.name}
          onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          placeholder="e.g. Weekend Production Freeze"
        />
      </div>

      {/* Mode toggle */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2">Schedule Type</label>
        <div className="flex gap-2">
          {(['recurring', 'fixed'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setForm((f) => ({ ...f, mode }))}
              className={`px-4 py-2 rounded-lg text-sm font-medium border transition-colors ${
                form.mode === mode
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
              }`}
            >
              {mode === 'recurring' ? 'Weekly Recurring' : 'One-Time Fixed Range'}
            </button>
          ))}
        </div>
      </div>

      {form.mode === 'recurring' ? (
        <div className="space-y-4">
          {/* Days of week */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Days (empty = every day)
            </label>
            <div className="flex gap-2">
              {DAY_NAMES.map((d, i) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setForm((f) => ({ ...f, daysOfWeek: toggleArr(f.daysOfWeek, i) }))}
                  className={`w-10 h-10 rounded-full text-xs font-medium border transition-colors ${
                    form.daysOfWeek.includes(i)
                      ? 'bg-indigo-600 text-white border-indigo-600'
                      : 'bg-white text-gray-600 border-gray-300 hover:border-indigo-400'
                  }`}
                >
                  {d}
                </button>
              ))}
            </div>
          </div>

          {/* Time range */}
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Start Time</label>
              <input
                type="time"
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                value={form.startTime}
                onChange={(e) => setForm((f) => ({ ...f, startTime: e.target.value }))}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">End Time</label>
              <input
                type="time"
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                value={form.endTime}
                onChange={(e) => setForm((f) => ({ ...f, endTime: e.target.value }))}
              />
              {form.startTime > form.endTime && (
                <p className="text-xs text-amber-600 mt-1">Overnight window (crosses midnight)</p>
              )}
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Timezone</label>
              <select
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                value={form.timezone}
                onChange={(e) => setForm((f) => ({ ...f, timezone: e.target.value }))}
              >
                {TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
              </select>
            </div>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Start Date & Time</label>
            <input
              type="datetime-local"
              className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              value={form.fixedStart}
              onChange={(e) => setForm((f) => ({ ...f, fixedStart: e.target.value }))}
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">End Date & Time</label>
            <input
              type="datetime-local"
              className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              value={form.fixedEnd}
              onChange={(e) => setForm((f) => ({ ...f, fixedEnd: e.target.value }))}
            />
          </div>
        </div>
      )}

      {/* Scope */}
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
            placeholder="account-id-1, sub-id-2"
          />
        </div>
      </div>

      <label className="flex items-center gap-2 cursor-pointer">
        <input
          type="checkbox"
          checked={form.isActive}
          onChange={(e) => setForm((f) => ({ ...f, isActive: e.target.checked }))}
          className="rounded border-gray-300 text-blue-600"
        />
        <span className="text-sm text-gray-700">Active</span>
      </label>

      <div className="flex gap-3 pt-2">
        <button
          type="button"
          onClick={() => onSave(form)}
          disabled={isSaving || !form.name}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {isSaving ? 'Saving…' : 'Save Freeze Window'}
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

// ─── Window card ──────────────────────────────────────────────────────────────

function WindowCard({
  win,
  onEdit,
  onDelete,
  onToggle,
  isToggling,
}: {
  win: FreezeWindow;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: () => void;
  isToggling: boolean;
}) {
  const isFixed = !!(win.fixedStart && win.fixedEnd);

  return (
    <div className={`bg-white rounded-xl border shadow-sm overflow-hidden ${
      win.isActive ? 'border-indigo-200' : 'border-gray-200 opacity-70'
    }`}>
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <div className={`p-1.5 rounded-lg ${win.isActive ? 'bg-indigo-50 text-indigo-600' : 'bg-gray-100 text-gray-400'}`}>
              {isFixed ? <Calendar className="w-4 h-4" /> : <Clock className="w-4 h-4" />}
            </div>
            <div>
              <h3 className="font-medium text-gray-900 text-sm">{win.name}</h3>
              <p className="text-xs text-gray-500">{isFixed ? 'One-time' : 'Recurring weekly'}</p>
            </div>
          </div>
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
            win.isActive ? 'bg-indigo-100 text-indigo-700' : 'bg-gray-100 text-gray-500'
          }`}>
            {win.isActive ? 'Active' : 'Disabled'}
          </span>
        </div>

        <div className="mt-3 text-xs text-gray-600 bg-gray-50 rounded-lg p-2">
          {scheduleLabel(win)}
        </div>

        <div className="mt-2 flex flex-wrap gap-1.5">
          {win.providers.length > 0 && win.providers.map((p) => (
            <span key={p} className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs">{p}</span>
          ))}
          {win.providers.length === 0 && (
            <span className="px-2 py-0.5 bg-gray-100 text-gray-500 rounded text-xs">All providers</span>
          )}
          {win.targetIds.length > 0 && (
            <span className="px-2 py-0.5 bg-gray-100 text-gray-600 rounded text-xs">
              {win.targetIds.length} target{win.targetIds.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      <div className="border-t border-gray-100 px-4 py-2 flex gap-3 bg-gray-50">
        <button
          onClick={onToggle}
          disabled={isToggling}
          className={`flex items-center gap-1.5 text-xs transition-colors ${
            win.isActive ? 'text-amber-600 hover:text-amber-800' : 'text-green-600 hover:text-green-800'
          }`}
        >
          {win.isActive
            ? <><PowerOff className="w-3 h-3" /> Disable</>
            : <><Power    className="w-3 h-3" /> Enable</>
          }
        </button>
        <button
          onClick={onEdit}
          className="flex items-center gap-1.5 text-xs text-gray-600 hover:text-gray-800 transition-colors"
        >
          <Edit2 className="w-3 h-3" /> Edit
        </button>
        <button
          onClick={onDelete}
          className="flex items-center gap-1.5 text-xs text-red-500 hover:text-red-700 ml-auto transition-colors"
        >
          <Trash2 className="w-3 h-3" /> Delete
        </button>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function FreezeWindows() {
  const qc = useQueryClient();
  const [showForm, setShowForm]       = useState(false);
  const [editingId, setEditingId]     = useState<string | null>(null);
  const [editInitial, setEditInitial] = useState<FreezeForm | null>(null);
  const [togglingId, setTogglingId]   = useState<string | null>(null);

  const { data: windows = [], isLoading } = useQuery({
    queryKey: ['freeze-windows'],
    queryFn:  freezeWindowsApi.list,
  });

  const createMut = useMutation({
    mutationFn: (form: FreezeForm) => freezeWindowsApi.create(formToApi(form)),
    onSuccess:  () => { void qc.invalidateQueries({ queryKey: ['freeze-windows'] }); setShowForm(false); },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, form }: { id: string; form: FreezeForm }) =>
      freezeWindowsApi.update(id, formToApi(form)),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['freeze-windows'] });
      setEditingId(null); setEditInitial(null);
    },
  });

  const deleteMut = useMutation({
    mutationFn: freezeWindowsApi.delete,
    onSuccess:  () => { void qc.invalidateQueries({ queryKey: ['freeze-windows'] }); },
  });

  const handleToggle = async (id: string) => {
    setTogglingId(id);
    try {
      await freezeWindowsApi.toggle(id);
      void qc.invalidateQueries({ queryKey: ['freeze-windows'] });
    } finally {
      setTogglingId(null);
    }
  };

  const handleEdit = (win: FreezeWindow) => {
    setEditInitial(windowToForm(win));
    setEditingId(win.id);
    setShowForm(false);
  };

  const active   = windows.filter((w) => w.isActive);
  const inactive = windows.filter((w) => !w.isActive);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-50 rounded-xl">
            <SnowflakeIcon className="w-6 h-6 text-indigo-600" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">Change Freeze Windows</h1>
            <p className="text-sm text-gray-500">Define periods where infrastructure changes trigger violation alerts</p>
          </div>
        </div>
        <button
          onClick={() => { setShowForm(true); setEditingId(null); setEditInitial(null); }}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors"
        >
          <Plus className="w-4 h-4" /> New Freeze Window
        </button>
      </div>

      {/* Info bar */}
      <div className="flex items-start gap-2 bg-indigo-50 border border-indigo-100 rounded-lg p-3 mb-6 text-sm text-indigo-800">
        <Info className="w-4 h-4 mt-0.5 shrink-0" />
        <p>
          Freeze windows are <strong>detective</strong>, not preventive — changes are still recorded but flagged as
          <strong> freeze violations</strong> and trigger dedicated alerts. The posture score penalises each violation.
        </p>
      </div>

      {/* Stats */}
      {windows.length > 0 && (
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-white rounded-xl border border-gray-200 p-4 text-center">
            <p className="text-2xl font-bold text-gray-900">{windows.length}</p>
            <p className="text-xs text-gray-500 mt-1">Total Windows</p>
          </div>
          <div className="bg-white rounded-xl border border-indigo-200 p-4 text-center">
            <p className="text-2xl font-bold text-indigo-700">{active.length}</p>
            <p className="text-xs text-gray-500 mt-1">Active</p>
          </div>
          <div className="bg-white rounded-xl border border-gray-200 p-4 text-center">
            <p className="text-2xl font-bold text-gray-400">{inactive.length}</p>
            <p className="text-xs text-gray-500 mt-1">Disabled</p>
          </div>
        </div>
      )}

      {/* Create form */}
      {showForm && !editingId && (
        <div className="bg-white rounded-xl border border-indigo-200 shadow-sm p-6 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">New Freeze Window</h2>
          <FreezeForm
            onSave={(form) => createMut.mutate(form)}
            onCancel={() => setShowForm(false)}
            isSaving={createMut.isPending}
          />
        </div>
      )}

      {/* Edit form */}
      {editingId && editInitial && (
        <div className="bg-white rounded-xl border border-amber-200 shadow-sm p-6 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">Edit Freeze Window</h2>
          <FreezeForm
            initial={editInitial}
            onSave={(form) => updateMut.mutate({ id: editingId, form })}
            onCancel={() => { setEditingId(null); setEditInitial(null); }}
            isSaving={updateMut.isPending}
          />
        </div>
      )}

      {/* Window list */}
      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading freeze windows…</div>
      ) : windows.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <SnowflakeIcon className="w-10 h-10 mx-auto text-gray-300 mb-3" />
          <p className="font-medium text-gray-600">No freeze windows defined</p>
          <p className="text-sm mt-1">Create one to enforce change control policies.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {active.length > 0 && (
            <div>
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Active</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {active.map((w) => (
                  <WindowCard
                    key={w.id}
                    win={w}
                    onEdit={() => handleEdit(w)}
                    onDelete={() => { if (confirm(`Delete "${w.name}"?`)) deleteMut.mutate(w.id); }}
                    onToggle={() => void handleToggle(w.id)}
                    isToggling={togglingId === w.id}
                  />
                ))}
              </div>
            </div>
          )}
          {inactive.length > 0 && (
            <div>
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Disabled</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {inactive.map((w) => (
                  <WindowCard
                    key={w.id}
                    win={w}
                    onEdit={() => handleEdit(w)}
                    onDelete={() => { if (confirm(`Delete "${w.name}"?`)) deleteMut.mutate(w.id); }}
                    onToggle={() => void handleToggle(w.id)}
                    isToggling={togglingId === w.id}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText, Plus, Trash2, Edit2, Play, ExternalLink, CheckCircle, XCircle, Clock } from 'lucide-react';
import { reportSchedulesApi, type ReportSchedule } from '../api/enterprise';

// ─── Constants ────────────────────────────────────────────────────────────────

const FREQUENCIES = ['DAILY', 'WEEKLY', 'MONTHLY', 'ON_DEMAND'];
const DAY_NAMES   = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const SECTIONS    = [
  { key: 'SUMMARY',         label: 'Executive Summary' },
  { key: 'CONFIG_CHANGES',  label: 'Config Changes' },
  { key: 'DRIFT',           label: 'Drift Detection' },
  { key: 'IAM_ESCALATION',  label: 'IAM Escalation' },
  { key: 'POSTURE',         label: 'Posture Scores' },
];

// ─── Form state ───────────────────────────────────────────────────────────────

interface FormState {
  name:       string;
  provider:   string;
  targetId:   string;
  frequency:  string;
  dayOfWeek:  number;
  dayOfMonth: number;
  hour:       number;
  sections:   string[];
  recipients: string;
  isActive:   boolean;
}

const defaultForm = (): FormState => ({
  name:       '',
  provider:   '',
  targetId:   '',
  frequency:  'WEEKLY',
  dayOfWeek:  1,
  dayOfMonth: 1,
  hour:       8,
  sections:   ['SUMMARY', 'CONFIG_CHANGES', 'POSTURE'],
  recipients: '',
  isActive:   true,
});

function scheduleToForm(s: ReportSchedule): FormState {
  return {
    name:       s.name,
    provider:   s.provider ?? '',
    targetId:   s.targetId ?? '',
    frequency:  s.frequency,
    dayOfWeek:  s.dayOfWeek  ?? 1,
    dayOfMonth: s.dayOfMonth ?? 1,
    hour:       s.hour,
    sections:   s.sections,
    recipients: s.recipients.join(', '),
    isActive:   s.isActive,
  };
}

function formToPayload(f: FormState) {
  return {
    name:       f.name,
    provider:   f.provider  || undefined,
    targetId:   f.targetId  || undefined,
    frequency:  f.frequency,
    dayOfWeek:  f.frequency === 'WEEKLY'  ? f.dayOfWeek  : undefined,
    dayOfMonth: f.frequency === 'MONTHLY' ? f.dayOfMonth : undefined,
    hour:       f.hour,
    sections:   f.sections,
    recipients: f.recipients.split(',').map((s) => s.trim()).filter(Boolean),
    isActive:   f.isActive,
  };
}

function nextRunLabel(s: ReportSchedule): string {
  if (s.frequency === 'ON_DEMAND') return 'On demand only';
  if (!s.nextRunAt) return '—';
  return new Date(s.nextRunAt).toLocaleString();
}

// ─── Schedule form ────────────────────────────────────────────────────────────

function ScheduleForm({
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

  const toggleSection = (key: string) =>
    setForm((f) => ({
      ...f,
      sections: f.sections.includes(key)
        ? f.sections.filter((s) => s !== key)
        : [...f.sections, key],
    }));

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-600 mb-1">Report Name</label>
          <input
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. Weekly Security Report — Production AWS"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Provider (optional)</label>
          <select
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
            value={form.provider}
            onChange={(e) => setForm((f) => ({ ...f, provider: e.target.value }))}
          >
            <option value="">All providers</option>
            {['AWS', 'AZURE', 'GCP'].map((p) => <option key={p}>{p}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Target ID (optional)</label>
          <input
            className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
            value={form.targetId}
            onChange={(e) => setForm((f) => ({ ...f, targetId: e.target.value }))}
            placeholder="Account / Subscription ID"
          />
        </div>
      </div>

      {/* Frequency */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-2">Frequency</label>
        <div className="flex gap-2">
          {FREQUENCIES.map((freq) => (
            <button
              key={freq}
              type="button"
              onClick={() => setForm((f) => ({ ...f, frequency: freq }))}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                form.frequency === freq
                  ? 'bg-blue-600 text-white border-blue-600'
                  : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
              }`}
            >
              {freq.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Schedule details */}
      {form.frequency !== 'ON_DEMAND' && (
        <div className="grid grid-cols-3 gap-4">
          {form.frequency === 'WEEKLY' && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Day of Week</label>
              <div className="flex gap-1 flex-wrap">
                {DAY_NAMES.map((d, i) => (
                  <button
                    key={d}
                    type="button"
                    onClick={() => setForm((f) => ({ ...f, dayOfWeek: i }))}
                    className={`w-9 h-9 rounded-full text-xs font-medium border transition-colors ${
                      form.dayOfWeek === i
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-600 border-gray-300'
                    }`}
                  >
                    {d}
                  </button>
                ))}
              </div>
            </div>
          )}
          {form.frequency === 'MONTHLY' && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Day of Month</label>
              <input
                type="number" min={1} max={28}
                className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                value={form.dayOfMonth}
                onChange={(e) => setForm((f) => ({ ...f, dayOfMonth: parseInt(e.target.value) || 1 }))}
              />
            </div>
          )}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Hour (UTC)</label>
            <input
              type="number" min={0} max={23}
              className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              value={form.hour}
              onChange={(e) => setForm((f) => ({ ...f, hour: parseInt(e.target.value) || 0 }))}
            />
          </div>
        </div>
      )}

      {/* Sections */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-2">Report Sections</label>
        <div className="flex flex-wrap gap-2">
          {SECTIONS.map((s) => (
            <button
              key={s.key}
              type="button"
              onClick={() => toggleSection(s.key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                form.sections.includes(s.key)
                  ? 'bg-purple-600 text-white border-purple-600'
                  : 'bg-white text-gray-600 border-gray-300 hover:border-purple-400'
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Recipients */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Email Recipients (comma separated)</label>
        <input
          className="w-full border rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
          value={form.recipients}
          onChange={(e) => setForm((f) => ({ ...f, recipients: e.target.value }))}
          placeholder="security@company.com, ciso@company.com"
        />
        <p className="text-xs text-gray-400 mt-1">Leave empty to generate without email delivery (preview-only).</p>
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

      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => onSave(form)}
          disabled={isSaving || !form.name || form.sections.length === 0}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {isSaving ? 'Saving…' : 'Save Schedule'}
        </button>
        <button type="button" onClick={onCancel} className="px-4 py-2 bg-white border border-gray-300 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors">Cancel</button>
      </div>
    </div>
  );
}

// ─── Schedule card ────────────────────────────────────────────────────────────

function ScheduleCard({
  schedule,
  onEdit,
  onDelete,
}: {
  schedule: ReportSchedule;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const [running, setRunning] = useState(false);

  const handleRun = async () => {
    setRunning(true);
    try {
      await reportSchedulesApi.run(schedule.id);
      // Open preview in new tab
      window.open(reportSchedulesApi.preview(schedule.id), '_blank');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="font-medium text-gray-900 text-sm">{schedule.name}</h3>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-xs text-gray-500">{schedule.frequency.replace('_', ' ')}</span>
              {schedule.provider && (
                <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                  schedule.provider === 'AWS' ? 'bg-orange-100 text-orange-700' :
                  schedule.provider === 'AZURE' ? 'bg-blue-100 text-blue-700' :
                  'bg-green-100 text-green-700'
                }`}>{schedule.provider}</span>
              )}
            </div>
          </div>
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
            schedule.isActive ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
          }`}>
            {schedule.isActive ? 'Active' : 'Disabled'}
          </span>
        </div>

        <div className="mt-3 flex flex-wrap gap-1.5">
          {schedule.sections.map((s) => (
            <span key={s} className="px-2 py-0.5 bg-purple-50 text-purple-700 rounded text-xs">
              {SECTIONS.find((ss) => ss.key === s)?.label ?? s}
            </span>
          ))}
        </div>

        {schedule.recipients.length > 0 && (
          <p className="mt-2 text-xs text-gray-500 truncate">
            To: {schedule.recipients.join(', ')}
          </p>
        )}

        <div className="flex items-center gap-3 mt-3 text-xs text-gray-400">
          <Clock className="w-3 h-3" />
          {schedule.lastRunAt
            ? `Last: ${new Date(schedule.lastRunAt).toLocaleString()}`
            : 'Never run'}
          {schedule.nextRunAt && (
            <span>· Next: {new Date(schedule.nextRunAt).toLocaleString()}</span>
          )}
        </div>
      </div>

      <div className="border-t border-gray-100 px-4 py-2 flex gap-3 bg-gray-50">
        <button
          onClick={() => void handleRun()}
          disabled={running}
          className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-800 disabled:opacity-50 transition-colors"
        >
          <Play className="w-3 h-3" /> {running ? 'Generating…' : 'Preview Now'}
        </button>
        <a
          href={reportSchedulesApi.preview(schedule.id)}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1.5 text-xs text-gray-600 hover:text-gray-800 transition-colors"
        >
          <ExternalLink className="w-3 h-3" /> Open
        </a>
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

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ScheduledReports() {
  const qc = useQueryClient();
  const [showForm, setShowForm]       = useState(false);
  const [editingId, setEditingId]     = useState<string | null>(null);
  const [editInitial, setEditInitial] = useState<FormState | null>(null);

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['report-schedules'],
    queryFn:  reportSchedulesApi.list,
  });

  const createMut = useMutation({
    mutationFn: (f: FormState) => reportSchedulesApi.create(formToPayload(f) as Parameters<typeof reportSchedulesApi.create>[0]),
    onSuccess:  () => { void qc.invalidateQueries({ queryKey: ['report-schedules'] }); setShowForm(false); },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, f }: { id: string; f: FormState }) =>
      reportSchedulesApi.update(id, formToPayload(f)),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['report-schedules'] });
      setEditingId(null); setEditInitial(null);
    },
  });

  const deleteMut = useMutation({
    mutationFn: reportSchedulesApi.delete,
    onSuccess:  () => void qc.invalidateQueries({ queryKey: ['report-schedules'] }),
  });

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-50 rounded-xl">
            <FileText className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-900">Scheduled Reports</h1>
            <p className="text-sm text-gray-500">Automated HTML security reports delivered by email · open in browser to print as PDF</p>
          </div>
        </div>
        <button
          onClick={() => { setShowForm(true); setEditingId(null); }}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-4 h-4" /> New Schedule
        </button>
      </div>

      {/* Create form */}
      {showForm && !editingId && (
        <div className="bg-white rounded-xl border border-blue-200 shadow-sm p-5 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">New Report Schedule</h2>
          <ScheduleForm
            onSave={(f) => createMut.mutate(f)}
            onCancel={() => setShowForm(false)}
            isSaving={createMut.isPending}
          />
        </div>
      )}

      {/* Edit form */}
      {editingId && editInitial && (
        <div className="bg-white rounded-xl border border-amber-200 shadow-sm p-5 mb-6">
          <h2 className="text-sm font-semibold text-gray-800 mb-4">Edit Report Schedule</h2>
          <ScheduleForm
            initial={editInitial}
            onSave={(f) => updateMut.mutate({ id: editingId, f })}
            onCancel={() => { setEditingId(null); setEditInitial(null); }}
            isSaving={updateMut.isPending}
          />
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading schedules…</div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <FileText className="w-10 h-10 mx-auto text-gray-300 mb-3" />
          <p className="font-medium text-gray-600">No report schedules configured</p>
          <p className="text-sm mt-1">Create a schedule to automate security report delivery.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {schedules.map((s) => (
            <ScheduleCard
              key={s.id}
              schedule={s}
              onEdit={() => { setEditInitial(scheduleToForm(s)); setEditingId(s.id); setShowForm(false); }}
              onDelete={() => { if (confirm(`Delete "${s.name}"?`)) deleteMut.mutate(s.id); }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

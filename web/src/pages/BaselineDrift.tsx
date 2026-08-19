import { useState, useMemo, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  GitCompareArrows, Plus, Trash2, RefreshCw, ChevronDown,
  CheckCircle, Search, X, RotateCcw, Clock, ShieldAlert, History,
  CheckSquare, XCircle, GitMerge, AlertTriangle, Terminal, ArrowLeftRight,
  Bell, User, Layers, Eye, ArrowRight, Zap,
  BookOpen, Shield, Activity, Database, Lock, Pause,
} from 'lucide-react';
import {
  baselinesApi, approvalsApi,
  type BaselineSummary, type DriftResult,
  type BaselineVersionSummary, type VersionCompareResult,
} from '../api/enterprise';
import { accountsApi }          from '../api/accounts';
import { azureApi }             from '../api/azure';
import { gcpApi }               from '../api/gcp';
import { resourceInventoryApi } from '../api/resourceInventory';

// ─── Diff helpers ─────────────────────────────────────────────────────────────
function getNestedValue(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let cur: unknown = obj;
  for (const p of parts) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}
function formatVal(v: unknown): string {
  if (v === undefined) return '(not set)';
  if (v === null)      return 'null';
  if (typeof v === 'object') { const s = JSON.stringify(v); return s.length > 300 ? s.slice(0, 300) + '…' : s; }
  return String(v);
}

// ─── Constants ────────────────────────────────────────────────────────────────
const DRIFT_TYPE_CONFIG = {
  ADDED:    { label: 'Added',    color: 'text-emerald-700 bg-emerald-50 border-emerald-200', dot: 'bg-emerald-500', row: 'border-l-emerald-400' },
  MODIFIED: { label: 'Modified', color: 'text-amber-700 bg-amber-50 border-amber-200',       dot: 'bg-amber-500',   row: 'border-l-amber-400'   },
  DELETED:  { label: 'Deleted',  color: 'text-red-700 bg-red-50 border-red-200',             dot: 'bg-red-500',     row: 'border-l-red-400'     },
};
const SEV_CONFIG: Record<string, { bg: string; text: string; dot: string; bar: string }> = {
  CRITICAL: { bg: 'bg-red-50',     text: 'text-red-700',    dot: 'bg-red-500',    bar: 'bg-red-500' },
  HIGH:     { bg: 'bg-orange-50',  text: 'text-orange-700', dot: 'bg-orange-500', bar: 'bg-orange-500' },
  MEDIUM:   { bg: 'bg-yellow-50',  text: 'text-yellow-700', dot: 'bg-yellow-400', bar: 'bg-yellow-400' },
  LOW:      { bg: 'bg-blue-50',    text: 'text-blue-600',   dot: 'bg-blue-400',   bar: 'bg-blue-400' },
};
const STATUS_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
  OPEN:         { label: 'Open',         color: 'text-red-600 bg-red-50 border-red-200',         icon: '●' },
  ACKNOWLEDGED: { label: 'Acknowledged', color: 'text-amber-700 bg-amber-50 border-amber-200',   icon: '◐' },
  RESOLVED:     { label: 'Resolved',     color: 'text-green-700 bg-green-50 border-green-200',   icon: '✓' },
  REVERTED:     { label: 'Reverted',     color: 'text-purple-700 bg-purple-50 border-purple-200', icon: '↩' },
  SUPPRESSED:   { label: 'Suppressed',   color: 'text-slate-700 bg-slate-100 border-slate-200',   icon: '⏸' },
  CLOSED:       { label: 'Closed',       color: 'text-gray-600 bg-gray-100 border-gray-200',      icon: '⊘' },
};
const DOMAIN_LABEL: Record<string, string> = {
  IAM:                 'IAM',
  NETWORK:             'Network',
  DATA_PROTECTION:     'Data Protection',
  LOGGING_MONITORING:  'Logging & Monitoring',
  WORKLOAD_HARDENING:  'Workload Hardening',
  OTHER:               'Other',
};
const PROVIDER_CONFIG: Record<string, { bg: string; text: string; icon: string }> = {
  AWS:   { bg: 'bg-orange-100', text: 'text-orange-700', icon: '☁' },
  AZURE: { bg: 'bg-blue-100',   text: 'text-blue-700',   icon: '⬡' },
  GCP:   { bg: 'bg-green-100',  text: 'text-green-700',  icon: '◈' },
};

function SevBadge({ sev }: { sev: string }) {
  const c = SEV_CONFIG[sev] ?? { bg: 'bg-gray-50', text: 'text-gray-600', dot: 'bg-gray-400' };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold border ${c.bg} ${c.text} border-${sev === 'CRITICAL' ? 'red' : sev === 'HIGH' ? 'orange' : sev === 'MEDIUM' ? 'yellow' : 'blue'}-200`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {sev}
    </span>
  );
}

// ─── Drift detail diff view ───────────────────────────────────────────────────
function DriftDiffView({ baselineId, driftId, driftType, driftedFields }: {
  baselineId: string; driftId: string; driftType: string; driftedFields: string[];
}) {
  const [view, setView] = useState<'fields' | 'full'>('fields');
  const { data, isLoading } = useQuery({
    queryKey: ['drift-detail', baselineId, driftId],
    queryFn:  () => baselinesApi.driftDetail(baselineId, driftId),
    staleTime: 60_000,
  });
  if (isLoading) return <div className="p-6 text-center text-sm text-gray-400 animate-pulse">Loading configuration diff…</div>;
  if (!data) return null;

  return (
    <div className="p-4 bg-gray-50 border-t border-gray-200">
      <div className="flex items-center gap-4 mb-4 text-xs text-gray-500">
        <span className="font-mono bg-white border border-gray-200 px-2 py-1 rounded truncate max-w-xs" title={data.nativeId}>{data.nativeId}</span>
        {data.firstDetectedAt    && <span>First detected: <strong className="text-gray-700">{new Date(data.firstDetectedAt).toLocaleString()}</strong></span>}
        {data.baselineCapturedAt && <span>Baseline taken: <strong className="text-gray-700">{new Date(data.baselineCapturedAt).toLocaleString()}</strong></span>}
        {data.currentLastSeenAt  && driftType === 'DELETED' && <span>Last seen in inventory: <strong className="text-red-600">{new Date(data.currentLastSeenAt).toLocaleString()}</strong></span>}
        {data.currentLastSeenAt  && driftType !== 'DELETED' && <span>Last synced: <strong className="text-gray-700">{new Date(data.currentLastSeenAt).toLocaleString()}</strong></span>}
      </div>

      {driftType === 'MODIFIED' && (
        <>
          {driftedFields.length > 0 && (
            <div className="flex gap-1 mb-3">
              <button onClick={() => setView('fields')}
                className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${view === 'fields' ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-gray-500 border-gray-200 hover:border-gray-300'}`}>
                Changed Fields ({driftedFields.length})
              </button>
              <button onClick={() => setView('full')}
                className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${view === 'full' ? 'bg-indigo-600 text-white border-indigo-600' : 'bg-white text-gray-500 border-gray-200 hover:border-gray-300'}`}>
                Full Config
              </button>
            </div>
          )}
          {view === 'fields' && driftedFields.length > 0 && (
            <div className="space-y-2">
              {driftedFields.map((field) => (
                <div key={field} className="bg-white rounded-lg border border-gray-200 overflow-hidden shadow-sm">
                  <div className="px-3 py-1.5 bg-gray-50 border-b border-gray-200 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                    <code className="text-xs font-semibold text-gray-600">{field}</code>
                  </div>
                  <div className="grid grid-cols-2 divide-x divide-gray-100">
                    <div className="p-3 bg-red-50/40">
                      <p className="text-[9px] font-bold text-red-400 uppercase tracking-wider mb-1">Before (Baseline)</p>
                      <p className="font-mono text-xs text-red-800 break-all leading-relaxed">{formatVal(getNestedValue(data.baselineConfig, field))}</p>
                    </div>
                    <div className="p-3 bg-green-50/40">
                      <p className="text-[9px] font-bold text-green-500 uppercase tracking-wider mb-1">After (Current)</p>
                      <p className="font-mono text-xs text-green-800 break-all leading-relaxed">{formatVal(getNestedValue(data.currentConfig, field))}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
          {(view === 'full' || driftedFields.length === 0) && (
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-white rounded-lg border border-red-200 overflow-hidden shadow-sm">
                <div className="px-3 py-2 bg-red-50 border-b border-red-100 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-400" />
                  <span className="text-xs font-semibold text-red-700">Baseline Config (Before)</span>
                </div>
                <pre className="p-3 text-xs text-gray-700 overflow-auto max-h-64 whitespace-pre-wrap leading-relaxed">{data.baselineConfig ? JSON.stringify(data.baselineConfig, null, 2) : '(none)'}</pre>
              </div>
              <div className="bg-white rounded-lg border border-green-200 overflow-hidden shadow-sm">
                <div className="px-3 py-2 bg-green-50 border-b border-green-100 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-green-400" />
                  <span className="text-xs font-semibold text-green-700">Current Config (After)</span>
                </div>
                <pre className="p-3 text-xs text-gray-700 overflow-auto max-h-64 whitespace-pre-wrap leading-relaxed">{data.currentConfig ? JSON.stringify(data.currentConfig, null, 2) : '(none)'}</pre>
              </div>
            </div>
          )}
        </>
      )}

      {driftType === 'DELETED' && (
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-white rounded-lg border border-red-200 overflow-hidden shadow-sm">
            <div className="px-3 py-2 bg-red-50 border-b border-red-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-400" /><span className="text-xs font-semibold text-red-700">Was Present (Baseline)</span>
            </div>
            <pre className="p-3 text-xs text-gray-700 overflow-auto max-h-64 whitespace-pre-wrap leading-relaxed">{data.baselineConfig ? JSON.stringify(data.baselineConfig, null, 2) : '(none)'}</pre>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden shadow-sm flex items-center justify-center min-h-32">
            <div className="text-center text-gray-400">
              <Trash2 className="w-8 h-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm">Resource no longer exists</p>
            </div>
          </div>
        </div>
      )}

      {driftType === 'ADDED' && (
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden shadow-sm flex items-center justify-center min-h-32">
            <div className="text-center text-gray-400">
              <BookOpen className="w-8 h-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm">Not in baseline snapshot</p>
            </div>
          </div>
          <div className="bg-white rounded-lg border border-green-200 overflow-hidden shadow-sm">
            <div className="px-3 py-2 bg-green-50 border-b border-green-100 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-400" /><span className="text-xs font-semibold text-green-700">New Resource Config</span>
            </div>
            <pre className="p-3 text-xs text-gray-700 overflow-auto max-h-64 whitespace-pre-wrap leading-relaxed">{data.currentConfig ? JSON.stringify(data.currentConfig, null, 2) : '(none)'}</pre>
          </div>
        </div>
      )}

      <RelatedControlsPanel baselineId={baselineId} driftId={driftId} />
    </div>
  );
}

// ─── Related compliance controls (BCDD-F13) ────────────────────────────────────
function RelatedControlsPanel({ baselineId, driftId }: { baselineId: string; driftId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['related-controls', baselineId, driftId],
    queryFn:  () => baselinesApi.relatedControls(baselineId, driftId),
    staleTime: 60_000,
  });

  if (isLoading) return null;
  if (!data || data.related.length === 0) return null;

  return (
    <div className="mt-4 pt-4 border-t border-gray-200">
      <p className="text-xs font-semibold text-gray-700 mb-1 flex items-center gap-1.5">
        <Shield className="w-3.5 h-3.5 text-indigo-500" /> Related Compliance Controls
      </p>
      <p className="text-[10px] text-gray-400 mb-2">
        Controls in the same domain ({DOMAIN_LABEL[data.controlDomain] ?? data.controlDomain}) worth reviewing for
        this resource — a relevance ranking, not a certified violation mapping.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {data.related.map((c) => (
          <span key={`${c.frameworkId}:${c.controlId}`}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-indigo-50 border border-indigo-100 text-[11px]"
            title={c.controlDescription}>
            <span className="font-bold text-indigo-700">{c.frameworkShortName}</span>
            <span className="text-indigo-600">{c.controlName}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── Revert request dialog ────────────────────────────────────────────────────
function RevertDialog({ baselineId, drift, onClose }: {
  baselineId: string; drift: DriftResult; onClose: () => void;
}) {
  const qc = useQueryClient();
  const [email, setEmail]     = useState('');
  const [name, setName]       = useState('');
  const [notes, setNotes]     = useState('');
  const [immediate, setImmediate] = useState(false);
  const [done, setDone]       = useState<string | null>(null);

  const { data: plan, isLoading: planLoading } = useQuery({
    queryKey: ['revert-plan', baselineId, drift.id],
    queryFn:  () => baselinesApi.revertPlan(baselineId, drift.id),
    staleTime: 5 * 60_000,
  });

  const revertMut = useMutation({
    mutationFn: () => baselinesApi.requestRevert(baselineId, drift.id, {
      requestedBy: email, requestedByName: name || undefined, notes: notes || undefined, immediate,
    }),
    onSuccess: (data) => {
      setDone(data.message);
      void qc.invalidateQueries({ queryKey: ['drift', baselineId] });
      void qc.invalidateQueries({ queryKey: ['approvals'] });
    },
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-5 border-b border-gray-100">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-amber-100 flex items-center justify-center">
              <RotateCcw className="w-4 h-4 text-amber-600" />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 text-sm">Request Config Revert</h3>
              <p className="text-xs text-gray-500 mt-0.5">{drift.resourceName ?? drift.nativeId}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded-lg transition-colors"><X className="w-4 h-4 text-gray-400" /></button>
        </div>

        {done ? (
          <div className="p-6">
            <div className="flex items-start gap-3 bg-green-50 border border-green-200 rounded-xl p-4">
              <CheckCircle className="w-5 h-5 text-green-600 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-green-800">{done}</p>
                <p className="text-xs text-green-600 mt-1">Check the Approval Queue to review and execute this request.</p>
              </div>
            </div>
            <button onClick={onClose} className="mt-4 w-full py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm font-medium text-gray-700 transition-colors">Close</button>
          </div>
        ) : (
          <div className="p-5 space-y-4">
            {planLoading ? (
              <div className="h-24 bg-gray-50 rounded-xl animate-pulse" />
            ) : plan ? (
              <div className="space-y-3">
                <div className={`flex items-center gap-3 p-3 rounded-xl border ${
                  plan.riskLevel === 'HIGH' ? 'bg-red-50 border-red-200' :
                  plan.riskLevel === 'MEDIUM' ? 'bg-amber-50 border-amber-200' : 'bg-blue-50 border-blue-200'}`}>
                  <ShieldAlert className={`w-5 h-5 shrink-0 ${plan.riskLevel === 'HIGH' ? 'text-red-600' : plan.riskLevel === 'MEDIUM' ? 'text-amber-600' : 'text-blue-600'}`} />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-bold ${plan.riskLevel === 'HIGH' ? 'text-red-700' : plan.riskLevel === 'MEDIUM' ? 'text-amber-700' : 'text-blue-700'}`}>{plan.riskLevel} RISK</span>
                      <span className="text-gray-300">·</span>
                      <span className="text-xs text-gray-600">{plan.canAutoRevert ? '✓ Auto-revert supported' : '⚠ Manual script required'}</span>
                    </div>
                    <p className="text-xs text-gray-600 mt-0.5">{plan.description}</p>
                  </div>
                </div>

                <div className="bg-gray-50 rounded-xl p-3 space-y-1">
                  <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">Execution Steps</p>
                  {plan.steps.map((s, i) => (
                    <div key={i} className="flex gap-2 text-xs text-gray-700">
                      <span className="w-4 h-4 rounded-full bg-indigo-100 text-indigo-600 font-bold flex items-center justify-center text-[9px] shrink-0 mt-0.5">{i + 1}</span>
                      {s}
                    </div>
                  ))}
                </div>

                {plan.warnings.map((w, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" /> {w}
                  </div>
                ))}

                {plan.remediationScript && (
                  <details className="text-xs">
                    <summary className="cursor-pointer text-gray-500 hover:text-gray-700 flex items-center gap-1.5 font-medium">
                      <Terminal className="w-3.5 h-3.5" /> View remediation script
                    </summary>
                    <pre className="mt-2 bg-gray-900 text-green-400 rounded-xl p-4 overflow-auto max-h-40 text-[10px] leading-relaxed whitespace-pre-wrap">{plan.remediationScript}</pre>
                  </details>
                )}
              </div>
            ) : null}

            <div className="border-t border-gray-100 pt-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Your Email *</label>
                  <input className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                    value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Your Name</label>
                  <input className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                    value={name} onChange={(e) => setName(e.target.value)} placeholder="Optional" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Reason for Revert</label>
                <textarea rows={2} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none resize-none"
                  value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Why is this revert needed?" />
              </div>
              {plan?.canAutoRevert && (
                <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer bg-gray-50 rounded-lg p-3">
                  <input type="checkbox" checked={immediate} onChange={(e) => setImmediate(e.target.checked)} className="rounded border-gray-300 text-indigo-600" />
                  <span><strong>Execute immediately</strong> — bypass approval gate (dev/non-prod only)</span>
                </label>
              )}
              <div className="flex gap-2 pt-1">
                <button onClick={() => revertMut.mutate()} disabled={!email || revertMut.isPending}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-amber-600 text-white rounded-xl text-sm font-semibold hover:bg-amber-700 disabled:opacity-50 transition-colors">
                  <RotateCcw className="w-4 h-4" />
                  {revertMut.isPending ? 'Submitting…' : immediate ? 'Execute Revert Now' : 'Submit for Approval'}
                </button>
                <button onClick={onClose} className="px-4 py-2.5 bg-gray-100 text-gray-700 rounded-xl text-sm font-medium hover:bg-gray-200 transition-colors">Cancel</button>
              </div>
              {revertMut.isError && <p className="text-xs text-red-600">{(revertMut.error as Error).message}</p>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Drift Results Table ──────────────────────────────────────────────────────
function DriftTable({ baselineId }: { baselineId: string }) {
  const [page, setPage]             = useState(1);
  const [status, setStatus]         = useState('OPEN');
  const [sevFilter, setSevFilter]   = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [domainFilter, setDomainFilter] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [revertDrift, setRevertDrift] = useState<DriftResult | null>(null);
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey:        ['drift', baselineId, page, status, domainFilter],
    queryFn:         () => baselinesApi.drift(baselineId, page, 20, status, domainFilter || undefined),
    refetchInterval: 30_000,
  });

  const [suppressTarget, setSuppressTarget] = useState<DriftResult | null>(null);

  const patchMut = useMutation({
    mutationFn: ({ driftId, s, opts }: { driftId: string; s: string; opts?: { suppressionReason?: string; suppressionExpiresAt?: string } }) =>
      baselinesApi.updateDrift(baselineId, driftId, s, opts),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['drift', baselineId] }),
  });

  const filteredResults = useMemo(() => {
    if (!data?.results) return [];
    return data.results.filter((d) => {
      if (sevFilter  && d.severity  !== sevFilter)  return false;
      if (typeFilter && d.driftType !== typeFilter)  return false;
      return true;
    });
  }, [data?.results, sevFilter, typeFilter]);

  const counts = useMemo(() => {
    const r = data?.results ?? [];
    return {
      CRITICAL: r.filter((x) => x.severity === 'CRITICAL').length,
      HIGH:     r.filter((x) => x.severity === 'HIGH').length,
      ADDED:    r.filter((x) => x.driftType === 'ADDED').length,
      MODIFIED: r.filter((x) => x.driftType === 'MODIFIED').length,
      DELETED:  r.filter((x) => x.driftType === 'DELETED').length,
    };
  }, [data?.results]);

  return (
    <div>
      <div className="flex items-center gap-1 mb-4 bg-gray-100 rounded-xl p-1">
        {['OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'REVERTED', 'SUPPRESSED', 'CLOSED', 'ALL'].map((s) => (
          <button key={s} onClick={() => { setStatus(s); setPage(1); }}
            className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-colors ${status === s ? 'bg-white shadow-sm text-gray-900' : 'text-gray-500 hover:text-gray-700'}`}>
            {s === 'REVERTED' ? '↩ Reverted' : s === 'ALL' ? 'All' : STATUS_CONFIG[s]?.label ?? s}
          </button>
        ))}
        <span className="ml-2 text-xs text-gray-400 shrink-0 px-2">{data?.total ?? 0} total</span>
      </div>

      <div className="flex items-center gap-3 mb-4 flex-wrap">
        {counts.CRITICAL > 0 && (
          <button onClick={() => setSevFilter(sevFilter === 'CRITICAL' ? '' : 'CRITICAL')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border transition-colors ${sevFilter === 'CRITICAL' ? 'bg-red-600 text-white border-red-600' : 'bg-red-50 text-red-700 border-red-200 hover:bg-red-100'}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-red-500" /> {counts.CRITICAL} Critical
          </button>
        )}
        {counts.HIGH > 0 && (
          <button onClick={() => setSevFilter(sevFilter === 'HIGH' ? '' : 'HIGH')}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border transition-colors ${sevFilter === 'HIGH' ? 'bg-orange-500 text-white border-orange-500' : 'bg-orange-50 text-orange-700 border-orange-200 hover:bg-orange-100'}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-orange-500" /> {counts.HIGH} High
          </button>
        )}
        <div className="flex items-center gap-1 ml-auto">
          <select value={domainFilter} onChange={(e) => { setDomainFilter(e.target.value); setPage(1); }}
            className="px-2.5 py-1 rounded-lg text-xs font-medium border border-gray-200 bg-white text-gray-600 focus:ring-2 focus:ring-indigo-500 focus:outline-none">
            <option value="">All Domains</option>
            {['IAM', 'NETWORK', 'DATA_PROTECTION', 'LOGGING_MONITORING', 'WORKLOAD_HARDENING', 'OTHER'].map((d) => (
              <option key={d} value={d}>{DOMAIN_LABEL[d] ?? d}</option>
            ))}
          </select>
          {['ADDED', 'MODIFIED', 'DELETED'].map((t) => (
            <button key={t} onClick={() => setTypeFilter(typeFilter === t ? '' : t)}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors ${typeFilter === t ? 'bg-gray-800 text-white border-gray-800' : 'bg-white text-gray-600 border-gray-200 hover:border-gray-300'}`}>
              {t === 'ADDED' ? `+${counts.ADDED}` : t === 'MODIFIED' ? `~${counts.MODIFIED}` : `-${counts.DELETED}`} {t.charAt(0) + t.slice(1).toLowerCase()}
            </button>
          ))}
          {(sevFilter || typeFilter || domainFilter) && (
            <button onClick={() => { setSevFilter(''); setTypeFilter(''); setDomainFilter(''); }} className="px-2 py-1 text-xs text-indigo-600 hover:text-indigo-800 font-medium flex items-center gap-1">
              <X className="w-3 h-3" /> Clear
            </button>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[...Array(4)].map((_, i) => <div key={i} className="h-14 bg-gray-100 rounded-xl animate-pulse" />)}
        </div>
      ) : filteredResults.length === 0 ? (
        <div className="py-12 text-center">
          <CheckCircle className="w-12 h-12 text-green-300 mx-auto mb-3" />
          <p className="font-medium text-gray-600">No {status.toLowerCase()} drift items</p>
          <p className="text-sm text-gray-400 mt-1">Your baseline is clean</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-12 gap-3 px-4 py-2 text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-1">
            <div className="col-span-1">Type</div>
            <div className="col-span-4">Resource</div>
            <div className="col-span-2">Resource Type</div>
            <div className="col-span-1">Severity</div>
            <div className="col-span-2">Changed Fields</div>
            <div className="col-span-1">Detected</div>
            <div className="col-span-1">Actions</div>
          </div>

          <div className="space-y-1">
            {filteredResults.map((d: DriftResult) => {
              const isExpanded = expandedId === d.id;
              const dt = DRIFT_TYPE_CONFIG[d.driftType as keyof typeof DRIFT_TYPE_CONFIG];
              const st = STATUS_CONFIG[d.status] ?? STATUS_CONFIG.OPEN;

              return (
                <div key={d.id} className={`bg-white rounded-xl border border-gray-100 border-l-4 ${dt?.row ?? ''} overflow-hidden shadow-sm hover:shadow-md transition-shadow`}>
                  <div className="grid grid-cols-12 gap-3 px-4 py-3 items-center cursor-pointer"
                    onClick={() => setExpandedId(isExpanded ? null : d.id)}>
                    {/* Type badge */}
                    <div className="col-span-1">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold border ${dt?.color ?? ''}`}>
                        {d.driftType === 'ADDED' ? '+' : d.driftType === 'DELETED' ? '−' : '~'}
                      </span>
                    </div>

                    {/* Resource */}
                    <div className="col-span-4 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-semibold text-gray-900 truncate">{d.resourceName ?? d.nativeId.split('/').pop()}</p>
                        {d.status !== 'OPEN' && (
                          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border shrink-0 ${st.color}`}>{st.icon} {st.label}</span>
                        )}
                        {d.pendingRevert && (
                          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border shrink-0 bg-amber-50 text-amber-700 border-amber-200">⏳ Revert Pending</span>
                        )}
                      </div>
                      {d.region && <p className="text-[10px] text-gray-400 mt-0.5">{d.region}</p>}
                    </div>

                    {/* Resource type */}
                    <div className="col-span-2">
                      <p className="text-xs text-gray-500 truncate">{d.resourceType}</p>
                    </div>

                    {/* Severity */}
                    <div className="col-span-1">
                      <SevBadge sev={d.severity} />
                    </div>

                    {/* Changed fields */}
                    <div className="col-span-2">
                      {d.driftedFields.length > 0 ? (
                        <div>
                          <p className="text-xs font-medium text-indigo-600">{d.driftedFields.length} field{d.driftedFields.length > 1 ? 's' : ''}</p>
                          <p className="text-[10px] text-gray-400 truncate">{d.driftedFields.slice(0, 2).join(', ')}{d.driftedFields.length > 2 ? ' …' : ''}</p>
                        </div>
                      ) : <p className="text-xs text-gray-400">—</p>}
                    </div>

                    {/* First Detected — preserved across re-scans */}
                    <div className="col-span-1">
                      <p className="text-[10px] text-gray-500">{new Date(d.firstDetectedAt ?? d.detectedAt).toLocaleDateString()}</p>
                      <p className="text-[10px] text-gray-400">{new Date(d.firstDetectedAt ?? d.detectedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p>
                    </div>

                    {/* Actions */}
                    <div className="col-span-1 flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                      <ChevronDown className={`w-3.5 h-3.5 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="flex items-center gap-3 px-4 py-2 bg-gray-50 border-t border-gray-100">
                      <span className="text-[10px] font-mono text-gray-400 truncate flex-1" title={d.nativeId}>{d.nativeId}</span>
                      <div className="flex gap-2 shrink-0">
                        {d.status === 'OPEN' && (
                          <button onClick={() => patchMut.mutate({ driftId: d.id, s: 'ACKNOWLEDGED' })}
                            className="flex items-center gap-1 px-3 py-1 bg-white border border-gray-200 rounded-lg text-xs font-medium text-gray-700 hover:border-gray-300 hover:bg-gray-50 transition-colors">
                            <CheckSquare className="w-3 h-3" /> Acknowledge
                          </button>
                        )}
                        {d.status === 'ACKNOWLEDGED' && (
                          <button onClick={() => patchMut.mutate({ driftId: d.id, s: 'RESOLVED' })}
                            className="flex items-center gap-1 px-3 py-1 bg-white border border-gray-200 rounded-lg text-xs font-medium text-gray-700 hover:border-gray-300 hover:bg-gray-50 transition-colors">
                            <CheckCircle className="w-3 h-3 text-green-500" /> Mark Resolved
                          </button>
                        )}
                        {['OPEN', 'ACKNOWLEDGED'].includes(d.status) && !d.pendingRevert && (
                          <button onClick={() => setRevertDrift(d)}
                            className="flex items-center gap-1 px-3 py-1 bg-amber-600 text-white rounded-lg text-xs font-semibold hover:bg-amber-700 transition-colors">
                            <RotateCcw className="w-3 h-3" /> Revert
                          </button>
                        )}
                        {['OPEN', 'ACKNOWLEDGED'].includes(d.status) && (
                          <button onClick={() => setSuppressTarget(d)}
                            className="flex items-center gap-1 px-3 py-1 bg-white border border-gray-200 rounded-lg text-xs font-medium text-gray-700 hover:border-gray-300 hover:bg-gray-50 transition-colors">
                            <Pause className="w-3 h-3" /> Suppress
                          </button>
                        )}
                        {d.status === 'SUPPRESSED' && (
                          <button onClick={() => patchMut.mutate({ driftId: d.id, s: 'OPEN' })}
                            className="flex items-center gap-1 px-3 py-1 bg-white border border-gray-200 rounded-lg text-xs font-medium text-gray-700 hover:border-gray-300 hover:bg-gray-50 transition-colors">
                            <RotateCcw className="w-3 h-3" /> Re-open
                          </button>
                        )}
                        {['RESOLVED', 'REVERTED'].includes(d.status) && (
                          <button onClick={() => patchMut.mutate({ driftId: d.id, s: 'CLOSED' })}
                            className="flex items-center gap-1 px-3 py-1 bg-white border border-gray-200 rounded-lg text-xs font-medium text-gray-700 hover:border-gray-300 hover:bg-gray-50 transition-colors">
                            <X className="w-3 h-3" /> Close
                          </button>
                        )}
                        {d.status === 'REVERTED' && d.resolvedAt && (
                          <span className="text-[10px] text-purple-600">↩ Auto-reverted {new Date(d.resolvedAt).toLocaleString()}</span>
                        )}
                        {d.status === 'SUPPRESSED' && d.suppressionExpiresAt && (
                          <span className="text-[10px] text-slate-500" title={d.suppressionReason ?? ''}>
                            ⏸ Suppressed until {new Date(d.suppressionExpiresAt).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {isExpanded && (
                    <DriftDiffView baselineId={baselineId} driftId={d.id} driftType={d.driftType} driftedFields={d.driftedFields} />
                  )}
                </div>
              );
            })}
          </div>

          {(data?.total ?? 0) > 20 && (
            <div className="flex items-center justify-center gap-3 mt-4">
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
                className="px-3 py-1.5 bg-white border border-gray-200 rounded-lg text-xs text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                ← Prev
              </button>
              <span className="text-xs text-gray-500">Page {page} of {Math.ceil((data?.total ?? 0) / 20)}</span>
              <button onClick={() => setPage((p) => p + 1)} disabled={page >= Math.ceil((data?.total ?? 0) / 20)}
                className="px-3 py-1.5 bg-white border border-gray-200 rounded-lg text-xs text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                Next →
              </button>
            </div>
          )}
        </>
      )}

      {revertDrift && <RevertDialog baselineId={baselineId} drift={revertDrift} onClose={() => setRevertDrift(null)} />}

      {/* Suppress dialog (BCDD-F16 — mandatory justification + expiry) */}
      {suppressTarget && (
        <SuppressDialog
          drift={suppressTarget}
          submitting={patchMut.isPending}
          onCancel={() => setSuppressTarget(null)}
          onSubmit={(reason, expiresAt) => {
            patchMut.mutate(
              { driftId: suppressTarget.id, s: 'SUPPRESSED', opts: { suppressionReason: reason, suppressionExpiresAt: expiresAt } },
              { onSuccess: () => setSuppressTarget(null) },
            );
          }}
        />
      )}
    </div>
  );
}

function SuppressDialog({ drift, submitting, onCancel, onSubmit }: {
  drift: DriftResult;
  submitting: boolean;
  onCancel: () => void;
  onSubmit: (reason: string, expiresAtIso: string) => void;
}) {
  const defaultExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const [reason, setReason] = useState('');
  const [expiry, setExpiry] = useState(defaultExpiry);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/40" onClick={onCancel} />
      <div className="relative bg-white rounded-xl shadow-2xl w-full max-w-md p-6">
        <h3 className="text-sm font-bold text-gray-900 mb-1">Suppress Finding</h3>
        <p className="text-xs text-gray-500 mb-4">
          {drift.resourceName ?? drift.nativeId} — accepted-risk exceptions need a justification and an
          expiry; the finding automatically re-opens once it lapses.
        </p>
        <label className="block text-xs font-medium text-gray-600 mb-1">Justification (required)</label>
        <textarea
          className="w-full border rounded-lg px-3 py-2 text-sm mb-3 focus:ring-2 focus:ring-blue-500 focus:outline-none"
          rows={3}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Why is this an accepted risk?"
        />
        <label className="block text-xs font-medium text-gray-600 mb-1">Expires on (required)</label>
        <input
          type="date"
          className="w-full border rounded-lg px-3 py-2 text-sm mb-4 focus:ring-2 focus:ring-blue-500 focus:outline-none"
          value={expiry}
          min={new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10)}
          onChange={(e) => setExpiry(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <button onClick={onCancel} className="px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 rounded-lg">
            Cancel
          </button>
          <button
            disabled={!reason.trim() || !expiry || submitting}
            onClick={() => onSubmit(reason.trim(), new Date(`${expiry}T23:59:59`).toISOString())}
            className="px-3 py-1.5 bg-slate-700 text-white rounded-lg text-xs font-semibold hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {submitting ? 'Suppressing…' : 'Suppress'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Remediation Audit Trail (BCDD-F25) ────────────────────────────────────────
const REMEDIATION_ACTION_LABEL: Record<string, string> = {
  AUTO_REVERT:            'Automated revert',
  MANUAL_RESOLVE:         'Manual resolve',
  GUIDED_PLAN_GENERATED:  'Guided plan generated',
};

function RemediationLogPanel({ baselineId }: { baselineId: string }) {
  const [page, setPage] = useState(1);
  const { data, isLoading } = useQuery({
    queryKey: ['remediation-log', baselineId, page],
    queryFn:  () => baselinesApi.remediationLog(baselineId, page, 25),
  });

  if (isLoading) return <div className="py-8 text-center text-sm text-gray-400 animate-pulse">Loading remediation log…</div>;
  const results = data?.results ?? [];
  if (results.length === 0) return (
    <div className="py-8 text-center">
      <BookOpen className="w-10 h-10 text-gray-200 mx-auto mb-3" />
      <p className="text-sm text-gray-500">No remediation actions yet</p>
      <p className="text-xs text-gray-400 mt-1">Every revert, manual resolve, or guided plan is logged here — actor, before/after state, and outcome</p>
    </div>
  );

  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-400">
        Immutable audit trail — {data?.total} action(s) logged. Rows are never edited or deleted, even when the
        underlying finding is re-created on a later scan.
      </p>
      {results.map((r) => (
        <div key={r.id} className="flex items-start gap-3 p-3 rounded-xl border border-gray-100 bg-white">
          <div className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${r.outcome === 'SUCCESS' ? 'bg-green-500' : 'bg-red-500'}`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-semibold text-gray-800">{REMEDIATION_ACTION_LABEL[r.action] ?? r.action}</span>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${r.outcome === 'SUCCESS' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                {r.outcome}
              </span>
              <span className="text-[10px] text-gray-400">by {r.actor}</span>
              <span className="text-[10px] text-gray-400">· {new Date(r.createdAt).toLocaleString()}</span>
            </div>
            {r.message && <p className="text-xs text-gray-600 mt-1">{r.message}</p>}
            {(r.beforeState !== null && r.beforeState !== undefined) && (
              <details className="mt-1.5">
                <summary className="text-[10px] text-indigo-600 cursor-pointer select-none">View before / after state</summary>
                <div className="grid grid-cols-2 gap-2 mt-1.5">
                  <pre className="text-[10px] bg-gray-50 border border-gray-100 rounded-lg p-2 overflow-x-auto max-h-40">{JSON.stringify(r.beforeState, null, 2)}</pre>
                  <pre className="text-[10px] bg-gray-50 border border-gray-100 rounded-lg p-2 overflow-x-auto max-h-40">{JSON.stringify(r.afterState, null, 2)}</pre>
                </div>
              </details>
            )}
          </div>
        </div>
      ))}
      {data && data.total > 25 && (
        <div className="flex items-center justify-center gap-2 pt-2">
          <button disabled={page === 1} onClick={() => setPage((p) => p - 1)}
            className="px-3 py-1.5 bg-white border border-gray-200 rounded-lg text-xs text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
            ← Prev
          </button>
          <span className="text-xs text-gray-400">Page {page}</span>
          <button disabled={page * 25 >= data.total} onClick={() => setPage((p) => p + 1)}
            className="px-3 py-1.5 bg-white border border-gray-200 rounded-lg text-xs text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
            Next →
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Version History ──────────────────────────────────────────────────────────
function VersionHistory({ baselineId, currentVersion }: { baselineId: string; currentVersion: number }) {
  const [compareV1, setCompareV1] = useState<string | null>(null);
  const [compareV2, setCompareV2] = useState<string | null>(null);
  const [compareResult, setCompareResult] = useState<VersionCompareResult | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);

  const { data: versions = [], isLoading } = useQuery({
    queryKey: ['baseline-versions', baselineId],
    queryFn:  () => baselinesApi.versions(baselineId),
    staleTime: 60_000,
  });

  async function doCompare() {
    if (!compareV1 || !compareV2 || compareV1 === compareV2) return;
    setCompareLoading(true);
    try { setCompareResult(await baselinesApi.compareVersions(baselineId, compareV1, compareV2)); }
    finally { setCompareLoading(false); }
  }

  if (isLoading) return <div className="py-8 text-center text-sm text-gray-400 animate-pulse">Loading version history…</div>;
  if ((versions as BaselineVersionSummary[]).length === 0) return (
    <div className="py-8 text-center">
      <History className="w-10 h-10 text-gray-200 mx-auto mb-3" />
      <p className="text-sm text-gray-500">No version history yet</p>
      <p className="text-xs text-gray-400 mt-1">A version is saved every time the baseline is refreshed</p>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-gray-700">Version Timeline</p>
        {compareV1 && compareV2 && compareV1 !== compareV2 && (
          <button onClick={doCompare} disabled={compareLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 text-white rounded-lg text-xs font-semibold hover:bg-indigo-700 disabled:opacity-50 transition-colors">
            <ArrowLeftRight className="w-3.5 h-3.5" />
            {compareLoading ? 'Comparing…' : 'Compare A vs B'}
          </button>
        )}
      </div>

      <div className="relative">
        <div className="absolute left-4 top-4 bottom-4 w-px bg-gray-200" />
        <div className="space-y-3">
          {(versions as BaselineVersionSummary[]).map((v) => (
            <div key={v.id} className="relative flex items-start gap-4 pl-10">
              <div className={`absolute left-0 w-8 h-8 rounded-full border-2 flex items-center justify-center text-xs font-bold z-10 ${
                v.versionNumber === currentVersion
                  ? 'bg-indigo-600 border-indigo-600 text-white shadow-lg shadow-indigo-200'
                  : 'bg-white border-gray-300 text-gray-500'}`}>
                {v.versionNumber}
              </div>
              <div className={`flex-1 p-3 rounded-xl border ${v.versionNumber === currentVersion ? 'border-indigo-200 bg-indigo-50' : 'border-gray-100 bg-white'}`}>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-xs font-semibold text-gray-800">{v.label ?? `Version ${v.versionNumber}`}</p>
                      {v.versionNumber === currentVersion && <span className="px-1.5 py-0.5 bg-indigo-600 text-white text-[9px] font-bold rounded">ACTIVE</span>}
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-[10px] text-gray-500">
                      <span><Clock className="w-2.5 h-2.5 inline mr-0.5" />{new Date(v.capturedAt).toLocaleString()}</span>
                      <span>·</span>
                      <span>{v.resourceCount.toLocaleString()} resources</span>
                      {v.capturedBy && <><span>·</span><span><User className="w-2.5 h-2.5 inline mr-0.5" />{v.capturedBy}</span></>}
                    </div>
                  </div>
                  <div className="flex gap-1 shrink-0">
                    <button onClick={() => setCompareV1(compareV1 === v.id ? null : v.id)}
                      className={`text-[9px] px-2 py-1 rounded border font-bold transition-colors ${compareV1 === v.id ? 'bg-blue-600 text-white border-blue-600' : 'bg-white text-gray-400 border-gray-200 hover:border-blue-400 hover:text-blue-600'}`}>
                      {compareV1 === v.id ? 'A ✓' : 'A'}
                    </button>
                    <button onClick={() => setCompareV2(compareV2 === v.id ? null : v.id)}
                      className={`text-[9px] px-2 py-1 rounded border font-bold transition-colors ${compareV2 === v.id ? 'bg-green-600 text-white border-green-600' : 'bg-white text-gray-400 border-gray-200 hover:border-green-400 hover:text-green-600'}`}>
                      {compareV2 === v.id ? 'B ✓' : 'B'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {compareResult && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden shadow-sm">
          <div className="px-4 py-3 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <GitMerge className="w-4 h-4 text-indigo-600" />
              <span className="text-sm font-semibold text-gray-800">v{compareResult.v1.versionNumber} vs v{compareResult.v2.versionNumber}</span>
            </div>
            <div className="flex gap-4 text-xs">
              <span className="text-emerald-600 font-semibold">+{compareResult.summary.added} added</span>
              <span className="text-amber-600 font-semibold">~{compareResult.summary.modified} modified</span>
              <span className="text-red-600 font-semibold">−{compareResult.summary.deleted} deleted</span>
            </div>
            <button onClick={() => setCompareResult(null)} className="p-1 hover:bg-gray-200 rounded transition-colors"><X className="w-3.5 h-3.5 text-gray-400" /></button>
          </div>
          <div className="max-h-72 overflow-y-auto divide-y divide-gray-50">
            {compareResult.modified.map((m) => (
              <div key={m.nativeId} className="px-4 py-2.5 flex items-center gap-3">
                <span className="w-12 text-[10px] font-bold text-amber-600 shrink-0">MODIFIED</span>
                <p className="text-xs font-medium text-gray-800 truncate flex-1">{m.resourceName ?? m.nativeId}</p>
                <p className="text-[10px] text-indigo-500 shrink-0">{m.changedFields.slice(0, 3).join(', ')}{m.changedFields.length > 3 ? ` +${m.changedFields.length - 3}` : ''}</p>
              </div>
            ))}
            {compareResult.added.map((r) => (
              <div key={r.nativeId} className="px-4 py-2.5 flex items-center gap-3">
                <span className="w-12 text-[10px] font-bold text-emerald-600 shrink-0">ADDED</span>
                <p className="text-xs font-medium text-gray-800 truncate flex-1">{r.resourceName ?? r.nativeId}</p>
                <p className="text-[10px] text-gray-400">{r.resourceType}</p>
              </div>
            ))}
            {compareResult.deleted.map((r) => (
              <div key={r.nativeId} className="px-4 py-2.5 flex items-center gap-3">
                <span className="w-12 text-[10px] font-bold text-red-600 shrink-0">DELETED</span>
                <p className="text-xs font-medium text-gray-800 truncate flex-1">{r.resourceName ?? r.nativeId}</p>
                <p className="text-[10px] text-gray-400">{r.resourceType}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Approval Queue Modal ─────────────────────────────────────────────────────
function ApprovalQueueModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [email, setEmail]         = useState('');
  const [name, setName]           = useState('');
  const [reviewNotes, setReviewNotes] = useState('');
  const [actingOn, setActingOn]   = useState<string | null>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey:        ['approvals', 'PENDING'],
    queryFn:         () => approvalsApi.list({ status: 'PENDING' }),
    refetchInterval: 15_000,
  });

  const approveMut = useMutation({
    mutationFn: (id: string) => approvalsApi.approve(id, { reviewedBy: email, reviewedByName: name || undefined, reviewNotes: reviewNotes || undefined }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['approvals'] }); void qc.invalidateQueries({ queryKey: ['baselines'] }); void refetch(); setActingOn(null); setReviewNotes(''); },
  });
  const rejectMut = useMutation({
    mutationFn: (id: string) => approvalsApi.reject(id, { reviewedBy: email, reviewedByName: name || undefined, reviewNotes: reviewNotes || undefined }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['approvals'] }); void refetch(); setActingOn(null); setReviewNotes(''); },
  });

  const items = data?.items ?? [];
  const ACTION_COLOR: Record<string, string> = {
    CAPTURE: 'bg-indigo-100 text-indigo-700',
    REFRESH: 'bg-blue-100 text-blue-700',
    REVERT:  'bg-amber-100 text-amber-700',
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-start justify-center pt-16 z-50 px-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[80vh] flex flex-col overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-amber-100 flex items-center justify-center">
              <Bell className="w-4 h-4 text-amber-600" />
            </div>
            <div>
              <h2 className="font-semibold text-gray-900">Approval Queue</h2>
              <p className="text-xs text-gray-500">{items.length} pending request{items.length !== 1 ? 's' : ''}</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded-lg transition-colors"><X className="w-5 h-5 text-gray-400" /></button>
        </div>

        <div className="px-6 py-3 bg-gray-50 border-b border-gray-100">
          <p className="text-xs font-medium text-gray-600 mb-2">Your identity (required to approve or reject)</p>
          <div className="grid grid-cols-2 gap-3">
            <input className="border border-gray-200 rounded-xl px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
              value={email} onChange={(e) => setEmail(e.target.value)} placeholder="your@email.com *" />
            <input className="border border-gray-200 rounded-xl px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
              value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name (optional)" />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="p-8 text-center text-sm text-gray-400 animate-pulse">Loading…</div>
          ) : items.length === 0 ? (
            <div className="p-12 text-center">
              <div className="w-16 h-16 bg-green-50 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <CheckCircle className="w-8 h-8 text-green-400" />
              </div>
              <p className="font-medium text-gray-700">All clear</p>
              <p className="text-sm text-gray-400 mt-1">No pending approvals at this time</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {items.map((item) => (
                <div key={item.id} className="p-5">
                  <div className="flex items-start gap-3 mb-3">
                    <span className={`px-2.5 py-1 rounded-lg text-xs font-bold shrink-0 mt-0.5 ${ACTION_COLOR[item.action] ?? 'bg-gray-100 text-gray-600'}`}>
                      {item.action}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-semibold text-gray-900">{item.baseline?.name ?? 'Baseline'}</p>
                        {item.baseline?.provider && <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${PROVIDER_CONFIG[item.baseline.provider]?.bg ?? ''} ${PROVIDER_CONFIG[item.baseline.provider]?.text ?? ''}`}>{item.baseline.provider}</span>}
                      </div>
                      {item.drift && (
                        <p className="text-xs text-amber-700 mt-0.5">
                          Revert: {item.drift.resourceName ?? item.drift.resourceType} · <span className="font-medium">{item.drift.driftType}</span> · <SevBadge sev={item.drift.severity} />
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-1.5 text-[10px] text-gray-400">
                        <span className="flex items-center gap-1"><User className="w-2.5 h-2.5" />{item.requestedByName ?? item.requestedBy}</span>
                        <span className="flex items-center gap-1"><Clock className="w-2.5 h-2.5" />{new Date(item.requestedAt).toLocaleString()}</span>
                        <span className="text-amber-500">Expires {new Date(item.expiresAt).toLocaleString()}</span>
                      </div>
                      {item.notes && <p className="text-xs text-gray-500 mt-1.5 italic bg-gray-50 rounded-lg px-3 py-1.5">"{item.notes}"</p>}
                    </div>
                  </div>

                  {actingOn === item.id ? (
                    <div className="ml-12 space-y-2">
                      <textarea rows={2} className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none resize-none"
                        value={reviewNotes} onChange={(e) => setReviewNotes(e.target.value)} placeholder="Review notes (optional)" />
                      <div className="flex gap-2">
                        <button onClick={() => approveMut.mutate(item.id)} disabled={!email || approveMut.isPending}
                          className="flex items-center gap-1.5 px-4 py-2 bg-green-600 text-white rounded-xl text-xs font-semibold hover:bg-green-700 disabled:opacity-50 transition-colors">
                          <CheckSquare className="w-3.5 h-3.5" />{approveMut.isPending ? 'Approving…' : 'Approve & Execute'}
                        </button>
                        <button onClick={() => rejectMut.mutate(item.id)} disabled={!email || rejectMut.isPending}
                          className="flex items-center gap-1.5 px-4 py-2 bg-red-600 text-white rounded-xl text-xs font-semibold hover:bg-red-700 disabled:opacity-50 transition-colors">
                          <XCircle className="w-3.5 h-3.5" />{rejectMut.isPending ? 'Rejecting…' : 'Reject'}
                        </button>
                        <button onClick={() => setActingOn(null)} className="px-3 py-2 text-xs text-gray-500 hover:text-gray-700">Cancel</button>
                      </div>
                      {(approveMut.isError || rejectMut.isError) && (
                        <p className="text-xs text-red-600">{((approveMut.error ?? rejectMut.error) as Error).message}</p>
                      )}
                    </div>
                  ) : (
                    <div className="ml-12">
                      <button onClick={() => setActingOn(item.id)} disabled={!email}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-gray-200 rounded-lg text-xs font-medium text-gray-700 hover:border-indigo-300 hover:text-indigo-600 disabled:opacity-40 transition-colors">
                        <Eye className="w-3 h-3" /> Review {!email && '(enter email above first)'}
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Baseline Detail Panel ────────────────────────────────────────────────────
function BaselineDetail({ baseline, onBack }: { baseline: BaselineSummary; onBack: () => void }) {
  const qc = useQueryClient();
  const [activeTab, setActiveTab]   = useState<'drift' | 'history' | 'remediation'>('drift');
  const [showRefresh, setShowRefresh] = useState(false);
  const [refreshEmail, setRefreshEmail] = useState('');
  const [refreshNotes, setRefreshNotes] = useState('');
  const [refreshImmediate, setRefreshImmediate] = useState(false);
  const [scanBanner, setScanBanner] = useState<{ added: number; deleted: number; modified: number; reverted: number } | null>(null);
  const [approvalMsg, setApprovalMsg] = useState<string | null>(null);

  const detectMut = useMutation({
    mutationFn: () => baselinesApi.detect(baseline.id),
    onSuccess:  (data) => { setScanBanner(data); void qc.invalidateQueries({ queryKey: ['baselines'] }); void qc.invalidateQueries({ queryKey: ['drift', baseline.id] }); },
  });

  const refreshMut = useMutation({
    mutationFn: () => baselinesApi.refresh(baseline.id, {
      requestedBy: refreshEmail || undefined, requestedByName: undefined, notes: refreshNotes || undefined, immediate: refreshImmediate,
    }),
    onSuccess: (data) => {
      setShowRefresh(false);
      if ('approvalRequired' in data && data.approvalRequired) {
        setApprovalMsg(data.message);
        void qc.invalidateQueries({ queryKey: ['approvals'] });
      } else {
        void qc.invalidateQueries({ queryKey: ['baselines'] });
        void qc.invalidateQueries({ queryKey: ['drift', baseline.id] });
      }
    },
  });

  // Auto-detect on mount + every 2 min
  const detectRef = useRef(detectMut.mutate);
  useEffect(() => { detectRef.current = detectMut.mutate; });
  useEffect(() => {
    detectRef.current();
    const id = setInterval(() => { if (!detectMut.isPending) detectRef.current(); }, 120_000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [baseline.id]);

  const prov = PROVIDER_CONFIG[baseline.provider] ?? { bg: 'bg-gray-100', text: 'text-gray-600', icon: '◇' };

  return (
    <div className="flex-1 flex flex-col min-h-0">
      <div className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="flex items-start gap-4">
          <button onClick={onBack} className="mt-1 p-1.5 hover:bg-gray-100 rounded-lg transition-colors shrink-0">
            <ArrowRight className="w-4 h-4 text-gray-400 rotate-180" />
          </button>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-lg font-bold text-gray-900">{baseline.name}</h2>
              <span className={`px-2.5 py-0.5 rounded-lg text-xs font-bold ${prov.bg} ${prov.text}`}>{prov.icon} {baseline.provider}</span>
              <span className="text-xs text-gray-400 font-mono">v{baseline.currentVersion}</span>
            </div>
            {baseline.description && <p className="text-sm text-gray-500 mt-0.5">{baseline.description}</p>}
            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
              <span><Layers className="w-3 h-3 inline mr-1" />{baseline.resourceCount.toLocaleString()} resources</span>
              <span><Clock className="w-3 h-3 inline mr-1" />Snapshot: {new Date(baseline.capturedAt).toLocaleString()}</span>
              {baseline.pendingApprovals.length > 0 && (
                <span className="flex items-center gap-1 text-amber-600 font-medium">
                  <Bell className="w-3 h-3" />{baseline.pendingApprovals.length} pending approval{baseline.pendingApprovals.length > 1 ? 's' : ''}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button onClick={() => detectMut.mutate()} disabled={detectMut.isPending}
              className="flex items-center gap-1.5 px-3 py-2 bg-white border border-gray-200 rounded-xl text-xs font-semibold text-gray-700 hover:border-indigo-300 hover:text-indigo-600 disabled:opacity-50 transition-colors">
              <RefreshCw className={`w-3.5 h-3.5 ${detectMut.isPending ? 'animate-spin' : ''}`} />
              {detectMut.isPending ? 'Scanning…' : 'Scan Now'}
            </button>
            <button onClick={() => setShowRefresh(!showRefresh)}
              className="flex items-center gap-1.5 px-3 py-2 bg-white border border-amber-200 text-amber-700 rounded-xl text-xs font-semibold hover:bg-amber-50 transition-colors">
              <RotateCcw className="w-3.5 h-3.5" /> Update Baseline
            </button>
          </div>
        </div>

        {baseline.openDrift > 0 && (
          <div className="flex items-center gap-3 mt-3 ml-10">
            <div className="flex-1 flex h-1.5 rounded-full overflow-hidden bg-gray-100 max-w-xs">
              {baseline.criticalDrift > 0 && <div className="bg-red-500 h-full" style={{ width: `${(baseline.criticalDrift / baseline.openDrift) * 100}%` }} />}
              {baseline.highDrift > 0    && <div className="bg-orange-500 h-full" style={{ width: `${(baseline.highDrift / baseline.openDrift) * 100}%` }} />}
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="text-red-600 font-semibold">{baseline.openDrift} open</span>
              {baseline.criticalDrift > 0 && <span className="text-red-500">{baseline.criticalDrift} critical</span>}
              {baseline.highDrift > 0     && <span className="text-orange-500">{baseline.highDrift} high</span>}
            </div>
          </div>
        )}

        {showRefresh && (
          <div className="ml-10 mt-3 p-4 bg-amber-50 border border-amber-200 rounded-xl">
            <p className="text-xs font-semibold text-amber-800 mb-3 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" /> Update Baseline — replaces current snapshot with live inventory state
            </p>
            <div className="grid grid-cols-3 gap-3 mb-3">
              <input className="col-span-1 border border-amber-200 bg-white rounded-lg px-3 py-2 text-xs focus:ring-2 focus:ring-amber-500 focus:outline-none"
                value={refreshEmail} onChange={(e) => setRefreshEmail(e.target.value)} placeholder="Your email (optional)" />
              <input className="col-span-2 border border-amber-200 bg-white rounded-lg px-3 py-2 text-xs focus:ring-2 focus:ring-amber-500 focus:outline-none"
                value={refreshNotes} onChange={(e) => setRefreshNotes(e.target.value)} placeholder="Reason for update…" />
            </div>
            <div className="flex items-center gap-3">
              {refreshEmail && (
                <label className="flex items-center gap-1.5 text-xs text-amber-700 cursor-pointer">
                  <input type="checkbox" checked={refreshImmediate} onChange={(e) => setRefreshImmediate(e.target.checked)} className="rounded text-amber-600" />
                  Skip approval gate
                </label>
              )}
              <button onClick={() => refreshMut.mutate()} disabled={refreshMut.isPending}
                className="px-4 py-2 bg-amber-600 text-white rounded-lg text-xs font-semibold hover:bg-amber-700 disabled:opacity-50 transition-colors">
                {refreshMut.isPending ? 'Submitting…' : refreshEmail && !refreshImmediate ? 'Submit for Approval' : 'Update Now'}
              </button>
              <button onClick={() => setShowRefresh(false)} className="text-xs text-amber-600 hover:text-amber-800">Cancel</button>
            </div>
          </div>
        )}

        {approvalMsg && (
          <div className="ml-10 mt-3 flex items-center gap-2 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            <Clock className="w-3.5 h-3.5 shrink-0" /> {approvalMsg}
            <button onClick={() => setApprovalMsg(null)} className="ml-auto text-amber-400 hover:text-amber-600"><X className="w-3 h-3" /></button>
          </div>
        )}

        {scanBanner && (
          <div className="ml-10 mt-3 flex items-center gap-2 text-xs text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-lg px-3 py-2">
            <Zap className="w-3.5 h-3.5 shrink-0" />
            Scan complete — +{scanBanner.added} added, −{scanBanner.deleted} deleted, ~{scanBanner.modified} modified
            {scanBanner.reverted > 0 && <span className="text-purple-600 ml-1">↩{scanBanner.reverted} reverted</span>}
            <button onClick={() => setScanBanner(null)} className="ml-auto text-indigo-400 hover:text-indigo-600"><X className="w-3 h-3" /></button>
          </div>
        )}
      </div>

      <div className="bg-white border-b border-gray-200 px-6">
        <div className="flex gap-0">
          {[
            { key: 'drift',       label: 'Drift Results', icon: Activity },
            { key: 'history',     label: 'Version History', icon: History },
            { key: 'remediation', label: 'Remediation Log', icon: BookOpen },
          ].map(({ key, label, icon: Icon }) => (
            <button key={key} onClick={() => setActiveTab(key as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === key ? 'border-indigo-600 text-indigo-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}>
              <Icon className="w-4 h-4" />{label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {activeTab === 'drift'       && <DriftTable baselineId={baseline.id} />}
        {activeTab === 'history'     && <VersionHistory baselineId={baseline.id} currentVersion={baseline.currentVersion} />}
        {activeTab === 'remediation' && <RemediationLogPanel baselineId={baseline.id} />}
      </div>
    </div>
  );
}

// ─── Baseline List Item ───────────────────────────────────────────────────────
function BaselineListItem({ baseline, isSelected, onClick, onDelete }: {
  baseline: BaselineSummary; isSelected: boolean;
  onClick: () => void; onDelete: () => void;
}) {
  const prov = PROVIDER_CONFIG[baseline.provider] ?? { bg: 'bg-gray-100', text: 'text-gray-600', icon: '◇' };
  const totalSev = { CRITICAL: baseline.criticalDrift, HIGH: baseline.highDrift };

  return (
    <div onClick={onClick} className={`p-4 cursor-pointer transition-all border-l-4 border-b border-gray-100 hover:bg-gray-50 ${
      isSelected ? 'bg-indigo-50 border-l-indigo-500' : 'bg-white border-l-transparent'}`}>
      <div className="flex items-start gap-3">
        <div className={`w-8 h-8 rounded-lg ${prov.bg} flex items-center justify-center shrink-0`}>
          <span className={`text-sm font-bold ${prov.text}`}>{prov.icon}</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-semibold text-gray-900 truncate">{baseline.name}</p>
            {baseline.openDrift > 0 && (
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full shrink-0 ${
                baseline.criticalDrift > 0 ? 'bg-red-100 text-red-700' :
                baseline.highDrift > 0     ? 'bg-orange-100 text-orange-700' :
                'bg-yellow-100 text-yellow-700'}`}>
                {baseline.openDrift} drift
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${prov.bg} ${prov.text}`}>{baseline.provider}</span>
            <span className="text-[10px] text-gray-400">{baseline.resourceCount.toLocaleString()} res · v{baseline.currentVersion}</span>
          </div>
          {baseline.openDrift > 0 && (
            <div className="flex items-center gap-1.5 mt-1.5">
              <div className="flex-1 h-1 rounded-full bg-gray-100 overflow-hidden max-w-24">
                {Object.entries(totalSev).map(([k, v]) => v > 0 && (
                  <div key={k} className={`h-full inline-block ${k === 'CRITICAL' ? 'bg-red-500' : 'bg-orange-400'}`}
                    style={{ width: `${(v / baseline.openDrift) * 100}%` }} />
                ))}
              </div>
              <div className="flex gap-1 text-[9px]">
                {baseline.criticalDrift > 0 && <span className="text-red-600 font-bold">{baseline.criticalDrift}C</span>}
                {baseline.highDrift > 0     && <span className="text-orange-600 font-bold">{baseline.highDrift}H</span>}
              </div>
            </div>
          )}
          {baseline.pendingApprovals.length > 0 && (
            <div className="flex items-center gap-1 mt-1 text-[10px] text-amber-600">
              <Clock className="w-2.5 h-2.5" /> {baseline.pendingApprovals.length} pending
            </div>
          )}
        </div>
        <button onClick={(e) => { e.stopPropagation(); onDelete(); }}
          className="shrink-0 p-1 text-gray-300 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}

// ─── Create Baseline Form ─────────────────────────────────────────────────────
function CreateBaselineModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [provider, setProvider]           = useState<'AWS' | 'AZURE' | 'GCP'>('AWS');
  const [targetId, setTargetId]           = useState('');
  const [name, setName]                   = useState('');
  const [description, setDescription]     = useState('');
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [nameSearch, setNameSearch]       = useState('');
  const [region, setRegion]               = useState('');
  const [typeSearch, setTypeSearch]       = useState('');
  const [reqEmail, setReqEmail]           = useState('');
  const [reqName]                         = useState('');
  const [notes, setNotes]                 = useState('');
  const [immediate, setImmediate]         = useState(false);
  const [done, setDone]                   = useState<string | null>(null);

  const { data: awsAccounts  = [] } = useQuery({ queryKey: ['accounts'],           queryFn: () => accountsApi.list(),                         select: (d) => d.data ?? [] });
  const { data: azureSubs    = [] } = useQuery({ queryKey: ['azure-subscriptions'], queryFn: () => azureApi.listSubscriptions({ limit: 200 }), select: (d) => d.data ?? [] });
  const { data: gcpProjects  = [] } = useQuery({ queryKey: ['gcp-projects'],        queryFn: () => gcpApi.listProjects({ limit: 200 }),        select: (d) => d.data ?? [] });

  const subscriptions = useMemo(() => {
    if (provider === 'AWS')   return awsAccounts.map(a  => ({ id: a.id, label: `${a.name} (${a.awsAccountId})`,   nativeId: a.awsAccountId  }));
    if (provider === 'AZURE') return azureSubs.map(s    => ({ id: s.id, label: `${s.name} (${s.subscriptionId})`, nativeId: s.subscriptionId }));
    return gcpProjects.map(p => ({ id: p.id, label: `${p.name} (${p.projectId})`, nativeId: p.projectId }));
  }, [provider, awsAccounts, azureSubs, gcpProjects]);

  const { data: invStats } = useQuery({
    queryKey: ['inv-stats-baseline', provider, targetId],
    queryFn:  () => resourceInventoryApi.getStats(provider, targetId),
    enabled:  !!targetId,
  });
  const allTypes      = useMemo(() => (invStats?.byType ?? []).map((t) => t.type).sort(), [invStats]);
  const filteredTypes = useMemo(() => typeSearch ? allTypes.filter((t) => t.toLowerCase().includes(typeSearch.toLowerCase())) : allTypes, [allTypes, typeSearch]);
  const allSelected   = selectedTypes.length === allTypes.length && allTypes.length > 0;

  const { data: nameResources } = useQuery({
    queryKey: ['inv-names-baseline', provider, targetId, selectedTypes[0]],
    queryFn:  () => resourceInventoryApi.list({
      provider, targetId,
      resourceType: selectedTypes.length === 1 ? selectedTypes[0] : undefined,
      pageSize: 200,
    }),
    enabled:  !!targetId,
    select:   (d) => d.data ?? [],
  });
  const nameSuggestions = useMemo(
    () => Array.from(new Set((nameResources ?? []).map((r) => r.resourceName).filter(Boolean))).sort(),
    [nameResources],
  );

  function toggleType(t: string) { setSelectedTypes((p) => p.includes(t) ? p.filter((x) => x !== t) : [...p, t]); }

  const createMut = useMutation({
    mutationFn: () => baselinesApi.create({
      provider, targetId, name,
      description: description || undefined,
      resourceTypes: selectedTypes.length > 0 && !allSelected ? selectedTypes : undefined,
      nameSearch: nameSearch || undefined,
      region: region || undefined,
      requestedBy: reqEmail || undefined, requestedByName: reqName || undefined,
      notes: notes || undefined, immediate,
    }),
    onSuccess: (data) => {
      if ('approvalRequired' in data && data.approvalRequired) {
        setDone(data.message);
        void qc.invalidateQueries({ queryKey: ['approvals'] });
      } else {
        void qc.invalidateQueries({ queryKey: ['baselines'] });
        onClose();
      }
    },
  });

  const PROVIDER_ICONS: Record<string, typeof Shield> = { AWS: Database, AZURE: Lock, GCP: Shield };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 border-b border-gray-100">
          <div>
            <h2 className="text-lg font-bold text-gray-900">Capture New Baseline</h2>
            <p className="text-sm text-gray-500 mt-0.5">Create a point-in-time snapshot of your cloud configuration</p>
          </div>
          <button onClick={onClose} className="p-1.5 hover:bg-gray-100 rounded-xl transition-colors"><X className="w-5 h-5 text-gray-400" /></button>
        </div>

        {done ? (
          <div className="p-8">
            <div className="flex items-start gap-4 bg-amber-50 border border-amber-200 rounded-2xl p-5">
              <div className="w-10 h-10 rounded-xl bg-amber-100 flex items-center justify-center shrink-0">
                <Clock className="w-5 h-5 text-amber-600" />
              </div>
              <div>
                <p className="font-semibold text-amber-900">Approval Request Submitted</p>
                <p className="text-sm text-amber-700 mt-1">{done}</p>
                <p className="text-xs text-amber-600 mt-2">Check the Approval Queue (bell icon) to review and approve this request.</p>
              </div>
            </div>
            <button onClick={onClose} className="mt-4 w-full py-2.5 bg-gray-100 hover:bg-gray-200 rounded-xl text-sm font-semibold text-gray-700 transition-colors">Done</button>
          </div>
        ) : (
          <div className="p-6 space-y-5">
            {/* Step 1: Provider */}
            <div>
              <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Cloud Provider</label>
              <div className="grid grid-cols-3 gap-2">
                {(['AWS', 'AZURE', 'GCP'] as const).map((p) => {
                  const Icon = PROVIDER_ICONS[p];
                  const pc = PROVIDER_CONFIG[p];
                  return (
                    <button key={p} onClick={() => { setProvider(p); setTargetId(''); setSelectedTypes([]); }}
                      className={`flex items-center gap-2 p-3 rounded-xl border-2 font-semibold text-sm transition-all ${provider === p ? `${pc.bg} ${pc.text} border-current` : 'bg-white text-gray-500 border-gray-200 hover:border-gray-300'}`}>
                      <Icon className="w-4 h-4" />{p}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Step 2: Subscription */}
            <div>
              <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Cloud Subscription / Account</label>
              <select className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                value={targetId} onChange={(e) => { setTargetId(e.target.value); setSelectedTypes([]); }}>
                <option value="">— Select account —</option>
                {/* value must be the internal Account/Subscription/Project id — that's
                    what ResourceInventory rows and ConfigBaseline.targetId are keyed by
                    (see resourceInventory.ts buildWhere / baselineService.captureBaseline),
                    NOT the cloud-native account number shown in the label. */}
                {subscriptions.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
              </select>
            </div>

            {/* Step 3: Name & description */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Baseline Name *</label>
                <input className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                  value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Pre-Release v2.4" />
              </div>
              <div>
                <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Description</label>
                <input className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                  value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Context for this snapshot" />
              </div>
            </div>

            {/* Resource filters */}
            {targetId && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs font-bold text-gray-500 uppercase tracking-wider">Resource Types {selectedTypes.length > 0 && !allSelected && <span className="text-indigo-600 normal-case font-normal">({selectedTypes.length} selected)</span>}</label>
                    {allTypes.length > 0 && <button type="button" onClick={() => setSelectedTypes(allSelected ? [] : [...allTypes])} className="text-xs text-indigo-600 hover:text-indigo-800">{allSelected ? 'Deselect all' : 'Select all'}</button>}
                  </div>
                  <div className="border border-gray-200 rounded-xl overflow-hidden">
                    <div className="px-3 py-2 border-b bg-gray-50 flex items-center gap-1.5">
                      <Search size={12} className="text-gray-400 shrink-0" />
                      <input type="text" value={typeSearch} onChange={(e) => setTypeSearch(e.target.value)} placeholder="Filter types…" className="flex-1 text-xs outline-none bg-transparent" />
                      {typeSearch && <button onClick={() => setTypeSearch('')}><X size={11} className="text-gray-400" /></button>}
                    </div>
                    <div className="max-h-36 overflow-y-auto">
                      {allTypes.length === 0 ? <p className="px-3 py-4 text-xs text-gray-400 text-center">No resources found</p>
                        : filteredTypes.map((t) => (
                          <label key={t} className="flex items-center gap-2 px-3 py-1.5 hover:bg-gray-50 cursor-pointer">
                            <input type="checkbox" checked={selectedTypes.includes(t)} onChange={() => toggleType(t)} className="rounded border-gray-300 text-indigo-600" />
                            <span className="text-xs text-gray-700 truncate flex-1">{t}</span>
                            <span className="text-[10px] text-gray-400">{invStats?.byType.find((x) => x.type === t)?.count ?? ''}</span>
                          </label>
                        ))}
                    </div>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Name Filter <span className="text-gray-400 font-normal normal-case">(optional)</span></label>
                  <div className="relative">
                    <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                    <input className="w-full border border-gray-200 rounded-xl pl-9 pr-9 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                      list="baseline-name-suggestions"
                      value={nameSearch} onChange={(e) => setNameSearch(e.target.value)} placeholder="e.g. prod-, my-bucket" />
                    <datalist id="baseline-name-suggestions">
                      {nameSuggestions.map((n) => <option key={n} value={n} />)}
                    </datalist>
                    {nameSearch && <button onClick={() => setNameSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2"><X size={13} className="text-gray-400" /></button>}
                  </div>
                  <p className="text-[10px] text-gray-400 mt-1">
                    Only resources whose name contains this text will be included.
                    {selectedTypes.length === 1 && nameSuggestions.length > 0 && ` ${nameSuggestions.length} real resource name(s) suggested from AWS.`}
                  </p>
                </div>
                <div>
                  <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Region <span className="text-gray-400 font-normal normal-case">(optional)</span></label>
                  <div className="relative">
                    <input className="w-full border border-gray-200 rounded-xl px-3 pr-9 py-2.5 text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                      value={region} onChange={(e) => setRegion(e.target.value)} placeholder="e.g. us-east-1" />
                    {region && <button onClick={() => setRegion('')} className="absolute right-3 top-1/2 -translate-y-1/2"><X size={13} className="text-gray-400" /></button>}
                  </div>
                  <p className="text-[10px] text-gray-400 mt-1">Scope this baseline to a single region — reapplied on every refresh and drift scan.</p>
                </div>
              </div>
            )}

            {/* Approval governance */}
            <div className="bg-gray-50 rounded-xl p-4 space-y-3">
              <p className="text-xs font-bold text-gray-600 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-amber-500" /> Approval Governance
              </p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Your Email <span className="text-gray-400">(omit to capture immediately)</span></label>
                  <input className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm bg-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                    value={reqEmail} onChange={(e) => setReqEmail(e.target.value)} placeholder="you@company.com" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Reason</label>
                  <input className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm bg-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent focus:outline-none"
                    value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Why is this baseline needed?" />
                </div>
              </div>
              {reqEmail && (
                <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer">
                  <input type="checkbox" checked={immediate} onChange={(e) => setImmediate(e.target.checked)} className="rounded text-indigo-600" />
                  Execute immediately (bypass approval — dev/non-prod only)
                </label>
              )}
              <p className="text-[10px] text-gray-400">
                {reqEmail ? immediate ? 'Will capture immediately without approval.' : 'An approval request will be created. A reviewer must approve before capture runs.' : 'No email = capture runs immediately.'}
              </p>
            </div>

            <div className="flex gap-3 pt-1">
              <button onClick={() => createMut.mutate()} disabled={!name || !targetId || createMut.isPending}
                className="flex-1 flex items-center justify-center gap-2 py-3 bg-indigo-600 text-white rounded-xl text-sm font-bold hover:bg-indigo-700 disabled:opacity-50 transition-colors">
                {createMut.isPending ? 'Submitting…' : reqEmail && !immediate ? '⏳ Submit for Approval' : 'Capture Baseline Now'}
              </button>
              <button onClick={onClose} className="px-6 py-3 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl text-sm font-semibold transition-colors">Cancel</button>
            </div>
            {createMut.isError && <p className="text-xs text-red-600">{(createMut.error as Error).message}</p>}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function BaselineDrift() {
  const qc = useQueryClient();
  const [selectedId, setSelectedId]     = useState<string | null>(null);
  const [showCreate, setShowCreate]     = useState(false);
  const [showApprovals, setShowApprovals] = useState(false);
  const [filterProvider, setFilterProvider] = useState('');

  const { data: baselines = [], isLoading } = useQuery({
    queryKey:        ['baselines', filterProvider],
    queryFn:         () => baselinesApi.list(filterProvider || undefined),
    refetchInterval: 5 * 60_000,
  });

  const { data: pendingCount } = useQuery({
    queryKey:        ['approvals', 'pending-count'],
    queryFn:         () => approvalsApi.pending(),
    refetchInterval: 30_000,
  });

  const deleteMut = useMutation({
    mutationFn: baselinesApi.delete,
    onSuccess:  (_, id) => {
      if (selectedId === id) setSelectedId(null);
      void qc.invalidateQueries({ queryKey: ['baselines'] });
    },
  });

  const selected = baselines.find((b) => b.id === selectedId) ?? null;

  const totalDrift    = baselines.reduce((s, b) => s + b.openDrift, 0);
  const criticalDrift = baselines.reduce((s, b) => s + b.criticalDrift, 0);
  const pendingApprovals = (pendingCount?.count ?? 0);

  return (
    <div className="h-full flex flex-col">
      <div className="bg-white border-b border-gray-200 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-200">
              <GitCompareArrows className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900">Baseline & Drift Detection</h1>
              <p className="text-sm text-gray-500">Snapshot configs · detect drift · approve reversions · full audit trail</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-4 mr-2">
              <div className="text-center">
                <p className="text-xl font-bold text-gray-900">{baselines.length}</p>
                <p className="text-[10px] text-gray-400 uppercase tracking-wider">Baselines</p>
              </div>
              <div className="w-px h-8 bg-gray-200" />
              <div className="text-center">
                <p className={`text-xl font-bold ${totalDrift > 0 ? 'text-amber-600' : 'text-gray-900'}`}>{totalDrift}</p>
                <p className="text-[10px] text-gray-400 uppercase tracking-wider">Open Drift</p>
              </div>
              <div className="w-px h-8 bg-gray-200" />
              <div className="text-center">
                <p className={`text-xl font-bold ${criticalDrift > 0 ? 'text-red-600' : 'text-gray-900'}`}>{criticalDrift}</p>
                <p className="text-[10px] text-gray-400 uppercase tracking-wider">Critical</p>
              </div>
            </div>
            <button onClick={() => setShowApprovals(true)}
              className="relative flex items-center gap-2 px-4 py-2.5 bg-white border border-gray-200 text-gray-700 rounded-xl text-sm font-semibold hover:border-gray-300 hover:bg-gray-50 transition-colors">
              <Bell className="w-4 h-4" /> Approvals
              {pendingApprovals > 0 && (
                <span className="absolute -top-1.5 -right-1.5 w-5 h-5 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center shadow-sm">
                  {pendingApprovals > 9 ? '9+' : pendingApprovals}
                </span>
              )}
            </button>
            <button onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-bold hover:bg-indigo-700 shadow-sm shadow-indigo-200 transition-colors">
              <Plus className="w-4 h-4" /> Capture Baseline
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        <div className="w-80 shrink-0 border-r border-gray-200 bg-gray-50 flex flex-col overflow-hidden">
          <div className="p-3 border-b border-gray-200 bg-white">
            <div className="flex gap-1">
              {['', 'AWS', 'AZURE', 'GCP'].map((p) => (
                <button key={p || 'all'} onClick={() => setFilterProvider(p)}
                  className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-colors ${filterProvider === p ? 'bg-indigo-600 text-white' : 'text-gray-500 hover:bg-gray-100'}`}>
                  {p || 'All'}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto">
            {isLoading ? (
              <div className="p-4 space-y-3">
                {[...Array(3)].map((_, i) => <div key={i} className="h-20 bg-gray-200 rounded-xl animate-pulse" />)}
              </div>
            ) : baselines.length === 0 ? (
              <div className="p-6 text-center">
                <div className="w-14 h-14 bg-gray-200 rounded-2xl flex items-center justify-center mx-auto mb-3">
                  <GitCompareArrows className="w-7 h-7 text-gray-400" />
                </div>
                <p className="text-sm font-medium text-gray-600">No baselines yet</p>
                <p className="text-xs text-gray-400 mt-1">Click "Capture Baseline" to get started</p>
              </div>
            ) : (
              <div className="group">
                {baselines.map((b) => (
                  <BaselineListItem key={b.id} baseline={b} isSelected={selectedId === b.id}
                    onClick={() => setSelectedId(b.id === selectedId ? null : b.id)}
                    onDelete={() => deleteMut.mutate(b.id)} />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right panel — detail or empty state */}
        {selected ? (
          <div className="flex-1 flex flex-col overflow-hidden">
            <BaselineDetail baseline={selected} onBack={() => setSelectedId(null)} />
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center bg-gray-50">
            <div className="text-center">
              <div className="w-20 h-20 bg-indigo-50 rounded-3xl flex items-center justify-center mx-auto mb-4">
                <GitCompareArrows className="w-10 h-10 text-indigo-400" />
              </div>
              <p className="text-lg font-semibold text-gray-700">Select a baseline</p>
              <p className="text-sm text-gray-400 mt-1 max-w-xs">Choose a baseline from the left panel to view drift results, version history, and run reversions</p>
              {baselines.length > 0 && (
                <div className="mt-6 space-y-2">
                  {baselines.slice(0, 3).map((b) => (
                    <button key={b.id} onClick={() => setSelectedId(b.id)}
                      className="flex items-center gap-3 px-4 py-2 bg-white border border-gray-200 rounded-xl text-sm text-gray-700 hover:border-indigo-300 hover:bg-indigo-50 transition-colors mx-auto">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${PROVIDER_CONFIG[b.provider]?.bg ?? ''} ${PROVIDER_CONFIG[b.provider]?.text ?? ''}`}>{b.provider}</span>
                      {b.name}
                      {b.openDrift > 0 && <span className="text-xs text-red-600 font-semibold">{b.openDrift} drift</span>}
                      <ArrowRight className="w-3.5 h-3.5 text-gray-400" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {showCreate    && <CreateBaselineModal onClose={() => setShowCreate(false)} />}
      {showApprovals && <ApprovalQueueModal  onClose={() => setShowApprovals(false)} />}
    </div>
  );
}

import { useState, useEffect, useRef } from 'react';
import { aspmFetch, aspmUrl } from '../aspmClient';
import {
  GitBranch, Search, ShieldCheck, KeyRound, Package, SlidersHorizontal,
  Lightbulb, Code2, Hammer, TestTube, GitPullRequest, Check, Play, X,
  Copy, CheckCheck, History, ArrowLeft, Clock, ShieldAlert, Eye,
  type LucideIcon,
} from 'lucide-react';

interface VulnPipelineProps {
  tenantId?: string;
}

const STAGES: Array<{ id: string; label: string; icon: LucideIcon }> = [
  { id: 'clone_node',  label: 'Ingest repo',   icon: GitBranch },
  { id: 'detect_node', label: 'Detect stack',  icon: Search },
  { id: 'sast_node',   label: 'SAST scan',     icon: ShieldCheck },
  { id: 'secret_node', label: 'Secret scan',   icon: KeyRound },
  { id: 'sca_node',    label: 'Dep scan',      icon: Package },
  { id: 'blindspot_node', label: 'Blind spots', icon: Eye },
  { id: 'triage_node', label: 'Triage',        icon: SlidersHorizontal },
  { id: 'fix_node',    label: 'Fix plan',      icon: Lightbulb },
  { id: 'patch_node',  label: 'Apply fix',     icon: Code2 },
  { id: 'build_node',  label: 'Build',         icon: Hammer },
  { id: 'test_node',   label: 'Run tests',     icon: TestTube },
  { id: 'pr_node',     label: 'Push & PR',     icon: GitPullRequest },
];

const NOT_IMPLEMENTED = new Set<string>([]);

interface PipelineRun {
  id: string;
  status: string;
  created_at: string;
  stage_logs: Record<string, string[]>;
  stage_durations?: Record<string, number>;
}

// "125" -> "2m 5s"; sub-second/zero -> "<1s" rather than "0s" (looks broken).
function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '<1s';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

function stagesCompletedFrom(stageLogs: Record<string, string[]>): Set<string> {
  return new Set(Object.keys(stageLogs));
}

function summarizeRun(stageLogs: Record<string, string[]>): { title: string; lastStageId: string } {
  const countFrom = (stage: string) => {
    const lines = stageLogs[stage] ?? [];
    for (const l of lines) {
      const m = l.match(/(?:Found|Ingested) (\d+) (?:issues?|finding)/i);
      if (m) return parseInt(m[1], 10);
    }
    return null;
  };
  const sast = countFrom('sast_node');
  const secret = countFrom('secret_node');
  const sca = countFrom('sca_node');
  const parts: string[] = [];
  if (sast !== null) parts.push(`${sast} SAST`);
  if (secret !== null) parts.push(`${secret} secret${secret === 1 ? '' : 's'}`);
  if (sca !== null) parts.push(`${sca} dependency`);

  let lastStageId = 'clone_node';
  for (const s of STAGES) if (stageLogs[s.id]?.length) lastStageId = s.id;
  const lastStageLabel = STAGES.find((s) => s.id === lastStageId)?.label ?? 'Ingest repo';

  const title = parts.length > 0 ? `${parts.join(' · ')} finding(s)` : `Reached: ${lastStageLabel}`;
  return { title, lastStageId };
}

export default function VulnPipeline({ tenantId }: VulnPipelineProps) {
  const [targets, setTargets] = useState<any[]>([]);
  const [tid, setTid] = useState('');
  const [running, setRunning] = useState(false);
  const [logsByStage, setLogsByStage] = useState<Record<string, string[]>>({});
  const [completedStages, setCompletedStages] = useState<Set<string>>(new Set());
  const [liveDurations, setLiveDurations] = useState<Record<string, number>>({});
  const [viewStage, setViewStage] = useState<string>(STAGES[0].id);
  const [history, setHistory] = useState<PipelineRun[]>([]);
  const [viewRunId, setViewRunId] = useState<string>(''); // '' = live/current run
  const [copied, setCopied] = useState(false);
  const [mode, setMode] = useState<'list' | 'detail'>('list');
  const esRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);
  const receivedCountRef = useRef(0); // total lines received this stream — lets a reconnect resume via ?after= instead of replaying everything

  useEffect(() => {
    aspmFetch('/api/aspm/targets')
      .then((r) => r.json())
      .then((d) => {
        const list = Array.isArray(d) ? d : [];
        setTargets(list);
        const preferred = tenantId ? list.find((t) => t.id === tenantId) : null;
        setTid((preferred ?? list[0])?.id ?? '');
      })
      .catch(() => {});
  }, [tenantId]);

  const loadHistory = (targetId: string, selectLatest: boolean) => {
    if (!targetId) { setHistory([]); return; }
    aspmFetch(`/api/aspm/pipeline/history?target_id=${encodeURIComponent(targetId)}`)
      .then((r) => r.json())
      .then((runs: PipelineRun[]) => {
        setHistory(Array.isArray(runs) ? runs : []);
        if (selectLatest && Array.isArray(runs) && runs.length > 0) {
          const latest = runs[0];
          setViewRunId(latest.id);
          setLogsByStage(latest.stage_logs);
          setCompletedStages(stagesCompletedFrom(latest.stage_logs));
          const firstStageWithLogs = STAGES.find((s) => latest.stage_logs[s.id]?.length)?.id ?? STAGES[0].id;
          setViewStage(firstStageWithLogs);
          setMode('list'); // land on the Executions feed first, like Drone's activity feed
        }
      })
      .catch(() => {});
  };

  useEffect(() => {
    if (!tid) return;
    aspmFetch(`/api/aspm/pipeline/active?target_id=${encodeURIComponent(tid)}`)
      .then((r) => r.json())
      .then((d) => {
        if (d?.running) {
          setLogsByStage({});
          setLiveDurations({});
          setCompletedStages(new Set());
          setViewStage(STAGES[0].id);
          setViewRunId('');
          setMode('detail');
          setRunning(true);
          attachStream(tid);
          loadHistory(tid, false);
        } else {
          loadHistory(tid, true);
        }
      })
      .catch(() => loadHistory(tid, true));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tid]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logsByStage, viewStage]);

  useEffect(() => () => esRef.current?.close(), []);

  const selectRun = (runId: string) => {
    setMode('detail');
    if (running) return; // don't let history browsing clobber a live run's view
    setViewRunId(runId);
    if (runId === '') {
      setLogsByStage({});
      setLiveDurations({});
      setCompletedStages(new Set());
      setViewStage(STAGES[0].id);
      return;
    }
    const run = history.find((r) => r.id === runId);
    if (!run) return;
    setLogsByStage(run.stage_logs);
    setCompletedStages(stagesCompletedFrom(run.stage_logs));
    const firstStageWithLogs = STAGES.find((s) => run.stage_logs[s.id]?.length)?.id ?? STAGES[0].id;
    setViewStage(firstStageWithLogs);
  };

  const attachStream = (targetId: string, after: number = 0) => {
    esRef.current?.close();
    receivedCountRef.current = after;
    const url = aspmUrl(`/api/aspm/pipeline/stream?target_id=${encodeURIComponent(targetId)}&after=${after}`);
    const es = new EventSource(url);
    esRef.current = es;

    es.onmessage = (ev) => {
      receivedCountRef.current += 1;
      let stage = 'clone_node';
      let log = ev.data;
      let ts: number | undefined;
      try {
        const parsed = JSON.parse(ev.data);
        stage = parsed.stage ?? stage;
        log = parsed.log ?? ev.data;
        ts = typeof parsed.ts === 'number' ? parsed.ts : undefined;
      } catch {
      }
      setLogsByStage((prev) => ({ ...prev, [stage]: [...(prev[stage] ?? []), log] }));
      setViewStage(stage);
      if (ts !== undefined) {
        setLiveDurations((prev) => {
          const key = `__start_${stage}`;
          const start = (prev[key] as number | undefined) ?? ts!;
          return { ...prev, [key]: start, [stage]: Math.max(0, ts! - start) };
        });
      }
      setCompletedStages((prev) => {
        const idx = STAGES.findIndex((s) => s.id === stage);
        const next = new Set(prev);
        for (let i = 0; i < idx; i++) next.add(STAGES[i].id);
        return next;
      });
      if (stage === 'pr_node' && /Pipeline run finished/.test(log)) {
        setCompletedStages((prev) => new Set([...prev, ...STAGES.map((s) => s.id)]));
        setRunning(false);
        es.close();
        loadHistory(targetId, false);
      }
    };
    es.onerror = () => {
      es.close();
      aspmFetch(`/api/aspm/pipeline/active?target_id=${encodeURIComponent(targetId)}`)
        .then((r) => r.json())
        .then((d) => {
          if (d?.running) {
            attachStream(targetId, receivedCountRef.current);
          } else {
            setRunning(false); // genuinely stopped (finished before the sentinel arrived, or errored)
            loadHistory(targetId, false);
          }
        })
        .catch(() => setRunning(false));
    };
  };

  const runPipeline = () => {
    if (!tid) return;
    setLogsByStage({});
    setLiveDurations({});
    setCompletedStages(new Set());
    setViewStage(STAGES[0].id);
    setViewRunId('');
    setMode('detail');
    setRunning(true);

    aspmFetch('/api/aspm/pipeline/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_id: tid }),
    })
      .then(() => attachStream(tid))
      .catch(() => setRunning(false));
  };

  const stopPipeline = () => {
    esRef.current?.close();
    setRunning(false);
  };

  const resumePipeline = () => {
    if (!tid || running) return;
    setLogsByStage({});
    setLiveDurations({});
    setCompletedStages(new Set());
    setViewStage(STAGES[0].id);
    setViewRunId('');
    setMode('detail');
    setRunning(true);

    aspmFetch('/api/aspm/pipeline/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_id: tid, resume: true }),
    })
      .then(() => attachStream(tid))
      .catch(() => setRunning(false));
  };

  const viewLogs = logsByStage[viewStage] ?? [];
  const viewNotImpl = NOT_IMPLEMENTED.has(viewStage) && viewLogs.length === 0;

  const copyLogs = () => {
    if (viewLogs.length === 0) return;
    navigator.clipboard.writeText(viewLogs.join('\n')).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {});
  };

  const currentRunNumber = viewRunId === ''
    ? history.length + 1
    : history.length - history.findIndex((r) => r.id === viewRunId);

  const viewDurations = viewRunId === ''
    ? liveDurations
    : (history.find((r) => r.id === viewRunId)?.stage_durations ?? {});

  const isAwaitingApproval = !running
    && (logsByStage['fix_node']?.some((l) => l.includes('[HITL]')) ?? false)
    && !(logsByStage['patch_node']?.length);

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
      <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
          <GitPullRequest size={18} color="var(--color-primary)" /> Vulnerability Pipeline
          {mode === 'detail' && (
            <span className="cyber-badge" style={{ fontSize: '0.7rem', fontWeight: 600, padding: '2px 9px' }}>
              #{currentRunNumber}{viewRunId === '' && running ? ' · live' : ''}
            </span>
          )}
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <select className="cyber-input" value={tid} onChange={(e) => setTid(e.target.value)} disabled={running} style={{ minWidth: '240px' }}>
            {targets.length === 0 && <option value="">No targets — onboard a Git target first</option>}
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.url})</option>)}
          </select>
          {!running ? (
            <button className="cyber-btn cyber-btn-accent" onClick={runPipeline} disabled={!tid}>
              <Play size={14} /> Run Pipeline
            </button>
          ) : (
            <button className="cyber-btn" onClick={stopPipeline} style={{ borderColor: 'var(--color-danger)' }}>
              <X size={14} /> Stop
            </button>
          )}
        </div>
      </div>

      {mode === 'list' && history.length > 0 && (
        <div>
          <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
            <History size={14} /> EXECUTIONS
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '340px', overflowY: 'auto' }}>
            {running && (
              <div
                onClick={() => selectRun('')}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '12px 16px', borderRadius: '10px',
                  border: `1px solid ${viewRunId === '' ? 'var(--color-primary)' : 'var(--border-glass)'}`,
                  background: viewRunId === '' ? 'rgba(59,130,246,0.06)' : 'transparent', cursor: 'pointer',
                }}
              >
                <span style={{
                  width: '28px', height: '28px', borderRadius: '50%', border: '3px solid var(--color-primary)',
                  borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite', flexShrink: 0, marginTop: '2px',
                }} />
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <span style={{ fontSize: '0.85rem', fontWeight: 700 }}>Run in progress…</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--color-muted)' }}>
                    <span style={{ width: '16px', height: '16px', borderRadius: '50%', background: 'var(--color-primary)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
                      <GitPullRequest size={10} color="#fff" />
                    </span>
                    streaming live · currently on {STAGES.find((s) => s.id === viewStage)?.label}
                  </div>
                </div>
              </div>
            )}
            {history.map((r, i) => {
              const runNumber = history.length - i;
              const isSelected = viewRunId === r.id && !running;
              const ok = r.status?.toLowerCase() === 'completed';
              const awaitingApproval = r.status?.toLowerCase() === 'awaitingapproval';
              const { title, lastStageId } = summarizeRun(r.stage_logs);
              const stageCount = Object.keys(r.stage_logs).length;
              return (
                <div
                  key={r.id} onClick={() => selectRun(r.id)}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '12px 16px', borderRadius: '10px',
                    border: `1px solid ${awaitingApproval ? 'var(--color-warning, #d97706)' : isSelected ? 'var(--color-primary)' : 'var(--border-glass)'}`,
                    background: isSelected ? 'rgba(59,130,246,0.06)' : awaitingApproval ? 'rgba(217,119,6,0.06)' : 'transparent',
                    cursor: running ? 'default' : 'pointer', opacity: running ? 0.6 : 1,
                  }}
                >
                  <span style={{
                    width: '28px', height: '28px', borderRadius: '50%', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', flexShrink: 0, color: '#fff', marginTop: '2px',
                    background: awaitingApproval ? 'var(--color-warning, #d97706)' : ok ? '#16a34a' : 'var(--color-danger, #dc2626)',
                  }}>
                    {awaitingApproval ? <Clock size={15} /> : ok ? <Check size={15} /> : <X size={15} />}
                  </span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, minWidth: 0 }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text)' }}>
                      <span style={{ color: 'var(--color-muted)', fontWeight: 600 }}>#{runNumber}.</span>{' '}
                      {awaitingApproval ? 'Fix plan ready — awaiting approval to apply' : title}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--color-muted)', flexWrap: 'wrap' }}>
                      <span style={{
                        width: '16px', height: '16px', borderRadius: '50%', background: 'var(--surface-2, #e2e8f0)',
                        display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                      }}>
                        <GitBranch size={9} />
                      </span>
                      reached <strong style={{ color: 'var(--color-text)', fontWeight: 600 }}>{STAGES.find((s) => s.id === lastStageId)?.label}</strong>
                      <span className="cyber-badge" style={{ fontSize: '0.65rem', padding: '1px 7px' }}>{stageCount}/{STAGES.length} stages</span>
                      <span style={{ fontSize: '0.68rem' }}>{new Date(r.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                  {i === 0 && awaitingApproval && !running && (
                    <button
                      onClick={(e) => { e.stopPropagation(); resumePipeline(); }}
                      className="cyber-btn cyber-btn-accent"
                      title="Approve the generated fix plan — applies the patches, runs the build check, and opens a PR"
                      style={{ display: 'flex', alignItems: 'center', gap: '4px', padding: '4px 10px', fontSize: '0.72rem', flexShrink: 0, borderColor: 'var(--color-warning, #d97706)' }}
                    >
                      <ShieldAlert size={11} /> Approve & Apply Fixes
                    </button>
                  )}
                  {i === 0 && !ok && !awaitingApproval && !running && (
                    <button
                      onClick={(e) => { e.stopPropagation(); resumePipeline(); }}
                      className="cyber-btn cyber-btn-accent"
                      title={`Resume from the last completed stage (${STAGES.find((s) => s.id === lastStageId)?.label}) instead of restarting from scratch`}
                      style={{ display: 'flex', alignItems: 'center', gap: '4px', padding: '4px 10px', fontSize: '0.72rem', flexShrink: 0 }}
                    >
                      <Play size={11} /> Resume
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {mode === 'detail' && (
      <>
      {history.length > 0 && (
        <button
          onClick={() => { setMode('list'); loadHistory(tid, false); }}
          className="cyber-btn"
          style={{ display: 'flex', alignItems: 'center', gap: '6px', alignSelf: 'flex-start', padding: '4px 10px', fontSize: '0.75rem' }}
        >
          <ArrowLeft size={13} /> Back to executions
        </button>
      )}

      <p style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
        Every stage is real: ingest, detect, SAST, secret, dependency scan, blind-spot sweep, triage, fix, apply fix,
        build, run tests (npm test / pytest against the target's own suite), and push &amp; PR.
      </p>

      {isAwaitingApproval && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap',
          padding: '12px 16px', borderRadius: '10px',
          border: '1px solid var(--color-warning, #d97706)', background: 'rgba(217,119,6,0.08)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Clock size={18} color="var(--color-warning, #d97706)" />
            <div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text)' }}>Awaiting approval to apply fixes</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--color-muted)' }}>
                The fix plan above is ready. Applying it will patch files, run the build check, and open a PR — nothing has been written yet.
              </div>
            </div>
          </div>
          <button
            onClick={resumePipeline}
            className="cyber-btn cyber-btn-accent"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 14px', fontSize: '0.8rem', flexShrink: 0, borderColor: 'var(--color-warning, #d97706)' }}
          >
            <ShieldAlert size={14} /> Approve & Apply Fixes
          </button>
        </div>
      )}

      {/* Stepper */}
      <style>{'@keyframes pulseRing { 0%, 100% { box-shadow: 0 0 0 0 rgba(37,99,235,0.35); } 50% { box-shadow: 0 0 0 5px rgba(37,99,235,0); } }'}</style>
      <div style={{ display: 'flex', overflowX: 'auto', paddingBottom: '6px', gap: '2px' }}>
        {STAGES.map((s, i) => {
          const done = completedStages.has(s.id);
          const hasLogs = !!logsByStage[s.id];
          const notImpl = NOT_IMPLEMENTED.has(s.id);
          const isActive = running && !done && s.id === viewStage;
          const duration = viewDurations[s.id];
          const Icon = s.icon;
          return (
            <div key={s.id} onClick={() => hasLogs && setViewStage(s.id)}
              style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center', flex: '1 0 88px',
                cursor: hasLogs ? 'pointer' : 'default', position: 'relative', paddingTop: '2px',
              }}>
              {i < STAGES.length - 1 && (
                <div style={{
                  position: 'absolute', top: '19px', left: '50%', width: '100%', height: '2px',
                  background: done ? '#16a34a' : 'var(--border-glass)', zIndex: 0,
                }} />
              )}
              <div style={{
                width: '34px', height: '34px', borderRadius: '50%', display: 'flex', alignItems: 'center',
                justifyContent: 'center', zIndex: 1, position: 'relative',
                background: done ? '#16a34a' : viewStage === s.id ? '#fff' : notImpl ? '#f1f5f9' : 'var(--surface-2, #f8fafc)',
                border: `2px solid ${done ? '#16a34a' : viewStage === s.id ? 'var(--color-primary)' : notImpl ? '#cbd5e1' : 'var(--border-glass)'}`,
                color: done ? '#fff' : viewStage === s.id ? 'var(--color-primary)' : notImpl ? '#94a3b8' : 'var(--color-muted)',
                animation: isActive ? 'pulseRing 1.6s ease-in-out infinite' : 'none',
              }}>
                {done ? <Check size={16} /> : <Icon size={15} />}
              </div>
              <span style={{
                fontSize: '10px', marginTop: '5px', textAlign: 'center', lineHeight: 1.25,
                color: done ? 'var(--color-text)' : viewStage === s.id ? 'var(--color-primary)' : notImpl ? '#94a3b8' : 'var(--color-muted)',
                fontWeight: viewStage === s.id ? 700 : 400,
              }}>
                {s.label}{notImpl && <><br /><em style={{ fontStyle: 'normal', fontSize: '9px' }}>(planned)</em></>}
              </span>
              {duration !== undefined && (
                <span style={{
                  fontSize: '9px', marginTop: '2px', color: isActive ? 'var(--color-primary)' : 'var(--color-muted)',
                  fontWeight: isActive ? 700 : 400, fontFamily: 'var(--font-mono)',
                }}>
                  {formatDuration(duration)}{isActive ? '…' : ''}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Per-stage log panel */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
          <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text)' }}>
            {STAGES.find((s) => s.id === viewStage)?.label} — Logs
          </p>
          <button
            onClick={copyLogs} disabled={viewLogs.length === 0} title="Copy logs to clipboard"
            className="cyber-btn"
            style={{
              display: 'flex', alignItems: 'center', gap: '4px', padding: '3px 8px', fontSize: '0.7rem',
              opacity: viewLogs.length === 0 ? 0.4 : 1, cursor: viewLogs.length === 0 ? 'default' : 'pointer',
            }}
          >
            {copied ? <><CheckCheck size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
          </button>
        </div>
        <div style={{
          position: 'relative', background: '#0b1220', borderRadius: '8px', padding: '12px', fontFamily: 'var(--font-mono)',
          fontSize: '0.72rem', maxHeight: '260px', overflowY: 'auto', border: '1px solid var(--border-glass)',
        }}>
          {viewLogs.length === 0 && !viewNotImpl && (
            <div style={{ color: 'var(--color-muted)' }}>No logs yet for this stage.</div>
          )}
          {viewLogs.map((l, i) => (
            <div key={i} style={{
              color: l.startsWith('[!]') ? 'var(--color-danger)' : l.startsWith('[+]') ? 'var(--color-success)' : '#cbd5e1',
              whiteSpace: 'pre-wrap',
            }}>{l}</div>
          ))}
          <div ref={logEndRef} />
        </div>
      </div>
      </>
      )}
    </div>
  );
}

import { useState, useEffect, useRef } from 'react';
import { aspmFetch, aspmUrl } from '../aspmClient';
import { Database, RefreshCw, Copy, CheckCheck, History, ArrowLeft, Check, X } from 'lucide-react';

interface RagIndexProps {
  tenantId?: string;
}

interface EmbedRun {
  id: string;
  status: string;
  created_at: string;
  logs: string[];
}

export default function RagIndex({ tenantId }: RagIndexProps) {
  const [targets, setTargets] = useState<any[]>([]);
  const [tid, setTid] = useState('');
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [history, setHistory] = useState<EmbedRun[]>([]);
  const [viewRunId, setViewRunId] = useState<string>(''); // '' = live/current run
  const [mode, setMode] = useState<'list' | 'detail'>('list');
  const esRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

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
    aspmFetch(`/api/aspm/pipeline/embed/history?target_id=${encodeURIComponent(targetId)}`)
      .then((r) => r.json())
      .then((runs: EmbedRun[]) => {
        setHistory(Array.isArray(runs) ? runs : []);
        if (selectLatest && Array.isArray(runs) && runs.length > 0) {
          setViewRunId(runs[0].id);
          setLogs(runs[0].logs);
          setMode('list');
        }
      })
      .catch(() => {});
  };

  useEffect(() => {
    if (!tid) return;
    setLogs([]);
    setViewRunId('');
    setMode('list');
    loadHistory(tid, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tid]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => () => esRef.current?.close(), []);

  const selectRun = (runId: string) => {
    setMode('detail');
    if (running) return;
    setViewRunId(runId);
    const run = history.find((r) => r.id === runId);
    if (run) setLogs(run.logs);
  };

  const buildEmbedding = () => {
    if (!tid || running) return;
    esRef.current?.close();
    setLogs([]);
    setViewRunId('');
    setMode('detail');
    setRunning(true);

    const url = aspmUrl(`/api/aspm/pipeline/embed?target_id=${encodeURIComponent(tid)}&force=true`);
    const es = new EventSource(url);
    esRef.current = es;
    es.onmessage = (ev) => setLogs((prev) => [...prev, ev.data]);
    es.onerror = () => {
      es.close();
      setRunning(false);
      loadHistory(tid, false);
    };
  };

  const copyLogs = () => {
    if (logs.length === 0) return;
    navigator.clipboard.writeText(logs.join('\n')).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {});
  };

  const currentRunNumber = viewRunId === ''
    ? history.length + 1
    : history.length - history.findIndex((r) => r.id === viewRunId);

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
      <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
          <Database size={18} color="var(--color-primary)" /> RAG Code Index
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
          <button className="cyber-btn cyber-btn-accent" onClick={buildEmbedding} disabled={!tid || running}>
            {running ? (
              <span style={{
                width: '14px', height: '14px', borderRadius: '50%', border: '2px solid currentColor',
                borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite', display: 'inline-block',
              }} />
            ) : (
              <RefreshCw size={14} />
            )}
            {running ? 'Building…' : 'Build Embedding'}
          </button>
        </div>
      </div>

      <p style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
        Chunks the selected target's source code and embeds it (Ollama nomic-embed-text) into the RAG store the
        Vulnerability Pipeline's Triage stage uses to ground its AI verdicts in real code context. Rebuilding here
        always re-indexes regardless of whether the repo changed — separate from the pipeline's own automatic
        skip-if-unchanged check.
      </p>

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
                  <span style={{ fontSize: '0.85rem', fontWeight: 700 }}>Build in progress…</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--color-muted)' }}>
                    streaming live
                  </div>
                </div>
              </div>
            )}
            {history.map((r, i) => {
              const runNumber = history.length - i;
              const isSelected = viewRunId === r.id && !running;
              const ok = r.status?.toLowerCase() === 'completed';
              const lastLine = r.logs.length > 0 ? r.logs[r.logs.length - 1] : '';
              return (
                <div
                  key={r.id} onClick={() => selectRun(r.id)}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: '12px', padding: '12px 16px', borderRadius: '10px',
                    border: `1px solid ${isSelected ? 'var(--color-primary)' : 'var(--border-glass)'}`,
                    background: isSelected ? 'rgba(59,130,246,0.06)' : 'transparent',
                    cursor: running ? 'default' : 'pointer', opacity: running ? 0.6 : 1,
                  }}
                >
                  <span style={{
                    width: '28px', height: '28px', borderRadius: '50%', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', flexShrink: 0, color: '#fff', marginTop: '2px',
                    background: ok ? '#16a34a' : 'var(--color-danger, #dc2626)',
                  }}>
                    {ok ? <Check size={15} /> : <X size={15} />}
                  </span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, minWidth: 0 }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text)' }}>
                      <span style={{ color: 'var(--color-muted)', fontWeight: 600 }}>#{runNumber}.</span>{' '}
                      <span style={{
                        display: 'inline-block', maxWidth: '520px', overflow: 'hidden', textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap', verticalAlign: 'bottom',
                      }}>
                        {lastLine.replace(/^\[[+!*]\]\s*/, '') || (ok ? 'Index build completed' : 'Index build interrupted')}
                      </span>
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--color-muted)', flexWrap: 'wrap' }}>
                      <span className="cyber-badge" style={{ fontSize: '0.65rem', padding: '1px 7px' }}>{r.logs.length} line(s)</span>
                      <span style={{ fontSize: '0.68rem' }}>{new Date(r.created_at).toLocaleString()}</span>
                    </div>
                  </div>
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

      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
          <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text)' }}>Logs</p>
          <button
            onClick={copyLogs} disabled={logs.length === 0} title="Copy logs to clipboard"
            className="cyber-btn"
            style={{
              display: 'flex', alignItems: 'center', gap: '4px', padding: '3px 8px', fontSize: '0.7rem',
              opacity: logs.length === 0 ? 0.4 : 1, cursor: logs.length === 0 ? 'default' : 'pointer',
            }}
          >
            {copied ? <><CheckCheck size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
          </button>
        </div>
        <div style={{
          background: '#0b1220', borderRadius: '8px', padding: '12px', fontFamily: 'var(--font-mono)',
          fontSize: '0.72rem', maxHeight: '400px', overflowY: 'auto', border: '1px solid var(--border-glass)',
        }}>
          {logs.length === 0 && (
            <div style={{ color: 'var(--color-muted)' }}>No logs yet — click "Build Embedding" to index the selected target.</div>
          )}
          {logs.map((l, i) => (
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

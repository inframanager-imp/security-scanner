import { useState, useEffect } from 'react';
import { aspmFetch } from '../aspmClient';
import { Network, RefreshCw, AlertTriangle, Info } from 'lucide-react';

interface TaintReportProps {
  tenantId?: string;
}

interface TagEntry {
  function: string;
  file: string;
  line: number;
  kind: string;
  detail: string;
  cwe?: string;
}

interface Report {
  error?: string;
  logs?: string[];
  files_parsed?: number;
  files_with_errors?: number;
  functions_analyzed?: number;
  call_graph_edges?: number;
  sources?: TagEntry[];
  sinks?: TagEntry[];
  sanitizers?: TagEntry[];
  parse_errors?: { file: string; error: string }[];
}

export default function TaintReport({ tenantId }: TaintReportProps) {
  const [targets, setTargets] = useState<any[]>([]);
  const [tid, setTid] = useState('');
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<Report | null>(null);

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

  const buildGraph = () => {
    if (!tid || running) return;
    setRunning(true);
    setReport(null);
    aspmFetch(`/api/aspm/pipeline/taint-report?target_id=${encodeURIComponent(tid)}`)
      .then((r) => r.json())
      .then((d) => setReport(d))
      .catch(() => setReport({ error: 'Request failed' }))
      .finally(() => setRunning(false));
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
      <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
          <Network size={18} color="var(--color-primary)" /> Taint Analysis (Phase 1 — Preview)
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <select className="cyber-input" value={tid} onChange={(e) => setTid(e.target.value)} disabled={running} style={{ minWidth: '240px' }}>
            {targets.length === 0 && <option value="">No targets — onboard a Git target first</option>}
            {targets.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.url})</option>)}
          </select>
          <button className="cyber-btn cyber-btn-accent" onClick={buildGraph} disabled={!tid || running}>
            {running ? (
              <span style={{ width: '14px', height: '14px', borderRadius: '50%', border: '2px solid currentColor', borderTopColor: 'transparent', animation: 'spin 0.8s linear infinite', display: 'inline-block' }} />
            ) : (
              <RefreshCw size={14} />
            )}
            {running ? 'Analyzing…' : 'Build Code Graph'}
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', padding: '10px 14px', borderRadius: '10px', border: '1px solid var(--color-warning, #d97706)', background: 'rgba(217,119,6,0.08)', fontSize: '0.75rem' }}>
        <Info size={15} color="var(--color-warning, #d97706)" style={{ flexShrink: 0, marginTop: '1px' }} />
        <span>
          <strong>Preview / infrastructure only.</strong> This parses source, builds a call graph, and tags known
          sources/sinks/sanitizers — it does NOT yet trace whether a source actually reaches a sink (that's taint
          propagation, not built yet). A "sink" listed below is a location worth reviewing, not a confirmed
          vulnerability. Python source only for now.
        </span>
      </div>

      {report?.error && (
        <div style={{ padding: '10px 14px', borderRadius: '10px', border: '1px solid var(--color-danger, #dc2626)', color: 'var(--color-danger, #dc2626)', fontSize: '0.85rem' }}>
          {report.error}
        </div>
      )}

      {report && !report.error && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '10px' }}>
            {[
              ['Files parsed', report.files_parsed],
              ['Parse errors', report.files_with_errors],
              ['Functions', report.functions_analyzed],
              ['Call graph edges', report.call_graph_edges],
              ['Sources', report.sources?.length ?? 0],
              ['Sinks', report.sinks?.length ?? 0],
              ['Sanitizers', report.sanitizers?.length ?? 0],
            ].map(([label, value]) => (
              <div key={label as string} style={{ padding: '10px', borderRadius: '10px', border: '1px solid var(--border-glass)', textAlign: 'center' }}>
                <div style={{ fontSize: '1.3rem', fontWeight: 700, color: 'var(--color-text)' }}>{value as number}</div>
                <div style={{ fontSize: '0.68rem', color: 'var(--color-muted)' }}>{label as string}</div>
              </div>
            ))}
          </div>

          {(report.sinks?.length ?? 0) > 0 && (
            <div>
              <p style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                <AlertTriangle size={14} color="var(--color-warning, #d97706)" /> Sinks tagged (worth reviewing, not confirmed)
              </p>
              <div style={{ maxHeight: '260px', overflowY: 'auto', border: '1px solid var(--border-glass)', borderRadius: '8px' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.75rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--color-muted)', textAlign: 'left' }}>
                      <th style={{ padding: '6px 10px' }}>CWE</th>
                      <th style={{ padding: '6px 10px' }}>Location</th>
                      <th style={{ padding: '6px 10px' }}>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.sinks!.map((s, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border-glass)' }}>
                        <td style={{ padding: '6px 10px', fontFamily: 'var(--font-mono)' }}>{s.cwe}</td>
                        <td style={{ padding: '6px 10px', fontFamily: 'var(--font-mono)' }}>{s.file}:{s.line}</td>
                        <td style={{ padding: '6px 10px', color: 'var(--color-muted)' }}>{s.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {(report.parse_errors?.length ?? 0) > 0 && (
            <div>
              <p style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-muted)', marginBottom: '4px' }}>Parse errors (skipped)</p>
              <div style={{ fontSize: '0.7rem', color: 'var(--color-muted)', fontFamily: 'var(--font-mono)' }}>
                {report.parse_errors!.map((e, i) => <div key={i}>{e.file}: {e.error}</div>)}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

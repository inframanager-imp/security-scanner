import React, { useEffect, useState } from 'react';
import { aspmFetch } from '../aspmClient';
import { ChevronDown, ChevronRight, ShieldAlert, Bot, Wrench, Gavel } from 'lucide-react';
import AttackChains from './AttackChains';

interface VulnerabilitiesProps {
  tenantId?: string;
}

const SEVERITY_BADGE: Record<string, string> = {
  Critical: 'badge-critical',
  High: 'badge-high',
  Medium: 'badge-medium',
  Low: 'badge-low',
};

function Section({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: '12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', fontWeight: 700, color: 'var(--color-text)', marginBottom: '4px' }}>
        {icon} {title}
      </div>
      <div style={{ fontSize: '0.8rem', color: 'var(--color-muted)', lineHeight: 1.5 }}>{children}</div>
    </div>
  );
}

function ExpandedRow({ vuln }: { vuln: any }) {
  const analysis = vuln.ai_analysis || {};
  const remediation = vuln.remediation || {};
  const verification = vuln.pt_verification;

  return (
    <tr>
      <td colSpan={7} style={{ padding: '16px', background: 'rgba(0,0,0,0.02)', borderBottom: '1px solid var(--border-glass)' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
          <div>
            <Section icon={<ShieldAlert size={14} color="var(--color-danger)" />} title="Description">
              {vuln.description || '—'}
            </Section>
            <Section icon={<Bot size={14} color="var(--color-primary)" />} title="AI Analysis (agent-api)">
              {analysis.exploitability ? (
                <>
                  <div><strong>Exploitability:</strong> {analysis.exploitability}</div>
                  <div style={{ marginTop: 4 }}><strong>Verdict:</strong> {analysis.false_positive}</div>
                  {typeof analysis.risk_score === 'number' && (
                    <div style={{ marginTop: 4 }}><strong>Risk score:</strong> {analysis.risk_score}/10</div>
                  )}
                </>
              ) : (
                <span style={{ fontStyle: 'italic' }}>No AI analysis on this finding yet.</span>
              )}
            </Section>
            {verification && (
              <Section icon={<Gavel size={14} color="var(--color-warning)" />} title="Judge Verification">
                <div>
                  <span className={`badge ${verification.confirmed ? 'badge-critical' : 'badge-low'}`} style={{ marginRight: 8 }}>
                    {verification.confirmed ? 'Confirmed' : 'Likely False Positive'}
                  </span>
                  {verification.reason}
                </div>
              </Section>
            )}
          </div>
          <div>
            <Section icon={<Wrench size={14} color="var(--color-success)" />} title="Remediation">
              {remediation.explanation ? (
                <>
                  <div>{remediation.explanation}</div>
                  {remediation.unsafe && (
                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-danger)' }}>UNSAFE</div>
                      <pre style={{ background: '#1e1e2e', color: '#f38ba8', padding: '8px', borderRadius: '6px', overflowX: 'auto', fontSize: '0.75rem' }}>{remediation.unsafe}</pre>
                    </div>
                  )}
                  {remediation.safe && (
                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--color-success)' }}>FIXED</div>
                      <pre style={{ background: '#1e1e2e', color: '#a6e3a1', padding: '8px', borderRadius: '6px', overflowX: 'auto', fontSize: '0.75rem' }}>{remediation.safe}</pre>
                    </div>
                  )}
                </>
              ) : (
                <span style={{ fontStyle: 'italic' }}>No remediation suggested.</span>
              )}
            </Section>
          </div>
        </div>
      </td>
    </tr>
  );
}

export default function Vulnerabilities({ tenantId }: VulnerabilitiesProps) {
  const [vulns, setVulns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const fetchVulns = () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (tenantId) params.set('tenant_id', tenantId);
    if (severityFilter !== 'All') params.set('severity', severityFilter);
    aspmFetch(`/api/aspm/vulnerabilities?${params.toString()}`)
      .then((res) => res.json())
      .then((data) => { setVulns(Array.isArray(data) ? data : []); setLoading(false); })
      .catch((err) => { console.error('Error fetching vulnerabilities:', err); setLoading(false); });
  };

  useEffect(() => { fetchVulns(); }, [tenantId, severityFilter]);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
    <AttackChains tenantId={tenantId} />
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
          <ShieldAlert size={18} color="var(--color-primary)" /> Vulnerabilities
        </h3>
        <select className="cyber-input" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} style={{ minWidth: '160px' }}>
          <option value="All">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </div>

      {loading ? (
        <p style={{ color: 'var(--color-muted)', fontSize: '0.85rem' }}>Loading vulnerabilities…</p>
      ) : vulns.length === 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '30px', color: 'var(--color-muted)' }}>
          <ShieldAlert size={48} style={{ marginBottom: '12px', color: 'var(--color-warning)' }} />
          <p style={{ fontSize: '0.9rem' }}>No vulnerabilities found. Run a scan to populate this list.</p>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--color-muted)' }}>
                <th style={{ padding: '10px', width: '30px' }}></th>
                <th style={{ padding: '10px', width: '48px' }}>#</th>
                <th style={{ padding: '10px' }}>Title</th>
                <th style={{ padding: '10px' }}>Severity</th>
                <th style={{ padding: '10px' }}>CWE</th>
                <th style={{ padding: '10px' }}>Asset</th>
                <th style={{ padding: '10px' }}>AI Triage</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map((v, i) => (
                <React.Fragment key={v.id}>
                  <tr
                    style={{ borderBottom: '1px solid var(--border-glass)', cursor: 'pointer' }}
                    onClick={() => toggle(v.id)}
                  >
                    <td style={{ padding: '12px 10px' }}>
                      {expanded.has(v.id) ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </td>
                    <td style={{ padding: '12px 10px', color: 'var(--color-muted)', fontSize: '0.8rem' }}>{i + 1}</td>
                    <td style={{ padding: '12px 10px', fontWeight: 600, color: 'var(--color-text)' }}>{v.title}</td>
                    <td style={{ padding: '12px 10px' }}>
                      <span className={`badge ${SEVERITY_BADGE[v.severity] || 'badge-low'}`}>{v.severity}</span>
                    </td>
                    <td style={{ padding: '12px 10px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-muted)' }}>{v.cwe}</td>
                    <td style={{ padding: '12px 10px', color: 'var(--color-muted)' }}>{v.asset}</td>
                    <td style={{ padding: '12px 10px' }}>
                      {v.ai_analysis?.exploitability ? (
                        <span className="badge badge-low" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <Bot size={12} /> Triaged
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.7rem', color: 'var(--color-muted)', fontStyle: 'italic' }}>—</span>
                      )}
                    </td>
                  </tr>
                  {expanded.has(v.id) && <ExpandedRow vuln={v} />}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
    </div>
  );
}

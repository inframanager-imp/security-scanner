import { useEffect, useState } from 'react';
import { aspmFetch } from '../aspmClient';
import { Link2, ChevronRight } from 'lucide-react';

interface AttackChainsProps {
  tenantId?: string;
}

interface ChainStep {
  finding_id: string;
  title: string;
  role: string;
  severity: string;
  asset: string;
  cwe: string;
}

interface Chain {
  score: number;
  step_count: number;
  steps: ChainStep[];
}

const ROLE_LABEL: Record<string, string> = {
  file_access: 'File Access',
  code_exec: 'Code Execution',
  information_theft: 'Info Theft',
  access_escalation: 'Access Escalation',
  auth_bypass: 'Auth Bypass',
};

const SEV_COLOR: Record<string, string> = {
  Critical: 'var(--color-danger, #dc2626)',
  High: '#f97316',
  Medium: 'var(--color-warning, #d97706)',
  Low: 'var(--color-muted)',
};

function shortAsset(asset: string): string {
  const withoutLine = asset.split(':')[0];
  const parts = withoutLine.split('/');
  const file = parts[parts.length - 1] || withoutLine;
  const line = asset.includes(':') ? asset.split(':').pop() : '';
  return line && /^\d+$/.test(line) ? `${file}:${line}` : file;
}

export default function AttackChains({ tenantId }: AttackChainsProps) {
  const [chains, setChains] = useState<Chain[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (!tenantId) { setChains([]); setLoading(false); return; }
    setLoading(true);
    aspmFetch(`/api/aspm/pipeline/attack-chains?target_id=${encodeURIComponent(tenantId)}`)
      .then((r) => r.json())
      .then((d) => setChains(Array.isArray(d) ? d : []))
      .catch(() => setChains([]))
      .finally(() => setLoading(false));
  }, [tenantId]);

  if (loading || chains.length === 0) return null;

  const visible = expanded ? chains : chains.slice(0, 3);

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
          <Link2 size={18} color="var(--color-danger, #dc2626)" /> Possible Attack Chains
        </h3>
        <span className="cyber-badge" style={{ fontSize: '0.7rem' }}>{chains.length} chain{chains.length === 1 ? '' : 's'}</span>
      </div>
      <p style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
        Open findings that could plausibly combine into a multi-step attack, based on vulnerability role compatibility —
        not a verified data-flow path. Treat as a prioritization hint, not proof.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {visible.map((chain, i) => (
          <div key={i} style={{ border: '1px solid var(--border-glass)', borderRadius: '10px', padding: '12px 14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '4px', fontSize: '0.82rem' }}>
              {chain.steps.map((step, j) => (
                <span key={step.finding_id} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  {j > 0 && <ChevronRight size={13} color="var(--color-muted)" />}
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: '5px', padding: '3px 9px',
                    borderRadius: '999px', border: `1px solid ${SEV_COLOR[step.severity] || 'var(--border-glass)'}`,
                    color: 'var(--color-text)', whiteSpace: 'nowrap',
                  }} title={`${step.title} — ${step.asset}`}>
                    <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: SEV_COLOR[step.severity] || 'var(--color-muted)' }} />
                    {ROLE_LABEL[step.role] || step.role}
                  </span>
                </span>
              ))}
            </div>
            <div style={{ marginTop: '6px', fontSize: '0.72rem', color: 'var(--color-muted)' }}>
              {chain.steps.map((s) => `${s.title} (${shortAsset(s.asset)})`).join(' → ')}
            </div>
          </div>
        ))}
      </div>

      {chains.length > 3 && (
        <button
          onClick={() => setExpanded((e) => !e)}
          className="cyber-btn"
          style={{ alignSelf: 'flex-start', padding: '4px 10px', fontSize: '0.72rem' }}
        >
          {expanded ? 'Show fewer' : `Show all ${chains.length} chains`}
        </button>
      )}
    </div>
  );
}

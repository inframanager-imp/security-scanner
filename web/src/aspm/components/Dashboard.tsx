import React, { useEffect, useState } from 'react';
import { aspmFetch, aspmUrl } from '../aspmClient';
import { Shield, AlertTriangle, CheckCircle, Activity, Clock, Server } from 'lucide-react';

interface DashboardProps {
  tenantId: string;
}

export default function Dashboard({ tenantId }: DashboardProps) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!tenantId) { setData(null); setLoading(false); return; }
    setLoading(true);
    aspmFetch(`/api/aspm/dashboard?tenant_id=${tenantId}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((resData) => {
        setData(resData && resData.vulnerability_counts ? resData : null);
        setLoading(false);
      })
      .catch((err) => { console.error("Error fetching dashboard details:", err); setData(null); setLoading(false); });
  }, [tenantId]);

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: 'var(--color-primary)' }}>
        <Activity className="animate-spin" style={{ marginRight: '8px' }} />
        <span>Loading ASPM Intelligence Matrix...</span>
      </div>
    );
  }

  if (!data || !data.vulnerability_counts) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', height: '100%', color: 'var(--color-muted)', padding: '40px', textAlign: 'center' }}>
        <Server size={40} style={{ marginBottom: '12px', color: 'var(--color-warning)' }} />
        <span>Select an application target to view its security posture.</span>
      </div>
    );
  }

  const { vulnerability_counts, compliance_score, open_findings, total_findings, easm_summary, history_chart, sla_breaches } = data;

  const chartMaxVal = Math.max(
    10,
    ...(history_chart ?? []).flatMap((hc: any) => [hc.Critical, hc.High, hc.Medium])
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', animation: 'fade-in 0.3s ease' }}>
      
      {/* Upper Cards Summary Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '20px' }}>
        
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', justifyItems: 'space-between', gap: '15px' }}>
          <div style={{ background: 'rgba(37, 99, 235, 0.1)', padding: '12px', borderRadius: '10px', color: 'var(--color-primary)' }}>
            <Shield size={28} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Posture Score</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-text)' }}>
              {compliance_score}%
            </div>
            <div style={{ fontSize: '0.7rem', color: compliance_score > 70 ? 'var(--color-success)' : 'var(--color-danger)', fontWeight: 600 }}>
              {compliance_score > 70 ? 'Secure Posture' : '⚠️ Action Required'}
            </div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ background: 'rgba(220, 38, 38, 0.1)', padding: '12px', borderRadius: '10px', color: 'var(--color-danger)' }}>
            <AlertTriangle size={28} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Critical / High</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-text)' }}>
              {vulnerability_counts.Critical} <span style={{ fontSize: '1rem', color: 'var(--color-muted)', fontWeight: 400 }}>/ {vulnerability_counts.High}</span>
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--color-danger)', fontWeight: 600 }}>Active Threat vectors</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ background: 'rgba(22, 163, 74, 0.1)', padding: '12px', borderRadius: '10px', color: 'var(--color-success)' }}>
            <CheckCircle size={28} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Remediation Rate</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-text)' }}>
              {total_findings - open_findings} <span style={{ fontSize: '1rem', color: 'var(--color-muted)', fontWeight: 400 }}>/ {total_findings}</span>
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--color-success)', fontWeight: 600 }}>Resolved findings</div>
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '20px', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <div style={{ background: 'rgba(217, 119, 6, 0.1)', padding: '12px', borderRadius: '10px', color: 'var(--color-warning)' }}>
            <Server size={28} />
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Attack Surface</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-text)' }}>
              {easm_summary.subdomains} <span style={{ fontSize: '1rem', color: 'var(--color-muted)', fontWeight: 400 }}>Subdomains</span>
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--color-warning)', fontWeight: 600 }}>
              {easm_summary.open_ports} Open ports found
            </div>
          </div>
        </div>

      </div>

      {/* Main Body Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px' }}>
        
        {/* Posture history and charts */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Activity size={18} color="var(--color-primary)" />
            Vulnerability Trends Over Time
          </h3>
          
          {/* Custom bar chart simulation */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', height: '220px', padding: '10px 0', borderBottom: '1px solid var(--border-glass)' }}>
            {history_chart.map((hc: any, index: number) => {
              const critHeight = (hc.Critical / chartMaxVal) * 180;
              const highHeight = (hc.High / chartMaxVal) * 180;
              const medHeight = (hc.Medium / chartMaxVal) * 180;
              
              return (
                <div key={index} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1, gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: '180px' }}>
                    <div style={{ width: '8px', height: `${Math.max(4, medHeight)}px`, background: 'var(--color-primary)', borderRadius: '2px 2px 0 0' }} title={`Medium: ${hc.Medium}`} />
                    <div style={{ width: '8px', height: `${Math.max(4, highHeight)}px`, background: 'var(--color-warning)', borderRadius: '2px 2px 0 0' }} title={`High: ${hc.High}`} />
                    <div style={{ width: '8px', height: `${Math.max(4, critHeight)}px`, background: 'var(--color-danger)', borderRadius: '2px 2px 0 0' }} title={`Critical: ${hc.Critical}`} />
                  </div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)', fontWeight: 500 }}>{hc.month}</span>
                </div>
              );
            })}
          </div>
          
          <div style={{ display: 'flex', gap: '15px', justifyContent: 'center', fontSize: '0.8rem' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <span style={{ width: '8px', height: '8px', background: 'var(--color-danger)', borderRadius: '50%' }}></span> Critical
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <span style={{ width: '8px', height: '8px', background: 'var(--color-warning)', borderRadius: '50%' }}></span> High
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
              <span style={{ width: '8px', height: '8px', background: 'var(--color-primary)', borderRadius: '50%' }}></span> Medium
            </span>
          </div>
        </div>

        {/* SLA tracking Alerts */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Clock size={18} color="var(--color-warning)" />
            SLA Warning Center
          </h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflowY: 'auto', maxHeight: '230px' }}>
            {sla_breaches.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--color-muted)', padding: '40px 0', fontSize: '0.85rem' }}>
                No SLA warnings. All targets are within remediation policies.
              </div>
            ) : (
              sla_breaches.map((sb: any) => (
                <div key={sb.id} style={{ padding: '12px', border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span className={`badge ${sb.severity === 'Critical' ? 'badge-critical' : 'badge-high'}`} style={{ fontSize: '0.65rem' }}>
                      {sb.severity}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--color-danger)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <Clock size={12} /> {sb.days_left} Days Left
                    </span>
                  </div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {sb.title}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

      </div>
    </div>
  );
}

import React, { useEffect, useState } from 'react';
import { aspmFetch, aspmUrl } from '../aspmClient';
import { BarChart3, Shield, Globe, ShieldAlert, Award, FileText, ExternalLink, AlertTriangle, Layers, Activity, Settings, X, Download, Loader2, Code, Server } from 'lucide-react';

interface ReportsProps {
  tenantId?: string;
}

// ----------------- SUB-COMPONENTS FOR CHARTS -----------------

function VBarChart({ title, bars }: { title: string; bars: { label: string; value: number; color: string }[] }) {
  const maxVal = Math.max(...bars.map((b) => b.value), 1);
  return (
    <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', overflow: 'hidden', background: '#f8fafc' }}>
      <div style={{ background: '#f1f5f9', padding: '10px 15px', borderBottom: '1px solid var(--border-glass)', fontSize: '0.78rem', fontWeight: 700, color: 'var(--color-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {title}
      </div>
      <div style={{ display: 'flex', height: '150px', alignItems: 'flex-end', justifyContent: 'space-around', padding: '16px 12px 12px', gap: '4px' }}>
        {bars.map((b) => (
          <div key={b.label} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'flex-end', flex: 1, gap: '6px' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: b.color }}>{b.value}</span>
            <div style={{ width: '60%', maxWidth: '34px', height: `${(b.value / maxVal) * 100}px`, minHeight: b.value > 0 ? '2px' : '0', background: b.color, borderRadius: '3px 3px 0 0' }} />
            <span style={{ fontSize: '0.6rem', color: 'var(--color-muted)', textAlign: 'center', lineHeight: 1.15 }}>{b.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsBySeverityChart({
  c_level5, c_level4, c_level3, c_level2, c_level1, c_sensitive, c_info_gathered
}: {
  c_level5: number; c_level4: number; c_level3: number; c_level2: number; c_level1: number; c_sensitive: number; c_info_gathered: number;
}) {
  return (
    <VBarChart
      title="Findings by Severity"
      bars={[
        { label: 'Critical', value: c_level5, color: '#b91c1c' },
        { label: 'High', value: c_level4, color: '#ea580c' },
        { label: 'Medium', value: c_level3, color: '#d4a017' },
        { label: 'Low', value: c_level2, color: '#2563eb' },
        { label: 'Info', value: c_level1, color: '#64748b' },
        { label: 'Secrets', value: c_sensitive, color: '#7c3aed' },
        { label: 'Recon', value: c_info_gathered, color: '#0e9aa7' },
      ]}
    />
  );
}

function VulnerabilitiesByGroupChart({
  c_xss, c_sqli, c_path, c_info, c_nogroup
}: {
  c_xss: number; c_sqli: number; c_path: number; c_info: number; c_nogroup: number;
}) {
  return (
    <VBarChart
      title="Vulnerabilities by Group"
      bars={[
        { label: 'XSS', value: c_xss, color: '#2563eb' },
        { label: 'SQLi', value: c_sqli, color: '#16a34a' },
        { label: 'Path Traversal', value: c_path, color: '#d4a017' },
        { label: 'Info Disclosure', value: c_info, color: '#0e9aa7' },
        { label: 'Other', value: c_nogroup, color: '#64748b' },
      ]}
    />
  );
}

function OwaspTop10Chart({ counts }: { counts: Record<string, number> }) {
  const maxVal = Math.max(...Object.values(counts), 1);

  return (
    <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', overflow: 'hidden', background: '#f8fafc' }}>
      <div style={{ background: '#f1f5f9', padding: '10px 15px', borderBottom: '1px solid var(--border-glass)', fontSize: '0.78rem', fontWeight: 700, color: 'var(--color-primary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        OWASP Top 10 (2021) Distribution
      </div>
      <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: '9px' }}>
        {Object.entries(counts).map(([cat, count]) => {
          const w = (count / maxVal) * 100;
          return (
            <div key={cat} style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.7rem' }}>
              <div style={{ width: '240px', flexShrink: 0, color: 'var(--color-muted)', textAlign: 'right', lineHeight: 1.2 }}>
                {cat}
              </div>
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ flex: 1, height: '14px', background: '#eef1f5', borderRadius: '3px', overflow: 'hidden', border: '1px solid var(--border-glass)' }}>
                  <div style={{ width: `${w}%`, height: '100%', background: '#3949ab', borderRadius: '3px', minWidth: count > 0 ? '2px' : '0', transition: 'width 0.5s ease-out' }} />
                </div>
                <span style={{ fontWeight: 700, color: count > 0 ? '#3949ab' : 'var(--color-muted)', width: '16px' }}>
                  {count}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ----------------- DETAIL PANEL (EXPANDED CONTENT) -----------------

interface JobReportsPanelProps {
  targetId: string;
  targetName: string;
}

function JobReportsPanel({ targetId, targetName }: JobReportsPanelProps) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeGroup, setActiveGroup] = useState<string>('Security Hygiene');
  const [expandedVulnId, setExpandedVulnId] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    const url = targetId === 'All' ? '/api/aspm/reports/summary' : `/api/aspm/reports/summary?tenant_id=${targetId}`;
    aspmFetch(url)
      .then((res) => res.json())
      .then((resData) => {
        setData(resData);
        // Default to a group that has items if possible
        if (resData.issue_groups_details) {
          const groups = Object.keys(resData.issue_groups_details);
          const groupWithItems = groups.find(g => resData.issue_groups_details[g]?.length > 0);
          if (groupWithItems) {
            setActiveGroup(groupWithItems);
          } else if (groups.length > 0) {
            setActiveGroup(groups[0]);
          }
        }
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching report summary details:", err);
        setLoading(false);
      });
  }, [targetId]);

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', padding: '40px', color: 'var(--color-primary)' }}>
        <Activity className="animate-spin" style={{ marginRight: '8px' }} />
        <span>Synthesizing Target Audit Metrics...</span>
      </div>
    );
  }

  if (!data) {
    return (
      <div style={{ textAlign: 'center', padding: '20px', color: 'var(--color-muted)' }}>
        <ShieldAlert size={36} style={{ margin: '0 auto 10px', color: 'var(--color-danger)' }} />
        <span>Could not retrieve report metrics.</span>
      </div>
    );
  }

  const { mitre_stages, issue_groups, issue_groups_details, compliance_gauges, priorities, assets_count } = data;

  const openVulns: any[] = [];
  if (issue_groups_details) {
    Object.values(issue_groups_details).forEach((list: any) => {
      list.forEach((v: any) => {
        if (v.status === 'Open' || v.status === 'In Progress') {
          openVulns.push(v);
        }
      });
    });
  }

  // Severity Counters
  let c_level5 = 0;
  let c_level4 = 0;
  let c_level3 = 0;
  let c_level2 = 0;
  let c_level1 = 0;
  let c_sensitive = 0;
  let c_info_gathered = 0;

  openVulns.forEach((v: any) => {
    const type = (v.type || '').toUpperCase();
    const sev = v.severity || '';
    if (type === 'SECRETS') {
      c_sensitive++;
    } else if (['EASM', 'NMAP', 'NMAP + NSE', 'SSLSCAN'].includes(type)) {
      c_info_gathered++;
    } else if (sev === 'Critical') {
      c_level5++;
    } else if (sev === 'High') {
      c_level4++;
    } else if (sev === 'Medium') {
      c_level3++;
    } else if (sev === 'Low') {
      c_level2++;
    } else {
      c_level1++;
    }
  });

  // Group Counters
  let c_xss = 0;
  let c_sqli = 0;
  let c_path = 0;
  let c_info = 0;
  let c_nogroup = 0;

  openVulns.forEach((v: any) => {
    const cwe = (v.cwe || '').toUpperCase();
    const title = (v.title || '').toLowerCase();
    if (title.includes('cross-site scripting') || title.includes('xss') || cwe === 'CWE-79') {
      c_xss++;
    } else if (title.includes('sql') || title.includes('sqli') || cwe === 'CWE-89') {
      c_sqli++;
    } else if (title.includes('path disclosure') || title.includes('directory traversal') || title.includes('file inclusion') || ['CWE-22', 'CWE-23'].includes(cwe)) {
      c_path++;
    } else if (title.includes('disclosure') || title.includes('header') || title.includes('csp') || title.includes('referrer') || title.includes('hsts') || title.includes('nosniff') || title.includes('x-frame-options') || title.includes('clickjacking') || cwe === 'CWE-200') {
      c_info++;
    } else {
      c_nogroup++;
    }
  });

  // OWASP top 10
  const owaspCounts: Record<string, number> = {
    'A01:2021-Broken Access Control': 0,
    'A02:2021-Cryptographic Failures': 0,
    'A03:2021-Injection': 0,
    'A04:2021-Insecure Design': 0,
    'A05:2021-Security Misconfiguration': 0,
    'A06:2021-Vulnerable and Outdated Components': 0,
    'A07:2021-Identification and Authentication Failures': 0,
    'A08:2021-Software and Data Integrity Failures': 0,
    'A09:2021-Security Logging and Monitoring Failures': 0,
    'A10:2021-Server-Side Request Forgery': 0
  };

  openVulns.forEach((v: any) => {
    const cwe = (v.cwe || '').toUpperCase();
    const title = (v.title || '').toLowerCase();
    const type = (v.type || '').toUpperCase();

    if (['CWE-287', 'CWE-639'].includes(cwe) || title.includes('x-frame-options') || title.includes('clickjacking')) {
      owaspCounts['A01:2021-Broken Access Control']++;
    } else if (['CWE-327', 'CWE-319'].includes(cwe) || title.includes('tls') || title.includes('ssl')) {
      owaspCounts['A02:2021-Cryptographic Failures']++;
    } else if (['CWE-89', 'CWE-79'].includes(cwe) || title.includes('sqli') || title.includes('injection') || title.includes('xss')) {
      owaspCounts['A03:2021-Injection']++;
    } else if (title.includes('csp') || title.includes('content-security-policy') || title.includes('referrer-policy') || title.includes('nosniff') || title.includes('x-content-type-options') || title.includes('hsts')) {
      owaspCounts['A05:2021-Security Misconfiguration']++;
    } else if (title.includes('outdated') || ['SCA', 'TRIVY'].includes(type)) {
      owaspCounts['A06:2021-Vulnerable and Outdated Components']++;
    } else if (title.includes('credential') || title.includes('password') || type === 'HYDRA' || type === 'SECRETS') {
      owaspCounts['A07:2021-Identification and Authentication Failures']++;
    } else if (title.includes('ssrf') || cwe === 'CWE-918') {
      owaspCounts['A10:2021-Server-Side Request Forgery']++;
    } else {
      owaspCounts['A05:2021-Security Misconfiguration']++;
    }
  });

  const getThreatLevel = () => {
    let score = 0;
    priorities.forEach((p: any) => {
      score += p.risk_weight;
    });
    if (score >= 10) return { label: 'CRITICAL THREAT', color: 'var(--color-danger)' };
    if (score >= 6) return { label: 'HIGH RISK', color: 'var(--color-warning)' };
    if (score >= 3) return { label: 'ELEVATED WARNING', color: 'var(--color-primary)' };
    return { label: 'LOW THREAT', color: 'var(--color-success)' };
  };

  const threatLevel = getThreatLevel();

  const handleExportReport = () => {
    const url = targetId === 'All' ? '/api/aspm/reports/export' : `/api/aspm/reports/export?tenant_id=${targetId}`;
    window.open(aspmUrl(url), '_blank');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', animation: 'fade-in 0.2s ease', padding: '5px' }}>
      
      {/* Target Metrics Summary Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '12px 15px', borderRadius: '8px', border: '1px solid var(--border-glass)' }}>
        <div style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 600 }}>
          AUDIT TARGET: <span style={{ color: 'var(--color-text)', fontWeight: 700 }}>{targetName.toUpperCase()}</span>
        </div>
        <button className="cyber-btn cyber-btn-accent" onClick={handleExportReport} style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px', fontSize: '0.75rem' }}>
          <Download size={14} /> Export C-Level PDF
        </button>
      </div>

      {/* Top Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
        
        {/* Compliance Average */}
        <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', padding: '15px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Shield size={24} color="var(--color-primary)" />
          <div>
            <div style={{ fontSize: '0.65rem', color: 'var(--color-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Compliance Average</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-text)' }}>
              {compliance_gauges["OWASP Top 10"]}%
            </div>
          </div>
        </div>

        {/* Assets Count */}
        <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', padding: '15px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Globe size={24} color="var(--color-success)" />
          <div>
            <div style={{ fontSize: '0.65rem', color: 'var(--color-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Audited Assets</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--color-text)' }}>{assets_count} Nodes</div>
          </div>
        </div>

        {/* Threat Level */}
        <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', padding: '15px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <ShieldAlert size={24} color={threatLevel.color} />
          <div>
            <div style={{ fontSize: '0.65rem', color: 'var(--color-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Threat Rating</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 800, color: threatLevel.color }}>{threatLevel.label}</div>
          </div>
        </div>

      </div>

      {/* SVG Charts Section */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
        <FindingsBySeverityChart
          c_level5={c_level5}
          c_level4={c_level4}
          c_level3={c_level3}
          c_level2={c_level2}
          c_level1={c_level1}
          c_sensitive={c_sensitive}
          c_info_gathered={c_info_gathered}
        />
        <VulnerabilitiesByGroupChart
          c_xss={c_xss}
          c_sqli={c_sqli}
          c_path={c_path}
          c_info={c_info}
          c_nogroup={c_nogroup}
        />
      </div>

      <OwaspTop10Chart counts={owaspCounts} />

      {/* MITRE ATT&CK Matrix Card */}
      <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', padding: '15px' }}>
        <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '8px', color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Layers size={16} color="var(--color-primary)" />
          MITRE ATT&CK Lifecycle Threat Matrix
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(100px, 1fr))', gap: '8px', overflowX: 'auto', marginTop: '10px' }}>
          {Object.entries(mitre_stages).map(([stage, count]: [string, any]) => {
            const hasThreats = count > 0;
            return (
              <div
                key={stage}
                style={{
                  border: `1px solid ${hasThreats ? 'rgba(220, 38, 38, 0.25)' : 'rgba(255,255,255,0.05)'}`,
                  background: hasThreats ? 'rgba(220, 38, 38, 0.03)' : 'rgba(255,255,255,0.01)',
                  borderRadius: '6px',
                  padding: '10px 6px',
                  textAlign: 'center',
                  minHeight: '80px',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div style={{ fontSize: '0.675rem', fontWeight: 600, color: hasThreats ? 'var(--color-text)' : 'var(--color-muted)', lineHeight: '1.2', textTransform: 'capitalize' }}>
                  {stage}
                </div>
                <div style={{ fontSize: '1.3rem', fontWeight: 800, color: hasThreats ? 'var(--color-danger)' : 'var(--color-muted)' }}>
                  {count}
                </div>
                <div style={{ fontSize: '0.55rem', fontWeight: 700, padding: '1px 5px', borderRadius: '8px', background: hasThreats ? 'rgba(220, 38, 38,0.15)' : 'rgba(255,255,255,0.03)', color: hasThreats ? 'var(--color-danger)' : 'var(--color-muted)' }}>
                  {hasThreats ? 'ACTIVE' : 'SECURE'}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Tenable Compliance Status Gauges & priorities */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
        
        {/* Compliance */}
        <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', padding: '15px' }}>
          <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Award size={16} color="var(--color-warning)" />
            Standard Compliance Audits
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '12px' }}>
            {Object.entries(compliance_gauges).map(([name, score]: [string, any]) => {
              const scoreColor = score > 80 ? 'var(--color-success)' : (score > 50 ? 'var(--color-warning)' : 'var(--color-danger)');
              return (
                <div key={name} style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', fontWeight: 600 }}>
                    <span>{name}</span>
                    <span style={{ color: scoreColor }}>{score}%</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.04)', borderRadius: '3px', overflow: 'hidden', border: '1px solid var(--border-glass)' }}>
                    <div style={{ width: `${score}%`, height: '100%', background: scoreColor, borderRadius: '3px' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Priorities Remediation Plan */}
        <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', padding: '15px', display: 'flex', flexDirection: 'column' }}>
          <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertTriangle size={16} color="var(--color-danger)" />
            Top Priorities Remediation Plan
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px', overflowY: 'auto', flex: 1 }}>
            {priorities.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--color-muted)', padding: '20px 0', fontSize: '0.75rem' }}>
                No critical vectors detected. Target scope is healthy.
              </div>
            ) : (
              priorities.map((item: any, idx: number) => (
                <div key={item.id || idx} style={{ padding: '8px 10px', border: '1px solid var(--border-glass)', background: 'rgba(220, 38, 38, 0.02)', borderRadius: '6px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.675rem' }}>
                    <span className={`badge ${item.severity === 'Critical' ? 'badge-critical' : item.severity === 'High' ? 'badge-high' : 'badge-medium'}`}>{item.severity}</span>
                    <span style={{ color: 'var(--color-muted)' }}>Risk Weight: {item.risk_weight}/5</span>
                  </div>
                  <div style={{ fontSize: '0.775rem', fontWeight: 700, color: 'var(--color-text)' }}>{item.title}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--color-muted)' }}><code>{item.asset}</code></div>
                </div>
              ))
            )}
          </div>
        </div>

      </div>

      {/* CyCognito Categories */}
      <div style={{ border: '1px solid var(--border-glass)', borderRadius: '8px', background: '#f8fafc', padding: '15px', marginTop: '5px' }}>
        <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '10px' }}>
          <BarChart3 size={16} color="var(--color-primary)" />
          CyCognito Category Classifier
        </h4>
        
        {/* Category Selection Tabs */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '12px' }}>
          {Object.keys(issue_groups).map((groupName) => {
            const count = issue_groups[groupName];
            const isActive = activeGroup === groupName;
            return (
              <button
                key={groupName}
                onClick={() => {
                  setActiveGroup(groupName);
                  setExpandedVulnId(null);
                }}
                style={{
                  padding: '4px 10px',
                  background: isActive ? 'rgba(37, 99, 235, 0.12)' : 'rgba(255, 255, 255, 0.01)',
                  color: isActive ? 'var(--color-primary)' : 'var(--color-muted)',
                  border: `1px solid ${isActive ? 'var(--color-primary)' : 'var(--border-glass)'}`,
                  borderRadius: '15px',
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px'
                }}
              >
                <span>{groupName}</span>
                <span style={{ background: isActive ? 'var(--color-primary)' : 'rgba(255,255,255,0.06)', color: isActive ? 'var(--color-text)' : 'var(--color-text)', padding: '1px 5px', borderRadius: '8px', fontSize: '0.6rem' }}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Category Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-glass)', fontSize: '0.725rem', color: 'var(--color-muted)' }}>
                <th style={{ padding: '8px' }}>Severity</th>
                <th style={{ padding: '8px' }}>Finding Description</th>
                <th style={{ padding: '8px', width: '150px' }}>Base Score</th>
                <th style={{ padding: '8px', width: '150px' }}>Enhanced Score</th>
                <th style={{ padding: '8px' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {!issue_groups_details[activeGroup] || issue_groups_details[activeGroup].length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '20px 8px', textAlign: 'center', color: 'var(--color-muted)' }}>
                    No findings recorded under this category.
                  </td>
                </tr>
              ) : (
                issue_groups_details[activeGroup].map((vuln: any) => {
                  const isExpanded = expandedVulnId === vuln.id;
                  return (
                    <React.Fragment key={vuln.id}>
                      <tr 
                        onClick={() => setExpandedVulnId(isExpanded ? null : vuln.id)}
                        style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', cursor: 'pointer', background: isExpanded ? 'rgba(37, 99, 235, 0.02)' : 'transparent' }}
                        className="table-row-hover"
                      >
                        <td style={{ padding: '10px 8px' }}>
                          <span className={`badge ${vuln.severity === 'Critical' ? 'badge-critical' : vuln.severity === 'High' ? 'badge-high' : vuln.severity === 'Medium' ? 'badge-medium' : 'badge-low'}`} style={{ fontSize: '0.625rem' }}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td style={{ padding: '10px 8px', fontWeight: 600, color: 'var(--color-text)' }}>
                          <span style={{ fontSize: '0.65rem', color: 'var(--color-primary)', marginRight: '6px' }}>{isExpanded ? '▼' : '▶'}</span>
                          {vuln.title}
                        </td>
                        <td style={{ padding: '10px 8px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, minWidth: '20px', color: 'var(--color-primary)' }}>{vuln.base_score.toFixed(1)}</span>
                            <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.04)', borderRadius: '2px' }}>
                              <div style={{ width: `${vuln.base_score * 10}%`, height: '100%', background: 'var(--color-primary)', borderRadius: '2px' }} />
                            </div>
                          </div>
                        </td>
                        <td style={{ padding: '10px 8px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, minWidth: '20px', color: vuln.enhanced_score > 7 ? 'var(--color-danger)' : 'var(--color-warning)' }}>{vuln.enhanced_score.toFixed(1)}</span>
                            <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.04)', borderRadius: '2px' }}>
                              <div style={{ width: `${vuln.enhanced_score * 10}%`, height: '100%', background: vuln.enhanced_score > 7 ? 'var(--color-danger)' : 'var(--color-warning)', borderRadius: '2px' }} />
                            </div>
                          </div>
                        </td>
                        <td style={{ padding: '10px 8px' }}>
                          <span style={{ fontWeight: 700, color: vuln.status === 'Resolved' ? 'var(--color-success)' : (vuln.status === 'In Progress' ? 'var(--color-warning)' : 'var(--color-danger)') }}>
                            {vuln.status}
                          </span>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr style={{ background: '#f8fafc' }}>
                          <td colSpan={5} style={{ padding: '12px 15px', borderBottom: '1px dashed var(--border-glass)' }}>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.775rem' }}>
                              <div>
                                <span style={{ color: 'var(--color-primary)', fontWeight: 700, textTransform: 'uppercase', display: 'block', fontSize: '0.65rem', marginBottom: '2px' }}>What was found</span>
                                <p style={{ color: 'var(--color-text)', margin: 0 }}>{vuln.what_was_found || vuln.description}</p>
                              </div>
                              <div>
                                <span style={{ color: 'var(--color-primary)', fontWeight: 700, textTransform: 'uppercase', display: 'block', fontSize: '0.65rem', marginBottom: '2px' }}>Business Impact</span>
                                <p style={{ color: 'var(--color-text)', margin: 0 }}>{vuln.business_impact}</p>
                              </div>
                              <div>
                                <span style={{ color: 'var(--color-primary)', fontWeight: 700, textTransform: 'uppercase', display: 'block', fontSize: '0.65rem', marginBottom: '2px' }}>Affected Endpoints</span>
                                <ul style={{ margin: 0, paddingLeft: '14px', color: 'var(--color-text)' }}>
                                  {vuln.assets?.map((a: string, aIdx: number) => <li key={aIdx}><code>{a}</code></li>)}
                                </ul>
                              </div>
                              <div>
                                <span style={{ color: 'var(--color-success)', fontWeight: 700, textTransform: 'uppercase', display: 'block', fontSize: '0.65rem', marginBottom: '4px' }}>Recommended Remediation</span>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                  {(vuln.remediation_steps || [vuln.remediation?.explanation]).map((step: string, sIdx: number) => (
                                    <div key={sIdx} style={{ display: 'flex', gap: '6px', alignItems: 'flex-start' }}>
                                      <span>{step}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}

// ----------------- MAIN REPORTS COMPONENT -----------------

export default function Reports({ tenantId }: ReportsProps) {
  const [targetsList, setTargetsList] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedTargets, setExpandedTargets] = useState<Record<string, boolean>>({});
  
  // Custom Wizard States
  const [showWizard, setShowWizard] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState('All');
  const [reportType, setReportType] = useState('ALL');
  const [reportTemplate, setReportTemplate] = useState('executive');
  
  // Simulation compile states
  const [compiling, setCompiling] = useState(false);
  const [compileProgress, setCompileProgress] = useState(0);

  const fetchTargets = () => {
    aspmFetch('/api/aspm/targets')
      .then(res => res.json())
      .then((data: any[]) => {
        setTargetsList(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Error setting targets in Reports:", err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  const toggleExpandTarget = (id: string) => {
    setExpandedTargets(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const handleCompileCustomReport = (e: React.FormEvent) => {
    e.preventDefault();
    setCompiling(true);
    setCompileProgress(0);

    const interval = setInterval(() => {
      setCompileProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setTimeout(() => {
            setCompiling(false);
            let url = selectedTarget === 'All' ? '/api/aspm/reports/export' : `/api/aspm/reports/export?tenant_id=${selectedTarget}`;
            if (reportType !== 'ALL') {
              url += (url.includes('?') ? '&' : '?') + `report_type=${reportType}`;
            }
            window.open(aspmUrl(url), '_blank');
          }, 300);
          return 100;
        }
        return prev + 10;
      });
    }, 150);
  };

  const handleExportPDFDirectly = (targetId: string, type: string = 'ALL') => {
    let url = targetId === 'All' ? '/api/aspm/reports/export' : `/api/aspm/reports/export?tenant_id=${targetId}`;
    if (type !== 'ALL') {
      url += (url.includes('?') ? '&' : '?') + `report_type=${type}`;
    }
    window.open(aspmUrl(url), '_blank');
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%', color: 'var(--color-primary)' }}>
        <Activity className="animate-spin" style={{ marginRight: '8px' }} />
        <span>Synthesizing Security Reporting Engine...</span>
      </div>
    );
  }

  const consolidatedRow = {
    id: 'All',
    name: 'Consolidated System Scope',
    url: 'All Monitored Targets',
    target_type: 'multi-cloud',
    auth_type: 'aggregated'
  };

  const displayList = [consolidatedRow, ...targetsList];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', animation: 'fade-in 0.3s ease' }}>
      
      {/* Target Reports Table */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
            <Award size={18} color="var(--color-primary)" />
            Target Security & Compliance Reports
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button 
              className="cyber-btn"
              onClick={() => setShowWizard(prev => !prev)}
              style={{ padding: '4px 10px', fontSize: '0.8rem', background: 'rgba(37, 99, 235, 0.1)', borderColor: 'var(--color-primary)' }}
            >
              + Compile Custom Report
            </button>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
              CIS Postures & PDF Exports
            </span>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--color-muted)', paddingBottom: '8px' }}>
                <th style={{ padding: '10px 5px' }}>Target Name</th>
                <th style={{ padding: '10px 5px' }}>Endpoint Scope</th>
                <th style={{ padding: '10px 5px' }}>Scope Type</th>
                <th style={{ padding: '10px 5px' }}>Status</th>
                <th style={{ padding: '10px 5px', textAlign: 'center' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {displayList.map((target) => {
                const isExpanded = !!expandedTargets[target.id];
                return (
                  <React.Fragment key={target.id}>
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', transition: 'background 0.2s' }} className="table-row-hover">
                      <td style={{ padding: '12px 5px', fontWeight: 600, color: 'var(--color-text)' }}>
                        {target.name}
                      </td>
                      <td style={{ padding: '12px 5px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--color-muted)' }}>
                        {target.url}
                      </td>
                      <td style={{ padding: '12px 5px', textTransform: 'uppercase', fontSize: '0.75rem' }}>
                        <span className={`badge ${target.id === 'All' ? 'badge-high' : (target.target_type === 'api' ? 'badge-medium' : 'badge-low')}`}>
                          {target.target_type}
                        </span>
                      </td>
                      <td style={{ padding: '12px 5px' }}>
                        <span className="badge" style={{ background: 'rgba(22, 163, 74, 0.1)', color: 'var(--color-success)', border: '1px solid rgba(22, 163, 74, 0.4)' }}>
                          ✓ READY
                        </span>
                      </td>
                      <td style={{ padding: '12px 5px', display: 'flex', gap: '6px', justifyContent: 'center', alignItems: 'center' }}>
                        {/* Expand/Inspect Dashboard button */}
                        <button 
                          className="cyber-btn"
                          style={{ padding: '4px 8px', borderColor: isExpanded ? 'var(--color-primary)' : 'rgba(37, 99, 235, 0.3)', background: isExpanded ? 'rgba(37, 99, 235, 0.08)' : 'transparent' }}
                          onClick={() => toggleExpandTarget(target.id)}
                          title="View Inline Security Metrics Panel"
                        >
                          <Layers size={12} color={isExpanded ? "var(--color-primary)" : "var(--color-muted)"} />
                        </button>
                        {/* Consolidated PDF button */}
                        <button 
                          className="cyber-btn"
                          style={{ padding: '4px 8px', borderColor: 'rgba(37, 99, 235, 0.2)', background: 'rgba(37, 99, 235, 0.03)' }}
                          onClick={() => handleExportPDFDirectly(target.id, 'ALL')}
                          title="Export Consolidated C-Level PDF"
                        >
                          <FileText size={12} color="var(--color-primary)" />
                        </button>
                        {/* DAST PDF button */}
                        <button
                          className="cyber-btn"
                          style={{ padding: '4px 8px', borderColor: 'rgba(59, 130, 246, 0.3)', background: 'rgba(59, 130, 246, 0.03)' }}
                          onClick={() => handleExportPDFDirectly(target.id, 'DAST')}
                          title="Export DAST Web/API PDF"
                        >
                          <Server size={12} color="#3b82f6" />
                        </button>
                        {/* SAST PDF button */}
                        <button
                          className="cyber-btn"
                          style={{ padding: '4px 8px', borderColor: 'rgba(168, 85, 247, 0.3)', background: 'rgba(168, 85, 247, 0.03)' }}
                          onClick={() => handleExportPDFDirectly(target.id, 'SAST')}
                          title="Export SAST Code Security PDF"
                        >
                          <Code size={12} color="#a855f7" />
                        </button>
                        {/* SCA PDF button */}
                        <button 
                          className="cyber-btn"
                          style={{ padding: '4px 8px', borderColor: 'rgba(16, 185, 129, 0.3)', background: 'rgba(16, 185, 129, 0.03)' }}
                          onClick={() => handleExportPDFDirectly(target.id, 'SCA')}
                          title="Export SCA Dependency Security PDF"
                        >
                          <Shield size={12} color="#10b981" />
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={5} style={{ padding: '15px 10px', background: 'rgba(0, 0, 0, 0.25)' }}>
                          <div style={{ border: '1px solid var(--border-glass-glow)', borderRadius: '8px', padding: '15px', background: '#f8fafc' }}>
                            <JobReportsPanel targetId={target.id} targetName={target.name} />
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>

      </div>

      {/* Add Custom Report Wizard (Collapsible) */}
      {showWizard && (
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px', animation: 'fade-in 0.2s ease' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
              <Settings size={18} color="var(--color-primary)" />
              Compile Custom Security & Compliance Report
            </h3>
            <button 
              onClick={() => setShowWizard(false)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-muted)' }}
            >
              <X size={16} />
            </button>
          </div>

          <form onSubmit={handleCompileCustomReport} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Select Target App Scope</label>
              <select
                className="cyber-input"
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                style={{ fontWeight: 600, padding: '8px 12px', background: 'rgba(15, 22, 33, 0.8)' }}
              >
                <option value="All">Consolidated System Scope (All Targets)</option>
                {targetsList.map(t => (
                  <option key={t.id} value={t.id}>{t.name} ({t.url})</option>
                ))}
              </select>
            </div>

            <div style={{ display: 'flex', gap: '15px' }}>
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Report Template Format</label>
                <select
                  className="cyber-input"
                  value={reportTemplate}
                  onChange={(e) => setReportTemplate(e.target.value)}
                >
                  <option value="executive">Comprehensive Executive Summary</option>
                  <option value="compliance">Regulatory Compliance Postures</option>
                  <option value="vuln_log">Technical Vulnerability Logs</option>
                </select>
              </div>

              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Standard Scope</label>
                <select
                  className="cyber-input"
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value)}
                >
                  <option value="ALL">Consolidated Audit (All Engines)</option>
                  <option value="DAST">DAST Web/API (Dynamic Analysis)</option>
                  <option value="SAST">SAST Code Security (Static Analysis)</option>
                  <option value="SCA">SCA Dependency Audit (Software Composition)</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end', marginTop: '10px' }}>
              <button 
                type="button" 
                className="cyber-btn"
                onClick={() => setShowWizard(false)}
                style={{ borderColor: 'var(--border-glass)' }}
              >
                Cancel
              </button>
              <button type="submit" className="cyber-btn cyber-btn-accent">
                Generate and Export PDF
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Progress Compilation Modal Overlay */}
      {compiling && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(2, 4, 8, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 99999
        }}>
          <div className="glass-panel" style={{
            width: '450px',
            background: '#f8fafc',
            border: '1px solid var(--border-glass-glow)',
            borderRadius: '12px',
            boxShadow: '0 8px 32px rgba(37, 99, 235, 0.15)',
            display: 'flex',
            flexDirection: 'column',
            padding: '25px',
            alignItems: 'center',
            gap: '15px'
          }}>
            <Loader2 className="animate-spin" size={40} color="var(--color-primary)" />
            <h4 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 }}>Synthesizing Security Report...</h4>
            <p style={{ fontSize: '0.75rem', color: 'var(--color-muted)', margin: 0, textAlign: 'center' }}>
              Compiling compliance matrices, threat stage mappings, and vulnerability logs. Please wait...
            </p>
            
            {/* Progress bar */}
            <div style={{ width: '100%', display: 'flex', alignItems: 'center', gap: '10px', marginTop: '5px' }}>
              <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 'bold', color: 'var(--color-primary)', minWidth: '35px' }}>
                {compileProgress}%
              </span>
              <div style={{ flex: 1, height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden', border: '1px solid var(--border-glass)' }}>
                <div style={{ width: `${compileProgress}%`, height: '100%', background: 'var(--color-primary)', boxShadow: '0 0 10px var(--color-primary)', borderRadius: '4px', transition: 'width 0.1s ease' }} />
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

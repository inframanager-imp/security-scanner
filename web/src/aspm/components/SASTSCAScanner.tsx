import React, { useState, useEffect, useRef } from 'react';
import { aspmFetch, aspmUrl } from '../aspmClient';
import { Terminal, Shield, Play, Square, Settings, Trash2, Eye, Activity, X, ShieldAlert } from 'lucide-react';

interface SASTSCAScannerProps {
  tenantId?: string;
}

export default function SASTSCAScanner({ tenantId }: SASTSCAScannerProps) {
  const [jobs, setJobs] = useState<any[]>([]);
  const [scanType, setScanType] = useState('SAST');
  const [loading, setLoading] = useState(true);
  const [activeJobForLogs, setActiveJobForLogs] = useState<any | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [targetUrl, setTargetUrl] = useState('');
  const [showWizard, setShowWizard] = useState(false);
  const [targetsList, setTargetsList] = useState<any[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState('');
  
  const pollIntervalRef = useRef<any>(null);
  const logsPollIntervalRef = useRef<any>(null);
  const modalTerminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    aspmFetch('/api/aspm/targets')
      .then(res => res.json())
      .then((data: any[]) => {
        setTargetsList(data);
        if (data.length > 0) {
          if (tenantId) {
            const active = data.find(t => t.id === tenantId);
            if (active) {
              setSelectedTenantId(active.id);
              setTargetUrl(active.url);
            } else {
              setSelectedTenantId(data[0].id);
              setTargetUrl(data[0].url);
            }
          } else {
            setSelectedTenantId(data[0].id);
            setTargetUrl(data[0].url);
          }
        }
      })
      .catch(err => console.error("Error setting targets in SAST/SCA:", err));
  }, [tenantId]);

  const fetchJobs = () => {
    const url = tenantId 
      ? `/api/aspm/scans/jobs?tenant_id=${tenantId}&scan_type=SAST,SCA` 
      : '/api/aspm/scans/jobs?scan_type=SAST,SCA';
    aspmFetch(url)
      .then(res => res.json())
      .then(data => {
        setJobs(data);
        setLoading(false);
      })
      .catch(err => {
        console.error("Error fetching SAST/SCA scan jobs:", err);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchJobs();
    pollIntervalRef.current = setInterval(() => {
      const url = tenantId 
        ? `/api/aspm/scans/jobs?tenant_id=${tenantId}&scan_type=SAST,SCA` 
        : '/api/aspm/scans/jobs?scan_type=SAST,SCA';
      aspmFetch(url)
        .then(res => res.json())
        .then(data => {
          setJobs(data);
        })
        .catch(err => console.error("Error polling SAST/SCA jobs:", err));
    }, 2000);

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [tenantId]);

  useEffect(() => {
    if (activeJobForLogs) {
      const fetchLogs = () => {
        const url = tenantId 
          ? `/api/aspm/scans/jobs?tenant_id=${tenantId}&scan_type=SAST,SCA` 
          : '/api/aspm/scans/jobs?scan_type=SAST,SCA';
        aspmFetch(url)
          .then(res => res.json())
          .then((allJobs: any[]) => {
            const current = allJobs.find(j => j.id === activeJobForLogs.id);
            if (current) {
              setLogs(current.logs ? current.logs.split('\n') : []);
              if (current.status !== activeJobForLogs.status) {
                setActiveJobForLogs(current);
              }
              if (current.status !== 'Scanning') {
                if (logsPollIntervalRef.current) clearInterval(logsPollIntervalRef.current);
              }
            }
          })
          .catch(err => console.error("Error polling logs details:", err));
      };

      fetchLogs(); // load immediately
      
      if (activeJobForLogs.status === 'Scanning') {
        logsPollIntervalRef.current = setInterval(fetchLogs, 1500);
      }
    } else {
      if (logsPollIntervalRef.current) {
        clearInterval(logsPollIntervalRef.current);
        logsPollIntervalRef.current = null;
      }
      setLogs([]);
    }

    return () => {
      if (logsPollIntervalRef.current) clearInterval(logsPollIntervalRef.current);
    };
  }, [activeJobForLogs, tenantId]);

  useEffect(() => {
    if (modalTerminalEndRef.current) {
      modalTerminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const handleCreateJob = (e: React.FormEvent) => {
    e.preventDefault();
    const activeId = tenantId || selectedTenantId;
    if (!activeId) {
      alert("Please onboard a target application first.");
      return;
    }
    aspmFetch('/api/aspm/scans/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: activeId,
        scan_type: scanType
      })
    })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
        setShowWizard(false);
      })
      .catch(err => console.error("Error creating SAST/SCA job:", err));
  };

  const handleStartJob = (jobId: string) => {
    aspmFetch(`/api/aspm/scans/jobs/${jobId}/start`, { method: 'POST' })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
      })
      .catch(err => console.error("Error starting SAST/SCA job:", err));
  };

  const handleStopJob = (jobId: string) => {
    aspmFetch(`/api/aspm/scans/jobs/${jobId}/stop`, { method: 'POST' })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
      })
      .catch(err => console.error("Error stopping SAST/SCA job:", err));
  };

  const handleDeleteJob = (jobId: string) => {
    if (!confirm("Are you sure you want to delete this SAST/SCA scan job?")) return;
    aspmFetch(`/api/aspm/scans/jobs/${jobId}`, { method: 'DELETE' })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
      })
      .catch(err => console.error("Error deleting SAST/SCA job:", err));
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Scanning':
        return (
          <span className="badge animate-pulse" style={{ background: 'rgba(37, 99, 235, 0.1)', color: 'var(--color-primary)', border: '1px solid rgba(37, 99, 235, 0.4)' }}>
            ANALYZING
          </span>
        );
      case 'Completed':
        return (
          <span className="badge" style={{ background: 'rgba(22, 163, 74, 0.1)', color: 'var(--color-success)', border: '1px solid rgba(22, 163, 74, 0.4)' }}>
            ✓ COMPLETED
          </span>
        );
      case 'Stopped':
        return (
          <span className="badge" style={{ background: 'rgba(217, 119, 6, 0.15)', color: 'var(--color-warning)', border: '1px solid rgba(217, 119, 6, 0.4)' }}>
            ⏹ STOPPED
          </span>
        );
      case 'Failed':
        return (
          <span className="badge" style={{ background: 'rgba(220, 38, 38, 0.15)', color: 'var(--color-danger)', border: '1px solid rgba(220, 38, 38, 0.4)' }}>
            FAILED
          </span>
        );
      case 'Skipped':
        return (
          <span className="badge" style={{ background: 'rgba(217, 119, 6, 0.12)', color: 'var(--color-warning)', border: '1px solid rgba(217, 119, 6, 0.4)' }}>
            ⊘ SKIPPED — NO SOURCE
          </span>
        );
      default:
        return (
          <span className="badge" style={{ background: 'rgba(140, 155, 165, 0.15)', color: 'var(--color-muted)', border: '1px solid rgba(140, 155, 165, 0.4)' }}>
            ⚙ IDLE
          </span>
        );
    }
  };

  if (loading) {
    return <div style={{ color: 'var(--color-primary)', textAlign: 'center', padding: '50px' }}>Loading Code Security Architecture...</div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', animation: 'fade-in 0.3s ease' }}>
      
      {/* SAST/SCA Scan Jobs Table */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
            <Activity size={18} color="var(--color-primary)" />
            SAST & SCA Scanning Jobs
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button 
              className="cyber-btn"
              onClick={() => setShowWizard(prev => !prev)}
              style={{ padding: '4px 10px', fontSize: '0.8rem', background: 'rgba(37, 99, 235, 0.1)', borderColor: 'var(--color-primary)' }}
            >
              + Add Code Audit Job
            </button>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
              Static Analysis & Dependency Auditor
            </span>
          </div>
        </div>

        {jobs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--color-muted)', display: 'flex', flexDirection: 'column', gap: '10px', alignItems: 'center' }}>
            <ShieldAlert size={36} style={{ opacity: 0.6 }} />
            <span>No SAST or SCA jobs created yet. Click "+ Add Code Audit Job" to start codebase audit campaigns.</span>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--color-muted)', paddingBottom: '8px' }}>
                  <th style={{ padding: '10px 5px' }}>Created</th>
                  <th style={{ padding: '10px 5px' }}>Target Scope URL</th>
                  <th style={{ padding: '10px 5px' }}>Engine Profile</th>
                  <th style={{ padding: '10px 5px' }}>Status</th>
                  <th style={{ padding: '10px 5px', width: '180px' }}>Job Progress %</th>
                  <th style={{ padding: '10px 5px', textAlign: 'center' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const isScanning = job.status === 'Scanning';
                  return (
                    <tr key={job.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', transition: 'background 0.2s' }} className="table-row-hover">
                      <td style={{ padding: '12px 5px', color: 'var(--color-muted)', fontSize: '0.75rem' }}>
                        {new Date(job.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td style={{ padding: '12px 5px', fontWeight: 600, color: 'var(--color-text)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={job.target_url}>
                        {job.target_url}
                      </td>
                      <td style={{ padding: '12px 5px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                        {job.scan_type === 'SAST' ? 'SAST Code Analyzer (Bandit)' : 'SCA Dependency Auditor (pip-audit)'}
                      </td>
                      <td style={{ padding: '12px 5px' }}>
                        {getStatusBadge(job.status)}
                      </td>
                      <td style={{ padding: '12px 5px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 'bold', minWidth: '32px', color: isScanning ? 'var(--color-primary)' : 'var(--color-text)' }}>
                            {job.status === 'Skipped' ? 'N/A' : `${job.progress}%`}
                          </span>
                          <div style={{ flex: 1, height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden', border: '1px solid var(--border-glass)' }}>
                            <div 
                              style={{
                                width: job.status === 'Skipped' ? '0%' : `${job.progress}%`,
                                height: '100%',
                                background: isScanning ? 'var(--color-primary)' : (job.status === 'Completed' ? 'var(--color-success)' : (job.status === 'Failed' ? 'var(--color-danger)' : 'var(--color-muted)')),
                                boxShadow: isScanning ? '0 0 8px var(--color-primary)' : 'none',
                                borderRadius: '3px',
                                transition: 'width 0.4s ease'
                              }} 
                            />
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: '12px 5px', display: 'flex', gap: '5px', justifyContent: 'center', alignItems: 'center' }}>
                        {/* Play/Stop trigger */}
                        {!isScanning ? (
                          <button 
                            className="cyber-btn" 
                            style={{ padding: '4px 8px', borderColor: 'rgba(37, 99, 235, 0.3)' }}
                            onClick={() => handleStartJob(job.id)}
                            title="Execute Audit Analyzer"
                          >
                            <Play size={12} color="var(--color-primary)" />
                          </button>
                        ) : (
                          <button 
                            className="cyber-btn" 
                            style={{ padding: '4px 8px', borderColor: 'rgba(220, 38, 38, 0.3)', background: 'rgba(220, 38, 38, 0.05)' }}
                            onClick={() => handleStopJob(job.id)}
                            title="Halt Running Job"
                          >
                            <Square size={12} color="var(--color-danger)" />
                          </button>
                        )}
                        {/* View console logs */}
                        <button 
                          className="cyber-btn" 
                          style={{ padding: '4px 8px', borderColor: 'rgba(255,255,255,0.1)' }}
                          onClick={() => setActiveJobForLogs(job)}
                          title="Audit Output Stream"
                        >
                          <Eye size={12} />
                        </button>
                        {/* Delete job */}
                        <button 
                          className="cyber-btn" 
                          style={{ padding: '4px 8px', borderColor: 'rgba(220, 38, 38,0.1)' }}
                          onClick={() => handleDeleteJob(job.id)}
                          title="Delete Job Record"
                        >
                          <Trash2 size={12} color="var(--color-danger)" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add SAST/SCA Scan Job Wizard (Collapsible) */}
      {showWizard && (
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px', animation: 'fade-in 0.2s ease' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
              <Settings size={18} color="var(--color-primary)" />
              Add SAST / SCA Code Audit Job
            </h3>
            <button 
              onClick={() => setShowWizard(false)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-muted)' }}
            >
              <X size={16} />
            </button>
          </div>

          <form onSubmit={handleCreateJob} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Target Application Scope</label>
              {tenantId ? (
                <input
                  type="text"
                  className="cyber-input"
                  value={targetUrl}
                  disabled
                  style={{ opacity: 0.8, cursor: 'not-allowed', background: 'rgba(0,0,0,0.2)' }}
                />
              ) : (
                <select
                  className="cyber-input"
                  value={selectedTenantId}
                  onChange={(e) => {
                    setSelectedTenantId(e.target.value);
                    const active = targetsList.find(t => t.id === e.target.value);
                    if (active) setTargetUrl(active.url);
                  }}
                  style={{ fontWeight: 600, padding: '8px 12px', background: 'rgba(15, 22, 33, 0.8)' }}
                >
                  {targetsList.map(t => (
                    <option key={t.id} value={t.id}>{t.name} ({t.url})</option>
                  ))}
                </select>
              )}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Audit Engine Profile</label>
              <select
                className="cyber-input"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
              >
                <option value="SAST">SAST: Multi-Language Static Application Security Testing (Semgrep / Bandit)</option>
                <option value="SCA">SCA: Multi-Language Software Composition Analysis (Trivy / pip-audit)</option>
              </select>
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
                Add Audit Job
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Terminal Details Log Modal Overlay */}
      {activeJobForLogs && (
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
            width: '800px',
            height: '550px',
            background: '#f8fafc',
            border: '1px solid var(--border-glass-glow)',
            borderRadius: '12px',
            boxShadow: '0 8px 32px rgba(37, 99, 235, 0.15)',
            display: 'flex',
            flexDirection: 'column',
            padding: '20px'
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '12px', marginBottom: '15px' }}>
              <div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Terminal size={18} color="var(--color-primary)" />
                  AUDIT LOG MONITOR: {activeJobForLogs.scan_type === 'SAST' ? 'SAST Code Analyzer' : 'SCA Dependency Auditor'} ({activeJobForLogs.id})
                </h3>
                <span style={{ fontSize: '0.725rem', color: 'var(--color-muted)' }}>
                  Target Scope: <code>{activeJobForLogs.target_url}</code>
                </span>
              </div>
              <button 
                onClick={() => setActiveJobForLogs(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-muted)' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Terminal Console View */}
            <div style={{
              flex: 1,
              background: '#040711',
              border: '1px solid var(--border-glass)',
              borderRadius: '8px',
              padding: '15px',
              overflowY: 'auto',
              display: 'flex',
              flexDirection: 'column',
              gap: '6px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.775rem',
              color: '#d1d9e6',
              boxShadow: 'inset 0 0 10px rgba(0,0,0,0.8)'
            }}>
              {logs.length === 0 ? (
                <div style={{ color: 'var(--color-muted)', textAlign: 'center', padding: '100px 0' }}>
                  ▋ Console stream loading or idle. Start the scan to fetch telemetry.
                </div>
              ) : (
                logs.map((log, idx) => {
                  let color = '#d1d9e6';
                  if (log.startsWith('[*]')) color = 'var(--color-primary)';
                  if (log.startsWith('[!!]') || log.startsWith('[!] SAST Alert') || log.startsWith('[!] SCA Alert')) color = 'var(--color-danger)';
                  if (log.startsWith('[!]')) color = 'var(--color-warning)';
                  if (log.startsWith('[+]')) color = 'var(--color-success)';
                  return <div key={idx} style={{ color, lineBreak: 'anywhere' }}>{log}</div>;
                })
              )}
              {activeJobForLogs.status === 'Scanning' && (
                <div className="glow-primary animate-pulse" style={{ color: 'var(--color-primary)' }}>
                  ▋ Active analysis executing in background thread...
                </div>
              )}
              <div ref={modalTerminalEndRef} />
            </div>

            {/* Modal Footer Controls */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '15px', gap: '10px' }}>
              <span style={{ fontSize: '0.725rem', color: 'var(--color-muted)', display: 'flex', alignItems: 'center', marginRight: 'auto' }}>
                Job Execution Status: &nbsp;<strong>{activeJobForLogs.status.toUpperCase()}</strong>
              </span>
              <button 
                className="cyber-btn" 
                onClick={() => setActiveJobForLogs(null)}
                style={{ padding: '6px 15px', fontSize: '0.8rem' }}
              >
                Close Console
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

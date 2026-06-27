import React, { useState, useEffect, useRef } from 'react';
import { aspmFetch, aspmUrl } from '../aspmClient';
import { Database, UploadCloud, Terminal, Server, Play, Square, Settings, Trash2, Eye, Activity, X, ShieldAlert, Shield, Globe } from 'lucide-react';

interface APIInventoryProps {
  tenantId?: string;
}

function JobMappingsPanel({ targetId, targetUrl }: { targetId: string; targetUrl: string }) {
  const [inventory, setInventory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    aspmFetch(`/api/aspm/api-inventory?tenant_id=${targetId}`)
      .then((res) => res.json())
      .then((data) => {
        setInventory(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching job mappings:", err);
        setLoading(false);
      });
  }, [targetId]);

  if (loading) {
    return <div style={{ color: 'var(--color-primary)', fontSize: '0.8rem', padding: '15px' }}>▋ Querying discovered API mappings...</div>;
  }

  return (
    <div className="glass-panel" style={{ padding: '15px', background: 'rgba(5, 8, 15, 0.9)', border: '1px solid var(--border-glass-glow)' }}>
      <h4 style={{ fontSize: '0.85rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '12px', color: 'var(--color-text)' }}>
        <Database size={14} color="var(--color-primary)" />
        API Inventory & Classification (Discovered Mappings)
      </h4>
      {inventory.length === 0 ? (
        <div style={{ padding: '10px 0', color: 'var(--color-muted)', fontSize: '0.8rem' }}>
          No mapped API routes found. Execute the scan job to perform automatic mapping.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-glass)', textAlign: 'left', color: 'var(--color-muted)' }}>
              <th style={{ padding: '8px 5px' }}>Method</th>
              <th style={{ padding: '8px 5px' }}>Route Path</th>
              <th style={{ padding: '8px 5px' }}>Authentication</th>
              <th style={{ padding: '8px 5px' }}>Data Classification</th>
              <th style={{ padding: '8px 5px' }}>Risk Level</th>
              <th style={{ padding: '8px 5px' }}>Findings</th>
            </tr>
          </thead>
          <tbody>
            {inventory.map((route: any, index: number) => {
              const methodColor = 
                route.method === 'POST' ? '#69f0ae' : 
                route.method === 'GET' ? 'var(--color-primary)' : 
                route.method === 'DELETE' ? 'var(--color-danger)' : 'var(--color-warning)';
                
              return (
                <tr key={index} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.02)' }} className="table-row-hover">
                  <td style={{ padding: '10px 5px', fontWeight: 800, color: methodColor, fontSize: '0.725rem' }}>{route.method}</td>
                  <td style={{ padding: '10px 5px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{route.path}</td>
                  <td style={{ padding: '10px 5px' }}>
                    <span style={{ fontSize: '0.75rem', color: route.auth === 'None' ? 'var(--color-danger)' : 'var(--color-text)' }}>
                      {route.auth}
                    </span>
                  </td>
                  <td style={{ padding: '10px 5px', color: 'var(--color-muted)' }}>{route.classification}</td>
                  <td style={{ padding: '10px 5px' }}>
                    <span className={`badge ${
                      route.risk === 'Critical' ? 'badge-critical' : 
                      route.risk === 'High' ? 'badge-high' : 
                      route.risk === 'Medium' ? 'badge-medium' : 'badge-low'
                    }`} style={{ fontSize: '0.6rem' }}>
                      {route.risk}
                    </span>
                  </td>
                  <td style={{ padding: '10px 5px' }}>
                    {route.findings > 0 ? (
                      <span style={{ color: 'var(--color-danger)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <ShieldAlert size={10} /> {route.findings} Finding
                      </span>
                    ) : (
                      <span style={{ color: 'var(--color-muted)' }}>-</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function APIInventory({ tenantId }: APIInventoryProps) {
  const [jobs, setJobs] = useState<any[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [expandedJobs, setExpandedJobs] = useState<Record<string, boolean>>({});
  
  // Wizard States
  const [showWizard, setShowWizard] = useState(false);
  const [scanType, setScanType] = useState('API'); // 'API', 'OPENAPI_JSON' or 'OPENAPI_URL'
  const [swaggerText, setSwaggerText] = useState('{\n  "swagger": "2.0",\n  "info": {\n    "title": "Core API",\n    "version": "1.0"\n  },\n  "paths": {\n    "/api/v1/billing": {\n      "post": {}\n    }\n  }\n}');
  const [swaggerUrl, setSwaggerUrl] = useState('/v3/api-docs');
  
  // Targets States
  const [targetUrl, setTargetUrl] = useState('');
  const [targetsList, setTargetsList] = useState<any[]>([]);
  const [selectedTenantId, setSelectedTenantId] = useState('');

  // Logs Modal States
  const [activeJobForLogs, setActiveJobForLogs] = useState<any | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  
  const pollIntervalRef = useRef<any>(null);
  const logsPollIntervalRef = useRef<any>(null);
  const modalTerminalEndRef = useRef<HTMLDivElement>(null);

  // Fetch target list & set active target
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
      .catch(err => console.error("Error setting targets in API Inventory:", err));
  }, [tenantId]);

  // Fetch API Scan Jobs
  const fetchJobs = () => {
    const url = tenantId 
      ? `/api/aspm/scans/jobs?tenant_id=${tenantId}&scan_type=API,OPENAPI` 
      : '/api/aspm/scans/jobs?scan_type=API,OPENAPI';
    aspmFetch(url)
      .then(res => res.json())
      .then(data => {
        setJobs(data);
        setJobsLoading(false);
      })
      .catch(err => {
        console.error("Error fetching scan jobs:", err);
        setJobsLoading(false);
      });
  };

  useEffect(() => {
    fetchJobs();
    pollIntervalRef.current = setInterval(() => {
      const url = tenantId 
        ? `/api/aspm/scans/jobs?tenant_id=${tenantId}&scan_type=API,OPENAPI` 
        : '/api/aspm/scans/jobs?scan_type=API,OPENAPI';
      aspmFetch(url)
        .then(res => res.json())
        .then(data => {
          setJobs(data);
        })
        .catch(err => console.error("Error polling API jobs:", err));
    }, 2000);

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, [tenantId]);

  // Polling for detail logs modal
  useEffect(() => {
    if (activeJobForLogs) {
      const fetchLogs = () => {
        const url = tenantId 
          ? `/api/aspm/scans/jobs?tenant_id=${tenantId}&scan_type=API,OPENAPI` 
          : '/api/aspm/scans/jobs?scan_type=API,OPENAPI';
        aspmFetch(url)
          .then(res => res.json())
          .then((allJobs: any[]) => {
            const current = allJobs.find(j => j.id === activeJobForLogs.id);
            if (current) {
              setLogs(current.logs ? current.logs.split('\n') : []);
              if (current.status !== 'Scanning') {
                if (logsPollIntervalRef.current) clearInterval(logsPollIntervalRef.current);
              }
            }
          })
          .catch(err => console.error("Error polling API logs details:", err));
      };

      fetchLogs(); // fetch immediately
      
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

  // Scroll to bottom of terminal in logs modal
  useEffect(() => {
    if (modalTerminalEndRef.current) {
      modalTerminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Create API Scan Job
  const handleCreateJob = (e: React.FormEvent) => {
    e.preventDefault();
    const activeId = tenantId || selectedTenantId;
    if (!activeId) {
      alert("Please onboard a target application first.");
      return;
    }

    // If using OpenAPI guided scan, validate JSON
    let spec: string | undefined = undefined;
    let finalScanType = scanType;
    if (scanType === 'OPENAPI_JSON') {
      try {
        JSON.parse(swaggerText);
        spec = swaggerText;
        finalScanType = 'OPENAPI';
      } catch (err) {
        alert("Invalid JSON format. Please verify Swagger / OpenAPI structure.");
        return;
      }
    } else if (scanType === 'OPENAPI_URL') {
      if (!swaggerUrl.trim()) {
        alert("Please enter a valid Swagger URL or Endpoint Path.");
        return;
      }
      spec = swaggerUrl;
      finalScanType = 'OPENAPI';
    }

    aspmFetch('/api/aspm/scans/jobs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tenant_id: activeId,
        scan_type: finalScanType,
        openapi_spec: spec
      })
    })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
        setShowWizard(false);
      })
      .catch(err => console.error("Error creating API scan job:", err));
  };

  // Start job
  const handleStartJob = (jobId: string) => {
    aspmFetch(`/api/aspm/scans/jobs/${jobId}/start`, { method: 'POST' })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
      })
      .catch(err => console.error("Error starting API scan job:", err));
  };

  // Stop job
  const handleStopJob = (jobId: string) => {
    aspmFetch(`/api/aspm/scans/jobs/${jobId}/stop`, { method: 'POST' })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
      })
      .catch(err => console.error("Error stopping API scan job:", err));
  };

  // Delete job
  const handleDeleteJob = (jobId: string) => {
    if (!confirm("Are you sure you want to delete this scan job record?")) return;
    aspmFetch(`/api/aspm/scans/jobs/${jobId}`, { method: 'DELETE' })
      .then(res => res.json())
      .then(() => {
        fetchJobs();
      })
      .catch(err => console.error("Error deleting API scan job:", err));
  };

  const toggleExpandJob = (jobId: string) => {
    setExpandedJobs(prev => ({
      ...prev,
      [jobId]: !prev[jobId]
    }));
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Scanning':
        return (
          <span className="badge animate-pulse" style={{ background: 'rgba(37, 99, 235, 0.1)', color: 'var(--color-primary)', border: '1px solid rgba(37, 99, 235, 0.4)' }}>
            ⚡ SCANNING
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
            🗙 FAILED
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

  if (jobsLoading) {
    return <div style={{ color: 'var(--color-primary)', textAlign: 'center', padding: '50px' }}>Loading API Security Architecture...</div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', animation: 'fade-in 0.3s ease' }}>
      
      {/* API Scan Jobs Table */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
            <Activity size={18} color="var(--color-primary)" />
            API Security Scan Jobs
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button 
              className="cyber-btn"
              onClick={() => setShowWizard(prev => !prev)}
              style={{ padding: '4px 10px', fontSize: '0.8rem', background: 'rgba(37, 99, 235, 0.1)', borderColor: 'var(--color-primary)' }}
            >
              + Add API Job
            </button>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
              Logical fuzzer and spec checkers
            </span>
          </div>
        </div>

        {jobs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--color-muted)', display: 'flex', flexDirection: 'column', gap: '10px', alignItems: 'center' }}>
            <Server size={36} style={{ opacity: 0.6 }} />
            <span>No API scan jobs created yet. Click "+ Add API Job" to launch a logical fuzzer campaign.</span>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--color-muted)', paddingBottom: '8px' }}>
                  <th style={{ padding: '10px 5px' }}>Created</th>
                  <th style={{ padding: '10px 5px' }}>Target Scope URL</th>
                  <th style={{ padding: '10px 5px' }}>Engine</th>
                  <th style={{ padding: '10px 5px' }}>Status</th>
                  <th style={{ padding: '10px 5px', width: '180px' }}>Job Progress %</th>
                  <th style={{ padding: '10px 5px', textAlign: 'center' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => {
                  const isScanning = job.status === 'Scanning';
                  const isExpanded = !!expandedJobs[job.id];
                  return (
                    <React.Fragment key={job.id}>
                      <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.02)', transition: 'background 0.2s' }} className="table-row-hover">
                        <td style={{ padding: '12px 5px', color: 'var(--color-muted)', fontSize: '0.75rem' }}>
                          {new Date(job.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </td>
                        <td style={{ padding: '12px 5px', fontWeight: 600, color: 'var(--color-text)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={job.target_url}>
                          {job.target_url}
                        </td>
                        <td style={{ padding: '12px 5px', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                          {job.scan_type === 'OPENAPI' ? 'OpenAPI Spec Audit' : 'API Security Sweep'}
                        </td>
                        <td style={{ padding: '12px 5px' }}>
                          {getStatusBadge(job.status)}
                        </td>
                        <td style={{ padding: '12px 5px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 'bold', minWidth: '32px', color: isScanning ? 'var(--color-primary)' : 'var(--color-text)' }}>
                              {job.progress}%
                            </span>
                            <div style={{ flex: 1, height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden', border: '1px solid var(--border-glass)' }}>
                              <div 
                                style={{ 
                                  width: `${job.progress}%`, 
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
                          {!isScanning ? (
                            <button 
                              className="cyber-btn" 
                              style={{ padding: '4px 8px', borderColor: 'rgba(37, 99, 235, 0.3)' }}
                              onClick={() => handleStartJob(job.id)}
                              title="Execute API Audit Scan"
                            >
                              <Play size={12} color="var(--color-primary)" />
                            </button>
                          ) : (
                            <button 
                              className="cyber-btn" 
                              style={{ padding: '4px 8px', borderColor: 'rgba(220, 38, 38, 0.3)', background: 'rgba(220, 38, 38, 0.05)' }}
                              onClick={() => handleStopJob(job.id)}
                              title="Halt API Audit Scan"
                            >
                              <Square size={12} color="var(--color-danger)" />
                            </button>
                          )}
                          <button 
                            className="cyber-btn" 
                            style={{ padding: '4px 8px', borderColor: isExpanded ? 'var(--color-primary)' : 'rgba(37, 99, 235, 0.3)', background: isExpanded ? 'rgba(37, 99, 235, 0.08)' : 'transparent' }}
                            onClick={() => toggleExpandJob(job.id)}
                            title="View Discovered API Mappings"
                          >
                            <Database size={12} color={isExpanded ? "var(--color-primary)" : "var(--color-muted)"} />
                          </button>
                          <button 
                            className="cyber-btn" 
                            style={{ padding: '4px 8px', borderColor: 'rgba(255,255,255,0.1)' }}
                            onClick={() => setActiveJobForLogs(job)}
                            title="Audit API Scan Logs"
                          >
                            <Eye size={12} />
                          </button>
                          <button 
                            className="cyber-btn" 
                            style={{ padding: '4px 8px', borderColor: 'rgba(220, 38, 38,0.1)' }}
                            onClick={() => handleDeleteJob(job.id)}
                            title="Delete API Job"
                          >
                            <Trash2 size={12} color="var(--color-danger)" />
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr>
                          <td colSpan={6} style={{ padding: '15px 10px', background: 'rgba(0, 0, 0, 0.25)' }}>
                            <JobMappingsPanel targetId={job.target_id} targetUrl={job.target_url} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add API Scan Job Wizard (Collapsible) */}
      {showWizard && (
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px', animation: 'fade-in 0.2s ease' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
              <Settings size={18} color="var(--color-primary)" />
              Add API Security Scan Job
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
              <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Target Endpoint Scope</label>
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
              <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Scan Engine / Audit Mode</label>
              <select
                className="cyber-input"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
              >
                <option value="API">API Security Sweep (Logic checks, Directory fuzzing, IDOR)</option>
                <option value="OPENAPI_JSON">OpenAPI Spec Guided Audit (Paste Raw JSON Spec)</option>
                <option value="OPENAPI_URL">OpenAPI Spec Guided Audit (Fetch from Swagger URL / Endpoint)</option>
              </select>
            </div>

            {scanType === 'OPENAPI_JSON' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', animation: 'fade-in 0.2s' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <UploadCloud size={16} color="var(--color-primary)" />
                  OpenAPI / Swagger Schema (JSON format)
                </label>
                <textarea
                  className="cyber-input"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', height: '140px', resize: 'vertical' }}
                  value={swaggerText}
                  onChange={(e) => setSwaggerText(e.target.value)}
                  placeholder="Paste OpenAPI JSON spec here..."
                  required
                />
              </div>
            )}

            {scanType === 'OPENAPI_URL' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', animation: 'fade-in 0.2s' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Globe size={16} color="var(--color-primary)" />
                  OpenAPI / Swagger Spec URL or Endpoint Path
                </label>
                <input
                  type="text"
                  className="cyber-input"
                  value={swaggerUrl}
                  onChange={(e) => setSwaggerUrl(e.target.value)}
                  placeholder="e.g. /v3/api-docs or https://api.example.com/swagger.json"
                  required
                />
                <span style={{ fontSize: '0.65rem', color: 'var(--color-warning)' }}>
                  * The backend will fetch the spec from this URL dynamically during scan execution.
                </span>
              </div>
            )}

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
                Add API Scan Job
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
                  API Job ID: <code>{activeJobForLogs.id}</code> Console Terminal
                </h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
                  Scoping Target: <code>{activeJobForLogs.target_url}</code>
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                {getStatusBadge(activeJobForLogs.status)}
                <button 
                  onClick={() => setActiveJobForLogs(null)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-muted)', display: 'inline-flex', alignItems: 'center' }}
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            {/* Modal Terminal Console logs */}
            <div style={{ 
              flex: 1, 
              background: '#040609', 
              border: '1px solid rgba(255,255,255,0.05)', 
              borderRadius: '8px', 
              padding: '15px', 
              overflowY: 'auto', 
              fontFamily: 'var(--font-mono)', 
              fontSize: '0.8rem', 
              color: '#334155', 
              display: 'flex', 
              flexDirection: 'column', 
              gap: '6px' 
            }}>
              {logs.length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--color-muted)', padding: '160px 0' }}>
                  ▋ Initializing API auditor console pipelines...
                </div>
              ) : (
                logs.map((log, index) => {
                  let color = '#334155';
                  if (log.startsWith('[!]') || log.includes('DETECTED') || log.includes('WARNING')) color = 'var(--color-warning)';
                  if (log.startsWith('[!!]') || log.includes('CONFIRMED')) color = 'var(--color-danger)';
                  if (log.startsWith('[+]') || log.includes('complete')) color = 'var(--color-success)';
                  if (log.startsWith('[*]')) color = 'var(--color-primary)';
                  
                  return (
                    <div key={index} style={{ color }}>
                      {log}
                    </div>
                  );
                })
              )}
              {activeJobForLogs.status === 'Scanning' && (
                <div className="glow-primary animate-pulse" style={{ color: 'var(--color-primary)', marginTop: '5px' }}>
                  ▋ background API fuzzer running sweeps...
                </div>
              )}
              <div ref={modalTerminalEndRef} />
            </div>

            {/* Modal Action Footer */}
            <div style={{ display: 'flex', gap: '10px', marginTop: '15px', justifyContent: 'flex-end' }}>
              {activeJobForLogs.status === 'Scanning' && (
                <button 
                  className="cyber-btn cyber-btn-danger" 
                  onClick={() => handleStopJob(activeJobForLogs.id)}
                >
                  <Square size={14} /> Stop API Job
                </button>
              )}
              <button 
                className="cyber-btn" 
                onClick={() => setActiveJobForLogs(null)}
                style={{ borderColor: 'var(--border-glass)' }}
              >
                Close Terminal
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}

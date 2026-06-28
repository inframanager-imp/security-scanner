import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Globe, Server, Plus, Trash2, X, ShieldAlert } from 'lucide-react';

import Dashboard from '../aspm/components/Dashboard';
import DASTScanner from '../aspm/components/DASTScanner';
import APIInventory from '../aspm/components/APIInventory';
import AIPentester from '../aspm/components/AIPentester';
import AISecurityModule from '../aspm/components/AISecurityModule';
import SASTSCAScanner from '../aspm/components/SASTSCAScanner';

import { aspmFetch } from '../aspm/aspmClient';
import '../aspm/aspm-theme.css';

const API = '/api/aspm';

// URL slug → behaviour. The left sidebar (Application Security group) links to these.
const MODULES: Record<string, { kind: string; scoped: boolean }> = {
  overview: { kind: 'dashboard', scoped: true },
  targets:  { kind: 'targets',   scoped: false },
  web:      { kind: 'dast',      scoped: true },
  api:      { kind: 'api',       scoped: true },
  code:     { kind: 'sast_sca',  scoped: true },
  pentest:  { kind: 'pentest',   scoped: true },
  'ai-red': { kind: 'ai_sec',    scoped: false },
};

/**
 * Application Security (ASPM) workspace. Driven by the URL module slug
 * (/appsec/:module) so the CSPM left-sidebar group navigates it — no internal nav.
 * A shared "Active Target" selector scopes the target-specific views.
 */
export default function AspmWorkspace() {
  const { module } = useParams();
  const mod = MODULES[module ?? 'overview'] ?? MODULES.overview;

  const [targets, setTargets] = useState<any[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [showOnboardWizard, setShowOnboardWizard] = useState(false);
  const [editingTarget, setEditingTarget] = useState<any | null>(null);

  const [newName, setNewName] = useState('');
  const [newUrl, setNewUrl] = useState('');
  const [newType, setNewType] = useState('web');
  const [newAuthType, setNewAuthType] = useState('none');
  const [newAuthKey, setNewAuthKey] = useState('Authorization');
  const [newAuthVal, setNewAuthVal] = useState('');

  const fetchTargets = () => {
    aspmFetch(`${API}/targets`)
      .then((res) => res.json())
      .then((data) => {
        const list = Array.isArray(data) ? data : [];
        setTargets(list);
        setSelectedTenant((cur) => (cur && list.some((t) => t.id === cur) ? cur : (list[0]?.id ?? '')));
        setLoading(false);
      })
      .catch((err) => { console.error('Error connecting to ASPM backend:', err); setLoading(false); });
  };

  useEffect(() => { fetchTargets(); }, []);

  const resetForm = () => {
    setShowOnboardWizard(false);
    setEditingTarget(null);
    setNewName(''); setNewUrl(''); setNewType('web');
    setNewAuthType('none'); setNewAuthKey('Authorization'); setNewAuthVal('');
  };

  const handleOnboardTarget = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName || !newUrl) return;
    const url = `${API}/targets${editingTarget ? `/${editingTarget.id}` : ''}`;
    const method = editingTarget ? 'PUT' : 'POST';
    aspmFetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: newName, url: newUrl, target_type: newType,
        auth_type: newAuthType, auth_key: newAuthKey, auth_val: newAuthVal,
      }),
    })
      .then((res) => res.json())
      .then((data) => { if (data.status === 'success') { resetForm(); fetchTargets(); } })
      .catch((err) => console.error('Error saving target:', err));
  };

  const handleDeleteTarget = (targetId: string) => {
    if (!confirm('Delete this target and all its scans/vulnerabilities?')) return;
    aspmFetch(`${API}/targets/${targetId}`, { method: 'DELETE' })
      .then((res) => res.json())
      .then(() => fetchTargets())
      .catch((err) => console.error('Error deleting target:', err));
  };

  const handleEditClick = (target: any) => {
    setEditingTarget(target);
    setNewName(target.name); setNewUrl(target.url); setNewType(target.target_type);
    setNewAuthType(target.auth_type || 'none');
    setNewAuthKey(target.auth_key || 'Authorization');
    setNewAuthVal(target.auth_val || '');
    setShowOnboardWizard(true);
  };

  const renderModule = () => {
    if (mod.scoped && !selectedTenant) {
      return (
        <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: 'var(--color-muted)' }}>
          <ShieldAlert size={40} style={{ marginBottom: '12px', color: 'var(--color-warning)' }} />
          <p>No application target yet. Go to <strong>Targets</strong> to onboard one, then run scans here.</p>
        </div>
      );
    }
    const tid = selectedTenant;
    switch (mod.kind) {
      case 'dashboard': return <Dashboard key={tid} tenantId={tid} />;
      case 'dast':      return <DASTScanner key={tid} tenantId={tid} />;
      case 'api':       return <APIInventory key={tid} tenantId={tid} />;
      case 'sast_sca':  return <SASTSCAScanner key={tid} tenantId={tid} />;
      case 'pentest':   return <AIPentester key={tid} tenantId={tid} />;
      case 'ai_sec':    return <AISecurityModule />;
      case 'targets':   return null; // rendered below
      default:          return <Dashboard key={tid} tenantId={tid} />;
    }
  };

  return (
    <div className="aspm-root" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

      {/* Shared scope selector — only for target-specific views */}
      {mod.scoped && targets.length > 0 && (
        <div className="glass-panel" style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Server size={15} color="var(--color-primary)" /> Active Target
          </span>
          <select className="cyber-input" value={selectedTenant} onChange={(e) => setSelectedTenant(e.target.value)} style={{ minWidth: '300px' }}>
            {targets.map((t) => (<option key={t.id} value={t.id}>{t.name} ({t.url})</option>))}
          </select>
        </div>
      )}

      {/* Targets module: onboarding + management table */}
      {mod.kind === 'targets' && (
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-text)' }}>
              <Globe size={18} color="var(--color-primary)" /> Onboarded Scope Targets / Applications
            </h3>
            <button className="cyber-btn cyber-btn-accent" onClick={() => (showOnboardWizard ? resetForm() : setShowOnboardWizard(true))}>
              <Plus size={16} /> {showOnboardWizard ? 'Cancel' : 'Onboard Application'}
            </button>
          </div>

          {showOnboardWizard && (
            <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px', background: '#f8fafc' }}>
              <div style={{ borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--color-text)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Plus size={16} color="var(--color-primary)" />
                  {editingTarget ? `Edit Application Scope: ${editingTarget.name}` : 'Configure New Application Scope'}
                </h4>
                <button onClick={resetForm} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--color-muted)' }}><X size={16} /></button>
              </div>

              <form onSubmit={handleOnboardTarget} style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Target / App Name</label>
                  <input type="text" className="cyber-input" placeholder="e.g. My Production Gateway" required value={newName} onChange={(e) => setNewName(e.target.value)} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>
                    {newType === 'git' ? 'Git Repository URL or Local Directory Path' : 'Target URL or IP Address'}
                  </label>
                  <input type="text" className="cyber-input" placeholder={newType === 'git' ? 'e.g. https://github.com/owner/repo.git' : 'e.g. https://staging.example.com'} required value={newUrl} onChange={(e) => setNewUrl(e.target.value)} />
                </div>
                <div style={{ display: 'flex', gap: '15px' }}>
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>Asset Scope Type</label>
                    <select className="cyber-input" value={newType} onChange={(e) => setNewType(e.target.value)}>
                      <option value="web">Web Application (DAST)</option>
                      <option value="api">API Endpoint (REST / Swagger)</option>
                      <option value="git">Git Repository / Source Code (SAST/SCA)</option>
                    </select>
                  </div>
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <label style={{ fontSize: '0.8rem', color: 'var(--color-muted)', fontWeight: 500 }}>
                      {newType === 'git' ? 'Repository Access' : 'Auth Profiling'}
                    </label>
                    <select
                      className="cyber-input"
                      value={newType === 'git' ? (newAuthType === 'none' ? 'none' : 'token') : newAuthType}
                      onChange={(e) => setNewAuthType(e.target.value)}
                    >
                      {newType === 'git' ? (
                        <>
                          <option value="none">Public repository (no token)</option>
                          <option value="token">Private — Personal Access Token</option>
                        </>
                      ) : (
                        <>
                          <option value="none">Unauthenticated Scope</option>
                          <option value="bearer">Header Injection (Bearer)</option>
                          <option value="cookie">Session Cookie Injection</option>
                        </>
                      )}
                    </select>
                  </div>
                </div>
                {newAuthType !== 'none' && (
                  <div style={{ display: 'flex', gap: '10px' }}>
                    {newType !== 'git' && (
                      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '5px' }}>
                        <label style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>Key Name</label>
                        <input type="text" className="cyber-input" value={newAuthKey} onChange={(e) => setNewAuthKey(e.target.value)} />
                      </div>
                    )}
                    <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: '5px' }}>
                      <label style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>
                        {newType === 'git' ? 'Personal Access Token (PAT)' : 'Secret Token Value'}
                      </label>
                      <input
                        type="password"
                        className="cyber-input"
                        placeholder={newType === 'git' ? 'Paste your Git access token' : 'session-token-hash'}
                        value={newAuthVal}
                        onChange={(e) => setNewAuthVal(e.target.value)}
                      />
                      {newType === 'git' && (
                        <span style={{ fontSize: '0.7rem', color: 'var(--color-muted)' }}>
                          Used only to clone private repos. GitHub: a classic/fine-grained token with repo read access. Azure DevOps: a PAT with Code → Read. Leave the access set to “Public” for public repos.
                        </span>
                      )}
                    </div>
                  </div>
                )}
                <div style={{ display: 'flex', gap: '10px', marginTop: '10px', justifyContent: 'flex-end' }}>
                  <button type="button" className="cyber-btn" onClick={resetForm}>Cancel</button>
                  <button type="submit" className="cyber-btn cyber-btn-accent">{editingTarget ? 'Update Target Scope' : 'Onboard Target'}</button>
                </div>
              </form>
            </div>
          )}

          {loading ? (
            <p style={{ color: 'var(--color-muted)', fontSize: '0.85rem' }}>Loading targets…</p>
          ) : targets.length === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '30px', color: 'var(--color-muted)' }}>
              <ShieldAlert size={48} style={{ marginBottom: '12px', color: 'var(--color-warning)' }} />
              <p style={{ fontSize: '0.9rem' }}>No scope targets onboarded yet. Add one to start scanning.</p>
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--color-muted)' }}>
                    <th style={{ padding: '10px' }}>Application Name</th>
                    <th style={{ padding: '10px' }}>Target Scope URL</th>
                    <th style={{ padding: '10px' }}>Scope Type</th>
                    <th style={{ padding: '10px' }}>Authentication</th>
                    <th style={{ padding: '10px', textAlign: 'center', width: '160px' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.map((target) => (
                    <tr key={target.id} style={{ borderBottom: '1px solid var(--border-glass)' }}>
                      <td style={{ padding: '12px 10px', fontWeight: 600, color: 'var(--color-text)' }}>{target.name}</td>
                      <td style={{ padding: '12px 10px', fontFamily: 'var(--font-mono)', color: 'var(--color-muted)' }}>{target.url}</td>
                      <td style={{ padding: '12px 10px', textTransform: 'uppercase', fontSize: '0.75rem' }}>
                        <span className={`badge ${target.target_type === 'api' ? 'badge-medium' : target.target_type === 'git' ? 'badge-high' : 'badge-low'}`}>{target.target_type}</span>
                      </td>
                      <td style={{ padding: '12px 10px', fontSize: '0.75rem', color: 'var(--color-muted)' }}>{target.auth_type === 'none' ? 'None' : target.auth_type}</td>
                      <td style={{ padding: '12px 10px', display: 'flex', gap: '6px', justifyContent: 'center' }}>
                        <button className="cyber-btn" style={{ padding: '4px 8px', fontSize: '0.8rem' }} onClick={() => handleEditClick(target)}>Edit</button>
                        <button className="cyber-btn cyber-btn-danger" style={{ padding: '4px 8px' }} onClick={() => handleDeleteTarget(target.id)} title="Delete Target">
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Active module view */}
      {renderModule()}
    </div>
  );
}

import React, { useEffect, useState } from 'react';
import { aspmFetch, aspmUrl } from '../aspmClient';
import { Settings, ToggleLeft, ToggleRight, Link, Check, AlertCircle } from 'lucide-react';

export default function SettingsIntegrations() {
  const [integrations, setIntegrations] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Form configs
  const [jiraUrl, setJiraUrl] = useState('https://acme.atlassian.net');
  const [slackChan, setSlackChan] = useState('#sec-alerts');

  useEffect(() => {
    aspmFetch('/api/aspm/integrations')
      .then(res => res.json())
      .then(data => {
        setIntegrations(data);
        setLoading(false);
      });
  }, []);

  const handleToggle = (name: string) => {
    aspmFetch(`/api/aspm/integrations/${name}/toggle`, { method: 'POST' })
      .then(res => res.json())
      .then(updated => {
        setIntegrations((prev: any) => ({
          ...prev,
          [name]: updated
        }));
      });
  };

  if (loading || !integrations) {
    return <div style={{ color: 'var(--color-primary)', textAlign: 'center', padding: '50px' }}>Loading integrations settings...</div>;
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '20px', animation: 'fade-in 0.3s ease' }}>
      
      {/* Integrations panel */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-glass)', paddingBottom: '10px' }}>
          <Link size={18} color="var(--color-primary)" />
          Enterprise Third-Party Integrations
        </h3>

        {/* Jira */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '15px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Atlassian JIRA Cloud</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>Automate task ticket creation for verified scanner findings.</span>
            
            {integrations.jira.connected && (
              <div style={{ display: 'flex', gap: '10px', marginTop: '6px', width: '280px' }}>
                <input
                  type="text"
                  className="cyber-input"
                  style={{ fontSize: '0.75rem', padding: '4px 8px', flex: 2 }}
                  value={jiraUrl}
                  onChange={(e) => setJiraUrl(e.target.value)}
                />
                <input
                  type="text"
                  placeholder="Proj Key"
                  className="cyber-input"
                  style={{ fontSize: '0.75rem', padding: '4px 8px', flex: 1 }}
                  value="SEC"
                  disabled
                />
              </div>
            )}
          </div>
          
          <button onClick={() => handleToggle('jira')} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: integrations.jira.connected ? 'var(--color-success)' : 'var(--color-muted)' }}>
            {integrations.jira.connected ? <ToggleRight size={38} /> : <ToggleLeft size={38} />}
          </button>
        </div>

        {/* Slack */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid rgba(255,255,255,0.03)', paddingBottom: '15px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Slack Webhooks Notification</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>Send security alerts to slack channels on critical SLA breaches.</span>
            
            {integrations.slack.connected && (
              <div style={{ display: 'flex', gap: '10px', marginTop: '6px', width: '280px' }}>
                <input
                  type="text"
                  className="cyber-input"
                  style={{ fontSize: '0.75rem', padding: '4px 8px', width: '100%' }}
                  value={slackChan}
                  onChange={(e) => setSlackChan(e.target.value)}
                />
              </div>
            )}
          </div>
          
          <button onClick={() => handleToggle('slack')} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: integrations.slack.connected ? 'var(--color-success)' : 'var(--color-muted)' }}>
            {integrations.slack.connected ? <ToggleRight size={38} /> : <ToggleLeft size={38} />}
          </button>
        </div>

        {/* Splunk SIEM */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Splunk / SIEM Log Forwarding</span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-muted)' }}>Forward dynamic scanner telemetry and attack logs to SIEM database.</span>
          </div>
          
          <button onClick={() => handleToggle('splunk')} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: integrations.splunk.connected ? 'var(--color-success)' : 'var(--color-muted)' }}>
            {integrations.splunk.connected ? <ToggleRight size={38} /> : <ToggleLeft size={38} />}
          </button>
        </div>

      </div>

      {/* RBAC Info panel */}
      <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Settings size={18} color="var(--color-warning)" />
          RBAC Security Policies
        </h3>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.8rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-glass)', paddingBottom: '6px' }}>
            <span style={{ fontWeight: 600 }}>Role Profile</span>
            <span style={{ color: 'var(--color-primary)', fontWeight: 600 }}>Security Admin</span>
          </div>
          <p style={{ color: 'var(--color-muted)', fontSize: '0.75rem', lineHeight: 1.3 }}>
            Your account is running in Security Admin authorization mode. You hold full credentials read/write properties, integration toggle, and scanner configurations rights.
          </p>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.75rem', marginTop: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-success)' }}>
            <Check size={14} /> Full Vulnerability Management
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-success)' }}>
            <Check size={14} /> Run Hacking / Discovery Scan Campaigns
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-success)' }}>
            <Check size={14} /> Modify Tenant Integrations Headers
          </div>
        </div>
      </div>

    </div>
  );
}

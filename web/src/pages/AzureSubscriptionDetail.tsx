import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, CheckCircle, XCircle, ArrowLeft, AlertTriangle } from 'lucide-react';
import { azureApi } from '../api/azure';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { ScanStatusBadge, SeverityBadge, FindingStatusBadge } from '../components/ui/Badge';
import type { AzureAuthMethod, AzureScan, AzureFinding } from '../types';
import { ApiRequestError } from '../api/client';

type Tab = 'overview' | 'scans' | 'credentials';

const AUTH_METHOD_OPTIONS = [
  { value: 'SERVICE_PRINCIPAL', label: 'Service Principal' },
  { value: 'MANAGED_IDENTITY',  label: 'Managed Identity'  },
];

function formatDate(dateStr?: string | null): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function formatDuration(ms?: number | null): string {
  if (!ms) return '—';
  if (ms < 1_000)  return `${ms}ms`;
  if (ms < 60_000) return `${Math.round(ms / 1_000)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1_000)}s`;
}

function humanizeAzureError(raw?: string | null): string {
  if (!raw) return 'An unknown error occurred during the scan.';
  const msg = raw.toLowerCase();
  if (msg.includes('no azure credentials') || msg.includes('credentials configured'))
    return 'No Azure credentials configured for this subscription. Add credentials in the Credentials tab and re-run the scan.';
  if (msg.includes('service_principal requires'))
    return 'Service Principal requires tenantId, clientId, and clientSecret. Please update credentials.';
  if (msg.includes('clientauthenticationerror') || msg.includes('invalid_client'))
    return 'Azure authentication failed — check that the Client ID and Client Secret are correct.';
  if (msg.includes('authorizationfailed') || msg.includes('does not have authorization'))
    return 'Authorization failed. The service principal does not have Reader or Security Reader permissions on this subscription.';
  if (msg.includes('tenantnotfound') || msg.includes('tenant'))
    return 'The Azure Tenant ID was not found. Verify the Tenant ID in your credentials.';
  if (msg.includes('subscriptionnotfound') || msg.includes('subscription'))
    return 'The Azure Subscription ID was not found or the service principal does not have access to it.';
  if (msg.includes('enotfound') || msg.includes('network') || msg.includes('econnrefused') || msg.includes('etimedout'))
    return 'Network error — could not reach Azure endpoints. Check your internet connection.';
  if (msg.includes('throttle') || msg.includes('too many requests') || msg.includes('rate limit'))
    return 'Azure API rate limit reached. Wait a few minutes and retry.';
  return raw.split('\n')[0].trim() || raw;
}

export function AzureSubscriptionDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [activeTab,    setActiveTab]    = useState<Tab>('overview');
  const [credError,    setCredError]    = useState<string | null>(null);
  const [credSuccess,  setCredSuccess]  = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ success: boolean; message: string } | null>(null);

  const [authMethod,   setAuthMethod]   = useState<AzureAuthMethod>('SERVICE_PRINCIPAL');
  const [tenantId,     setTenantId]     = useState('');
  const [clientId,     setClientId]     = useState('');
  const [clientSecret, setClientSecret] = useState('');

  const { data: sub, isLoading } = useQuery({
    queryKey: ['azure-subscription', id],
    queryFn:  () => azureApi.getSubscription(id!),
    enabled:  !!id,
  });

  const { data: scansPage, isLoading: scansLoading } = useQuery({
    queryKey: ['azure-scans', { subscriptionId: id }],
    queryFn:  () => azureApi.listScans({ subscriptionId: id, limit: 20 }),
    enabled:  !!id && activeTab === 'scans',
  });
  const scans: AzureScan[] = scansPage?.data ?? [];

  const findingsScanId = sub?.lastSuccessfulScanId ?? sub?.latestScan?.id;

  // Top-5 for overview tab
  const { data: recentFindings } = useQuery({
    queryKey: ['azure-findings', findingsScanId, 'top5'],
    queryFn:  () => azureApi.getFindings(findingsScanId!, { pageSize: 5, page: 1 }),
    enabled:  !!findingsScanId && activeTab === 'overview',
  });
  const topFindings: AzureFinding[] = recentFindings?.data ?? [];

  const triggerScan = useMutation({
    mutationFn: () => azureApi.triggerScan(id!),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['azure-subscription', id] });
      void qc.invalidateQueries({ queryKey: ['azure-scans', { subscriptionId: id }] });
    },
  });

  const saveCreds = useMutation({
    mutationFn: () => azureApi.setCredentials(id!, {
      authMethod,
      tenantId:     authMethod === 'SERVICE_PRINCIPAL' ? tenantId     : undefined,
      clientId:     authMethod === 'SERVICE_PRINCIPAL' ? clientId     : undefined,
      clientSecret: authMethod === 'SERVICE_PRINCIPAL' ? clientSecret : undefined,
    }),
    onSuccess: () => {
      setCredError(null);
      setCredSuccess('Credentials saved successfully.');
      setClientSecret('');
      void qc.invalidateQueries({ queryKey: ['azure-subscription', id] });
    },
    onError: (err) => {
      setCredError(err instanceof ApiRequestError ? err.message : 'Failed to save credentials');
    },
  });

  const verifyCreds = useMutation({
    mutationFn: () => azureApi.verifyCredentials(id!),
    onSuccess: (result) => {
      setVerifyResult({
        success: result.valid,
        message: result.valid ? 'Credentials are valid — Azure token acquired.' : (result.error ?? 'Verification failed'),
      });
    },
    onError: (err) => {
      setVerifyResult({ success: false, message: err instanceof ApiRequestError ? err.message : 'Verification failed' });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-blue-600 border-t-transparent" />
      </div>
    );
  }

  if (!sub) {
    return <div className="text-center py-16 text-gray-500">Subscription not found.</div>;
  }

  const emptySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const scanFailed   = sub.latestScan?.status === 'FAILED';
  const summary      = sub.latestScan?.summary ?? emptySummary;

  // Detect "all scanner errors" scenario: total == info and no real findings
  const realFindings = (summary.critical + summary.high + summary.medium + summary.low);
  const allErrors    = summary.total > 0 && realFindings === 0 && summary.info === summary.total;

  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: 'overview',    label: 'Overview' },
    { key: 'scans',       label: 'Scans' },
    { key: 'credentials', label: 'Credentials' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" leftIcon={<ArrowLeft size={16} />} onClick={() => navigate('/cloud')}>
            Cloud Subscriptions
          </Button>
          <div>
            <h2 className="text-xl font-bold text-gray-900">{sub.name}</h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-xs font-mono bg-gray-100 text-gray-600 px-2 py-0.5 rounded">
                {sub.subscriptionId}
              </span>
              {sub.hasCredentials ? (
                <span className="inline-flex items-center gap-1 text-xs text-green-700">
                  <CheckCircle size={12} /> Credentials configured
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                  <XCircle size={12} /> No credentials
                </span>
              )}
            </div>
          </div>
        </div>
        <Button
          variant="primary"
          leftIcon={<Play size={16} />}
          loading={triggerScan.isPending}
          disabled={!sub.hasCredentials}
          onClick={() => triggerScan.mutate()}
        >
          Run Scan
        </Button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6">
          {tabs.map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.key
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label}
              {tab.count != null && tab.count > 0 && (
                <span className={`ml-1.5 text-xs rounded-full px-1.5 py-0.5 ${
                  activeTab === tab.key ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-500'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ── Overview tab ── */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Failed scan banner */}
          {scanFailed && (
            <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-4">
              <XCircle size={18} className="mt-0.5 shrink-0 text-red-500" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-red-800">Last scan failed</p>
                <p className="text-sm text-red-700 mt-1">
                  {humanizeAzureError(sub.latestScan?.errorMessage)}
                </p>
                {sub.lastSuccessfulScanId && (
                  <p className="text-xs text-red-500 mt-2">
                    Findings and summary below are from the last successful scan.
                  </p>
                )}
              </div>
              <Button
                variant="primary"
                size="sm"
                leftIcon={<Play size={13} />}
                loading={triggerScan.isPending}
                disabled={!sub.hasCredentials}
                onClick={() => triggerScan.mutate()}
              >
                Retry Scan
              </Button>
            </div>
          )}

          {/* All-errors warning banner */}
          {allErrors && !scanFailed && (
            <div className="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-4">
              <AlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-500" />
              <div className="flex-1">
                <p className="text-sm font-semibold text-amber-800">Scan completed but no resources were scanned</p>
                <p className="text-sm text-amber-700 mt-1">
                  All {summary.total} findings are scanner errors — the service principal likely lacks permission to list resources.
                  Verify the service principal has the <strong>Reader</strong> role on this subscription.
                </p>
              </div>
              <Button variant="secondary" size="sm" onClick={() => setActiveTab('credentials')}>
                Check Credentials
              </Button>
            </div>
          )}

          <div className="grid grid-cols-3 gap-6">
            <Card title={scanFailed && sub.lastSuccessfulScanId ? 'Last Successful Scan — Findings' : 'Latest Scan Findings'}>
              <SeverityDonut summary={summary} />
            </Card>

            <Card title="Severity Breakdown">
              <div className="space-y-3">
                {[
                  { label: 'Critical', count: summary.critical, color: 'bg-red-600' },
                  { label: 'High',     count: summary.high,     color: 'bg-orange-500' },
                  { label: 'Medium',   count: summary.medium,   color: 'bg-yellow-500' },
                  { label: 'Low',      count: summary.low,      color: 'bg-blue-500'   },
                  { label: 'Info',     count: summary.info,     color: 'bg-gray-400'   },
                ].map(item => (
                  <div key={item.label} className="flex items-center gap-3">
                    <div className={`h-3 w-3 rounded-full ${item.color}`} />
                    <span className="flex-1 text-sm text-gray-600">{item.label}</span>
                    <span className={`text-sm font-bold ${item.count > 0 ? 'text-gray-900' : 'text-gray-400'}`}>
                      {item.count}
                    </span>
                  </div>
                ))}
                <div className="border-t pt-2 flex justify-between">
                  <span className="text-sm font-medium text-gray-600">Total</span>
                  <span className="text-sm font-bold text-gray-900">{summary.total}</span>
                </div>
              </div>
            </Card>

            <Card title="Latest Scan">
              {sub.latestScan ? (
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500">Status</span>
                    <ScanStatusBadge status={sub.latestScan.status} />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Started</span>
                    <span className="text-gray-900">{formatDate(sub.latestScan.startedAt)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Duration</span>
                    <span className={`font-medium ${(sub.latestScan.durationMs ?? 0) < 500 ? 'text-amber-600' : 'text-gray-900'}`}>
                      {formatDuration(sub.latestScan.durationMs)}
                    </span>
                  </div>
                  {(sub.latestScan.durationMs ?? 0) > 0 && (sub.latestScan.durationMs ?? 0) < 500 && (
                    <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-2 py-1">
                      Very fast scan — likely a permission or credential issue. Check the Credentials tab.
                    </p>
                  )}
                  {scanFailed && sub.latestScan.errorMessage && (
                    <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2">
                      <p className="text-xs font-semibold text-red-700 mb-1">Failure reason</p>
                      <p className="text-xs text-red-600 break-words">
                        {humanizeAzureError(sub.latestScan.errorMessage)}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-sm text-gray-500">No scans yet.</p>
              )}
            </Card>
          </div>

          {/* Recent findings — only show non-INFO in overview */}
          {topFindings.filter(f => f.severity !== 'INFO').length > 0 && (
            <Card title="Recent Findings (Top 5)">
              <div className="divide-y divide-gray-100">
                {topFindings.filter(f => f.severity !== 'INFO').map(f => (
                  <div key={f.id} className="py-3 flex items-start gap-3">
                    <SeverityBadge severity={f.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">{f.title}</p>
                      <p className="text-xs text-gray-500">{f.service} {f.resourceGroup ? `· ${f.resourceGroup}` : ''}</p>
                    </div>
                    <FindingStatusBadge status={f.findingStatus} />
                  </div>
                ))}
              </div>
              <div className="mt-4 pt-4 border-t">
                <Button variant="secondary" size="sm" onClick={() => setActiveTab('scans')}>
                  View all scans
                </Button>
              </div>
            </Card>
          )}

        </div>
      )}

      {/* ── Scans tab ── */}
      {activeTab === 'scans' && (
        <Card padding={false}>
          {scansLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
            </div>
          ) : scans.length === 0 ? (
            <div className="py-16 text-center text-gray-500 text-sm">No scans yet.</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 bg-gray-50">
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Started</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Duration</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">C / H / M / L / Info</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Services</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {scans.map(scan => {
                  const s = scan.summary;
                  const onlyErrors = s && s.total > 0 && (s.critical + s.high + s.medium + s.low) === 0;
                  return (
                    <tr key={scan.id} className={scan.status === 'FAILED' ? 'bg-red-50' : onlyErrors ? 'bg-amber-50' : 'hover:bg-gray-50'}>
                      <td className="px-6 py-4">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="px-6 py-4 text-gray-700">{formatDate(scan.startedAt ?? scan.createdAt)}</td>
                      <td className="px-6 py-4 text-gray-700">{formatDuration(scan.durationMs)}</td>
                      <td className="px-6 py-4">
                        {scan.status === 'FAILED' ? (
                          <span className="text-xs text-red-600">{humanizeAzureError(scan.errorMessage)}</span>
                        ) : s ? (
                          <div className="flex items-center gap-1 text-xs font-mono">
                            <span className={s.critical > 0 ? 'text-red-600 font-bold' : 'text-gray-400'}>{s.critical}</span>
                            <span className="text-gray-300">/</span>
                            <span className={s.high > 0 ? 'text-orange-500 font-bold' : 'text-gray-400'}>{s.high}</span>
                            <span className="text-gray-300">/</span>
                            <span className={s.medium > 0 ? 'text-yellow-600 font-bold' : 'text-gray-400'}>{s.medium}</span>
                            <span className="text-gray-300">/</span>
                            <span className={s.low > 0 ? 'text-blue-500 font-bold' : 'text-gray-400'}>{s.low}</span>
                            <span className="text-gray-300">/</span>
                            <span className={onlyErrors ? 'text-amber-600 font-bold' : 'text-gray-400'}>{s.info}</span>
                            {onlyErrors && (
                              <span className="ml-2 text-xs text-amber-600 bg-amber-100 rounded px-1">errors only</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-gray-400">—</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-gray-500 text-xs max-w-xs truncate">{scan.services.join(', ')}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {/* ── Credentials tab ── */}
      {activeTab === 'credentials' && (
        <Card title="Azure Credentials">
          <div className="space-y-5 max-w-lg">
            <div className="rounded-md bg-blue-50 border border-blue-200 px-4 py-3 text-sm text-blue-800">
              <p className="font-semibold mb-1">Required permissions</p>
              <p className="text-xs text-blue-700">
                The service principal needs at minimum the <strong>Reader</strong> role on the subscription.
                For full security scanning, also assign: <strong>Security Reader</strong>, <strong>Key Vault Reader</strong>.
              </p>
            </div>

            {credError && (
              <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">
                {credError}
              </div>
            )}
            {credSuccess && (
              <div className="rounded-md bg-green-50 border border-green-200 px-3 py-2 text-sm text-green-700">
                {credSuccess}
              </div>
            )}
            {verifyResult && (
              <div className={`rounded-md border px-3 py-2 text-sm ${
                verifyResult.success
                  ? 'bg-green-50 border-green-200 text-green-700'
                  : 'bg-red-50 border-red-200 text-red-700'
              }`}>
                {verifyResult.message}
              </div>
            )}

            <Select
              label="Authentication Method"
              value={authMethod}
              onChange={e => setAuthMethod(e.target.value as AzureAuthMethod)}
              options={AUTH_METHOD_OPTIONS}
            />

            {authMethod === 'SERVICE_PRINCIPAL' && (
              <>
                <Input
                  label="Tenant ID"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  value={tenantId}
                  onChange={e => setTenantId(e.target.value)}
                />
                <Input
                  label="Client ID (Application ID)"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  value={clientId}
                  onChange={e => setClientId(e.target.value)}
                />
                <Input
                  label="Client Secret"
                  type="password"
                  placeholder="••••••••••••••••"
                  value={clientSecret}
                  onChange={e => setClientSecret(e.target.value)}
                />
              </>
            )}

            {authMethod === 'MANAGED_IDENTITY' && (
              <p className="text-sm text-gray-500 bg-blue-50 border border-blue-200 rounded-md px-3 py-2">
                Managed Identity uses the identity of the Azure VM or service running this scanner. No additional credentials are needed.
              </p>
            )}

            <div className="flex gap-3 pt-2">
              <Button
                variant="primary"
                loading={saveCreds.isPending}
                onClick={() => saveCreds.mutate()}
              >
                Save Credentials
              </Button>
              <Button
                variant="secondary"
                loading={verifyCreds.isPending}
                disabled={!sub.hasCredentials}
                onClick={() => { setVerifyResult(null); verifyCreds.mutate(); }}
              >
                Verify
              </Button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

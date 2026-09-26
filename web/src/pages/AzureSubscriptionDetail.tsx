import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, CheckCircle, XCircle, ArrowLeft, AlertTriangle, Key, ChevronRight } from 'lucide-react';
import { azureApi } from '../api/azure';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { ScanStatusBadge, SeverityBadge, FindingStatusBadge } from '../components/ui/Badge';
import { Tooltip } from '../components/ui/Tooltip';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';
import type { AzureAuthMethod, AzureScan, AzureFinding } from '../types';
import { ApiRequestError } from '../api/client';



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
  const [credModalOpen, setCredModalOpen] = useState(false);
  const [authMethod,   setAuthMethod]   = useState<AzureAuthMethod>('SERVICE_PRINCIPAL');
  const [tenantId,     setTenantId]     = useState('');
  const [clientId,     setClientId]     = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [credError,    setCredError]    = useState<string | null>(null);
  const [credSuccess,  setCredSuccess]  = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ success: boolean; message: string } | null>(null);

  const { data: sub, isLoading } = useQuery({
    queryKey: ['azure-subscription', id],
    queryFn:  () => azureApi.getSubscription(id!),
    enabled:  !!id,
  });

  const { data: scansPage, isLoading: scansLoading } = useQuery({
    queryKey: ['azure-scans', { subscriptionId: id }],
    queryFn:  () => azureApi.listScans({ subscriptionId: id, limit: 20 }),
    enabled:  !!id,
  });
  const scans: AzureScan[] = scansPage?.data ?? [];

  const findingsScanId = sub?.lastSuccessfulScanId ?? sub?.latestScan?.id;

  // Top-5 for overview tab
  const { data: recentFindings } = useQuery({
    queryKey: ['azure-findings', findingsScanId, 'top5'],
    queryFn:  () => azureApi.getFindings(findingsScanId!, { pageSize: 5, page: 1 }),
    enabled:  !!findingsScanId,
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

  return (
    <div className="space-y-6">
      {/* Redesigned Header Row matching Compliance details consistency */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-1">
        
        {/* Left Section: Back Arrow -> Azure Logo -> Title & Subtitle */}
        <div className="flex items-center gap-3.5">
          {/* 1. Back Button */}
          <Tooltip content="Back to Cloud Subscriptions" position="right">
            <button
              onClick={() => navigate('/cloud')}
              className="p-2 text-gray-500 hover:text-gray-900 hover:bg-gray-100 rounded-xl transition-all shrink-0 -ml-1"
              aria-label="Back to Cloud Subscriptions"
            >
              <ArrowLeft size={20} strokeWidth={2.2} />
            </button>
          </Tooltip>

          {/* Divider */}
          <div className="h-8 w-px bg-gray-200/80 shrink-0" />

          {/* 2. Azure Logo */}
          <div className="flex items-center justify-center p-2 rounded-xl bg-slate-50 border border-slate-200/80 shrink-0 shadow-2xs">
            <CloudProviderLogo provider="AZURE" className="w-6 h-6 shrink-0" />
          </div>

          {/* 3 & 4. Subscription Name & Subscription ID Subtitle */}
          <div className="space-y-0.5">
            <h1 className="text-xl sm:text-2xl font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
              {sub.name}
            </h1>

            {/* Subscription Details Row */}
            <div className="flex items-center gap-2 text-xs text-gray-500 flex-wrap">
              <span className="font-semibold text-gray-400">Subscription ID:</span>
              <span className="font-mono font-medium text-gray-700 bg-gray-100/90 border border-gray-200 px-2 py-0.5 rounded-md text-[11px] shadow-2xs">
                {sub.subscriptionId}
              </span>
              <span className="text-gray-300">•</span>
              {sub.hasCredentials ? (
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200/80 px-2 py-0.5 rounded-full">
                  <CheckCircle size={12} /> Credentials configured
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-500 bg-gray-100 border border-gray-200 px-2 py-0.5 rounded-full">
                  <XCircle size={12} /> No credentials
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Right Section: Action Buttons */}
        <div className="flex items-center gap-2.5">
          <Button
            variant="secondary"
            leftIcon={<Key size={16} />}
            onClick={() => setCredModalOpen(true)}
          >
            Credentials
          </Button>
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
      </div>

      {/* Main Single Page Layout */}
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
            <Button variant="secondary" size="sm" onClick={() => setCredModalOpen(true)}>
              Check Credentials
            </Button>
          </div>
        )}

        {/* Top Cards Grid: Asymmetric 60/40 Split (col-span-7 / col-span-5) with 100% Equal Height */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          {/* Findings & Breakdown (60% width = col-span-7) */}
          <div className="lg:col-span-7 flex flex-col">
            <Card title={scanFailed && sub.lastSuccessfulScanId ? 'Last Successful Scan Findings' : 'Findings & Breakdown'} className="h-full">
              <div className="flex items-center gap-6 py-1 my-auto">
                {/* Left: Donut Chart with bigger size */}
                <div className="w-[180px] shrink-0 flex items-center justify-center">
                  <SeverityDonut summary={summary} showLegend={false} size={180} />
                </div>

                {/* Right: Severity Breakdown List */}
                <div className="flex-1 space-y-2 min-w-0 pr-1">
                  {[
                    { label: 'Critical', count: summary.critical, color: 'bg-red-600', textCls: 'text-red-600' },
                    { label: 'High',     count: summary.high,     color: 'bg-orange-500', textCls: 'text-orange-500' },
                    { label: 'Medium',   count: summary.medium,   color: 'bg-yellow-500', textCls: 'text-amber-500' },
                    { label: 'Low',      count: summary.low,      color: 'bg-blue-500', textCls: 'text-blue-600' },
                    { label: 'Info',     count: summary.info,     color: 'bg-gray-400', textCls: 'text-gray-500' },
                  ].map((item) => {
                    const pct = summary.total > 0 ? Math.round((item.count / summary.total) * 100) : 0;
                    return (
                      <div key={item.label} className="space-y-0.5">
                        <div className="flex items-center justify-between text-xs font-medium">
                          <div className="flex items-center gap-1.5 min-w-0">
                            <span className={`h-2 w-2 rounded-full shrink-0 ${item.color}`} />
                            <span className="text-gray-700 font-semibold truncate text-[11px]">{item.label}</span>
                          </div>
                          <div className="flex items-center gap-1.5 shrink-0">
                            <span className="text-[10px] text-gray-400 font-normal">{pct}%</span>
                            <span className={`font-bold tabular-nums text-xs ${item.count > 0 ? item.textCls : 'text-gray-400'}`}>{item.count}</span>
                          </div>
                        </div>
                        <div className="h-1 w-full bg-gray-100 rounded-full overflow-hidden">
                          <div className={`h-full ${item.color} transition-all duration-300`} style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </Card>
          </div>

          {/* Scan Info (40% width = col-span-5) */}
          <div className="lg:col-span-5 flex flex-col">
            <Card title="Latest Scan" className="h-full">
              {sub.latestScan ? (
                <div className="space-y-3.5 text-sm flex-1 flex flex-col justify-between">
                  <div className="space-y-3.5 my-auto">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-500 font-medium">Status</span>
                      <ScanStatusBadge status={sub.latestScan.status} />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 font-medium">Started</span>
                      <span className="text-gray-900 font-semibold">{formatDate(sub.latestScan.startedAt)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 font-medium">Duration</span>
                      <span className={`font-semibold ${(sub.latestScan.durationMs ?? 0) < 500 ? 'text-amber-600' : 'text-gray-900'}`}>
                        {formatDuration(sub.latestScan.durationMs)}
                      </span>
                    </div>
                    {(sub.latestScan.durationMs ?? 0) > 0 && (sub.latestScan.durationMs ?? 0) < 500 && (
                      <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-2 py-1">
                        Very fast scan — likely a permission issue.
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
                </div>
              ) : (
                <p className="text-sm text-gray-500">No scans yet.</p>
              )}
            </Card>
          </div>
        </div>

        {/* Recent findings */}
        {topFindings.filter(f => f.severity !== 'INFO').length > 0 && (
          <Card title="Recent Findings (Top 5)" padding={false}>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200/80">
                <thead className="bg-slate-50/80">
                  <tr>
                    {['Severity', 'Service', 'Title', 'Status'].map((h) => (
                      <th key={h} className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-100">
                  {topFindings.filter(f => f.severity !== 'INFO').map(f => (
                    <tr key={f.id} className="hover:bg-gray-50/80 transition-colors cursor-pointer" onClick={() => navigate(`/scans/${f.scanId}`)}>
                      <td className="px-5 py-3.5">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-5 py-3.5">
                        <span className="font-mono text-xs font-semibold text-gray-700 bg-slate-100/90 border border-slate-200/80 px-2 py-0.5 rounded-md shadow-2xs">
                          {f.service}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-xs font-semibold text-gray-900 hover:text-blue-600 transition-colors">
                        {f.title}
                        {f.resourceGroup && <span className="ml-2 font-normal text-gray-400">({f.resourceGroup})</span>}
                      </td>
                      <td className="px-5 py-3.5">
                        <FindingStatusBadge status={f.findingStatus} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* Scan History Table */}
        <Card title="Scan History" padding={false}>
          {scansLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
            </div>
          ) : scans.length === 0 ? (
            <div className="py-16 text-center text-gray-500 text-sm">No scans yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200/80">
                <thead className="bg-slate-50/80">
                  <tr>
                    <th className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Status</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Started</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Duration</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Findings</th>
                    <th className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Services</th>
                    <th className="px-5 py-3 text-right text-xs font-semibold text-gray-500 uppercase tracking-wide"></th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-100">
                  {scans.map(scan => {
                    const s = scan.summary;
                    const onlyErrors = s && s.total > 0 && (s.critical + s.high + s.medium + s.low) === 0;
                    return (
                      <tr
                        key={scan.id}
                        className={`cursor-pointer transition-colors ${scan.status === 'FAILED' ? 'bg-red-50/50' : onlyErrors ? 'bg-amber-50/50' : 'hover:bg-gray-50/80'}`}
                        onClick={() => navigate(`/scans/${scan.id}`)}
                      >
                        <td className="px-5 py-3.5">
                          <ScanStatusBadge status={scan.status} />
                        </td>
                        <td className="px-5 py-3.5 text-xs font-medium text-gray-700 whitespace-nowrap">{formatDate(scan.startedAt ?? scan.createdAt)}</td>
                        <td className="px-5 py-3.5 text-xs text-gray-600 font-mono whitespace-nowrap">{formatDuration(scan.durationMs)}</td>
                        <td className="px-5 py-3.5 text-xs">
                          {scan.status === 'FAILED' ? (
                            <span className="text-xs text-red-600 font-medium">{humanizeAzureError(scan.errorMessage)}</span>
                          ) : s ? (
                            <div className="flex items-center gap-1.5 text-[11px] font-bold tabular-nums">
                              <span className="px-1.5 py-0.5 rounded bg-red-50 text-red-600 border border-red-200/80">C:{s.critical}</span>
                              <span className="px-1.5 py-0.5 rounded bg-orange-50 text-orange-600 border border-orange-200/80">H:{s.high}</span>
                              <span className="px-1.5 py-0.5 rounded bg-amber-50 text-amber-600 border border-amber-200/80">M:{s.medium}</span>
                              <span className="px-1.5 py-0.5 rounded bg-blue-50 text-blue-600 border border-blue-200/80">L:{s.low}</span>
                              {onlyErrors && (
                                <span className="ml-1 text-[10px] text-amber-700 bg-amber-100/90 border border-amber-200 rounded px-1.5 py-0.5 font-semibold">errors only</span>
                              )}
                            </div>
                          ) : (
                            <span className="text-gray-400">—</span>
                          )}
                        </td>
                        <td className="px-5 py-3.5 text-gray-500 text-xs max-w-xs truncate">{scan.services.join(', ')}</td>
                        <td className="px-5 py-3.5 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/scans/${scan.id}`);
                            }}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold text-blue-700 bg-blue-50/90 border border-blue-200/80 rounded-lg hover:bg-blue-600 hover:text-white hover:border-blue-600 shadow-2xs hover:shadow-xs transition-all duration-200 group cursor-pointer"
                          >
                            <span>Detail</span>
                            <ChevronRight size={13} className="transition-transform duration-200 group-hover:translate-x-0.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {/* Credentials Modal Popup */}
      <Modal open={credModalOpen} onClose={() => setCredModalOpen(false)} title="Configure Azure Credentials" size="md">
        <div className="space-y-5">
          <div className="rounded-xl bg-blue-50/80 border border-blue-200/90 p-3.5 text-xs text-blue-900">
            <p className="font-bold mb-1">Required Permissions</p>
            <p className="text-[11px] text-blue-700 leading-relaxed">
              The service principal needs at minimum the <strong>Reader</strong> role on the subscription.
              For full security scanning, also assign: <strong>Security Reader</strong>, <strong>Key Vault Reader</strong>.
            </p>
          </div>

          {credError && (
            <div className="rounded-lg bg-red-50 border border-red-200 px-3.5 py-2.5 text-xs text-red-700">
              {credError}
            </div>
          )}
          {credSuccess && (
            <div className="rounded-lg bg-green-50 border border-green-200 px-3.5 py-2.5 text-xs text-green-700">
              {credSuccess}
            </div>
          )}
          {verifyResult && (
            <div className={`rounded-lg border px-3.5 py-2.5 text-xs ${
              verifyResult.success
                ? 'bg-green-50 border-green-200 text-green-700 font-semibold'
                : 'bg-red-50 border-red-200 text-red-700 font-semibold'
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
            <p className="text-xs text-gray-600 bg-gray-50 border border-gray-200 rounded-xl p-3">
              Managed Identity uses the identity of the Azure VM or service running this scanner. No additional credentials are needed.
            </p>
          )}

          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-gray-100">
            <Button
              variant="secondary"
              loading={verifyCreds.isPending}
              disabled={!sub.hasCredentials}
              onClick={() => { setVerifyResult(null); verifyCreds.mutate(); }}
            >
              Verify Credentials
            </Button>
            <Button
              variant="primary"
              loading={saveCreds.isPending}
              onClick={() => saveCreds.mutate()}
            >
              Save Changes
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

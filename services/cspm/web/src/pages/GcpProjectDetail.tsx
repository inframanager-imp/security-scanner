import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, CheckCircle, XCircle, ArrowLeft } from 'lucide-react';
import { gcpApi } from '../api/gcp';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { ScanStatusBadge, SeverityBadge, FindingStatusBadge } from '../components/ui/Badge';
import type { GcpAuthMethod, GcpScan, GcpFinding } from '../types';
import { ApiRequestError } from '../api/client';

type Tab = 'overview' | 'scans' | 'credentials';

const AUTH_METHOD_OPTIONS = [
  { value: 'SERVICE_ACCOUNT_KEY', label: 'Service Account Key (JSON)' },
  { value: 'WORKLOAD_IDENTITY',   label: 'Workload Identity'           },
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

function humanizeGcpError(raw?: string | null): string {
  if (!raw) return 'An unknown error occurred during the scan.';
  const msg = raw.toLowerCase();
  if (msg.includes('no gcp credentials') || msg.includes('credentials configured'))
    return 'No GCP credentials configured for this project. Add a service account key in the Credentials tab and re-run the scan.';
  if (msg.includes('invalid service account key'))
    return 'The service account key JSON is invalid. Please upload the correct key file.';
  if (msg.includes('permission denied') || msg.includes('403'))
    return 'Permission denied. Ensure the service account has the required viewer roles (roles/viewer or individual service roles).';
  if (msg.includes('project not found') || msg.includes('404'))
    return 'The GCP project was not found. Verify the Project ID is correct.';
  if (msg.includes('enotfound') || msg.includes('network') || msg.includes('econnrefused') || msg.includes('etimedout'))
    return 'Network error — could not reach GCP endpoints. Check your internet connection.';
  if (msg.includes('quota') || msg.includes('rate limit') || msg.includes('429'))
    return 'GCP API quota exceeded. Wait a few minutes and retry, or request a quota increase.';
  return raw.split('\n')[0].trim() || raw;
}

export function GcpProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [activeTab,    setActiveTab]    = useState<Tab>('overview');
  const [credError,    setCredError]    = useState<string | null>(null);
  const [credSuccess,  setCredSuccess]  = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ success: boolean; message: string } | null>(null);

  const [authMethod,         setAuthMethod]         = useState<GcpAuthMethod>('SERVICE_ACCOUNT_KEY');
  const [serviceAccountKey,  setServiceAccountKey]  = useState('');
  const [serviceAccountEmail, setServiceAccountEmail] = useState('');

  const { data: project, isLoading } = useQuery({
    queryKey: ['gcp-project', id],
    queryFn:  () => gcpApi.getProject(id!),
    enabled:  !!id,
  });

  const { data: scansPage, isLoading: scansLoading } = useQuery({
    queryKey: ['gcp-scans', { projectId: id }],
    queryFn:  () => gcpApi.listScans({ projectId: id, limit: 20 }),
    enabled:  !!id && activeTab === 'scans',
  });
  const scans: GcpScan[] = scansPage?.data ?? [];

  const findingsScanId = project?.lastSuccessfulScanId ?? project?.latestScan?.id;
  const { data: recentFindings } = useQuery({
    queryKey: ['gcp-findings', findingsScanId, 'top5'],
    queryFn:  () => gcpApi.getFindings(findingsScanId!, { pageSize: 5, page: 1 }),
    enabled:  !!findingsScanId && activeTab === 'overview',
  });
  const findings: GcpFinding[] = recentFindings?.data ?? [];

  const triggerScan = useMutation({
    mutationFn: () => gcpApi.triggerScan(id!),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['gcp-project', id] });
      void qc.invalidateQueries({ queryKey: ['gcp-scans', { projectId: id }] });
    },
  });

  const saveCreds = useMutation({
    mutationFn: () => gcpApi.setCredentials(id!, {
      authMethod,
      serviceAccountKey:   authMethod === 'SERVICE_ACCOUNT_KEY' ? serviceAccountKey : undefined,
      serviceAccountEmail: serviceAccountEmail || undefined,
    }),
    onSuccess: () => {
      setCredError(null);
      setCredSuccess('Credentials saved successfully.');
      setServiceAccountKey('');
      void qc.invalidateQueries({ queryKey: ['gcp-project', id] });
    },
    onError: (err) => {
      setCredError(err instanceof ApiRequestError ? err.message : 'Failed to save credentials');
    },
  });

  const verifyCreds = useMutation({
    mutationFn: () => gcpApi.verifyCredentials(id!),
    onSuccess: (result) => {
      setVerifyResult({
        success: result.valid,
        message: result.valid ? 'Credentials are valid — GCP project accessible.' : (result.error ?? 'Verification failed'),
      });
    },
    onError: (err) => {
      setVerifyResult({ success: false, message: err instanceof ApiRequestError ? err.message : 'Verification failed' });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-green-600 border-t-transparent" />
      </div>
    );
  }

  if (!project) {
    return <div className="text-center py-16 text-gray-500">GCP project not found.</div>;
  }

  const emptySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const scanFailed   = project.latestScan?.status === 'FAILED';
  const summary      = project.latestScan?.summary ?? emptySummary;

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview',    label: 'Overview'    },
    { key: 'scans',       label: 'Scans'       },
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
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-gray-900">{project.name}</h2>
              <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold bg-green-50 text-green-700 border border-green-200">
                GCP
              </span>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-xs font-mono bg-gray-100 text-gray-600 px-2 py-0.5 rounded">
                {project.projectId}
              </span>
              {project.hasCredentials ? (
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
          disabled={!project.hasCredentials}
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
                  ? 'border-green-600 text-green-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label}
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
                  {humanizeGcpError(project.latestScan?.errorMessage)}
                </p>
                {project.lastSuccessfulScanId && (
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
                disabled={!project.hasCredentials}
                onClick={() => triggerScan.mutate()}
              >
                Retry Scan
              </Button>
            </div>
          )}

          <div className="grid grid-cols-3 gap-6">
            {/* Donut */}
            <Card title={scanFailed && project.lastSuccessfulScanId ? 'Last Successful Scan — Findings' : 'Latest Scan Findings'}>
              <SeverityDonut summary={summary} />
            </Card>

            {/* Severity breakdown */}
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
                    <span className="text-sm font-bold text-gray-900">{item.count}</span>
                  </div>
                ))}
                <div className="border-t pt-2 flex justify-between">
                  <span className="text-sm font-medium text-gray-600">Total</span>
                  <span className="text-sm font-bold text-gray-900">{summary.total}</span>
                </div>
              </div>
            </Card>

            {/* Scan info */}
            <Card title="Latest Scan">
              {project.latestScan ? (
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500">Status</span>
                    <ScanStatusBadge status={project.latestScan.status} />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Started</span>
                    <span className="text-gray-900">{formatDate(project.latestScan.startedAt)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Duration</span>
                    <span className="text-gray-900">{formatDuration(project.latestScan.durationMs)}</span>
                  </div>
                  {scanFailed && project.latestScan.errorMessage && (
                    <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2">
                      <p className="text-xs font-semibold text-red-700 mb-1">Failure reason</p>
                      <p className="text-xs text-red-600 break-words">
                        {humanizeGcpError(project.latestScan.errorMessage)}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-sm text-gray-500">No scans yet.</p>
              )}
            </Card>
          </div>

          {/* Recent findings */}
          {findings.length > 0 && (
            <Card title="Recent Findings (Top 5)">
              <div className="divide-y divide-gray-100">
                {findings.map(f => (
                  <div key={f.id} className="py-3 flex items-start gap-3">
                    <SeverityBadge severity={f.severity} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900 truncate">{f.title}</p>
                      <p className="text-xs text-gray-500">
                        {f.service}{f.resourceName ? ` · ${f.resourceName}` : ''}{f.region ? ` · ${f.region}` : ''}
                      </p>
                    </div>
                    <FindingStatusBadge status={f.findingStatus} />
                  </div>
                ))}
              </div>
              {(recentFindings?.total ?? 0) > 5 && (
                <div className="mt-4 pt-4 border-t">
                  <Button variant="secondary" size="sm" onClick={() => setActiveTab('scans')}>
                    View all {recentFindings!.total} findings
                  </Button>
                </div>
              )}
            </Card>
          )}
        </div>
      )}

      {/* ── Scans tab ── */}
      {activeTab === 'scans' && (
        <Card padding={false}>
          {scansLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="animate-spin rounded-full h-7 w-7 border-2 border-green-600 border-t-transparent" />
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
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Findings</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Services</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {scans.map(scan => (
                  <tr key={scan.id} className={scan.status === 'FAILED' ? 'bg-red-50' : 'hover:bg-gray-50'}>
                    <td className="px-6 py-4"><ScanStatusBadge status={scan.status} /></td>
                    <td className="px-6 py-4 text-gray-700">{formatDate(scan.startedAt ?? scan.createdAt)}</td>
                    <td className="px-6 py-4 text-gray-700">{formatDuration(scan.durationMs)}</td>
                    <td className="px-6 py-4">
                      {scan.status === 'FAILED' ? (
                        <span className="text-xs text-red-600">{humanizeGcpError(scan.errorMessage)}</span>
                      ) : scan.summary ? (
                        <span className="text-gray-700">{scan.summary.total} total</span>
                      ) : (
                        <span className="text-gray-400">—</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-gray-500 text-xs">{scan.services.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {/* ── Credentials tab ── */}
      {activeTab === 'credentials' && (
        <Card title="GCP Credentials">
          <div className="space-y-5 max-w-lg">
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
              onChange={e => setAuthMethod(e.target.value as GcpAuthMethod)}
              options={AUTH_METHOD_OPTIONS}
            />

            {authMethod === 'SERVICE_ACCOUNT_KEY' && (
              <>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Service Account Key (JSON)
                  </label>
                  <textarea
                    rows={6}
                    className="w-full rounded-md border border-gray-300 px-3 py-2 text-xs font-mono text-gray-900 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
                    placeholder='{"type":"service_account","project_id":"...","private_key":"...","client_email":"..."}'
                    value={serviceAccountKey}
                    onChange={e => setServiceAccountKey(e.target.value)}
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    Paste the full JSON contents of your service account key file. The key will be encrypted at rest.
                  </p>
                </div>
                <Input
                  label="Service Account Email (optional — auto-detected from key)"
                  placeholder="scanner@my-project.iam.gserviceaccount.com"
                  value={serviceAccountEmail}
                  onChange={e => setServiceAccountEmail(e.target.value)}
                />
              </>
            )}

            {authMethod === 'WORKLOAD_IDENTITY' && (
              <div className="space-y-3">
                <p className="text-sm text-gray-500 bg-green-50 border border-green-200 rounded-md px-3 py-2">
                  Workload Identity uses the identity of the GCP service running this scanner (e.g., a GKE pod or Cloud Run service). No key file is needed.
                </p>
                <Input
                  label="Service Account Email (optional)"
                  placeholder="scanner@my-project.iam.gserviceaccount.com"
                  value={serviceAccountEmail}
                  onChange={e => setServiceAccountEmail(e.target.value)}
                />
              </div>
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
                disabled={!project.hasCredentials}
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

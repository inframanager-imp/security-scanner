import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, CheckCircle, XCircle, ArrowLeft, FileBarChart, Key } from 'lucide-react';
import { gcpApi } from '../api/gcp';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { ScanStatusBadge, SeverityBadge, FindingStatusBadge } from '../components/ui/Badge';
import { Tooltip } from '../components/ui/Tooltip';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';
import type { GcpAuthMethod, GcpScan, GcpFinding } from '../types';
import { ApiRequestError } from '../api/client';
import { VaptReportModal } from '../components/ui/VaptReportModal';



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
  const [credError,    setCredError]    = useState<string | null>(null);
  const [credSuccess,  setCredSuccess]  = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ success: boolean; message: string } | null>(null);
  const [vaptModalOpen, setVaptModalOpen] = useState(false);
  const [credModalOpen, setCredModalOpen] = useState(false);

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
    enabled:  !!id,
  });
  const scans: GcpScan[] = scansPage?.data ?? [];

  const findingsScanId = project?.lastSuccessfulScanId ?? project?.latestScan?.id;
  const { data: recentFindings } = useQuery({
    queryKey: ['gcp-findings', findingsScanId, 'top5'],
    queryFn:  () => gcpApi.getFindings(findingsScanId!, { pageSize: 5, page: 1 }),
    enabled:  !!findingsScanId,
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

  return (
    <div className="space-y-6">
      {/* Redesigned Header Row matching Compliance details consistency */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-1">
        
        {/* Left Section: Back Arrow -> GCP Logo -> Title & Subtitle */}
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

          {/* 2. GCP Logo */}
          <div className="flex items-center justify-center p-2 rounded-xl bg-slate-50 border border-slate-200/80 shrink-0 shadow-2xs">
            <CloudProviderLogo provider="GCP" className="w-6 h-6 shrink-0" />
          </div>

          {/* 3 & 4. Project Name & Project ID Subtitle */}
          <div className="space-y-0.5">
            <h1 className="text-xl sm:text-2xl font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
              {project.name}
            </h1>

            {/* Project Details Row */}
            <div className="flex items-center gap-2 text-xs text-gray-50 flex-wrap">
              <span className="font-semibold text-gray-400">Project ID:</span>
              <span className="font-mono font-medium text-gray-700 bg-gray-100/90 border border-gray-200 px-2 py-0.5 rounded-md text-[11px] shadow-2xs">
                {project.projectId}
              </span>
              <span className="text-gray-300">•</span>
              {project.hasCredentials ? (
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
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            leftIcon={<FileBarChart size={16} />}
            onClick={() => setVaptModalOpen(true)}
            title="Generate a professional VAPT-style security report (view HTML, print to PDF)"
          >
            VAPT Report
          </Button>
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
            disabled={!project.hasCredentials}
            onClick={() => triggerScan.mutate()}
          >
            Run Scan
          </Button>
        </div>
      </div>

      {id && (
        <VaptReportModal
          open={vaptModalOpen}
          onClose={() => setVaptModalOpen(false)}
          provider="GCP"
          targetId={id}
          targetName={project.name}
        />
      )}

      {/* Main Single Page Layout */}
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

        {/* Top Cards Grid: Asymmetric 60/40 Split (col-span-7 / col-span-5) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Findings & Breakdown (60% width = col-span-7) */}
          <div className="lg:col-span-7 flex flex-col">
            <Card title={scanFailed && project.lastSuccessfulScanId ? 'Last Successful Scan Findings' : 'Findings & Breakdown'}>
              <div className="flex items-center gap-6 py-1">
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

          {/* Scan info (40% width = col-span-5) */}
          <div className="lg:col-span-5 flex flex-col">
            <Card title="Latest Scan">
              {project.latestScan ? (
                <div className="space-y-3.5 text-sm flex-1 flex flex-col justify-between">
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-500 font-medium">Status</span>
                      <ScanStatusBadge status={project.latestScan.status} />
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 font-medium">Started</span>
                      <span className="text-gray-900 font-semibold">{formatDate(project.latestScan.startedAt)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-500 font-medium">Duration</span>
                      <span className="text-gray-900 font-semibold">{formatDuration(project.latestScan.durationMs)}</span>
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
                </div>
              ) : (
                <p className="text-sm text-gray-500">No scans yet.</p>
              )}
            </Card>
          </div>
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
          </Card>
        )}

        {/* Scan History Table */}
        <Card title="Scan History" padding={false}>
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
      </div>

      {/* Credentials Modal Popup */}
      <Modal open={credModalOpen} onClose={() => setCredModalOpen(false)} title="Configure GCP Credentials" size="md">
        <div className="space-y-5">
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
            onChange={e => setAuthMethod(e.target.value as GcpAuthMethod)}
            options={AUTH_METHOD_OPTIONS}
          />

          {authMethod === 'SERVICE_ACCOUNT_KEY' && (
            <>
              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1.5">
                  Service Account Key (JSON)
                </label>
                <textarea
                  rows={5}
                  className="w-full rounded-xl border border-gray-300 px-3 py-2 text-xs font-mono text-gray-900 focus:outline-none focus:ring-2 focus:ring-green-500/20 focus:border-green-600 transition-all resize-none"
                  placeholder='{"type":"service_account","project_id":"...","private_key":"...","client_email":"..."}'
                  value={serviceAccountKey}
                  onChange={e => setServiceAccountKey(e.target.value)}
                />
                <p className="mt-1 text-[11px] text-gray-400">
                  Paste the full JSON contents of your service account key file. Encrypted at rest.
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
              <p className="text-xs text-gray-600 bg-gray-50 border border-gray-200 rounded-xl p-3">
                Workload Identity uses the identity of the GCP service running this scanner (e.g. GKE pod / Cloud Run). No key file needed.
              </p>
              <Input
                label="Service Account Email (optional)"
                placeholder="scanner@my-project.iam.gserviceaccount.com"
                value={serviceAccountEmail}
                onChange={e => setServiceAccountEmail(e.target.value)}
              />
            </div>
          )}

          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-gray-100">
            <Button
              variant="secondary"
              loading={verifyCreds.isPending}
              disabled={!project.hasCredentials}
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

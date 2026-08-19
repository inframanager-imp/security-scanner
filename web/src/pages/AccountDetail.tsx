import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, CheckCircle, XCircle, Shield, ArrowLeft } from 'lucide-react';
import { accountsApi } from '../api/accounts';
import { scansApi } from '../api/scans';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { SeverityDonut } from '../components/charts/SeverityDonut';
import { ScanStatusBadge, SeverityBadge, FindingStatusBadge } from '../components/ui/Badge';
import type { AuthMethod, Scan, Finding } from '../types';
import { ApiRequestError } from '../api/client';

type Tab = 'overview' | 'scans' | 'credentials';

const AUTH_METHOD_OPTIONS = [
  { value: 'ACCESS_KEY', label: 'Access Key' },
  { value: 'ASSUME_ROLE', label: 'Assume Role (IAM)' },
];

function formatDate(dateStr?: string): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatDuration(ms?: number): string {
  if (!ms) return '—';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

/** Translate raw AWS / Node error strings into plain-English messages. */
function humanizeScanError(raw?: string | null): string {
  if (!raw) return 'An unknown error occurred during the scan.';
  const msg = raw.toLowerCase();

  if (msg.includes('no credentials') || msg.includes('no aws credentials'))
    return 'No AWS credentials configured for this account. Add credentials in the Credentials tab and re-run the scan.';
  if (msg.includes('missing access key') || msg.includes('missing secretaccesskey'))
    return 'Access Key ID or Secret Access Key is missing. Update credentials in the Credentials tab.';
  if (msg.includes('invalidclienttokenid') || msg.includes('the security token included in the request is invalid'))
    return 'The AWS Access Key ID is invalid or has been deactivated. Please rotate or replace it.';
  if (msg.includes('signaturedoesnotmatch') || msg.includes('authfailure'))
    return 'AWS authentication failed — the Secret Access Key does not match the Access Key ID. Check your credentials.';
  if (msg.includes('expiredtokenexception') || msg.includes('token has expired'))
    return 'The AWS session token has expired. Refresh your temporary credentials or switch to a long-term access key.';
  if (msg.includes('accessdenied') || msg.includes('access denied') || msg.includes('not authorized'))
    return 'Permission denied. The IAM user or role does not have the required read permissions. Attach the SecurityAudit or ViewOnlyAccess policy.';
  if (msg.includes('tokenrefresherror') || msg.includes('assume role') || msg.includes('sts'))
    return 'Failed to assume the IAM role via STS. Verify the Role ARN and that the trust policy allows this account to assume it.';
  if (msg.includes('unrecognizedclientexception'))
    return 'AWS did not recognise the Access Key. It may have been deleted. Please create a new key and update credentials.';
  if (msg.includes('enotfound') || msg.includes('network') || msg.includes('econnrefused') || msg.includes('etimedout'))
    return 'Network error — could not reach AWS endpoints. Check your internet connection, proxy settings, or VPC configuration.';
  if (msg.includes('throttling') || msg.includes('rate exceeded') || msg.includes('toomanyrequests'))
    return 'AWS API rate limit reached. Wait a few minutes and re-run the scan.';
  if (msg.includes('region') && msg.includes('invalid'))
    return 'One or more selected AWS regions are invalid or not enabled for this account.';

  // Return the original message, but strip any Node.js stack-trace cruft
  return raw.split('\n')[0].trim() || raw;
}

export function AccountDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [credError, setCredError] = useState<string | null>(null);
  const [credSuccess, setCredSuccess] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ success: boolean; message: string } | null>(null);

  const [authMethod, setAuthMethod] = useState<AuthMethod>('ACCESS_KEY');
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [roleArn, setRoleArn] = useState('');
  const [externalId, setExternalId] = useState('');

  const { data: account, isLoading: accountLoading } = useQuery({
    queryKey: ['accounts', id],
    queryFn: () => accountsApi.get(id!),
    enabled: !!id,
  });

  const { data: scansPage, isLoading: scansLoading } = useQuery({
    queryKey: ['scans', { accountId: id }],
    queryFn: () => scansApi.list(id),
    enabled: !!id,
  });
  const scans: Scan[] = scansPage?.data ?? [];

  const { data: credentials, isLoading: credLoading } = useQuery({
    queryKey: ['credentials', id],
    queryFn: () => accountsApi.getCredentials(id!),
    enabled: !!id && activeTab === 'credentials',
  });

  const latestScan = account?.latestScan;
  const findingsScanId = account?.lastSuccessfulScanId ?? latestScan?.id;
  const { data: recentFindings } = useQuery({
    queryKey: ['scan-findings', findingsScanId, 'top5'],
    queryFn: () =>
      scansApi.getFindings(findingsScanId!, { pageSize: 5, page: 1 }),
    enabled: !!findingsScanId && activeTab === 'overview',
  });

  const triggerScan = useMutation({
    mutationFn: () => scansApi.trigger({ accountId: id! }),
    onSuccess: (scan: Scan) => {
      void qc.invalidateQueries({ queryKey: ['accounts', id] });
      navigate(`/scans/${scan.id}`);
    },
  });

  const saveCreds = useMutation({
    mutationFn: () =>
      credentials
        ? accountsApi.updateCredentials(id!, {
            authMethod,
            accessKeyId: authMethod === 'ACCESS_KEY' ? accessKeyId : undefined,
            secretAccessKey:
              authMethod === 'ACCESS_KEY' ? secretAccessKey : undefined,
            roleArn: authMethod === 'ASSUME_ROLE' ? roleArn : undefined,
            externalId:
              authMethod === 'ASSUME_ROLE' && externalId ? externalId : undefined,
          })
        : accountsApi.setCredentials(id!, {
            authMethod,
            accessKeyId: authMethod === 'ACCESS_KEY' ? accessKeyId : undefined,
            secretAccessKey:
              authMethod === 'ACCESS_KEY' ? secretAccessKey : undefined,
            roleArn: authMethod === 'ASSUME_ROLE' ? roleArn : undefined,
            externalId:
              authMethod === 'ASSUME_ROLE' && externalId ? externalId : undefined,
          }),
    onSuccess: () => {
      setCredError(null);
      setCredSuccess('Credentials saved successfully.');
      setSecretAccessKey('');
      void qc.invalidateQueries({ queryKey: ['credentials', id] });
      void qc.invalidateQueries({ queryKey: ['accounts', id] });
      void qc.invalidateQueries({ queryKey: ['accounts'] });
    },
    onError: (err) => {
      setCredError(
        err instanceof ApiRequestError ? err.message : 'Failed to save credentials',
      );
    },
  });

  const verifyCreds = useMutation({
    mutationFn: () => accountsApi.verifyCredentials(id!),
    onSuccess: (result) => {
      setVerifyResult({
        success: result.valid,
        message: result.valid
          ? `Valid — AWS Account: ${result.awsAccountId ?? 'unknown'}`
          : (result.error ?? 'Verification failed'),
      });
    },
    onError: (err) => {
      setVerifyResult({
        success: false,
        message: err instanceof ApiRequestError ? err.message : 'Verification failed',
      });
    },
  });

  if (accountLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-blue-600 border-t-transparent" />
      </div>
    );
  }

  if (!account) {
    return (
      <div className="text-center py-16 text-gray-500">Account not found.</div>
    );
  }

  const emptySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  const scanFailed = account.latestScan?.status === 'FAILED';
  // Show summary from last successful scan when latest failed/is running
  const summary = account.latestScan?.summary ?? emptySummary;

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'scans', label: 'Scans' },
    { key: 'credentials', label: 'Credentials' },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            leftIcon={<ArrowLeft size={16} />}
            onClick={() => navigate('/cloud')}
          >
            Cloud Subscriptions
          </Button>
          <div>
            <h2 className="text-xl font-bold text-gray-900">{account.name}</h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-xs font-mono bg-gray-100 text-gray-600 px-2 py-0.5 rounded">
                {account.awsAccountId}
              </span>
              {account.hasCredentials ? (
                <span className="inline-flex items-center gap-1 text-xs text-green-700">
                  <CheckCircle size={12} />
                  Credentials configured
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                  <XCircle size={12} />
                  No credentials
                </span>
              )}
            </div>
          </div>
        </div>
        <Button
          variant="primary"
          leftIcon={<Play size={16} />}
          loading={triggerScan.isPending}
          disabled={!account.hasCredentials}
          onClick={() => triggerScan.mutate()}
        >
          Run Scan
        </Button>
      </div>

      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6">
          {tabs.map((tab) => (
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
            </button>
          ))}
        </nav>
      </div>

      {activeTab === 'overview' && (
        <div className="space-y-6">

          {scanFailed && (
            <div className="flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 px-4 py-4">
              <XCircle size={18} className="mt-0.5 shrink-0 text-red-500" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-red-800">Last scan failed</p>
                <p className="text-sm text-red-700 mt-1">
                  {humanizeScanError(account.latestScan?.errorMessage)}
                </p>
                {account.lastSuccessfulScanId && (
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
                disabled={!account.hasCredentials}
                onClick={() => triggerScan.mutate()}
              >
                Retry Scan
              </Button>
            </div>
          )}

          <div className="grid grid-cols-3 gap-6">
            {/* Donut — labelled to clarify it may be from a prior scan */}
            <Card title={scanFailed && account.lastSuccessfulScanId ? 'Last Successful Scan — Findings' : 'Latest Scan Findings'}>
              <SeverityDonut summary={summary} />
            </Card>

            <Card title="Severity Breakdown">
              <div className="space-y-3">
                {[
                  { label: 'Critical', count: summary.critical, color: 'bg-red-600' },
                  { label: 'High', count: summary.high, color: 'bg-orange-500' },
                  { label: 'Medium', count: summary.medium, color: 'bg-yellow-500' },
                  { label: 'Low', count: summary.low, color: 'bg-blue-500' },
                  { label: 'Info', count: summary.info, color: 'bg-gray-400' },
                ].map((item) => (
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

            <Card title="Latest Scan">
              {account.latestScan ? (
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-500">Status</span>
                    <ScanStatusBadge status={account.latestScan.status} />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Started</span>
                    <span className="text-gray-900">
                      {formatDate(account.latestScan.startedAt)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Duration</span>
                    <span className="text-gray-900">
                      {formatDuration(account.latestScan.durationMs)}
                    </span>
                  </div>
                  {scanFailed && account.latestScan.errorMessage && (
                    <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2">
                      <p className="text-xs font-semibold text-red-700 mb-1">Failure reason</p>
                      <p className="text-xs text-red-600 break-words">
                        {humanizeScanError(account.latestScan.errorMessage)}
                      </p>
                    </div>
                  )}
                  <Button
                    variant="secondary"
                    size="sm"
                    className="w-full mt-2"
                    onClick={() =>
                      navigate(`/scans/${account.latestScan!.id}`)
                    }
                  >
                    View Full Scan
                  </Button>
                </div>
              ) : (
                <p className="text-sm text-gray-500">No scans yet.</p>
              )}
            </Card>
          </div>

          <Card title={scanFailed && account.lastSuccessfulScanId ? 'Recent Findings — Last Successful Scan (Top 5)' : 'Recent Findings (Top 5)'} padding={false}>
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {['Severity', 'Service', 'Title', 'Status'].map((h) => (
                      <th
                        key={h}
                        className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {recentFindings?.data.length === 0 ? (
                    <tr>
                      <td
                        colSpan={4}
                        className="px-4 py-8 text-center text-gray-400 text-sm"
                      >
                        No findings in the latest scan.
                      </td>
                    </tr>
                  ) : (
                    (recentFindings?.data ?? []).map((f: Finding) => (
                      <tr key={f.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">
                          {f.service}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-900">
                          {f.title}
                        </td>
                        <td className="px-4 py-3">
                          <FindingStatusBadge status={f.findingStatus} />
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {activeTab === 'scans' && (
        <Card padding={false}>
          {scansLoading ? (
            <div className="p-6 space-y-3">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-8 bg-gray-100 rounded animate-pulse" />
              ))}
            </div>
          ) : scans.length === 0 ? (
            <div className="p-12 text-center text-gray-500 text-sm">
              No scans found for this account.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {['Scan ID', 'Status', 'Started', 'Duration', 'Findings', ''].map(
                      (h) => (
                        <th
                          key={h}
                          className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider"
                        >
                          {h}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {scans.map((scan: Scan) => (
                    <tr
                      key={scan.id}
                      className={`cursor-pointer ${scan.status === 'FAILED' ? 'bg-red-50 hover:bg-red-100' : 'hover:bg-gray-50'}`}
                      onClick={() => navigate(`/scans/${scan.id}`)}
                    >
                      <td className="px-4 py-3 text-sm font-mono text-gray-600">
                        {scan.id.slice(0, 8)}...
                      </td>
                      <td className="px-4 py-3">
                        <ScanStatusBadge status={scan.status} />
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500">
                        {formatDate(scan.startedAt ?? scan.createdAt)}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500">
                        {formatDuration(scan.durationMs)}
                      </td>
                      <td className="px-4 py-3 text-sm">
                        {scan.status === 'FAILED' ? (
                          <span
                            className="text-xs text-red-600 max-w-xs truncate block"
                            title={humanizeScanError(scan.errorMessage)}
                          >
                            {humanizeScanError(scan.errorMessage)}
                          </span>
                        ) : scan.summary ? (
                          <div className="flex gap-2 text-xs font-semibold">
                            <span className="text-red-600">C:{scan.summary.critical}</span>
                            <span className="text-orange-500">H:{scan.summary.high}</span>
                            <span className="text-yellow-500">M:{scan.summary.medium}</span>
                            <span className="text-blue-500">L:{scan.summary.low}</span>
                          </div>
                        ) : (
                          <span className="text-gray-400 text-xs">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/scans/${scan.id}`);
                          }}
                        >
                          View
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {activeTab === 'credentials' && (
        <div className="max-w-2xl space-y-6">
          {credLoading ? (
            <div className="animate-pulse space-y-3">
              <div className="h-8 bg-gray-100 rounded" />
              <div className="h-8 bg-gray-100 rounded" />
            </div>
          ) : (
            <>
              {credentials && (
                <Card title="Current Credentials">
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-500">Method</span>
                      <span className="text-gray-900 font-medium">
                        {credentials.authMethod}
                      </span>
                    </div>
                    {credentials.authMethod === 'ACCESS_KEY' && credentials.accessKeyId && (
                      <div className="flex justify-between">
                        <span className="text-gray-500">Access Key ID</span>
                        <span className="font-mono text-gray-900">
                          {credentials.accessKeyId}
                        </span>
                      </div>
                    )}
                    {credentials.authMethod === 'ASSUME_ROLE' && credentials.roleArn && (
                      <div className="flex justify-between">
                        <span className="text-gray-500">Role ARN</span>
                        <span className="font-mono text-gray-900 text-xs">
                          {credentials.roleArn}
                        </span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-gray-500">Verified</span>
                      <span>
                        {credentials.isVerified ? (
                          <span className="text-green-700 inline-flex items-center gap-1">
                            <CheckCircle size={12} />
                            Verified
                          </span>
                        ) : (
                          <span className="text-gray-400">Not verified</span>
                        )}
                      </span>
                    </div>
                  </div>
                </Card>
              )}

              <Card title={credentials ? 'Update Credentials' : 'Add Credentials'}>
                <div className="space-y-4">
                  {credError && (
                    <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
                      {credError}
                    </div>
                  )}
                  {credSuccess && (
                    <div className="rounded-lg bg-green-50 border border-green-200 px-4 py-3 text-sm text-green-700">
                      {credSuccess}
                    </div>
                  )}

                  <Select
                    label="Authentication Method"
                    value={authMethod}
                    onChange={(e) => setAuthMethod(e.target.value as AuthMethod)}
                    options={AUTH_METHOD_OPTIONS}
                  />

                  {authMethod === 'ACCESS_KEY' && (
                    <>
                      <Input
                        label="Access Key ID"
                        value={accessKeyId}
                        onChange={(e) => setAccessKeyId(e.target.value)}
                        placeholder="AKIAIOSFODNN7EXAMPLE"
                      />
                      <Input
                        label="Secret Access Key"
                        type="password"
                        value={secretAccessKey}
                        onChange={(e) => setSecretAccessKey(e.target.value)}
                        placeholder="Enter secret access key"
                      />
                    </>
                  )}

                  {authMethod === 'ASSUME_ROLE' && (
                    <>
                      <Input
                        label="Role ARN"
                        value={roleArn}
                        onChange={(e) => setRoleArn(e.target.value)}
                        placeholder="arn:aws:iam::123456789012:role/ScannerRole"
                      />
                      <Input
                        label="External ID (optional)"
                        value={externalId}
                        onChange={(e) => setExternalId(e.target.value)}
                        placeholder="Optional external ID"
                      />
                    </>
                  )}

                  <div className="flex gap-3 pt-2">
                    <Button
                      variant="primary"
                      loading={saveCreds.isPending}
                      onClick={() => saveCreds.mutate()}
                    >
                      <Shield size={14} />
                      Save Credentials
                    </Button>
                    <Button
                      variant="secondary"
                      loading={verifyCreds.isPending}
                      onClick={() => {
                        setVerifyResult(null);
                        verifyCreds.mutate();
                      }}
                    >
                      Verify
                    </Button>
                  </div>

                  {verifyResult && (
                    <div
                      className={`rounded-lg border px-4 py-3 text-sm ${
                        verifyResult.success
                          ? 'bg-green-50 border-green-200 text-green-700'
                          : 'bg-red-50 border-red-200 text-red-700'
                      }`}
                    >
                      {verifyResult.success ? (
                        <span className="inline-flex items-center gap-1">
                          <CheckCircle size={14} />
                          {verifyResult.message}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1">
                          <XCircle size={14} />
                          {verifyResult.message}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </Card>
            </>
          )}
        </div>
      )}
    </div>
  );
}

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Box,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronRight,
  Shield,
  Info,
  Search,
  Play,
  Loader2,
} from 'lucide-react';
import { findingsApi } from '../api/findings';
import { accountsApi } from '../api/accounts';
import { scansApi } from '../api/scans';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Select } from '../components/ui/Select';
import { Input } from '../components/ui/Input';
import { SeverityBadge } from '../components/ui/Badge';
import type { Finding, FindingStatus } from '../types';

// ─── Constants ───────────────────────────────────────────────────────────────

const CONFIG_FINDING_TITLES = new Set([
  'ECR Enhanced Scanning Not Enabled',
  'ECR Scan on Push Disabled',
  'ECR Image Scan Failed',
]);

const CVE_FINDING_TITLES = new Set([
  'ECR Image OS Package CVE',
  'ECR Image High Severity CVEs',
  'ECR Image Medium/Low CVEs',
]);

// ─── Helpers ────────────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

function formatDate(d?: string) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function getRepoName(f: Finding): string {
  return String(f.evidence?.repositoryName ?? 'Unknown Repository');
}

function getImageTag(f: Finding): string {
  const repo = String(f.evidence?.repositoryName ?? '');
  const tag  = String(f.evidence?.imageTag ?? '');
  if (!repo) return '—';
  return tag ? `${repo}:${tag}` : repo;
}

function summarise(findings: Finding[]) {
  return findings.reduce(
    (acc, f) => {
      const k = f.severity.toLowerCase() as keyof typeof acc;
      acc[k] = (acc[k] ?? 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function SummaryPill({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="text-center">
      <div className={`text-xl font-bold ${color}`}>{count}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}

interface FindingRowProps {
  finding: Finding;
  onStatusChange: (id: string, status: FindingStatus) => void;
  updating: boolean;
}

function FindingRow({ finding, onStatusChange, updating }: FindingRowProps) {
  const [expanded, setExpanded] = useState(false);
  const imageTag  = getImageTag(finding);
  const cveId     = String(finding.evidence?.cveId ?? finding.evidence?.vulnId ?? '');
  const pkg       = String(finding.evidence?.packageName ?? finding.evidence?.package ?? '');
  const ver       = String(finding.evidence?.installedVersion ?? finding.evidence?.version ?? '');
  const fix       = String(finding.evidence?.fixedVersion ?? '');
  const pkgType   = String(finding.evidence?.packageType ?? '');
  const os        = String(finding.evidence?.operatingSystem ?? '');

  return (
    <>
      <tr
        className="hover:bg-gray-50 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-4 py-3 w-8">
          {expanded
            ? <ChevronDown size={14} className="text-gray-400" />
            : <ChevronRight size={14} className="text-gray-400" />}
        </td>
        <td className="px-4 py-3">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-4 py-3 text-sm text-gray-900 font-medium max-w-xs truncate">
          {finding.title}
        </td>
        <td className="px-4 py-3 text-xs text-gray-500 font-mono">{imageTag}</td>
        <td className="px-4 py-3 text-xs font-mono text-indigo-700 font-semibold">
          {cveId || '—'}
        </td>
        <td className="px-4 py-3 text-xs text-gray-700">
          {pkg
            ? <><span className="font-mono">{pkg}{ver ? `@${ver}` : ''}</span>
                {pkgType && <span className="ml-1 text-gray-400">({pkgType})</span>}</>
            : '—'}
        </td>
        <td className="px-4 py-3 text-xs font-mono text-green-700 font-semibold">
          {fix || '—'}
        </td>
        <td className="px-4 py-3 text-xs text-gray-400">{formatDate(finding.discoveredAt)}</td>
        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
          <Select
            value={finding.findingStatus}
            onChange={(e) => onStatusChange(finding.id, e.target.value as FindingStatus)}
            disabled={updating}
            className="text-xs py-1"
            options={[
              { value: 'OPEN',           label: 'Open' },
              { value: 'ACKNOWLEDGED',   label: 'Acknowledged' },
              { value: 'RESOLVED',       label: 'Resolved' },
              { value: 'FALSE_POSITIVE', label: 'False Positive' },
            ]}
          />
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={9} className="px-6 py-4 bg-gray-50 border-b border-gray-200">
            <div className="grid grid-cols-2 gap-6 text-sm">
              <div>
                <h4 className="font-semibold text-gray-900 mb-1">Description</h4>
                <p className="text-gray-600 leading-relaxed">{finding.description}</p>
              </div>
              <div>
                <h4 className="font-semibold text-gray-900 mb-1">Remediation</h4>
                <p className="text-gray-600 leading-relaxed">{finding.remediation}</p>
              </div>
              {os && (
                <div>
                  <h4 className="font-semibold text-gray-900 mb-1">Base OS</h4>
                  <p className="text-gray-600 font-mono text-xs">{os}</p>
                </div>
              )}
              {Object.keys(finding.evidence ?? {}).length > 0 && (
                <div className="col-span-2">
                  <h4 className="font-semibold text-gray-900 mb-1">Evidence</h4>
                  <pre className="text-xs bg-gray-100 rounded p-3 overflow-auto max-h-48 text-gray-700">
                    {JSON.stringify(finding.evidence, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── Repository accordion ────────────────────────────────────────────────────

interface RepoSectionProps {
  repoName: string;
  findings: Finding[];
  onStatusChange: (id: string, status: FindingStatus) => void;
  updatingId: string | null;
}

function RepoSection({ repoName, findings, onStatusChange, updatingId }: RepoSectionProps) {
  const [open, setOpen] = useState(true);
  const counts = summarise(findings);

  return (
    <div className="border border-gray-200 rounded-lg overflow-hidden mb-3">
      <button
        className="w-full flex items-center justify-between px-4 py-3 bg-white hover:bg-gray-50 transition-colors"
        onClick={() => setOpen((v) => !v)}
      >
        <div className="flex items-center gap-3">
          {open
            ? <ChevronDown size={16} className="text-gray-400" />
            : <ChevronRight size={16} className="text-gray-400" />}
          <Box size={16} className="text-indigo-500" />
          <span className="font-semibold text-gray-900 text-sm">{repoName}</span>
          <span className="text-xs text-gray-400">
            {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="flex items-center gap-4">
          {counts.critical > 0 && (
            <span className="flex items-center gap-1 text-xs font-bold text-red-600">
              <XCircle size={13} /> {counts.critical} Critical
            </span>
          )}
          {counts.high > 0 && (
            <span className="flex items-center gap-1 text-xs font-bold text-orange-500">
              <AlertTriangle size={13} /> {counts.high} High
            </span>
          )}
          {counts.medium > 0 && (
            <span className="flex items-center gap-1 text-xs font-bold text-yellow-500">
              {counts.medium} Medium
            </span>
          )}
          {counts.low > 0 && (
            <span className="flex items-center gap-1 text-xs font-bold text-blue-500">
              {counts.low} Low
            </span>
          )}
          {counts.critical === 0 && counts.high === 0 && (
            <span className="flex items-center gap-1 text-xs text-green-600">
              <CheckCircle2 size={13} /> No Critical/High
            </span>
          )}
        </div>
      </button>

      {open && (
        <div className="overflow-x-auto border-t border-gray-100">
          <table className="min-w-full divide-y divide-gray-100">
            <thead className="bg-gray-50">
              <tr>
                <th className="w-8" />
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Severity</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Finding</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Image</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">CVE ID</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Package</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Fixed In</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Discovered</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-100">
              {findings
                .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))
                .map((f) => (
                  <FindingRow
                    key={f.id}
                    finding={f}
                    onStatusChange={onStatusChange}
                    updating={updatingId === f.id}
                  />
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Scan Container Modal ────────────────────────────────────────────────────

interface ScanModalProps {
  accounts: any[];
  onClose: () => void;
  onScan: (accountId: string) => void;
  scanning: boolean;
}

function ScanModal({ accounts, onClose, onScan, scanning }: ScanModalProps) {
  const [selectedAccount, setSelectedAccount] = useState(accounts[0]?.id ?? '');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-md p-6">
        <h3 className="text-base font-bold text-gray-900 mb-1">Scan Container Images</h3>
        <p className="text-sm text-gray-500 mb-4">
          Scans ECR image layers for OS package CVEs and language dependency vulnerabilities.
          Images unchanged since the last scan are automatically skipped.
        </p>
        <label className="block text-xs font-semibold text-gray-700 mb-1">Account</label>
        <select
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 mb-5"
          value={selectedAccount}
          onChange={(e) => setSelectedAccount(e.target.value)}
        >
          {accounts.map((a: any) => (
            <option key={a.id} value={a.id}>
              {a.name} ({a.awsAccountId})
            </option>
          ))}
        </select>
        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-gray-600 hover:text-gray-900 border border-gray-300 rounded-lg"
            disabled={scanning}
          >
            Cancel
          </button>
          <button
            onClick={() => onScan(selectedAccount)}
            disabled={!selectedAccount || scanning}
            className="flex items-center gap-2 px-4 py-2 text-sm text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg disabled:opacity-50"
          >
            {scanning ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            {scanning ? 'Starting…' : 'Start Container Scan'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main page ───────────────────────────────────────────────────────────────

export function ContainerSecurity() {
  const queryClient = useQueryClient();
  const [accountId, setAccountId]       = useState('');
  const [severity, setSeverity]         = useState('');
  const [statusFilter, setStatusFilter] = useState('OPEN');
  const [search, setSearch]             = useState('');
  const [updatingId, setUpdatingId]     = useState<string | null>(null);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanMessage, setScanMessage]   = useState<string | null>(null);

  const { data: accountsData = [] } = useQuery({
    queryKey: ['accounts-list'],
    queryFn: () => accountsApi.list(),
  });

  const accounts: any[] = Array.isArray(accountsData)
    ? accountsData
    : (accountsData as any)?.data ?? [];

  const accountOptions = [
    { value: '', label: 'All Accounts' },
    ...accounts.map((a: any) => ({
      value: a.id,
      label: `${a.name} (${a.awsAccountId})`,
    })),
  ];

  // Fetch only CVE-type ECR findings (exclude config findings from this view)
  const { data, isLoading } = useQuery({
    queryKey: ['ecr-findings', accountId, severity, statusFilter],
    queryFn: () =>
      findingsApi.list({
        service: 'ECR',
        accountId: accountId || undefined,
        severity: (severity as any) || undefined,
        findingStatus: (statusFilter as any) || undefined,
        pageSize: 500,
      }),
  });

  const allFindings: Finding[] = (data as any)?.data ?? [];

  const cveFindings    = allFindings.filter((f) => CVE_FINDING_TITLES.has(f.title));
  const configFindings = allFindings.filter((f) => CONFIG_FINDING_TITLES.has(f.title));

  const filtered = search.trim()
    ? cveFindings.filter(
        (f) =>
          f.title.toLowerCase().includes(search.toLowerCase()) ||
          String(f.evidence?.repositoryName ?? '').toLowerCase().includes(search.toLowerCase()) ||
          String(f.evidence?.cveId ?? f.evidence?.vulnId ?? '').toLowerCase().includes(search.toLowerCase()) ||
          String(f.evidence?.packageName ?? f.evidence?.package ?? '').toLowerCase().includes(search.toLowerCase()),
      )
    : cveFindings;

  const byRepo = new Map<string, Finding[]>();
  for (const f of filtered) {
    const key = getRepoName(f);
    if (!byRepo.has(key)) byRepo.set(key, []);
    byRepo.get(key)!.push(f);
  }

  // Sort repos: CRITICAL first
  const sortedRepos = Array.from(byRepo.entries()).sort(([, a], [, b]) => {
    const aCrit = a.filter((f) => f.severity === 'CRITICAL').length;
    const bCrit = b.filter((f) => f.severity === 'CRITICAL').length;
    if (aCrit !== bCrit) return bCrit - aCrit;
    return b.length - a.length;
  });

  const totals = summarise(filtered);

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      findingsApi.updateStatus(id, status),
    onMutate: ({ id }) => setUpdatingId(id),
    onSettled: () => {
      setUpdatingId(null);
      queryClient.invalidateQueries({ queryKey: ['ecr-findings'] });
    },
  });

  // Trigger ECR-only scan
  const triggerScan = useMutation({
    mutationFn: (acctId: string) =>
      scansApi.trigger({ accountId: acctId, services: ['ecr'] }),
    onSuccess: () => {
      setShowScanModal(false);
      setScanMessage('Container scan queued — results will appear here when complete.');
      queryClient.invalidateQueries({ queryKey: ['ecr-findings'] });
      setTimeout(() => setScanMessage(null), 8000);
    },
    onError: () => {
      setShowScanModal(false);
      setScanMessage('Failed to start scan. Check account credentials and try again.');
      setTimeout(() => setScanMessage(null), 6000);
    },
  });

  return (
    <div className="space-y-6">
      {showScanModal && (
        <ScanModal
          accounts={accounts}
          onClose={() => setShowScanModal(false)}
          onScan={(acctId) => triggerScan.mutate(acctId)}
          scanning={triggerScan.isPending}
        />
      )}

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900 flex items-center gap-2">
            <Box size={20} className="text-indigo-600" />
            Container Security (ECR)
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            OS package CVEs &amp; language dependency vulnerabilities — scanned directly from image layers
          </p>
        </div>
        <div className="flex items-center gap-5">
          {!isLoading && (
            <>
              <SummaryPill label="Critical" count={totals.critical} color={totals.critical > 0 ? 'text-red-600' : 'text-gray-400'} />
              <SummaryPill label="High"     count={totals.high}     color={totals.high > 0 ? 'text-orange-500' : 'text-gray-400'} />
              <SummaryPill label="Medium"   count={totals.medium}   color={totals.medium > 0 ? 'text-yellow-500' : 'text-gray-400'} />
              <SummaryPill label="Low"      count={totals.low}      color="text-blue-500" />
              <SummaryPill label="Repos"    count={byRepo.size}     color="text-indigo-600" />
            </>
          )}
          <Button
            variant="primary"
            size="sm"
            onClick={() => setShowScanModal(true)}
            disabled={accounts.length === 0}
            className="flex items-center gap-2"
          >
            <Play size={14} />
            Scan Containers
          </Button>
        </div>
      </div>

      {scanMessage && (
        <div className="rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-3 text-sm text-indigo-800 flex items-center gap-2">
          <Info size={14} className="shrink-0" />
          {scanMessage}
        </div>
      )}

      {/* Config issues banner — informational only, not shown in main table */}
      {configFindings.length > 0 && (
        <div className="rounded-lg border border-orange-200 bg-orange-50 p-4 flex items-start gap-3">
          <AlertTriangle size={16} className="text-orange-500 mt-0.5 shrink-0" />
          <div className="text-sm">
            <span className="font-semibold text-orange-800">
              {configFindings.length} ECR configuration issue{configFindings.length !== 1 ? 's' : ''} detected:
            </span>{' '}
            <span className="text-orange-700">
              {[...new Set(configFindings.map((f) => f.title))].join(' · ')}
            </span>
            <p className="text-orange-600 text-xs mt-1">
              Enable scan-on-push for all repositories. These issues are visible in the Reports page.
            </p>
          </div>
        </div>
      )}

      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex-1 min-w-48">
            <Select
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              options={accountOptions}
            />
          </div>
          <Select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            options={[
              { value: '',         label: 'All Severities' },
              { value: 'CRITICAL', label: 'Critical' },
              { value: 'HIGH',     label: 'High' },
              { value: 'MEDIUM',   label: 'Medium' },
              { value: 'LOW',      label: 'Low' },
            ]}
          />
          <Select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            options={[
              { value: '',              label: 'All Statuses' },
              { value: 'OPEN',          label: 'Open' },
              { value: 'ACKNOWLEDGED',  label: 'Acknowledged' },
              { value: 'RESOLVED',      label: 'Resolved' },
              { value: 'FALSE_POSITIVE',label: 'False Positive' },
            ]}
          />
          <div className="flex-1 min-w-48">
            <Input
              placeholder="Search CVE, package, repository…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              leftIcon={<Search size={14} />}
            />
          </div>
        </div>
      </Card>

      {isLoading ? (
        <Card>
          <div className="space-y-3 p-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-12 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        </Card>
      ) : filtered.length === 0 ? (
        <Card>
          <div className="py-16 text-center">
            <Box className="mx-auto h-12 w-12 text-gray-300 mb-4" />
            <p className="text-gray-500 text-sm font-medium">No CVE findings found</p>
            <p className="text-gray-400 text-xs mt-1">
              {allFindings.length === 0
                ? 'Click "Scan Containers" to detect OS package and dependency vulnerabilities in your ECR images.'
                : 'Try adjusting your filters.'}
            </p>
          </div>
        </Card>
      ) : (
        <div>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <Card>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-red-50">
                  <XCircle size={18} className="text-red-500" />
                </div>
                <div>
                  <div className="text-lg font-bold text-gray-900">{filtered.length}</div>
                  <div className="text-xs text-gray-500">CVE Findings</div>
                </div>
                <div className="ml-auto flex gap-3 text-xs">
                  <span className="font-bold text-red-600">{totals.critical} Critical</span>
                  <span className="font-bold text-orange-500">{totals.high} High</span>
                  <span className="font-bold text-yellow-500">{totals.medium} Medium</span>
                </div>
              </div>
            </Card>
            <Card>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-indigo-50">
                  <Shield size={18} className="text-indigo-500" />
                </div>
                <div>
                  <div className="text-lg font-bold text-gray-900">{sortedRepos.length}</div>
                  <div className="text-xs text-gray-500">Affected Repositories</div>
                </div>
                {configFindings.length > 0 && (
                  <div className="ml-auto flex items-center gap-1 text-xs text-orange-600 font-medium">
                    <Info size={13} />
                    {configFindings.length} config issue{configFindings.length !== 1 ? 's' : ''}
                  </div>
                )}
              </div>
            </Card>
          </div>

          {sortedRepos.map(([repoName, repoFindings]) => (
            <RepoSection
              key={repoName}
              repoName={repoName}
              findings={repoFindings}
              onStatusChange={(id, status) => updateStatus.mutate({ id, status })}
              updatingId={updatingId}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default ContainerSecurity;

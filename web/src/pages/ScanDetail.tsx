import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  Download,
  ChevronDown,
  ChevronRight,
  Search,
  Play,
} from 'lucide-react';
import { scansApi } from '../api/scans';
import { findingsApi } from '../api/findings';
import { Button } from '../components/ui/Button';
import { Card, StatCard } from '../components/ui/Card';
import { Select } from '../components/ui/Select';
import { Input } from '../components/ui/Input';
import { ScanStatusBadge, SeverityBadge, FindingStatusBadge } from '../components/ui/Badge';
import { ScanProgress } from '../components/ScanProgress';
import { Pagination } from '../components/ui/Table';
import type { Finding, Severity, FindingStatus } from '../types';
import { getResourceName } from '../utils/resourceName';
import { CloudProviderLogo } from '../components/ui/CloudProviderLogo';

const SEVERITY_OPTIONS = [
  { value: '', label: 'All Severities' },
  { value: 'CRITICAL', label: 'Critical' },
  { value: 'HIGH', label: 'High' },
  { value: 'MEDIUM', label: 'Medium' },
  { value: 'LOW', label: 'Low' },
  { value: 'INFO', label: 'Info' },
];

const STATUS_OPTIONS = [
  { value: '', label: 'All Statuses' },
  { value: 'OPEN', label: 'Open' },
  { value: 'ACKNOWLEDGED', label: 'Acknowledged' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'FALSE_POSITIVE', label: 'False Positive' },
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

interface ExpandedFindingProps {
  finding: Finding;
}

function ExpandedFinding({ finding }: ExpandedFindingProps) {
  return (
    <tr>
      <td colSpan={6} className="px-4 py-4 bg-gray-50 border-b border-gray-200">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <h4 className="font-semibold text-gray-900 mb-1">Description</h4>
            <p className="text-gray-600 leading-relaxed">{finding.description}</p>

            <h4 className="font-semibold text-gray-900 mt-3 mb-1">Remediation</h4>
            <p className="text-gray-600 leading-relaxed">{finding.remediation}</p>

            {finding.tags?.length > 0 && (
              <div className="mt-3">
                <h4 className="font-semibold text-gray-900 mb-1">Tags</h4>
                <div className="flex flex-wrap gap-1">
                  {finding.tags.map((t) => (
                    <span
                      key={t}
                      className="bg-gray-200 text-gray-600 text-xs px-2 py-0.5 rounded"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
          <div>
            <h4 className="font-semibold text-gray-900 mb-1">Evidence</h4>
            <pre className="bg-gray-900 text-green-400 text-xs p-3 rounded overflow-auto max-h-48 font-mono">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>
        </div>
      </td>
    </tr>
  );
}

export function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [service, setService] = useState('');
  const [findingStatus, setFindingStatus] = useState('');
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scans', id],
    queryFn: () => scansApi.get(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'RUNNING' || status === 'QUEUED' ? 5000 : false;
    },
  });

  const { data: findingsPage, isLoading: findingsLoading } = useQuery({
    queryKey: ['scan-findings', id, { page, severity, service, findingStatus, search }],
    queryFn: () =>
      scansApi.getFindings(id!, {
        page,
        pageSize: 20,
        severity: severity as Severity || undefined,
        service: service || undefined,
        findingStatus: findingStatus as FindingStatus || undefined,
        search: search || undefined,
      }),
    enabled: !!id,
  });

  const updateStatus = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: FindingStatus }) =>
      findingsApi.updateStatus(findingId, status),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['scan-findings', id] });
    },
  });

  const triggerScan = useMutation({
    mutationFn: () => scansApi.trigger({ accountId: scan!.accountId }),
    onSuccess: (newScan) => {
      navigate(`/scans/${newScan.id}`);
    },
  });

  const handleSearch = () => {
    setSearch(searchInput);
    setPage(1);
  };

  const handleExport = (format: 'json' | 'csv') => {
    if (!id) return;
    const url = scansApi.exportFindings(id, format);
    window.open(url, '_blank');
  };

  // Collect unique services from findings
  const services = [...new Set(findingsPage?.data.map((f) => f.service) ?? [])];
  const serviceOptions = [
    { value: '', label: 'All Services' },
    ...services.map((s) => ({ value: s, label: s })),
  ];

  if (scanLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-blue-600 border-t-transparent" />
      </div>
    );
  }

  if (!scan) {
    return <div className="text-center py-16 text-gray-500">Scan not found.</div>;
  }

  const summary = scan.summary ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
  };
  const shortId = scan.id.slice(0, 8).toUpperCase();

  const isActive = scan.status === 'RUNNING' || scan.status === 'QUEUED';

  return (
    <div className="space-y-6">
      {/* Redesigned Header Row matching Account & Compliance details consistency */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-1 border-b border-gray-200/80">
        {/* Left Section: Back Arrow + Divider + Provider Logo + Title & Metadata */}
        <div className="flex items-center gap-3.5 min-w-0">
          {/* 1. Back Arrow Button */}
          <Button
            variant="ghost"
            size="sm"
            className="p-2.5 rounded-xl text-gray-500 hover:text-gray-900 hover:bg-slate-100 shrink-0 border border-transparent hover:border-slate-200 transition-all"
            onClick={() => navigate(-1)}
            aria-label="Go back"
            title="Go back"
          >
            <ArrowLeft size={18} />
          </Button>

          {/* Divider Line */}
          <div className="h-8 w-px bg-gray-200/80 shrink-0" />

          {/* 2. Provider Logo / Scan Badge Tile */}
          <div className="flex items-center justify-center p-2 rounded-xl bg-slate-50 border border-slate-200/80 shrink-0 shadow-2xs">
            <CloudProviderLogo provider={(scan.account as any)?.provider ?? 'AWS'} className="w-6 h-6 shrink-0 object-contain" />
          </div>

          {/* 3 & 4. Title & Details Subtitle */}
          <div className="space-y-0.5">
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl sm:text-2xl font-extrabold text-gray-900 tracking-tight" style={{ fontFamily: 'var(--font-heading)' }}>
                Scan #{shortId}
              </h1>
              <ScanStatusBadge status={scan.status} />
            </div>

            {/* Scan Subtitle Details Row */}
            <div className="flex items-center gap-2 text-xs text-gray-500 flex-wrap">
              {scan.account && (
                <>
                  <span className="font-semibold text-gray-400">Account ID:</span>
                  <span className="font-mono font-medium text-gray-700 bg-gray-100/90 border border-gray-200 px-2 py-0.5 rounded-md text-[11px] shadow-2xs">
                    {scan.account.awsAccountId}
                  </span>
                  <span className="text-gray-300">•</span>
                  <span className="font-semibold text-gray-700">{scan.account.name}</span>
                  <span className="text-gray-300">•</span>
                </>
              )}
              <span className="text-gray-600">{formatDate(scan.startedAt ?? scan.createdAt)}</span>
              {scan.durationMs && (
                <>
                  <span className="text-gray-300">•</span>
                  <span className="font-mono text-gray-600 font-medium">{formatDuration(scan.durationMs)}</span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Right Section: Action Buttons */}
        <div className="flex items-center gap-2.5 shrink-0">
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<Download size={14} />}
            onClick={() => handleExport('json')}
          >
            Export JSON
          </Button>
          <Button
            variant="secondary"
            size="sm"
            leftIcon={<Download size={14} />}
            onClick={() => handleExport('csv')}
          >
            Export CSV
          </Button>
          <Button
            variant="primary"
            size="sm"
            leftIcon={<Play size={14} />}
            loading={triggerScan.isPending}
            onClick={() => triggerScan.mutate()}
          >
            Re-scan
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-5 gap-4">
        <StatCard title="Total" value={summary.total} />
        <StatCard
          title="Critical"
          value={summary.critical}
          valueClassName={summary.critical > 0 ? 'text-red-600' : undefined}
        />
        <StatCard
          title="High"
          value={summary.high}
          valueClassName={summary.high > 0 ? 'text-orange-500' : undefined}
        />
        <StatCard
          title="Medium"
          value={summary.medium}
          valueClassName={summary.medium > 0 ? 'text-yellow-500' : undefined}
        />
        <StatCard
          title="Low"
          value={summary.low}
          valueClassName={summary.low > 0 ? 'text-blue-500' : undefined}
        />
      </div>

      {/* Progress (if active) */}
      {isActive && (
        <ScanProgress
          scanId={scan.id}
          initialStatus={scan.status}
          onComplete={() => {
            void qc.invalidateQueries({ queryKey: ['scans', id] });
          }}
        />
      )}

      {/* Findings */}
      <Card padding={false}>
        {/* Filters */}
        <div className="px-4 py-3 border-b border-gray-200 flex flex-wrap items-end gap-3">
          <Select
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
            options={SEVERITY_OPTIONS}
            className="w-36"
          />
          <Select
            value={service}
            onChange={(e) => { setService(e.target.value); setPage(1); }}
            options={serviceOptions}
            className="w-40"
          />
          <Select
            value={findingStatus}
            onChange={(e) => { setFindingStatus(e.target.value); setPage(1); }}
            options={STATUS_OPTIONS}
            className="w-40"
          />
          <div className="flex gap-2 flex-1">
            <Input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Search findings..."
              className="flex-1"
            />
            <Button variant="secondary" size="sm" onClick={handleSearch}>
              <Search size={14} />
            </Button>
          </div>
          <span className="text-xs text-gray-500 ml-auto">
            {findingsPage?.total ?? 0} findings
          </span>
        </div>

        {/* Table */}
        {findingsLoading ? (
          <div className="p-6 space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-8 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="w-8 px-4 py-3" />
                  {['Severity', 'Service', 'Resource Name', 'Title', 'Status', 'Discovered', 'Actions'].map(
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
                {(findingsPage?.data ?? []).length === 0 ? (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-4 py-12 text-center text-gray-500 text-sm"
                    >
                      No findings match the current filters.
                    </td>
                  </tr>
                ) : (
                  (findingsPage?.data ?? []).map((finding: Finding) => (
                    <React.Fragment key={finding.id}>
                      <tr
                        className="hover:bg-gray-50 cursor-pointer"
                        onClick={() =>
                          setExpandedId(
                            expandedId === finding.id ? null : finding.id,
                          )
                        }
                      >
                        <td className="px-4 py-3 text-gray-400">
                          {expandedId === finding.id ? (
                            <ChevronDown size={14} />
                          ) : (
                            <ChevronRight size={14} />
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">
                          {finding.service}
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm font-mono text-gray-800 bg-gray-100 px-2 py-0.5 rounded">
                            {getResourceName(finding.service, finding.evidence)}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-900 max-w-xs truncate">
                          {finding.title}
                        </td>
                        <td className="px-4 py-3">
                          <FindingStatusBadge status={finding.findingStatus} />
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500">
                          {formatDate(finding.discoveredAt)}
                        </td>
                        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                          <select
                            className="text-xs border border-gray-300 rounded px-2 py-1 text-gray-600"
                            value={finding.findingStatus}
                            onChange={(e) =>
                              updateStatus.mutate({
                                findingId: finding.id,
                                status: e.target.value as FindingStatus,
                              })
                            }
                          >
                            <option value="OPEN">Open</option>
                            <option value="ACKNOWLEDGED">Acknowledged</option>
                            <option value="RESOLVED">Resolved</option>
                            <option value="FALSE_POSITIVE">False Positive</option>
                          </select>
                        </td>
                      </tr>
                      {expandedId === finding.id && (
                        <ExpandedFinding finding={finding} />
                      )}
                    </React.Fragment>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {findingsPage && findingsPage.totalPages > 1 && (
          <Pagination
            page={page}
            totalPages={findingsPage.totalPages}
            total={findingsPage.total}
            pageSize={20}
            onPageChange={setPage}
          />
        )}
      </Card>
    </div>
  );
}

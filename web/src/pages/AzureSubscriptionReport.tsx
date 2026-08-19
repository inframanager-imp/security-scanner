import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Search,
  CheckSquare,
  Trash2,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';
import { azureApi } from '../api/azure';
import { AzureReadinessSection } from '../components/ui/ReadinessSection';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Select } from '../components/ui/Select';
import { MultiSelect } from '../components/ui/MultiSelect';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { SeverityBadge, FindingStatusBadge } from '../components/ui/Badge';
import { Pagination } from '../components/ui/Table';
import { ComplianceTagBadges } from '../components/ui/ComplianceTagBadges';
import type { AzureFinding, FindingStatus } from '../types';

// ─── Constants ────────────────────────────────────────────────────────────────

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

const BULK_STATUS_OPTIONS = [
  { value: 'OPEN', label: 'Open' },
  { value: 'ACKNOWLEDGED', label: 'Acknowledged' },
  { value: 'RESOLVED', label: 'Resolved' },
  { value: 'FALSE_POSITIVE', label: 'False Positive' },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(dateStr?: string | null): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

// ─── Types ────────────────────────────────────────────────────────────────────

type SortField = 'severity' | 'service' | 'status' | 'discoveredAt' | 'title';

interface SortState {
  field: SortField;
  order: 'asc' | 'desc';
}

// ─── Expanded detail row ──────────────────────────────────────────────────────

function ExpandedDetail({ finding }: { finding: AzureFinding }) {
  return (
    <tr>
      <td colSpan={10} className="px-6 py-4 bg-gray-50 border-b border-gray-200">
        <div className="grid grid-cols-2 gap-6 text-sm">
          <div>
            <h4 className="font-semibold text-gray-900 mb-2">Description</h4>
            <p className="text-gray-600 leading-relaxed">{finding.description}</p>

            <h4 className="font-semibold text-gray-900 mt-4 mb-2">Remediation</h4>
            <p className="text-gray-600 leading-relaxed">{finding.remediation}</p>

            {(finding.resourceGroup || finding.resourceId) && (
              <div className="mt-4 space-y-1">
                {finding.resourceGroup && (
                  <p className="text-xs text-gray-500">
                    <span className="font-semibold">Resource Group:</span>{' '}
                    <span className="font-mono">{finding.resourceGroup}</span>
                  </p>
                )}
                {finding.resourceId && (
                  <p className="text-xs text-gray-500">
                    <span className="font-semibold">Resource ID:</span>{' '}
                    <span className="font-mono break-all">{finding.resourceId}</span>
                  </p>
                )}
              </div>
            )}

            {finding.tags?.length > 0 && (
              <div className="mt-4">
                <h4 className="font-semibold text-gray-900 mb-2">Tags</h4>
                <div className="flex flex-wrap gap-1">
                  {finding.tags.map((t) => (
                    <span key={t} className="bg-gray-200 text-gray-600 text-xs px-2 py-0.5 rounded">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
          <div>
            <h4 className="font-semibold text-gray-900 mb-2">Evidence</h4>
            <pre className="bg-gray-900 text-green-400 text-xs p-3 rounded overflow-auto max-h-56 font-mono">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          </div>
        </div>
      </td>
    </tr>
  );
}

// ─── Sortable column header ───────────────────────────────────────────────────

function SortTh({
  label,
  field,
  sort,
  onSort,
  className,
}: {
  label: string;
  field: SortField;
  sort: SortState;
  onSort: (f: SortField) => void;
  className?: string;
}) {
  const active = sort.field === field;
  return (
    <th
      className={`px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider cursor-pointer select-none hover:text-gray-700 ${className ?? ''}`}
      onClick={() => onSort(field)}
    >
      <span className="flex items-center gap-1">
        {label}
        <span className="flex flex-col">
          <ChevronUp
            size={10}
            className={active && sort.order === 'asc' ? 'text-blue-600' : 'text-gray-300'}
          />
          <ChevronDown
            size={10}
            className={active && sort.order === 'desc' ? 'text-blue-600' : 'text-gray-300'}
          />
        </span>
      </span>
    </th>
  );
}

// ─── Page component ───────────────────────────────────────────────────────────

export function AzureSubscriptionReport() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [selectedServices, setSelectedServices] = useState<string[]>([]);
  const [findingStatus, setFindingStatus] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<SortState>({ field: 'severity', order: 'asc' });
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkModalOpen, setBulkModalOpen] = useState(false);
  const [bulkStatus, setBulkStatus] = useState<FindingStatus>('ACKNOWLEDGED');
  const [cleanupResult, setCleanupResult] = useState<{ deleted: number; message: string } | null>(null);

  const { data: sub, isLoading: subLoading } = useQuery({
    queryKey: ['azure-subscription', id],
    queryFn:  () => azureApi.getSubscription(id!),
    enabled:  !!id,
  });

  const { data: allServices = [] } = useQuery({
    queryKey: ['azure-subscription-services', id],
    queryFn:  () => azureApi.getSubscriptionServices(id!),
    enabled:  !!id,
  });

  const serviceOptions = allServices.map((s: string) => ({ value: s, label: s.toUpperCase() }));

  const { data: findingsPage, isLoading: findingsLoading } = useQuery({
    queryKey: ['azure-subscription-findings', id, { page, severity, selectedServices, findingStatus, search, sort }],
    queryFn:  () =>
      azureApi.getSubscriptionFindings(id!, {
        page,
        pageSize: 20,
        severity: severity || undefined,
        services: selectedServices.length > 0 ? selectedServices : undefined,
        status:   findingStatus || undefined,
        search:   search || undefined,
      }),
    enabled: !!id,
  });

  const updateStatus = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: string }) =>
      azureApi.updateFindingStatus(findingId, status),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['azure-subscription-findings', id] });
    },
  });

  const bulkUpdate = useMutation({
    mutationFn: () =>
      Promise.all(
        [...selected].map((findingId) =>
          azureApi.updateFindingStatus(findingId, bulkStatus),
        ),
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['azure-subscription-findings', id] });
      setSelected(new Set());
      setBulkModalOpen(false);
    },
  });

  const cleanupMutation = useMutation({
    mutationFn: () => azureApi.cleanupScannerErrors(),
    onSuccess: (res) => {
      setCleanupResult(res);
      void qc.invalidateQueries({ queryKey: ['azure-subscription-findings', id] });
      void qc.invalidateQueries({ queryKey: ['azure-subscription', id] });
    },
  });

  const handleSort = (field: SortField) => {
    setSort((prev) =>
      prev.field === field
        ? { field, order: prev.order === 'asc' ? 'desc' : 'asc' }
        : { field, order: 'asc' },
    );
    setPage(1);
  };

  const handleSearch = () => {
    setSearch(searchInput);
    setPage(1);
  };

  const handleFilterChange = <T,>(setter: (v: T) => void, v: T) => {
    setter(v);
    setPage(1);
  };

  const toggleSelect = (findingId: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  const toggleSelectAll = () => {
    const ids = findingsPage?.data.map((f) => f.id) ?? [];
    if (ids.every((fid) => selected.has(fid))) {
      setSelected((prev) => {
        const next = new Set(prev);
        ids.forEach((fid) => next.delete(fid));
        return next;
      });
    } else {
      setSelected((prev) => new Set([...prev, ...ids]));
    }
  };

  const isLoading = subLoading || findingsLoading;
  const findings = findingsPage?.data ?? [];
  const allPageSelected = findings.length > 0 && findings.every((f) => selected.has(f.id));
  const summary = sub?.latestScan?.summary;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            leftIcon={<ArrowLeft size={16} />}
            onClick={() => navigate('/reports')}
          >
            Reports
          </Button>
          <div>
            <h2 className="text-xl font-bold text-gray-900">
              {sub?.name ?? 'Azure Subscription Report'}
            </h2>
            {sub && (
              <span className="text-xs font-mono bg-gray-100 text-gray-600 px-2 py-0.5 rounded mt-1 inline-block">
                {sub.subscriptionId}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {summary && (
            <div className="flex items-center gap-2">
              {summary.critical > 0 && (
                <span className="bg-red-50 text-red-700 border border-red-200 rounded px-2 py-1 text-xs font-bold">
                  {summary.critical} Critical
                </span>
              )}
              {summary.high > 0 && (
                <span className="bg-orange-50 text-orange-700 border border-orange-200 rounded px-2 py-1 text-xs font-bold">
                  {summary.high} High
                </span>
              )}
              {summary.medium > 0 && (
                <span className="bg-yellow-50 text-yellow-700 border border-yellow-200 rounded px-2 py-1 text-xs font-bold">
                  {summary.medium} Medium
                </span>
              )}
              {summary.low > 0 && (
                <span className="bg-blue-50 text-blue-700 border border-blue-200 rounded px-2 py-1 text-xs font-bold">
                  {summary.low} Low
                </span>
              )}
            </div>
          )}

          {selected.size > 0 && (
            <Button
              variant="secondary"
              size="sm"
              leftIcon={<CheckSquare size={14} />}
              onClick={() => setBulkModalOpen(true)}
            >
              Update {selected.size} selected
            </Button>
          )}

          {sub?.lastSuccessfulScanId ?? sub?.latestScan?.id ? (
            <a
              href={azureApi.exportFindings(sub?.lastSuccessfulScanId ?? sub?.latestScan?.id ?? '')}
              download
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border border-gray-300 bg-white text-gray-700 hover:bg-gray-50"
            >
              Export CSV
            </a>
          ) : null}

          <div className="flex flex-col items-end gap-1">
            <Button
              variant="ghost"
              size="sm"
              leftIcon={<Trash2 size={14} />}
              onClick={() => { setCleanupResult(null); cleanupMutation.mutate(); }}
              disabled={cleanupMutation.isPending}
            >
              {cleanupMutation.isPending ? 'Cleaning...' : 'Clean Scanner Errors'}
            </Button>
            {cleanupResult && (
              <div className={`flex items-center gap-1.5 text-xs px-3 py-1 rounded-full ${cleanupResult.deleted > 0 ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-600'}`}>
                {cleanupResult.deleted > 0 ? <CheckCircle2 size={12} /> : <AlertCircle size={12} />}
                {cleanupResult.message}
              </div>
            )}
          </div>
        </div>
      </div>

      {id && <AzureReadinessSection subscriptionId={id} />}

      <Card padding={false}>
        <div className="px-4 py-3 border-b border-gray-200 flex flex-wrap items-end gap-3">
          <Select
            value={severity}
            onChange={(e) => handleFilterChange(setSeverity, e.target.value)}
            options={SEVERITY_OPTIONS}
            className="w-36"
          />

          <MultiSelect
            options={serviceOptions}
            value={selectedServices}
            onChange={(v) => handleFilterChange(setSelectedServices, v)}
            placeholder="All Services"
            className="w-44"
          />

          <Select
            value={findingStatus}
            onChange={(e) => handleFilterChange(setFindingStatus, e.target.value)}
            options={STATUS_OPTIONS}
            className="w-40"
          />

          <div className="flex gap-2 flex-1 min-w-48">
            <Input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Search title, description, resource..."
              className="flex-1"
            />
            <Button variant="secondary" size="sm" onClick={handleSearch}>
              <Search size={14} />
            </Button>
          </div>

          <span className="text-xs text-gray-500 whitespace-nowrap">
            {findingsPage?.total ?? 0} findings
          </span>
        </div>

        {isLoading ? (
          <div className="p-6 space-y-3">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-8 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={allPageSelected}
                      onChange={toggleSelectAll}
                      className="rounded border-gray-300 text-blue-600"
                    />
                  </th>
                  <th className="w-8 px-2 py-3" />
                  <SortTh label="Severity" field="severity" sort={sort} onSort={handleSort} />
                  <SortTh label="Service" field="service" sort={sort} onSort={handleSort} />
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Resource Group
                  </th>
                  <SortTh label="Finding" field="title" sort={sort} onSort={handleSort} className="min-w-48" />
                  <SortTh label="Status" field="status" sort={sort} onSort={handleSort} />
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Compliance
                  </th>
                  <SortTh label="Discovered" field="discoveredAt" sort={sort} onSort={handleSort} />
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {findings.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="px-4 py-12 text-center text-gray-500 text-sm">
                      No findings match the current filters.
                    </td>
                  </tr>
                ) : (
                  findings.map((finding: AzureFinding) => (
                    <React.Fragment key={finding.id}>
                      <tr className={`${selected.has(finding.id) ? 'bg-blue-50' : 'hover:bg-gray-50'}`}>
                        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selected.has(finding.id)}
                            onChange={() => toggleSelect(finding.id)}
                            className="rounded border-gray-300 text-blue-600"
                          />
                        </td>
                        <td
                          className="px-2 py-3 text-gray-400 cursor-pointer"
                          onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        >
                          {expandedId === finding.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </td>
                        <td
                          className="px-4 py-3 cursor-pointer"
                          onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        >
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td
                          className="px-4 py-3 text-sm font-medium text-gray-600 uppercase cursor-pointer"
                          onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        >
                          {finding.service}
                        </td>
                        <td
                          className="px-4 py-3 cursor-pointer"
                          onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        >
                          {finding.resourceGroup ? (
                            <span className="text-sm font-mono text-gray-800 bg-gray-100 px-2 py-0.5 rounded">
                              {finding.resourceGroup}
                            </span>
                          ) : (
                            <span className="text-gray-400 text-sm">—</span>
                          )}
                        </td>
                        <td
                          className="px-4 py-3 text-sm text-gray-900 max-w-xs truncate cursor-pointer"
                          onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        >
                          {finding.title}
                        </td>
                        <td className="px-4 py-3">
                          <FindingStatusBadge status={finding.findingStatus} />
                        </td>
                        <td className="px-4 py-3">
                          <ComplianceTagBadges tags={finding.complianceTags} />
                        </td>
                        <td
                          className="px-4 py-3 text-sm text-gray-500 cursor-pointer whitespace-nowrap"
                          onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                        >
                          {formatDate(finding.discoveredAt)}
                        </td>
                        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                          <select
                            className="text-xs border border-gray-300 rounded px-2 py-1 text-gray-600"
                            value={finding.findingStatus}
                            onChange={(e) =>
                              updateStatus.mutate({ findingId: finding.id, status: e.target.value })
                            }
                          >
                            <option value="OPEN">Open</option>
                            <option value="ACKNOWLEDGED">Acknowledged</option>
                            <option value="RESOLVED">Resolved</option>
                            <option value="FALSE_POSITIVE">False Positive</option>
                          </select>
                        </td>
                      </tr>
                      {expandedId === finding.id && <ExpandedDetail finding={finding} />}
                    </React.Fragment>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}

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

      <Modal
        open={bulkModalOpen}
        onClose={() => setBulkModalOpen(false)}
        title={`Update ${selected.size} Findings`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setBulkModalOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={bulkUpdate.isPending}
              onClick={() => bulkUpdate.mutate()}
            >
              Apply
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-600">
            Change the status of {selected.size} selected findings to:
          </p>
          <Select
            label="New Status"
            value={bulkStatus}
            onChange={(e) => setBulkStatus(e.target.value as FindingStatus)}
            options={BULK_STATUS_OPTIONS}
          />
        </div>
      </Modal>
    </div>
  );
}

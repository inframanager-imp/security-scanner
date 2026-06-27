import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, Search, CheckSquare } from 'lucide-react';
import { findingsApi } from '../api/findings';
import { accountsApi } from '../api/accounts';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Select } from '../components/ui/Select';
import { Input } from '../components/ui/Input';
import { Modal } from '../components/ui/Modal';
import { SeverityBadge } from '../components/ui/Badge';
import { Pagination } from '../components/ui/Table';
import type { Finding, Severity, FindingStatus } from '../types';

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

function formatDate(dateStr?: string): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

interface ExpandedDetailProps {
  finding: Finding;
}

function ExpandedDetail({ finding }: ExpandedDetailProps) {
  return (
    <tr>
      <td colSpan={7} className="px-6 py-4 bg-gray-50 border-b border-gray-200">
        <div className="grid grid-cols-2 gap-6 text-sm">
          <div>
            <h4 className="font-semibold text-gray-900 mb-2">Description</h4>
            <p className="text-gray-600 leading-relaxed">{finding.description}</p>

            <h4 className="font-semibold text-gray-900 mt-4 mb-2">Remediation</h4>
            <p className="text-gray-600 leading-relaxed">{finding.remediation}</p>

            {finding.tags?.length > 0 && (
              <div className="mt-4">
                <h4 className="font-semibold text-gray-900 mb-2">Tags</h4>
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

export function Findings() {
  const qc = useQueryClient();

  const [page, setPage] = useState(1);
  const [accountId, setAccountId] = useState('');
  const [severity, setSeverity] = useState('');
  const [service, setService] = useState('');
  const [findingStatus, setFindingStatus] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkModalOpen, setBulkModalOpen] = useState(false);
  const [bulkStatus, setBulkStatus] = useState<FindingStatus>('ACKNOWLEDGED');

  const { data: accountsPage } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => accountsApi.list(),
  });
  const accounts = accountsPage?.data ?? [];

  const { data: findingsPage, isLoading } = useQuery({
    queryKey: [
      'findings',
      { page, accountId, severity, service, findingStatus, search },
    ],
    queryFn: () =>
      findingsApi.list({
        page,
        pageSize: 20,
        accountId: accountId || undefined,
        severity: severity as Severity || undefined,
        service: service || undefined,
        findingStatus: findingStatus as FindingStatus || undefined,
        search: search || undefined,
      }),
  });

  const updateStatus = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: FindingStatus }) =>
      findingsApi.updateStatus(findingId, status),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['findings'] });
    },
  });

  const bulkUpdate = useMutation({
    mutationFn: () =>
      findingsApi.bulkUpdateStatus([...selected], bulkStatus),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['findings'] });
      setSelected(new Set());
      setBulkModalOpen(false);
    },
  });

  const handleSearch = () => {
    setSearch(searchInput);
    setPage(1);
  };

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    const ids = findingsPage?.data.map((f) => f.id) ?? [];
    if (ids.every((id) => selected.has(id))) {
      setSelected((prev) => {
        const next = new Set(prev);
        ids.forEach((id) => next.delete(id));
        return next;
      });
    } else {
      setSelected((prev) => new Set([...prev, ...ids]));
    }
  };

  const accountOptions = [
    { value: '', label: 'All Accounts' },
    ...accounts.map((a) => ({ value: a.id, label: a.name })),
  ];

  // Collect unique services from current page
  const services = [...new Set(findingsPage?.data.map((f) => f.service) ?? [])];
  const serviceOptions = [
    { value: '', label: 'All Services' },
    ...services.map((s) => ({ value: s, label: s })),
  ];

  const findings = findingsPage?.data ?? [];
  const allPageSelected =
    findings.length > 0 && findings.every((f) => selected.has(f.id));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">All Findings</h2>
          <p className="text-sm text-gray-500 mt-1">
            {findingsPage ? (
              <>
                <span className="font-medium">{findingsPage.total}</span> findings
                across all accounts
              </>
            ) : (
              'Loading...'
            )}
          </p>
        </div>
        {selected.size > 0 && (
          <Button
            variant="secondary"
            leftIcon={<CheckSquare size={16} />}
            onClick={() => setBulkModalOpen(true)}
          >
            Update {selected.size} selected
          </Button>
        )}
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-end gap-3">
        <Select
          value={accountId}
          onChange={(e) => { setAccountId(e.target.value); setPage(1); }}
          options={accountOptions}
          className="w-44"
        />
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
      </div>

      {/* Table */}
      <Card padding={false}>
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
                  {['Severity', 'Account', 'Service', 'Title', 'Status', 'Discovered'].map(
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
                {findings.length === 0 ? (
                  <tr>
                    <td
                      colSpan={8}
                      className="px-4 py-12 text-center text-gray-500 text-sm"
                    >
                      No findings match the current filters.
                    </td>
                  </tr>
                ) : (
                  findings.map((finding: Finding) => (
                    <React.Fragment key={finding.id}>
                      <tr
                        className={`hover:bg-gray-50 ${
                          selected.has(finding.id) ? 'bg-blue-50' : ''
                        }`}
                      >
                        <td
                          className="px-4 py-3"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <input
                            type="checkbox"
                            checked={selected.has(finding.id)}
                            onChange={() => toggleSelect(finding.id)}
                            className="rounded border-gray-300 text-blue-600"
                          />
                        </td>
                        <td
                          className="px-2 py-3 text-gray-400 cursor-pointer"
                          onClick={() =>
                            setExpandedId(
                              expandedId === finding.id ? null : finding.id,
                            )
                          }
                        >
                          {expandedId === finding.id ? (
                            <ChevronDown size={14} />
                          ) : (
                            <ChevronRight size={14} />
                          )}
                        </td>
                        <td
                          className="px-4 py-3 cursor-pointer"
                          onClick={() =>
                            setExpandedId(
                              expandedId === finding.id ? null : finding.id,
                            )
                          }
                        >
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td
                          className="px-4 py-3 text-sm text-gray-600 cursor-pointer"
                          onClick={() =>
                            setExpandedId(
                              expandedId === finding.id ? null : finding.id,
                            )
                          }
                        >
                          {finding.accountName ?? '—'}
                        </td>
                        <td
                          className="px-4 py-3 text-sm text-gray-600 cursor-pointer"
                          onClick={() =>
                            setExpandedId(
                              expandedId === finding.id ? null : finding.id,
                            )
                          }
                        >
                          {finding.service}
                        </td>
                        <td
                          className="px-4 py-3 text-sm text-gray-900 max-w-xs truncate cursor-pointer"
                          onClick={() =>
                            setExpandedId(
                              expandedId === finding.id ? null : finding.id,
                            )
                          }
                        >
                          {finding.title}
                        </td>
                        <td className="px-4 py-3">
                          <select
                            className="text-xs border border-gray-300 rounded px-2 py-1 text-gray-600"
                            value={finding.findingStatus}
                            onChange={(e) =>
                              updateStatus.mutate({
                                findingId: finding.id,
                                status: e.target.value as FindingStatus,
                              })
                            }
                            onClick={(e) => e.stopPropagation()}
                          >
                            <option value="OPEN">Open</option>
                            <option value="ACKNOWLEDGED">Acknowledged</option>
                            <option value="RESOLVED">Resolved</option>
                            <option value="FALSE_POSITIVE">False Positive</option>
                          </select>
                        </td>
                        <td
                          className="px-4 py-3 text-sm text-gray-500 cursor-pointer"
                          onClick={() =>
                            setExpandedId(
                              expandedId === finding.id ? null : finding.id,
                            )
                          }
                        >
                          {formatDate(finding.discoveredAt)}
                        </td>
                      </tr>
                      {expandedId === finding.id && (
                        <ExpandedDetail finding={finding} />
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

      {/* Bulk Status Update Modal */}
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

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Play, Trash2, Eye, CheckCircle, XCircle, Cloud } from 'lucide-react';
import { azureApi } from '../api/azure';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { ScanStatusBadge } from '../components/ui/Badge';
import type { AzureSubscription } from '../types';
import { ApiRequestError } from '../api/client';

function formatDate(dateStr?: string): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
  });
}

function SeverityBar({ summary }: { summary?: { critical: number; high: number; medium: number; low: number; info: number; total: number } | null }) {
  if (!summary) return <span className="text-xs text-gray-400">No data</span>;
  const total = summary.total || 1;
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-24 rounded-full overflow-hidden bg-gray-100">
        {summary.critical > 0 && <div style={{ width: `${(summary.critical / total) * 100}%` }} className="bg-red-600" />}
        {summary.high     > 0 && <div style={{ width: `${(summary.high     / total) * 100}%` }} className="bg-orange-500" />}
        {summary.medium   > 0 && <div style={{ width: `${(summary.medium   / total) * 100}%` }} className="bg-yellow-500" />}
        {summary.low      > 0 && <div style={{ width: `${(summary.low      / total) * 100}%` }} className="bg-blue-500" />}
        {summary.info     > 0 && <div style={{ width: `${(summary.info     / total) * 100}%` }} className="bg-gray-400" />}
      </div>
      <span className="text-xs text-gray-600">{summary.total} findings</span>
    </div>
  );
}

interface AddForm {
  name:           string;
  subscriptionId: string;
  tenantId:       string;
  description:    string;
}

const EMPTY_FORM: AddForm = { name: '', subscriptionId: '', tenantId: '', description: '' };

export function AzureSubscriptions() {
  const navigate = useNavigate();
  const qc       = useQueryClient();

  const [addModalOpen,   setAddModalOpen]   = useState(false);
  const [deleteConfirm,  setDeleteConfirm]  = useState<AzureSubscription | null>(null);
  const [form,           setForm]           = useState<AddForm>(EMPTY_FORM);
  const [addError,       setAddError]       = useState<string | null>(null);
  const [scanningId,     setScanningId]     = useState<string | null>(null);

  const { data: page, isLoading } = useQuery({
    queryKey: ['azure-subscriptions'],
    queryFn:  () => azureApi.listSubscriptions({ limit: 50 }),
  });
  const subscriptions = [...(page?.data ?? [])].sort((a, b) => a.name.localeCompare(b.name));

  const createSub = useMutation({
    mutationFn: () => azureApi.createSubscription({
      name:           form.name,
      subscriptionId: form.subscriptionId,
      tenantId:       form.tenantId || undefined,
      description:    form.description || undefined,
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['azure-subscriptions'] });
      setAddModalOpen(false);
      setForm(EMPTY_FORM);
      setAddError(null);
    },
    onError: (err) => {
      setAddError(err instanceof ApiRequestError ? err.message : 'Failed to create subscription');
    },
  });

  const deleteSub = useMutation({
    mutationFn: (id: string) => azureApi.deleteSubscription(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['azure-subscriptions'] });
      setDeleteConfirm(null);
    },
  });

  const triggerScan = useMutation({
    mutationFn: (id: string) => azureApi.triggerScan(id),
    onSuccess: (_result, id) => {
      setScanningId(null);
      void qc.invalidateQueries({ queryKey: ['azure-subscriptions'] });
      navigate(`/azure/${id}`);
    },
    onError: () => setScanningId(null),
  });

  function handleTriggerScan(id: string) {
    setScanningId(id);
    triggerScan.mutate(id);
  }

  const totalFindings = subscriptions.reduce((acc, s) => acc + (s.latestScan?.summary?.total ?? 0), 0);
  const totalCritical = subscriptions.reduce((acc, s) => acc + (s.latestScan?.summary?.critical ?? 0), 0);
  const totalHigh     = subscriptions.reduce((acc, s) => acc + (s.latestScan?.summary?.high ?? 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Azure Subscriptions</h2>
          <p className="text-sm text-gray-500 mt-0.5">Manage and scan your Azure cloud subscriptions</p>
        </div>
        <Button
          variant="primary"
          leftIcon={<Plus size={16} />}
          onClick={() => { setAddModalOpen(true); setAddError(null); }}
        >
          Add Subscription
        </Button>
      </div>

      {/* Severity summary bar */}
      {subscriptions.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <Card className="!p-0">
            <div className="p-4">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Total Findings</p>
              <p className="mt-1 text-2xl font-bold text-gray-900">{totalFindings}</p>
            </div>
          </Card>
          <Card className="!p-0">
            <div className="p-4">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Critical</p>
              <p className="mt-1 text-2xl font-bold text-red-600">{totalCritical}</p>
            </div>
          </Card>
          <Card className="!p-0">
            <div className="p-4">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">High</p>
              <p className="mt-1 text-2xl font-bold text-orange-500">{totalHigh}</p>
            </div>
          </Card>
        </div>
      )}

      {/* Table */}
      <Card padding={false}>
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
          </div>
        ) : subscriptions.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
            <Cloud size={40} className="text-gray-300" />
            <p className="text-gray-500 font-medium">No Azure subscriptions yet</p>
            <p className="text-sm text-gray-400">Add a subscription to start scanning Azure resources</p>
            <Button
              variant="primary"
              size="sm"
              leftIcon={<Plus size={14} />}
              onClick={() => setAddModalOpen(true)}
            >
              Add Subscription
            </Button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50">
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Name</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Subscription ID</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Credentials</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Last Scan</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">Findings</th>
                <th className="px-6 py-3 text-right text-xs font-semibold text-gray-500 uppercase tracking-wide">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {subscriptions.map((sub) => (
                <tr key={sub.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4 font-medium text-gray-900">{sub.name}</td>
                  <td className="px-6 py-4 font-mono text-xs text-gray-500">{sub.subscriptionId}</td>
                  <td className="px-6 py-4">
                    {sub.hasCredentials ? (
                      <span className="inline-flex items-center gap-1 text-xs text-green-700">
                        <CheckCircle size={12} /> Configured
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                        <XCircle size={12} /> None
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    {sub.latestScan ? (
                      <div className="flex items-center gap-2">
                        <ScanStatusBadge status={sub.latestScan.status} />
                        <span className="text-xs text-gray-400">{formatDate(sub.latestScan.createdAt)}</span>
                      </div>
                    ) : (
                      <span className="text-gray-400">—</span>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <SeverityBar summary={sub.latestScan?.summary} />
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        leftIcon={<Eye size={14} />}
                        onClick={() => navigate(`/azure/${sub.id}`)}
                      >
                        View
                      </Button>
                      <Button
                        variant="secondary"
                        size="sm"
                        leftIcon={<Play size={14} />}
                        loading={scanningId === sub.id}
                        disabled={!sub.hasCredentials}
                        onClick={() => handleTriggerScan(sub.id)}
                      >
                        Scan
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        leftIcon={<Trash2 size={14} />}
                        onClick={() => setDeleteConfirm(sub)}
                        className="text-red-500 hover:text-red-700 hover:bg-red-50"
                      >
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* Add Modal */}
      <Modal
        open={addModalOpen}
        onClose={() => { setAddModalOpen(false); setForm(EMPTY_FORM); setAddError(null); }}
        title="Add Azure Subscription"
      >
        <div className="space-y-4">
          {addError && (
            <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">
              {addError}
            </div>
          )}
          <Input
            label="Subscription Name"
            placeholder="My Azure Production"
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            required
          />
          <Input
            label="Azure Subscription ID (GUID)"
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            value={form.subscriptionId}
            onChange={e => setForm(f => ({ ...f, subscriptionId: e.target.value }))}
            required
          />
          <Input
            label="Tenant ID (optional)"
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            value={form.tenantId}
            onChange={e => setForm(f => ({ ...f, tenantId: e.target.value }))}
          />
          <Input
            label="Description (optional)"
            placeholder="Production environment"
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
          />
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="secondary" onClick={() => { setAddModalOpen(false); setForm(EMPTY_FORM); }}>
              Cancel
            </Button>
            <Button
              variant="primary"
              loading={createSub.isPending}
              disabled={!form.name || !form.subscriptionId}
              onClick={() => createSub.mutate()}
            >
              Add Subscription
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirm */}
      <Modal
        open={!!deleteConfirm}
        onClose={() => setDeleteConfirm(null)}
        title="Delete Subscription"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-600">
            Are you sure you want to delete <strong>{deleteConfirm?.name}</strong>? All scans and
            findings for this subscription will be permanently deleted.
          </p>
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={() => setDeleteConfirm(null)}>Cancel</Button>
            <Button
              variant="primary"
              className="bg-red-600 hover:bg-red-700"
              loading={deleteSub.isPending}
              onClick={() => deleteConfirm && deleteSub.mutate(deleteConfirm.id)}
            >
              Delete
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

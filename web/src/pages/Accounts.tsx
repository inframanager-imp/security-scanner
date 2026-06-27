import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Play, Trash2, Eye, CheckCircle, XCircle, Cloud } from 'lucide-react';
import { accountsApi } from '../api/accounts';
import { scansApi } from '../api/scans';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { ScanStatusBadge } from '../components/ui/Badge';
import type { Account } from '../types';
import { ApiRequestError } from '../api/client';

function formatDate(dateStr?: string): string {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

interface AddAccountForm {
  name: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

export function Accounts() {
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [addModalOpen, setAddModalOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<Account | null>(null);
  const [form, setForm] = useState<AddAccountForm>({
    name: '',
    accessKeyId: '',
    secretAccessKey: '',
    region: 'us-east-1',
  });
  const [formErrors, setFormErrors] = useState<Partial<AddAccountForm>>({});
  const [addError, setAddError] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const { data: accountsPage, isLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => accountsApi.list(),
  });
  const accounts = accountsPage?.data ?? [];

  const createAccount = useMutation({
    mutationFn: (payload: AddAccountForm) =>
      accountsApi.setup({
        name: payload.name,
        accessKeyId: payload.accessKeyId,
        secretAccessKey: payload.secretAccessKey,
        region: payload.region || 'us-east-1',
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['accounts'] });
      setAddModalOpen(false);
      setForm({ name: '', accessKeyId: '', secretAccessKey: '', region: 'us-east-1' });
    },
    onError: (err) => {
      setAddError(
        err instanceof ApiRequestError ? err.message : 'Failed to create account',
      );
    },
  });

  const deleteAccount = useMutation({
    mutationFn: (id: string) => accountsApi.delete(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['accounts'] });
      setDeleteConfirm(null);
    },
  });

  const triggerScan = useMutation({
    mutationFn: (accountId: string) => scansApi.trigger({ accountId }),
    onSuccess: (scan) => {
      navigate(`/scans/${scan.id}`);
    },
    onError: (err) => {
      setScanError(
        err instanceof ApiRequestError ? err.message : 'Failed to trigger scan',
      );
    },
  });

  const validate = (): boolean => {
    const errors: Partial<AddAccountForm> = {};
    if (!form.name.trim()) errors.name = 'Client name is required';
    if (!form.accessKeyId.trim()) errors.accessKeyId = 'Access Key ID is required';
    else if (form.accessKeyId.trim().length < 16) errors.accessKeyId = 'Access Key ID must be at least 16 characters';
    if (!form.secretAccessKey.trim()) errors.secretAccessKey = 'Secret Access Key is required';
    setFormErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleAdd = () => {
    setAddError(null);
    if (!validate()) return;
    createAccount.mutate(form);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">AWS Accounts</h2>
          <p className="text-sm text-gray-500 mt-1">
            Manage your connected AWS accounts and credentials
          </p>
        </div>
        <Button
          variant="primary"
          leftIcon={<Plus size={16} />}
          onClick={() => {
            setAddModalOpen(true);
            setAddError(null);
            setFormErrors({});
          }}
        >
          Add Account
        </Button>
      </div>

      {scanError && (
        <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          {scanError}
        </div>
      )}


      {/* Table */}
      <Card padding={false}>
        {isLoading ? (
          <div className="p-6 space-y-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-10 bg-gray-100 rounded animate-pulse" />
            ))}
          </div>
        ) : accounts.length === 0 ? (
          <div className="p-16 text-center">
            <Cloud className="mx-auto h-12 w-12 text-gray-300 mb-4" />
            <p className="text-gray-500 text-sm">No accounts yet.</p>
            <Button
              variant="primary"
              size="sm"
              className="mt-4"
              onClick={() => setAddModalOpen(true)}
            >
              Add your first account
            </Button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {[
                    'Name',
                    'AWS Account ID',
                    'Credentials',
                    'Last Scan',
                    'Findings',
                    'Actions',
                  ].map((h) => (
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
                {accounts.map((acc) => (
                  <tr key={acc.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm font-medium text-gray-900">
                      {acc.name}
                      {acc.description && (
                        <p className="text-xs text-gray-400 mt-0.5">
                          {acc.description}
                        </p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500 font-mono">
                      {acc.awsAccountId}
                    </td>
                    <td className="px-4 py-3">
                      {acc.hasCredentials ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-700">
                          <CheckCircle size={12} />
                          Configured
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                          <XCircle size={12} />
                          Not set
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500">
                      <div className="flex flex-col gap-1">
                        <span>
                          {formatDate(
                            acc.latestScan?.completedAt ?? acc.latestScan?.startedAt,
                          )}
                        </span>
                        {acc.latestScan && (
                          <ScanStatusBadge status={acc.latestScan.status} />
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {acc.latestScan?.summary ? (
                        <div className="flex gap-2 text-xs font-semibold">
                          <span className="text-red-600">
                            C:{acc.latestScan.summary.critical}
                          </span>
                          <span className="text-orange-500">
                            H:{acc.latestScan.summary.high}
                          </span>
                          <span className="text-yellow-500">
                            M:{acc.latestScan.summary.medium}
                          </span>
                          <span className="text-blue-500">
                            L:{acc.latestScan.summary.low}
                          </span>
                        </div>
                      ) : (
                        <span className="text-gray-400 text-xs">No data</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          leftIcon={<Eye size={14} />}
                          onClick={() => navigate(`/accounts/${acc.id}`)}
                        >
                          View
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          leftIcon={<Play size={14} />}
                          loading={triggerScan.isPending}
                          onClick={() => triggerScan.mutate(acc.id)}
                          disabled={!acc.hasCredentials}
                        >
                          Scan
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          leftIcon={<Trash2 size={14} />}
                          className="text-red-500 hover:text-red-700 hover:bg-red-50"
                          onClick={() => setDeleteConfirm(acc)}
                        >
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Add Account Modal */}
      <Modal
        open={addModalOpen}
        onClose={() => setAddModalOpen(false)}
        title="Add AWS Account"
        footer={
          <>
            <Button variant="secondary" onClick={() => setAddModalOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleAdd}
              loading={createAccount.isPending}
            >
              {createAccount.isPending ? 'Verifying & Adding...' : 'Add Account'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {addError && (
            <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
              {addError}
            </div>
          )}
          <Input
            label="Client Name"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="e.g. Acme Corp Production"
            error={formErrors.name}
          />
          <Input
            label="AWS Access Key ID"
            value={form.accessKeyId}
            onChange={(e) => setForm((f) => ({ ...f, accessKeyId: e.target.value.trim() }))}
            placeholder="AKIAIOSFODNN7EXAMPLE"
            error={formErrors.accessKeyId}
            autoComplete="off"
          />
          <Input
            label="AWS Secret Access Key"
            type="password"
            value={form.secretAccessKey}
            onChange={(e) => setForm((f) => ({ ...f, secretAccessKey: e.target.value.trim() }))}
            placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            error={formErrors.secretAccessKey}
            autoComplete="off"
          />
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Default Region
            </label>
            <select
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
              value={form.region}
              onChange={(e) => setForm((f) => ({ ...f, region: e.target.value }))}
            >
              {['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1','eu-west-2','eu-central-1','ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-south-1','ca-central-1','sa-east-1'].map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <p className="text-xs text-gray-400">
            AWS Account ID will be automatically detected from your credentials.
          </p>
        </div>
      </Modal>

      {/* Delete Confirm Modal */}
      <Modal
        open={deleteConfirm !== null}
        onClose={() => setDeleteConfirm(null)}
        title="Delete Account"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteConfirm(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={deleteAccount.isPending}
              onClick={() =>
                deleteConfirm && deleteAccount.mutate(deleteConfirm.id)
              }
            >
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-gray-600">
          Are you sure you want to delete{' '}
          <span className="font-semibold text-gray-900">
            {deleteConfirm?.name}
          </span>
          ? This will also delete all associated scans and findings. This action
          cannot be undone.
        </p>
      </Modal>
    </div>
  );
}

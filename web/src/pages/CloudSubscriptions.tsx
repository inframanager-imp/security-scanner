import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Plus, Eye, Play, Trash2, CheckCircle, XCircle, ChevronLeft, ChevronRight, ChevronDown, Check,
  Loader2, AlertCircle, Search, X,
} from 'lucide-react';
import { accountsApi } from '../api/accounts';
import { azureApi } from '../api/azure';
import { gcpApi } from '../api/gcp';
import { scansApi } from '../api/scans';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { ScanStatusBadge } from '../components/ui/Badge';
import { Tooltip } from '../components/ui/Tooltip';
import type { Account, AzureSubscription, GcpProject, ScanStatus, InventoryStatus } from '../types';
import { ApiRequestError } from '../api/client';

// ─── Types ────────────────────────────────────────────────────────────────────

type CloudProvider = 'AWS' | 'AZURE' | 'GCP';
type WizardStep    = 'pick-provider' | 'fill-form';

interface CloudRow {
  id:              string;
  provider:        CloudProvider;
  name:            string;
  accountId:       string;
  hasCredentials:  boolean;
  inventoryStatus?: InventoryStatus;
  lastDiscoveryAt?: string | null;
  lastConfigSyncAt?: string | null;
  pipelineError?:  string | null;
  latestScan?:     { status: ScanStatus; createdAt: string } | null;
  summary?:        { critical: number; high: number; medium: number; low: number; info: number; total: number } | null;
  detailPath:      string;
  scanFn?:         () => void;
}

// ─── Cloud Provider Logos ───────────────────────────────────────────────────

function CloudLogo({ provider, className = "w-4 h-4" }: { provider: CloudProvider | 'ALL'; className?: string }) {
  if (provider === 'AWS') {
    return <img src="/img/aws-logo.svg" alt="AWS" className={`${className} object-contain`} />;
  }
  if (provider === 'AZURE') {
    return <img src="/img/azure-logo.svg" alt="Azure" className={`${className} object-contain`} />;
  }
  if (provider === 'GCP') {
    return <img src="/img/gcp-logo.svg" alt="GCP" className={`${className} object-contain`} />;
  }
  // ALL
  return (
    <svg className={`${className} text-blue-600`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
    </svg>
  );
}

// ─── Provider Config ──────────────────────────────────────────────────────────

const PROVIDER_CONFIG: Record<CloudProvider, { label: string; color: string; bg: string; border: string; dot: string }> = {
  AWS:   { label: 'AWS',   color: 'text-orange-700', bg: 'bg-orange-50',  border: 'border-orange-200', dot: 'bg-orange-500' },
  AZURE: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-50',    border: 'border-blue-200',   dot: 'bg-blue-500'   },
  GCP:   { label: 'GCP',   color: 'text-green-700',  bg: 'bg-green-50',   border: 'border-green-200',  dot: 'bg-green-500'  },
};

function ProviderBadge({ provider }: { provider: CloudProvider }) {
  const cfg = PROVIDER_CONFIG[provider];
  return (
    <div className={`inline-flex items-center justify-center p-1.5 rounded-lg ${cfg.bg} border ${cfg.border}`} title={cfg.label}>
      <CloudLogo provider={provider} className="w-5 h-5 shrink-0" />
    </div>
  );
}

function SeverityBar({ summary }: { summary?: CloudRow['summary'] }) {
  if (!summary || summary.total === 0) return <span className="text-xs text-gray-400">No data</span>;
  const t = summary.total;
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-24 rounded-full overflow-hidden bg-gray-100">
        {summary.critical > 0 && <div style={{ width: `${(summary.critical / t) * 100}%` }} className="bg-red-600" />}
        {summary.high     > 0 && <div style={{ width: `${(summary.high     / t) * 100}%` }} className="bg-orange-500" />}
        {summary.medium   > 0 && <div style={{ width: `${(summary.medium   / t) * 100}%` }} className="bg-yellow-500" />}
        {summary.low      > 0 && <div style={{ width: `${(summary.low      / t) * 100}%` }} className="bg-blue-500" />}
        {summary.info     > 0 && <div style={{ width: `${(summary.info     / t) * 100}%` }} className="bg-gray-400" />}
      </div>
      <span className="text-xs text-gray-600 tabular-nums">{t}</span>
    </div>
  );
}

function formatDate(d?: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatRelative(d?: string | null) {
  if (!d) return null;
  const diff = Date.now() - new Date(d).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1)   return 'just now';
  if (mins < 60)  return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)   return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function InventoryPipelineBadge({ row }: { row: CloudRow }) {
  const status = row.inventoryStatus ?? 'PENDING';

  if (status === 'READY') {
    return (
      <div className="flex flex-col gap-1 items-start">
        <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
          Monitoring
        </span>
        {(row.lastConfigSyncAt ?? row.lastDiscoveryAt) && (
          <span className="text-[11px] text-gray-400 whitespace-nowrap">
            Config synced {formatRelative(row.lastConfigSyncAt ?? row.lastDiscoveryAt!)}
          </span>
        )}
      </div>
    );
  }

  if (status === 'INITIALIZING') {
    return (
      <div className="flex flex-col gap-1 items-start">
        <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
          <Loader2 size={11} className="animate-spin" />
          Initializing
        </span>
        <span className="text-[11px] text-gray-400 whitespace-nowrap">Discovering resources…</span>
      </div>
    );
  }

  if (status === 'FAILED') {
    return (
      <div className="flex flex-col gap-1 items-start" title={row.pipelineError ?? undefined}>
        <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
          <AlertCircle size={11} />
          Failed
        </span>
        <span className="text-[11px] text-gray-400 max-w-[150px] truncate">{row.pipelineError ?? 'Pipeline error'}</span>
      </div>
    );
  }

  // PENDING
  return (
    <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-500 border border-gray-200">
      Pending
    </span>
  );
}

// ─── Provider Picker ──────────────────────────────────────────────────────────

function ProviderCard({
  provider, selected, onClick,
}: { provider: CloudProvider; selected: boolean; onClick: () => void }) {
  const cfg = PROVIDER_CONFIG[provider];
  const icons: Record<CloudProvider, string> = {
    AWS:   '🟠',
    AZURE: '🔵',
    GCP:   '🟢',
  };
  return (
    <button
      onClick={onClick}
      className={`relative flex flex-col items-center gap-3 p-5 rounded-xl border-2 w-full transition-all ${
        selected
          ? `${cfg.border} ${cfg.bg} ring-2 ring-offset-1 ring-current ${cfg.color}`
          : 'border-gray-200 hover:border-gray-300 bg-white'
      }`}
    >
      <span className="text-3xl">{icons[provider]}</span>
      <span className="text-sm font-semibold text-gray-800">{cfg.label}</span>
    </button>
  );
}

// ─── AWS Form ─────────────────────────────────────────────────────────────────

interface AWSForm { name: string; accessKeyId: string; secretAccessKey: string; region: string }
const AWS_DEFAULT: AWSForm = { name: '', accessKeyId: '', secretAccessKey: '', region: 'us-east-1' };

function AWSAddForm({
  form, onChange, error,
}: { form: AWSForm; onChange: (f: AWSForm) => void; error: string | null }) {
  const set = (k: keyof AWSForm) => (e: React.ChangeEvent<HTMLInputElement>) =>
    onChange({ ...form, [k]: e.target.value });
  return (
    <div className="space-y-4">
      {error && <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">{error}</div>}
      <Input label="Account Name" placeholder="My AWS Production" value={form.name} onChange={set('name')} required />
      <Input label="Access Key ID" placeholder="AKIAIOSFODNN7EXAMPLE" value={form.accessKeyId} onChange={set('accessKeyId')} required />
      <Input label="Secret Access Key" type="password" placeholder="••••••••••••••••" value={form.secretAccessKey} onChange={set('secretAccessKey')} required />
      <Input label="Default Region" placeholder="us-east-1" value={form.region} onChange={set('region')} />
    </div>
  );
}

// ─── Azure Form ───────────────────────────────────────────────────────────────

interface AzureForm { name: string; subscriptionId: string; tenantId: string; clientId: string; clientSecret: string; description: string }
const AZURE_DEFAULT: AzureForm = { name: '', subscriptionId: '', tenantId: '', clientId: '', clientSecret: '', description: '' };

function AzureAddForm({
  form, onChange, error,
}: { form: AzureForm; onChange: (f: AzureForm) => void; error: string | null }) {
  const set = (k: keyof AzureForm) => (e: React.ChangeEvent<HTMLInputElement>) =>
    onChange({ ...form, [k]: e.target.value });
  return (
    <div className="space-y-4">
      {error && <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">{error}</div>}
      <Input label="Subscription Name" placeholder="My Azure Production" value={form.name} onChange={set('name')} required />
      <Input label="Azure Subscription ID" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value={form.subscriptionId} onChange={set('subscriptionId')} required />
      <Input label="Description (optional)" placeholder="Production environment" value={form.description} onChange={set('description')} />
      <div className="border-t border-gray-100 pt-3">
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Service Principal Credentials</p>
        <div className="space-y-3">
          <Input label="Tenant ID" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value={form.tenantId} onChange={set('tenantId')} required />
          <Input label="Client ID (Application ID)" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value={form.clientId} onChange={set('clientId')} required />
          <Input label="Client Secret" type="password" placeholder="••••••••••••••••" value={form.clientSecret} onChange={set('clientSecret')} required />
        </div>
      </div>
      <p className="text-xs text-blue-700 bg-blue-50 border border-blue-100 rounded px-3 py-2">
        Assign the <strong>Reader</strong> role to your service principal in Azure Portal → Subscriptions → Access Control (IAM).
      </p>
    </div>
  );
}

// ─── GCP Form ─────────────────────────────────────────────────────────────────

interface GcpForm { name: string; projectId: string; serviceAccountKey: string; description: string }
const GCP_DEFAULT: GcpForm = { name: '', projectId: '', serviceAccountKey: '', description: '' };

function GcpAddForm({
  form, onChange, error,
}: { form: GcpForm; onChange: (f: GcpForm) => void; error: string | null }) {
  const setInput = (k: keyof GcpForm) => (e: React.ChangeEvent<HTMLInputElement>) =>
    onChange({ ...form, [k]: e.target.value });
  return (
    <div className="space-y-4">
      {error && <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">{error}</div>}
      <Input label="Project Name" placeholder="My GCP Production" value={form.name} onChange={setInput('name')} required />
      <Input label="GCP Project ID" placeholder="my-project-123456" value={form.projectId} onChange={setInput('projectId')} required />
      <Input label="Description (optional)" placeholder="Production environment" value={form.description} onChange={setInput('description')} />
      <div className="border-t border-gray-100 pt-3">
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Service Account Key (optional)</p>
        <textarea
          rows={5}
          placeholder={'{\n  "type": "service_account",\n  "project_id": "...",\n  ...\n}'}
          value={form.serviceAccountKey}
          onChange={e => onChange({ ...form, serviceAccountKey: e.target.value })}
          className="w-full rounded-md border border-gray-300 px-3 py-2 text-xs font-mono text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
        />
        <p className="mt-1 text-xs text-gray-400">Paste your service account JSON key. You can also add it later.</p>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export function CloudSubscriptions() {
  const navigate   = useNavigate();
  const qc         = useQueryClient();

  const [modalOpen,    setModalOpen]    = useState(false);
  const [step,         setStep]         = useState<WizardStep>('pick-provider');
  const [provider,     setProvider]     = useState<CloudProvider>('AWS');
  const [awsForm,      setAwsForm]      = useState<AWSForm>(AWS_DEFAULT);
  const [azureForm,    setAzureForm]    = useState<AzureForm>(AZURE_DEFAULT);
  const [gcpForm,      setGcpForm]      = useState<GcpForm>(GCP_DEFAULT);
  const [addError,     setAddError]     = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CloudRow | null>(null);
  const [scanningId,   setScanningId]   = useState<string | null>(null);
  const [provFilter,   setProvFilter]   = useState<CloudProvider | 'ALL'>('ALL');
  const [search,       setSearch]       = useState('');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef                     = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // ── Data fetching ──────────────────────────────────────────────────────────

  const { data: awsPage, isLoading: awsLoading } = useQuery({
    queryKey:    ['accounts'],
    queryFn:     () => accountsApi.list(),
    refetchInterval: 15_000, // refresh every 15s so INITIALIZING → READY updates live
  });

  const { data: azurePage, isLoading: azureLoading } = useQuery({
    queryKey:    ['azure-subscriptions'],
    queryFn:     () => azureApi.listSubscriptions({ limit: 100 }),
    refetchInterval: 15_000,
  });

  const { data: gcpPage, isLoading: gcpLoading } = useQuery({
    queryKey:    ['gcp-projects'],
    queryFn:     () => gcpApi.listProjects({ limit: 100 }),
    refetchInterval: 15_000,
  });

  const isLoading = awsLoading || azureLoading || gcpLoading;

  // ── Merge into unified rows ────────────────────────────────────────────────

  const awsRows: CloudRow[] = (awsPage?.data ?? []).map((a: Account) => ({
    id:               a.id,
    provider:         'AWS' as CloudProvider,
    name:             a.name,
    accountId:        a.awsAccountId,
    hasCredentials:   !!a.hasCredentials,
    inventoryStatus:  a.inventoryStatus,
    lastDiscoveryAt:  a.lastDiscoveryAt,
    lastConfigSyncAt: a.lastConfigSyncAt,
    pipelineError:    a.pipelineError,
    latestScan:       a.latestScan ? { status: a.latestScan.status, createdAt: a.latestScan.createdAt } : null,
    summary:          a.latestScan?.summary ?? null,
    detailPath:       `/accounts/${a.id}`,
  }));

  const azureRows: CloudRow[] = (azurePage?.data ?? []).map((s: AzureSubscription) => ({
    id:               s.id,
    provider:         'AZURE' as CloudProvider,
    name:             s.name,
    accountId:        s.subscriptionId,
    hasCredentials:   s.hasCredentials,
    inventoryStatus:  s.inventoryStatus,
    lastDiscoveryAt:  s.lastDiscoveryAt,
    lastConfigSyncAt: s.lastConfigSyncAt,
    pipelineError:    s.pipelineError,
    latestScan:       s.latestScan ? { status: s.latestScan.status, createdAt: s.latestScan.createdAt } : null,
    summary:          s.latestScan?.summary ?? null,
    detailPath:       `/azure/${s.id}`,
  }));

  const gcpRows: CloudRow[] = (gcpPage?.data ?? []).map((p: GcpProject) => ({
    id:               p.id,
    provider:         'GCP' as CloudProvider,
    name:             p.name,
    accountId:        p.projectId,
    hasCredentials:   p.hasCredentials,
    inventoryStatus:  p.inventoryStatus,
    lastDiscoveryAt:  p.lastDiscoveryAt,
    lastConfigSyncAt: p.lastConfigSyncAt,
    pipelineError:    p.pipelineError,
    latestScan:       p.latestScan ? { status: p.latestScan.status, createdAt: p.latestScan.createdAt } : null,
    summary:          p.latestScan?.summary ?? null,
    detailPath:       `/gcp/${p.id}`,
  }));

  const allRows = [...awsRows, ...azureRows, ...gcpRows].sort((a, b) => a.name.localeCompare(b.name));
  const rows    = allRows.filter(r => {
    if (provFilter !== 'ALL' && r.provider !== provFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase().trim();
      return (
        r.name.toLowerCase().includes(q) ||
        r.accountId.toLowerCase().includes(q) ||
        r.provider.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Summary counts
  const totalCritical  = allRows.reduce((s, r) => s + (r.summary?.critical ?? 0), 0);
  const totalHigh      = allRows.reduce((s, r) => s + (r.summary?.high     ?? 0), 0);
  const totalFindings  = allRows.reduce((s, r) => s + (r.summary?.total    ?? 0), 0);
  const totalMonitored = allRows.filter(r => r.inventoryStatus === 'READY').length;
  const totalInitializing = allRows.filter(r => r.inventoryStatus === 'INITIALIZING').length;

  // ── Mutations ──────────────────────────────────────────────────────────────

  const createAWS = useMutation({
    mutationFn: () => accountsApi.setup({
      name:            awsForm.name,
      accessKeyId:     awsForm.accessKeyId,
      secretAccessKey: awsForm.secretAccessKey,
      region:          awsForm.region || 'us-east-1',
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['accounts'] });
      closeModal();
    },
    onError: (err) => setAddError(err instanceof ApiRequestError ? err.message : 'Failed to add AWS account'),
  });

  const createAzure = useMutation({
    mutationFn: async () => {
      const sub = await azureApi.createSubscription({
        name:           azureForm.name,
        subscriptionId: azureForm.subscriptionId,
        tenantId:       azureForm.tenantId || undefined,
        description:    azureForm.description || undefined,
      });
      if (azureForm.tenantId && azureForm.clientId && azureForm.clientSecret) {
        await azureApi.setCredentials(sub.id, {
          authMethod:   'SERVICE_PRINCIPAL',
          tenantId:     azureForm.tenantId,
          clientId:     azureForm.clientId,
          clientSecret: azureForm.clientSecret,
        });
      }
      return sub;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['azure-subscriptions'] });
      closeModal();
    },
    onError: (err) => setAddError(err instanceof ApiRequestError ? err.message : 'Failed to add Azure subscription'),
  });

  const createGcp = useMutation({
    mutationFn: async () => {
      const proj = await gcpApi.createProject({
        name:        gcpForm.name,
        projectId:   gcpForm.projectId,
        description: gcpForm.description || undefined,
      });
      if (gcpForm.serviceAccountKey.trim()) {
        await gcpApi.setCredentials(proj.id, {
          authMethod:        'SERVICE_ACCOUNT_KEY',
          serviceAccountKey: gcpForm.serviceAccountKey.trim(),
        });
      }
      return proj;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['gcp-projects'] });
      closeModal();
    },
    onError: (err) => setAddError(err instanceof ApiRequestError ? err.message : 'Failed to add GCP project'),
  });

  const deleteAWS = useMutation({
    mutationFn: (id: string) => accountsApi.delete(id),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['accounts'] }); setDeleteTarget(null); },
  });

  const deleteAzure = useMutation({
    mutationFn: (id: string) => azureApi.deleteSubscription(id),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['azure-subscriptions'] }); setDeleteTarget(null); },
  });

  const deleteGcp = useMutation({
    mutationFn: (id: string) => gcpApi.deleteProject(id),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['gcp-projects'] }); setDeleteTarget(null); },
  });

  const triggerAWSScan = useMutation({
    mutationFn: (accountId: string) => scansApi.trigger({ accountId }),
    onSuccess: (_scan, id) => { setScanningId(null); void qc.invalidateQueries({ queryKey: ['accounts'] }); navigate(`/accounts/${id}`); },
    onError:   ()           => setScanningId(null),
  });

  const triggerAzureScan = useMutation({
    mutationFn: (id: string) => azureApi.triggerScan(id),
    onSuccess: (_r, id) => { setScanningId(null); void qc.invalidateQueries({ queryKey: ['azure-subscriptions'] }); navigate(`/azure/${id}`); },
    onError:   ()        => setScanningId(null),
  });

  const triggerGcpScan = useMutation({
    mutationFn: (id: string) => gcpApi.triggerScan(id),
    onSuccess: (_r, id) => { setScanningId(null); void qc.invalidateQueries({ queryKey: ['gcp-projects'] }); navigate(`/gcp/${id}`); },
    onError:   ()        => setScanningId(null),
  });

  // ── Handlers ───────────────────────────────────────────────────────────────

  function closeModal() {
    setModalOpen(false);
    setStep('pick-provider');
    setProvider('AWS');
    setAwsForm(AWS_DEFAULT);
    setAzureForm(AZURE_DEFAULT);
    setGcpForm(GCP_DEFAULT);
    setAddError(null);
  }

  function handleScan(row: CloudRow) {
    setScanningId(row.id);
    if (row.provider === 'AWS')   triggerAWSScan.mutate(row.id);
    if (row.provider === 'AZURE') triggerAzureScan.mutate(row.id);
    if (row.provider === 'GCP')   triggerGcpScan.mutate(row.id);
  }

  function handleDelete() {
    if (!deleteTarget) return;
    if (deleteTarget.provider === 'AWS')   deleteAWS.mutate(deleteTarget.id);
    if (deleteTarget.provider === 'AZURE') deleteAzure.mutate(deleteTarget.id);
    if (deleteTarget.provider === 'GCP')   deleteGcp.mutate(deleteTarget.id);
  }

  function handleAdd() {
    setAddError(null);
    if (provider === 'AWS')   createAWS.mutate();
    if (provider === 'AZURE') createAzure.mutate();
    if (provider === 'GCP')   createGcp.mutate();
  }

  const addPending = createAWS.isPending || createAzure.isPending || createGcp.isPending;
  const deletePending = deleteAWS.isPending || deleteAzure.isPending || deleteGcp.isPending;

  const addDisabled =
    (provider === 'AWS'   && (!awsForm.name   || !awsForm.accessKeyId || !awsForm.secretAccessKey)) ||
    (provider === 'AZURE' && (!azureForm.name || !azureForm.subscriptionId || !azureForm.tenantId || !azureForm.clientId || !azureForm.clientSecret)) ||
    (provider === 'GCP'   && (!gcpForm.name   || !gcpForm.projectId));

  const formLabel =
    provider === 'AWS'   ? 'AWS Account' :
    provider === 'AZURE' ? 'Azure Subscription' : 'GCP Project';

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-gray-900">Cloud Subscriptions</h2>
          <p className="text-sm text-gray-500 mt-0.5">Manage AWS, Azure and GCP cloud accounts in one place</p>
        </div>
        <Button variant="primary" leftIcon={<Plus size={16} />} onClick={() => setModalOpen(true)}>
          Add Subscription
        </Button>
      </div>

      {/* Summary cards */}
      {allRows.length > 0 && (
        <div className="grid grid-cols-5 gap-4">
          {[
            { label: 'Total Subscriptions', value: allRows.length,      cls: 'text-gray-900' },
            { label: 'Monitored (READY)',    value: totalMonitored,      cls: totalMonitored > 0 ? 'text-emerald-600' : 'text-gray-400',
              sub: totalInitializing > 0 ? `${totalInitializing} initializing` : null },
            { label: 'Total Findings',       value: totalFindings,       cls: totalFindings  > 0 ? 'text-gray-900' : 'text-gray-400' },
            { label: 'Critical',             value: totalCritical,       cls: totalCritical  > 0 ? 'text-red-600'  : 'text-gray-400' },
            { label: 'High',                 value: totalHigh,           cls: totalHigh      > 0 ? 'text-orange-500' : 'text-gray-400' },
          ].map(c => (
            <div key={c.label} className="bg-white rounded-lg border border-gray-200 p-4">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{c.label}</p>
              <p className={`mt-1 text-2xl font-bold ${c.cls}`}>{c.value}</p>
              {'sub' in c && c.sub && (
                <p className="text-[10px] text-blue-500 mt-0.5 flex items-center gap-1">
                  <Loader2 size={9} className="animate-spin" />{c.sub}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Toolbar above table: Search bar on Left, Styled Dropdown on Right (No card outline) */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        {/* Left Side: Search Bar */}
        <div className="relative w-full sm:w-96">
          <Input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search subscriptions by name, ID..."
            leftIcon={<Search size={15} className="text-gray-400" />}
            className="pr-8 text-xs sm:text-sm h-10 w-full bg-white border-gray-300 rounded-lg shadow-sm focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
          />
          {search && (
            <button
              onClick={() => setSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 p-1 rounded-full hover:bg-gray-100 transition-colors"
            >
              <X size={14} />
            </button>
          )}
        </div>

        {/* Right Side: Custom Styled Dropdown Menu */}
        <div className="flex items-center gap-3">
          {(provFilter !== 'ALL' || search) && (
            <button
              onClick={() => { setProvFilter('ALL'); setSearch(''); }}
              className="text-xs text-blue-600 hover:text-blue-800 hover:underline font-medium transition-colors"
            >
              Clear filters
            </button>
          )}

          <div className="relative" ref={dropdownRef}>
            <button
              type="button"
              onClick={() => setDropdownOpen(prev => !prev)}
              className="h-10 px-3.5 flex items-center gap-2.5 text-xs sm:text-sm font-semibold bg-white text-gray-700 border border-gray-300 rounded-lg shadow-sm hover:border-gray-400 hover:bg-gray-50 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all outline-none"
            >
              <CloudLogo provider={provFilter} className="w-4 h-4 shrink-0" />
              <span>
                {provFilter === 'ALL' ? `All Clouds (${allRows.length})` :
                 provFilter === 'AWS' ? `AWS (${awsRows.length})` :
                 provFilter === 'AZURE' ? `Azure (${azureRows.length})` :
                 `GCP (${gcpRows.length})`}
              </span>
              <ChevronDown
                size={15}
                className={`text-gray-400 transition-transform duration-200 ${dropdownOpen ? 'rotate-180 text-blue-600' : ''}`}
              />
            </button>

            {/* Expanded Dropdown Card */}
            {dropdownOpen && (
              <div className="absolute right-0 top-full mt-1.5 w-52 bg-white border border-gray-200 rounded-xl shadow-xl z-50 py-1.5 overflow-hidden animate-in fade-in slide-in-from-top-2 duration-150">
                <div className="px-3.5 py-1.5 text-[10px] font-bold text-gray-400 uppercase tracking-wider border-b border-gray-100">
                  Select Provider
                </div>
                {[
                  { id: 'ALL',   label: 'All Clouds', count: allRows.length },
                  { id: 'AWS',   label: 'AWS',        count: awsRows.length },
                  { id: 'AZURE', label: 'Azure',      count: azureRows.length },
                  { id: 'GCP',   label: 'GCP',        count: gcpRows.length },
                ].map((opt) => {
                  const isSelected = provFilter === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => {
                        setProvFilter(opt.id as CloudProvider | 'ALL');
                        setDropdownOpen(false);
                      }}
                      className={`w-full px-3.5 py-2.5 flex items-center justify-between text-xs transition-colors ${
                        isSelected
                          ? 'bg-blue-50/80 text-blue-700 font-semibold'
                          : 'text-gray-700 hover:bg-gray-50'
                      }`}
                    >
                      <div className="flex items-center gap-2.5">
                        <CloudLogo provider={opt.id as CloudProvider | 'ALL'} className="w-4 h-4 shrink-0" />
                        <span>{opt.label}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${
                          isSelected ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-500'
                        }`}>
                          {opt.count}
                        </span>
                        {isSelected && <Check size={14} className="text-blue-600 ml-0.5" />}
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Table */}
      <Card padding={false}>
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
          </div>
        ) : rows.length === 0 ? (
          allRows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
              <div className="text-5xl">☁️</div>
              <p className="text-gray-600 font-medium">No cloud subscriptions yet</p>
              <p className="text-sm text-gray-400">Add an AWS, Azure or GCP account to start scanning</p>
              <Button variant="primary" size="sm" leftIcon={<Plus size={14} />} onClick={() => setModalOpen(true)}>
                Add Subscription
              </Button>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
              <div className="text-4xl">🔍</div>
              <p className="text-gray-600 font-medium">No subscriptions match your filter or search</p>
              <p className="text-sm text-gray-400">Try clearing your filters or search query</p>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => { setProvFilter('ALL'); setSearch(''); }}
              >
                Clear Filters & Search
              </Button>
            </div>
          )
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50">
                {['Cloud', 'Name', 'Account / Project ID', 'Credentials', 'Inventory Pipeline', 'Last Scan', 'Findings', 'Actions'].map(h => (
                  <th key={h} className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map(row => (
                <tr key={`${row.provider}-${row.id}`} className="hover:bg-gray-50 transition-colors">
                  <td className="px-5 py-4"><ProviderBadge provider={row.provider} /></td>
                  <td className="px-5 py-4 font-medium text-gray-900">{row.name}</td>
                  <td className="px-5 py-4 font-mono text-xs text-gray-500 max-w-[200px] truncate">{row.accountId}</td>
                  <td className="px-5 py-4">
                    {row.hasCredentials
                      ? <span className="inline-flex items-center gap-1 text-xs text-green-700"><CheckCircle size={12} /> Configured</span>
                      : <span className="inline-flex items-center gap-1 text-xs text-gray-400"><XCircle size={12} /> None</span>}
                  </td>
                  <td className="px-5 py-4"><InventoryPipelineBadge row={row} /></td>
                  <td className="px-5 py-4">
                    {row.latestScan ? (
                      <div className="flex flex-col gap-1 items-start">
                        <ScanStatusBadge status={row.latestScan.status} />
                        <span className="text-[11px] text-gray-400 whitespace-nowrap">{formatDate(row.latestScan.createdAt)}</span>
                      </div>
                    ) : <span className="text-gray-400">—</span>}
                  </td>
                  <td className="px-5 py-4"><SeverityBar summary={row.summary} /></td>
                  <td className="px-5 py-4">
                    <div className="flex items-center gap-1">
                      <Tooltip content="View Details" position="top">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="p-1.5 text-gray-500 hover:text-blue-600 hover:bg-blue-50"
                          aria-label="View Details"
                          onClick={() => navigate(row.detailPath)}
                        >
                          <Eye size={15} />
                        </Button>
                      </Tooltip>
                      <Tooltip content="Trigger Scan" position="top">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="p-1.5 text-gray-500 hover:text-green-600 hover:bg-green-50"
                          aria-label="Trigger Scan"
                          loading={scanningId === row.id}
                          disabled={!row.hasCredentials}
                          onClick={() => handleScan(row)}
                        >
                          {scanningId !== row.id && <Play size={15} />}
                        </Button>
                      </Tooltip>
                      <Tooltip content="Delete Subscription" position="top">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="p-1.5 text-red-500 hover:text-red-700 hover:bg-red-50"
                          aria-label="Delete Subscription"
                          onClick={() => setDeleteTarget(row)}
                        >
                          <Trash2 size={15} />
                        </Button>
                      </Tooltip>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* ── Add Subscription Modal ── */}
      <Modal open={modalOpen} onClose={closeModal} title="Add Cloud Subscription" size="md">
        {step === 'pick-provider' ? (
          <div className="space-y-5">
            <p className="text-sm text-gray-600">Select the cloud provider to add:</p>
            <div className="grid grid-cols-3 gap-3">
              <ProviderCard provider="AWS"   selected={provider === 'AWS'}   onClick={() => setProvider('AWS')} />
              <ProviderCard provider="AZURE" selected={provider === 'AZURE'} onClick={() => setProvider('AZURE')} />
              <ProviderCard provider="GCP"   selected={provider === 'GCP'}   onClick={() => setProvider('GCP')} />
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <Button variant="secondary" onClick={closeModal}>Cancel</Button>
              <Button variant="primary" rightIcon={<ChevronRight size={15} />}
                onClick={() => setStep('fill-form')}>
                Continue
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-5">
            {/* Step header */}
            <div className="flex items-center gap-2">
              <button onClick={() => { setStep('pick-provider'); setAddError(null); }}
                className="text-gray-400 hover:text-gray-600">
                <ChevronLeft size={18} />
              </button>
              <ProviderBadge provider={provider} />
              <span className="text-sm text-gray-500">{formLabel}</span>
            </div>

            {/* Provider-specific form */}
            {provider === 'AWS' && (
              <AWSAddForm form={awsForm} onChange={setAwsForm} error={addError} />
            )}
            {provider === 'AZURE' && (
              <AzureAddForm form={azureForm} onChange={setAzureForm} error={addError} />
            )}
            {provider === 'GCP' && (
              <GcpAddForm form={gcpForm} onChange={setGcpForm} error={addError} />
            )}

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="secondary" onClick={closeModal}>Cancel</Button>
              <Button variant="primary" loading={addPending} disabled={addDisabled} onClick={handleAdd}>
                Add {formLabel}
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* ── Delete Confirm Modal ── */}
      <Modal open={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Confirm Deletion" size="sm">
        <div className="space-y-4 pt-1">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-red-50 text-red-600 rounded-full shrink-0 mt-0.5 border border-red-100">
              <Trash2 size={20} />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-gray-900">Delete "{deleteTarget?.name}"?</h3>
              <p className="text-xs text-gray-500 mt-1 leading-relaxed">
                Are you sure you want to delete this {deleteTarget?.provider} subscription (ID: <code className="font-mono text-gray-700 bg-gray-100 px-1 py-0.5 rounded">{deleteTarget?.accountId}</code>)? All historical scans, assets, and security findings will be permanently removed.
              </p>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-gray-100">
            <Button variant="secondary" size="sm" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              className="bg-red-600 hover:bg-red-700 text-white"
              loading={deletePending}
              onClick={handleDelete}
            >
              Delete Subscription
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

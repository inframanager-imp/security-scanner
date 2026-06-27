import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeft, Database, GitBranch, Clock, CheckCircle2, Trash2,
  ChevronDown, ChevronUp, Server, Tag, MapPin, GitCompare, Network,
  Share2,
} from 'lucide-react';
import { resourceInventoryApi } from '../api/resourceInventory';
import { ResourceGraph } from '../components/ResourceGraph';
import type { DependencyType } from '../types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PROVIDER_CONFIG = {
  AWS:   { label: 'AWS',   color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200', dot: 'bg-orange-500' },
  AZURE: { label: 'Azure', color: 'text-blue-700',   bg: 'bg-blue-50',   border: 'border-blue-200',   dot: 'bg-blue-500'   },
  GCP:   { label: 'GCP',   color: 'text-green-700',  bg: 'bg-green-50',  border: 'border-green-200',  dot: 'bg-green-500'  },
};

const DEP_TYPE_CONFIG: Record<DependencyType, { color: string; label: string }> = {
  NETWORK:  { color: 'text-blue-600 bg-blue-50 border-blue-200',   label: 'Network'  },
  IAM:      { color: 'text-purple-600 bg-purple-50 border-purple-200', label: 'IAM'   },
  STORAGE:  { color: 'text-yellow-600 bg-yellow-50 border-yellow-200', label: 'Storage' },
  COMPUTE:  { color: 'text-green-600 bg-green-50 border-green-200',  label: 'Compute'  },
  DATABASE: { color: 'text-red-600 bg-red-50 border-red-200',       label: 'Database' },
  OTHER:    { color: 'text-gray-600 bg-gray-50 border-gray-200',    label: 'Other'    },
};

const CHANGE_TYPE_CONFIG = {
  CREATED:  { color: 'text-green-700 bg-green-50 border-green-200', icon: CheckCircle2 },
  MODIFIED: { color: 'text-blue-700 bg-blue-50 border-blue-200',    icon: GitCompare   },
  DELETED:  { color: 'text-red-700 bg-red-50 border-red-200',       icon: Trash2       },
};

function fmt(d: string) {
  return new Date(d).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function friendlyType(resourceType: string): string {
  return resourceType
    .replace(/^AWS::/, '').replace(/^Microsoft\./, '').replace(/\.googleapis\.com/, '')
    .replace(/\//g, ' ').replace(/::/g, ' ');
}

// ─── JSON Viewer ─────────────────────────────────────────────────────────────

function JsonViewer({ data, maxHeight = '400px' }: { data: Record<string, unknown>; maxHeight?: string }) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  function renderValue(val: unknown, path: string, depth = 0): React.ReactNode {
    if (val === null || val === undefined) return <span className="text-gray-400">null</span>;
    if (typeof val === 'boolean') return <span className="text-purple-600">{String(val)}</span>;
    if (typeof val === 'number')  return <span className="text-orange-600">{val}</span>;
    if (typeof val === 'string')  return <span className="text-green-700">"{val}"</span>;

    if (Array.isArray(val)) {
      if (val.length === 0) return <span className="text-gray-500">[]</span>;
      const isCollapsed = collapsed.has(path);
      return (
        <span>
          <button onClick={() => setCollapsed((p) => { const n = new Set(p); n.has(path) ? n.delete(path) : n.add(path); return n; })}
            className="text-gray-400 hover:text-gray-700">
            {isCollapsed ? <ChevronDown size={10} className="inline" /> : <ChevronUp size={10} className="inline" />}
          </button>
          {' '}[{isCollapsed ? `${val.length} items` : (
            <div style={{ paddingLeft: `${(depth + 1) * 12}px` }}>
              {val.map((item, i) => (
                <div key={i}>{renderValue(item, `${path}[${i}]`, depth + 1)}{i < val.length - 1 ? ',' : ''}</div>
              ))}
            </div>
          )}]
        </span>
      );
    }

    if (typeof val === 'object') {
      const entries = Object.entries(val as Record<string, unknown>);
      if (entries.length === 0) return <span className="text-gray-500">{'{}'}</span>;
      const isCollapsed = collapsed.has(path);
      return (
        <span>
          <button onClick={() => setCollapsed((p) => { const n = new Set(p); n.has(path) ? n.delete(path) : n.add(path); return n; })}
            className="text-gray-400 hover:text-gray-700">
            {isCollapsed ? <ChevronDown size={10} className="inline" /> : <ChevronUp size={10} className="inline" />}
          </button>
          {' '}{'{'}
          {isCollapsed ? `${entries.length} keys` : (
            <div style={{ paddingLeft: `${(depth + 1) * 12}px` }}>
              {entries.map(([k, v], i) => (
                <div key={k}>
                  <span className="text-blue-800">"{k}"</span>
                  <span className="text-gray-500">: </span>
                  {renderValue(v, `${path}.${k}`, depth + 1)}
                  {i < entries.length - 1 ? ',' : ''}
                </div>
              ))}
            </div>
          )}
          {'}'}
        </span>
      );
    }
    return <span>{String(val)}</span>;
  }

  return (
    <div className={`font-mono text-xs bg-gray-900 text-gray-100 rounded-lg p-4 overflow-auto`} style={{ maxHeight }}>
      {renderValue(data, 'root')}
    </div>
  );
}

// ─── Diff Viewer ─────────────────────────────────────────────────────────────

function DiffViewer({ diff }: { diff: Record<string, { from: unknown; to: unknown }> }) {
  const entries = Object.entries(diff);
  if (entries.length === 0) return <p className="text-gray-400 text-sm">No property changes detected.</p>;

  return (
    <div className="space-y-2">
      {entries.map(([key, { from, to }]) => (
        <div key={key} className="border border-gray-200 rounded-lg overflow-hidden text-xs">
          <div className="px-3 py-1.5 bg-gray-100 font-mono font-semibold text-gray-700">{key}</div>
          <div className="grid grid-cols-2 divide-x divide-gray-200">
            <div className="p-3 bg-red-50">
              <p className="text-xs text-red-500 font-medium mb-1">Before</p>
              <pre className="text-red-800 whitespace-pre-wrap break-all">
                {from === null || from === undefined ? 'null' : JSON.stringify(from, null, 2)}
              </pre>
            </div>
            <div className="p-3 bg-green-50">
              <p className="text-xs text-green-600 font-medium mb-1">After</p>
              <pre className="text-green-800 whitespace-pre-wrap break-all">
                {to === null || to === undefined ? 'null' : JSON.stringify(to, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Tab: Timeline ────────────────────────────────────────────────────────────

function TimelineTab({ resourceId }: { resourceId: string }) {
  const [expandedSnap, setExpandedSnap] = useState<string | null>(null);

  const { data: timeline, isLoading } = useQuery({
    queryKey: ['resource-timeline', resourceId],
    queryFn:  () => resourceInventoryApi.getTimeline(resourceId, 100),
    staleTime: 30_000,
  });

  if (isLoading) return (
    <div className="flex items-center justify-center h-40">
      <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
    </div>
  );

  if (!timeline || timeline.length === 0) return (
    <div className="flex flex-col items-center justify-center py-16 gap-2 text-gray-400">
      <Clock className="h-10 w-10" />
      <p>No snapshots yet. Run a discovery to capture the current state.</p>
    </div>
  );

  return (
    <div className="relative">
      {/* Vertical line */}
      <div className="absolute left-5 top-0 bottom-0 w-0.5 bg-gray-200" />

      <div className="space-y-4 pl-12">
        {timeline.map((snap) => {
          const cfg    = CHANGE_TYPE_CONFIG[snap.changeType as keyof typeof CHANGE_TYPE_CONFIG] ?? CHANGE_TYPE_CONFIG.MODIFIED;
          const CIcon  = cfg.icon;
          const isOpen = expandedSnap === snap.id;

          return (
            <div key={snap.id} className="relative">
              {/* Dot */}
              <div className={`absolute -left-7 top-1.5 h-4 w-4 rounded-full border-2 border-white flex items-center justify-center ${
                snap.changeType === 'CREATED' ? 'bg-green-500' :
                snap.changeType === 'DELETED' ? 'bg-red-500' : 'bg-blue-500'
              }`}>
                <CIcon size={8} className="text-white" />
              </div>

              <div className="border border-gray-200 rounded-lg overflow-hidden">
                <button
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-gray-50 transition-colors text-left"
                  onClick={() => setExpandedSnap(isOpen ? null : snap.id)}
                >
                  <div className="flex items-center gap-3">
                    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-semibold rounded-full border ${cfg.color}`}>
                      <CIcon size={10} /> {snap.changeType}
                    </span>
                    <span className="text-sm text-gray-700">{fmt(snap.capturedAt)}</span>
                    {snap.diff && Object.keys(snap.diff).length > 0 && (
                      <span className="text-xs text-gray-400">{Object.keys(snap.diff).length} properties changed</span>
                    )}
                  </div>
                  {isOpen ? <ChevronUp size={14} className="text-gray-400" /> : <ChevronDown size={14} className="text-gray-400" />}
                </button>

                {isOpen && (
                  <div className="border-t border-gray-100 p-4">
                    {snap.diff && Object.keys(snap.diff).length > 0 ? (
                      <>
                        <h4 className="text-sm font-semibold text-gray-800 mb-3 flex items-center gap-1.5">
                          <GitCompare size={14} className="text-blue-600" /> Property Changes
                        </h4>
                        <DiffViewer diff={snap.diff} />
                      </>
                    ) : (
                      <>
                        <h4 className="text-sm font-semibold text-gray-800 mb-3">Full Configuration at this Point</h4>
                        <JsonViewer data={snap.configState} maxHeight="300px" />
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Tab: Dependencies ────────────────────────────────────────────────────────

function DepsTab({ resourceId }: { resourceId: string }) {
  const { data: deps, isLoading } = useQuery({
    queryKey: ['resource-deps', resourceId],
    queryFn:  () => resourceInventoryApi.getDeps(resourceId),
    staleTime: 30_000,
  });

  if (isLoading) return (
    <div className="flex items-center justify-center h-40">
      <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
    </div>
  );

  const dependsOn = deps?.dependsOn ?? [];
  const usedBy    = deps?.usedBy    ?? [];

  if (dependsOn.length === 0 && usedBy.length === 0) return (
    <div className="flex flex-col items-center justify-center py-16 gap-2 text-gray-400">
      <Network className="h-10 w-10" />
      <p>No dependencies mapped yet. Run discovery to detect relationships.</p>
    </div>
  );

  function DepCard({ edge, direction }: { edge: typeof dependsOn[0]; direction: 'depends' | 'used' }) {
    const dcfg = DEP_TYPE_CONFIG[edge.depType as DependencyType] ?? DEP_TYPE_CONFIG.OTHER;
    const res  = edge.resource;
    const pcfg = PROVIDER_CONFIG[res.provider as keyof typeof PROVIDER_CONFIG];

    return (
      <Link
        to={`/resource-inventory/${res.id}`}
        className={`block border rounded-lg p-3 hover:shadow-sm transition-shadow ${res.state === 'DELETED' ? 'opacity-60' : ''}`}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs font-medium rounded border ${dcfg.color}`}>
                {dcfg.label}
              </span>
              {direction === 'depends' ? (
                <span className="text-xs text-gray-400">← this depends on</span>
              ) : (
                <span className="text-xs text-gray-400">→ used by</span>
              )}
            </div>
            <p className="text-sm font-medium text-gray-900 truncate">{res.resourceName ?? res.nativeId}</p>
            <p className="text-xs text-gray-400 truncate">{friendlyType(res.resourceType)}</p>
            {edge.description && <p className="text-xs text-gray-500 mt-0.5 italic">{edge.description}</p>}
          </div>
          <div className="shrink-0">
            {pcfg && (
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold rounded-full border ${pcfg.bg} ${pcfg.color} ${pcfg.border}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${pcfg.dot}`} /> {pcfg.label}
              </span>
            )}
          </div>
        </div>
      </Link>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-6">
      {/* Depends On */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
          <GitBranch size={14} className="text-blue-600" />
          Depends On ({dependsOn.length})
        </h3>
        <div className="space-y-2">
          {dependsOn.length === 0 ? (
            <p className="text-sm text-gray-400 italic">No outgoing dependencies.</p>
          ) : (
            dependsOn.map((edge) => <DepCard key={edge.id} edge={edge} direction="depends" />)
          )}
        </div>
      </div>
      {/* Used By */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
          <GitBranch size={14} className="text-green-600" />
          Used By ({usedBy.length})
        </h3>
        <div className="space-y-2">
          {usedBy.length === 0 ? (
            <p className="text-sm text-gray-400 italic">No incoming dependencies.</p>
          ) : (
            usedBy.map((edge) => <DepCard key={edge.id} edge={edge} direction="used" />)
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Tab: Config State ────────────────────────────────────────────────────────

function ConfigTab({ configState }: { configState: Record<string, unknown> }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500">Full configuration as returned by the cloud provider API</p>
      </div>
      <JsonViewer data={configState} maxHeight="600px" />
    </div>
  );
}

// ─── Main Detail Page ─────────────────────────────────────────────────────────

type TabId = 'config' | 'timeline' | 'deps' | 'graph';

export function ResourceDetail() {
  const { id }     = useParams<{ id: string }>();
  const navigate   = useNavigate();
  const [searchParams] = useState(() => new URLSearchParams(window.location.search));
  const initialTab = (searchParams.get('tab') as TabId | null) ?? 'config';
  const [tab, setTab] = useState<TabId>(initialTab);

  const { data: resource, isLoading } = useQuery({
    queryKey: ['resource-detail', id],
    queryFn:  () => resourceInventoryApi.getById(id!),
    enabled:  !!id,
    staleTime: 30_000,
  });

  if (isLoading) return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-2 border-blue-600 border-t-transparent" />
    </div>
  );

  if (!resource) return (
    <div className="flex flex-col items-center justify-center py-32 gap-2 text-gray-400">
      <Database className="h-12 w-12" />
      <p>Resource not found</p>
    </div>
  );

  const pcfg    = PROVIDER_CONFIG[resource.provider as keyof typeof PROVIDER_CONFIG];
  const isDeleted = resource.state === 'DELETED';

  const totalDeps = (resource._count?.depsFrom ?? 0) + (resource._count?.depsTo ?? 0);

  const TABS: { id: TabId; label: string; icon: typeof Database; count?: number }[] = [
    { id: 'config',   label: 'Configuration State', icon: Database },
    { id: 'timeline', label: 'Version Timeline',    icon: Clock,    count: resource._count?.snapshots },
    { id: 'deps',     label: 'Dependencies',        icon: GitBranch, count: totalDeps },
    { id: 'graph',    label: 'Relationship Graph',  icon: Share2,    count: totalDeps > 0 ? totalDeps : undefined },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <button
            onClick={() => navigate('/resource-inventory')}
            className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800 mb-1.5 transition-colors"
          >
            <ArrowLeft size={14} /> Resource Inventory
          </button>

          <div className="flex items-center gap-3 mb-1">
            {pcfg && (
              <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold border ${pcfg.bg} ${pcfg.color} ${pcfg.border}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${pcfg.dot}`} /> {pcfg.label}
              </span>
            )}
            <span className="text-xs text-gray-500 bg-gray-100 rounded px-2 py-0.5">{friendlyType(resource.resourceType)}</span>
            {isDeleted ? (
              <span className="inline-flex items-center gap-1 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-full px-2 py-0.5">
                <Trash2 size={10} /> Deleted {resource.deletedAt ? fmt(resource.deletedAt) : ''}
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-xs font-medium text-green-700 bg-green-50 border border-green-200 rounded-full px-2 py-0.5">
                <CheckCircle2 size={10} /> Active
              </span>
            )}
          </div>

          <h2 className="text-xl font-bold text-gray-900">{resource.resourceName ?? resource.nativeId}</h2>
          <p className="text-xs font-mono text-gray-400 mt-0.5">{resource.nativeId}</p>
        </div>
      </div>

      {/* Meta strip */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { icon: Tag,     label: 'Resource Type', value: friendlyType(resource.resourceType) },
          { icon: MapPin,  label: 'Region',        value: resource.region ?? '—' },
          { icon: Server,  label: 'Resource Group', value: resource.resourceGroup ?? '—' },
          { icon: Clock,   label: 'Discovered',    value: fmt(resource.discoveredAt) },
        ].map(({ icon: Icon, label, value }) => (
          <div key={label} className="bg-white border border-gray-200 rounded-lg px-4 py-3">
            <p className="text-xs text-gray-400 flex items-center gap-1 mb-0.5"><Icon size={11} /> {label}</p>
            <p className="text-sm font-medium text-gray-800 truncate" title={value}>{value}</p>
          </div>
        ))}
      </div>

      {/* Tags */}
      {resource.tags && Object.keys(resource.tags).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(resource.tags).map(([k, v]) => (
            <span key={k} className="inline-flex items-center gap-1 px-2 py-0.5 bg-gray-100 rounded text-xs text-gray-600">
              <span className="font-medium">{k}:</span> {v}
            </span>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div>
        <div className="flex items-center gap-0 border-b border-gray-200">
          {TABS.map((t) => {
            const TIcon = t.icon;
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
                  tab === t.id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
              >
                <TIcon size={13} />
                {t.label}
                {t.count != null && t.count > 0 && (
                  <span className="ml-1 text-xs text-gray-400">({t.count})</span>
                )}
              </button>
            );
          })}
        </div>

        <div className="mt-5">
          {tab === 'config'   && <ConfigTab   configState={resource.configState} />}
          {tab === 'timeline' && id && <TimelineTab resourceId={id} />}
          {tab === 'deps'     && id && <DepsTab     resourceId={id} />}
          {tab === 'graph'    && id && <ResourceGraph resourceId={id} resource={resource} />}
        </div>
      </div>
    </div>
  );
}

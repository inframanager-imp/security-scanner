import { useEffect, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  type Edge,
  type Node,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Network, RefreshCw, Globe, ShieldAlert, Database } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { accountsApi } from '../api/accounts';
import { azureApi } from '../api/azure';
import { gcpApi } from '../api/gcp';
import { resourceInventoryApi } from '../api/resourceInventory';
import { graphApi, type DependencyType, type GraphEdge, type GraphNode } from '../api/graphApi';

type Provider = 'AWS' | 'AZURE' | 'GCP';

const EDGE_COLORS: Record<DependencyType, string> = {
  NETWORK:          '#0ea5e9',
  IAM:              '#a855f7',
  STORAGE:          '#10b981',
  COMPUTE:          '#f59e0b',
  DATABASE:         '#ec4899',
  IDENTITY_ASSUME:  '#8b5cf6',
  IDENTITY_PERMITS: '#7c3aed',
  INTERNET_EXPOSURE:'#ef4444',
  ENCRYPTION_KEY:   '#14b8a6',
  CONTAINS_DATA:    '#06b6d4',
  RUNS_ON:          '#64748b',
  OTHER:            '#94a3b8',
};

const NODE_COLORS: Record<string, string> = {
  PUBLIC_INTERNET: '#fee2e2',
  HIGH:            '#fef3c7',
  CRITICAL:        '#fee2e2',
};

function radialLayout(nodes: GraphNode[], focalId: string | null): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  if (nodes.length === 0) return positions;
  const focal = focalId ? nodes.find((n) => n.id === focalId) : nodes[0];
  if (!focal) return positions;

  positions.set(focal.id, { x: 0, y: 0 });
  const others = nodes.filter((n) => n.id !== focal.id);
  const radius = Math.max(250, others.length * 22);
  others.forEach((node, i) => {
    const angle = (i / others.length) * Math.PI * 2;
    positions.set(node.id, {
      x: Math.cos(angle) * radius,
      y: Math.sin(angle) * radius,
    });
  });
  return positions;
}

function nodeBackground(node: GraphNode): string {
  if (node.exposureType === 'PUBLIC_INTERNET') return NODE_COLORS.PUBLIC_INTERNET;
  if (node.dataSensitivity === 'HIGH' || node.dataSensitivity === 'CRITICAL') return NODE_COLORS.HIGH;
  return '#ffffff';
}

function shortLabel(nativeId: string): string {
  // Strip ARN / Azure ID prefixes to show the last meaningful segment
  const arnTail = nativeId.split(':').pop() ?? nativeId;
  const pathTail = arnTail.split('/').pop() ?? arnTail;
  return pathTail.slice(0, 28);
}

export function AssetGraph() {
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState<Provider>('AWS');
  const [targetId, setTargetId] = useState<string>('');
  const [focusResourceId, setFocusResourceId] = useState<string>('');
  const [depth, setDepth] = useState<number>(2);
  const [edgeFilter, setEdgeFilter] = useState<Set<DependencyType>>(new Set());

  // Load accounts/subs/projects per provider
  const { data: awsAccounts = [] } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => accountsApi.list(),
    select: (d: any) => d?.data ?? [],
  });
  const { data: azureSubs = [] } = useQuery({
    queryKey: ['azure-subscriptions'],
    queryFn: () => azureApi.listSubscriptions({ limit: 200 }),
    select: (d: any) => d?.data ?? [],
  });
  const { data: gcpProjects = [] } = useQuery({
    queryKey: ['gcp-projects'],
    queryFn: () => gcpApi.listProjects({ limit: 200 }),
    select: (d: any) => d?.data ?? [],
  });

  const targets = useMemo(() => {
    if (provider === 'AWS')   return awsAccounts.map((a: any) => ({ id: a.id, label: `${a.name} (${a.awsAccountId})` }));
    if (provider === 'AZURE') return azureSubs.map((s: any) => ({ id: s.id, label: `${s.name} (${s.subscriptionId})` }));
    return gcpProjects.map((p: any) => ({ id: p.id, label: `${p.name} (${p.projectId})` }));
  }, [provider, awsAccounts, azureSubs, gcpProjects]);

  useEffect(() => {
    if (targets.length > 0 && !targetId) setTargetId(targets[0].id);
  }, [targets, targetId]);

  // Stats
  const { data: stats } = useQuery({
    queryKey: ['graph-stats', provider, targetId],
    queryFn: () => graphApi.stats(provider, targetId),
    enabled: Boolean(targetId),
    staleTime: 30_000,
  });

  // Exposed resources for the picker
  const { data: exposed = [] } = useQuery({
    queryKey: ['graph-exposed', provider, targetId],
    queryFn: () => graphApi.exposure(provider, targetId),
    enabled: Boolean(targetId),
    staleTime: 30_000,
  });

  // Resource list (first 50) so user can pick a node to inspect
  const { data: resources = [] } = useQuery({
    queryKey: ['graph-resources', provider, targetId],
    queryFn: () =>
      resourceInventoryApi.list({
        provider,
        targetId,
        page: 1,
        pageSize: 200,
      }),
    enabled: Boolean(targetId),
    select: (d: any) => d?.data ?? [],
    staleTime: 30_000,
  });

  useEffect(() => {
    if (resources.length > 0 && !focusResourceId) {
      setFocusResourceId(resources[0].id);
    }
  }, [resources, focusResourceId]);

  // Neighborhood subgraph
  const { data: subgraph, isLoading: subgraphLoading } = useQuery({
    queryKey: ['graph-neighborhood', focusResourceId, depth, Array.from(edgeFilter).sort()],
    queryFn: () =>
      graphApi.neighborhood(focusResourceId, {
        depth,
        edges: edgeFilter.size > 0 ? Array.from(edgeFilter) : undefined,
      }),
    enabled: Boolean(focusResourceId),
    staleTime: 15_000,
  });

  const rebuildMutation = useMutation({
    mutationFn: () => graphApi.build(provider, targetId),
    onSuccess: () => {
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['graph-stats', provider, targetId] });
        queryClient.invalidateQueries({ queryKey: ['graph-exposed', provider, targetId] });
        queryClient.invalidateQueries({ queryKey: ['graph-neighborhood'] });
      }, 4000);
    },
  });

  // Convert subgraph to react-flow nodes/edges
  const { rfNodes, rfEdges } = useMemo(() => {
    if (!subgraph) return { rfNodes: [] as Node[], rfEdges: [] as Edge[] };
    const positions = radialLayout(subgraph.nodes, focusResourceId);
    const rfNodes: Node[] = subgraph.nodes.map((n: GraphNode) => {
      const pos = positions.get(n.id) ?? { x: 0, y: 0 };
      const isFocus = n.id === focusResourceId;
      return {
        id: n.id,
        position: pos,
        data: {
          label: (
            <div className="text-xs">
              <div className="font-mono text-[10px] text-gray-500">{n.resourceType}</div>
              <div className="font-semibold">{shortLabel(n.nativeId)}</div>
              {n.exposureType === 'PUBLIC_INTERNET' && (
                <div className="mt-0.5 inline-flex items-center gap-1 text-[10px] text-red-700">
                  <Globe size={10} /> Public
                </div>
              )}
              {(n.dataSensitivity === 'HIGH' || n.dataSensitivity === 'CRITICAL') && (
                <div className="mt-0.5 inline-flex items-center gap-1 text-[10px] text-amber-700">
                  <Database size={10} /> Sensitive
                </div>
              )}
            </div>
          ) as any,
        },
        style: {
          background: nodeBackground(n),
          border: isFocus ? '2px solid #2563eb' : '1px solid #cbd5e1',
          borderRadius: 8,
          padding: 8,
          width: 200,
        },
      };
    });
    const rfEdges: Edge[] = subgraph.edges.map((e: GraphEdge, i: number) => ({
      id: `${e.fromId}->${e.toId}->${e.depType}->${i}`,
      source: e.fromId,
      target: e.toId,
      label: e.depType,
      labelStyle: { fontSize: 9, fill: EDGE_COLORS[e.depType] ?? '#475569' },
      style: { stroke: EDGE_COLORS[e.depType] ?? '#94a3b8', strokeWidth: 1.5 },
      markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_COLORS[e.depType] ?? '#94a3b8' },
      animated: e.depType === 'INTERNET_EXPOSURE',
    }));
    return { rfNodes, rfEdges };
  }, [subgraph, focusResourceId]);

  const allEdgeTypes: DependencyType[] = useMemo(
    () => Object.keys(EDGE_COLORS) as DependencyType[],
    [],
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <Network className="text-blue-600" size={28} />
            Asset Graph
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Unified resource graph: identity edges, internet exposure paths, encryption links, data flows.
          </p>
        </div>
        <Button
          variant="primary"
          onClick={() => rebuildMutation.mutate()}
          disabled={!targetId || rebuildMutation.isPending}
        >
          <RefreshCw size={14} className={rebuildMutation.isPending ? 'animate-spin' : ''} />
          {rebuildMutation.isPending ? 'Rebuilding…' : 'Rebuild graph'}
        </Button>
      </div>

      {/* Provider / account picker */}
      <Card>
        <div className="flex flex-wrap gap-4 items-end">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Provider</label>
            <select
              className="border rounded px-2 py-1 text-sm"
              value={provider}
              onChange={(e) => { setProvider(e.target.value as Provider); setTargetId(''); setFocusResourceId(''); }}
            >
              <option value="AWS">AWS</option>
              <option value="AZURE">Azure</option>
              <option value="GCP">GCP</option>
            </select>
          </div>

          <div className="flex-1 min-w-[260px]">
            <label className="block text-xs font-medium text-gray-600 mb-1">Account / Subscription / Project</label>
            <select
              className="border rounded px-2 py-1 text-sm w-full"
              value={targetId}
              onChange={(e) => { setTargetId(e.target.value); setFocusResourceId(''); }}
            >
              {targets.length === 0 && <option>No accounts</option>}
              {targets.map((t: { id: string; label: string }) => (
                <option key={t.id} value={t.id}>{t.label}</option>
              ))}
            </select>
          </div>

          <div className="flex-1 min-w-[260px]">
            <label className="block text-xs font-medium text-gray-600 mb-1">Focus resource</label>
            <select
              className="border rounded px-2 py-1 text-sm w-full"
              value={focusResourceId}
              onChange={(e) => setFocusResourceId(e.target.value)}
            >
              {resources.length === 0 && <option>No resources</option>}
              {resources.map((r: any) => (
                <option key={r.id} value={r.id}>
                  {r.resourceType} — {shortLabel(r.nativeId)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Depth</label>
            <input
              type="number"
              min={1}
              max={5}
              value={depth}
              onChange={(e) => setDepth(Math.max(1, Math.min(5, parseInt(e.target.value, 10) || 1)))}
              className="border rounded px-2 py-1 text-sm w-16"
            />
          </div>
        </div>

        {/* Edge type filter chips */}
        <div className="mt-4 flex flex-wrap gap-2">
          {allEdgeTypes.map((t) => {
            const active = edgeFilter.has(t);
            return (
              <button
                key={t}
                type="button"
                onClick={() => {
                  const next = new Set(edgeFilter);
                  if (active) next.delete(t); else next.add(t);
                  setEdgeFilter(next);
                }}
                className={`px-2 py-0.5 rounded-full text-xs font-medium ring-1 transition ${
                  active
                    ? 'text-white ring-transparent'
                    : 'bg-white text-gray-600 ring-gray-200 hover:ring-gray-400'
                }`}
                style={active ? { backgroundColor: EDGE_COLORS[t] } : undefined}
              >
                {t}
              </button>
            );
          })}
          {edgeFilter.size > 0 && (
            <button
              type="button"
              onClick={() => setEdgeFilter(new Set())}
              className="text-xs text-gray-500 underline ml-2"
            >
              Clear
            </button>
          )}
        </div>
      </Card>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <div className="text-xs text-gray-500">Resources</div>
          <div className="text-2xl font-semibold">{stats?.nodes ?? '—'}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-500">Edges</div>
          <div className="text-2xl font-semibold">
            {stats?.edgesByType.reduce((s, x) => s + x.count, 0) ?? '—'}
          </div>
        </Card>
        <Card>
          <div className="text-xs text-gray-500 flex items-center gap-1">
            <Globe size={12} /> Public exposed
          </div>
          <div className="text-2xl font-semibold text-red-600">{stats?.exposedCount ?? '—'}</div>
        </Card>
        <Card>
          <div className="text-xs text-gray-500 flex items-center gap-1">
            <ShieldAlert size={12} /> Most common edge
          </div>
          <div className="text-2xl font-semibold capitalize">
            {stats?.edgesByType[0]?.type?.toLowerCase().replace(/_/g, ' ') ?? '—'}
          </div>
        </Card>
      </div>

      {/* Graph canvas */}
      <Card>
        <div style={{ height: 560 }}>
          {subgraphLoading && (
            <div className="h-full flex items-center justify-center text-gray-500 text-sm">Loading graph…</div>
          )}
          {!subgraphLoading && rfNodes.length === 0 && (
            <div className="h-full flex flex-col items-center justify-center text-gray-500 text-sm">
              <Network size={32} className="mb-2 text-gray-300" />
              <div>No graph data yet for this resource.</div>
              <div className="text-xs mt-1">Run a scan or click "Rebuild graph" to populate edges.</div>
            </div>
          )}
          {!subgraphLoading && rfNodes.length > 0 && (
            <ReactFlow nodes={rfNodes} edges={rfEdges} fitView minZoom={0.2} maxZoom={1.5}>
              <Background gap={20} />
              <Controls />
            </ReactFlow>
          )}
        </div>
      </Card>

      {/* Exposed-resource list */}
      <Card title="Internet-exposed resources">
        {exposed.length === 0 ? (
          <div className="text-sm text-gray-500 py-4">
            No resources currently reachable from the public internet (or graph not yet built).
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-gray-500 border-b">
                <tr>
                  <th className="py-2">Resource</th>
                  <th>Type</th>
                  <th>Region</th>
                  <th>Path</th>
                  <th>Computed</th>
                </tr>
              </thead>
              <tbody>
                {exposed.map((row: any) => (
                  <tr
                    key={row.id}
                    className="border-b last:border-0 hover:bg-gray-50 cursor-pointer"
                    onClick={() => setFocusResourceId(row.resourceInventoryId)}
                  >
                    <td className="py-2 font-mono text-xs">{shortLabel(row.resource.nativeId)}</td>
                    <td className="text-xs">{row.resource.resourceType}</td>
                    <td className="text-xs">{row.resource.region ?? '—'}</td>
                    <td className="text-xs text-gray-500">
                      {row.pathJson.length} hop{row.pathJson.length === 1 ? '' : 's'}
                    </td>
                    <td className="text-xs">{new Date(row.computedAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

export default AssetGraph;

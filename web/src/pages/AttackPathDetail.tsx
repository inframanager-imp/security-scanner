import { useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import ReactFlow, { Background, Controls, MarkerType, type Edge, type Node } from 'reactflow';
import 'reactflow/dist/style.css';
import { ArrowLeft, Globe, Shield, ChevronRight } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { ciemApi, type AttackPathHop } from '../api/ciemApi';

const HOP_COLORS: Record<string, string> = {
  INTERNET_EXPOSURE: '#ef4444',
  IDENTITY_ASSUME:   '#8b5cf6',
  IDENTITY_PERMITS:  '#7c3aed',
  PRINCIPAL:         '#2563eb',
  NETWORK:           '#0ea5e9',
  COMPUTE:           '#f59e0b',
  STORAGE:           '#10b981',
  DATABASE:          '#ec4899',
  ENCRYPTION_KEY:    '#14b8a6',
  CONTAINS_DATA:     '#06b6d4',
  RUNS_ON:           '#64748b',
  IAM:               '#a855f7',
  OTHER:             '#94a3b8',
};

export function AttackPathDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: path, isLoading } = useQuery({
    queryKey: ['attack-path', id],
    queryFn: () => ciemApi.getAttackPath(id!),
    enabled: Boolean(id),
  });

  const { rfNodes, rfEdges } = useMemo(() => {
    if (!path) return { rfNodes: [] as Node[], rfEdges: [] as Edge[] };
    const hops = path.pathJson as AttackPathHop[];
    const xStep = 260;
    const rfNodes: Node[] = hops.map((h, i) => ({
      id: `${h.nodeId}-${i}`,
      position: { x: i * xStep, y: 0 },
      data: {
        label: (
          <div className="text-xs">
            <div className="font-mono text-[10px] text-gray-500">{h.edgeType}</div>
            <div className="font-semibold">{h.label.length > 28 ? h.label.slice(0, 26) + '…' : h.label}</div>
            <div className="text-[10px] text-gray-500 mt-1">{h.detail.slice(0, 60)}</div>
          </div>
        ) as any,
      },
      style: {
        background: i === 0 ? '#fee2e2' : i === hops.length - 1 ? '#dcfce7' : '#ffffff',
        border: '1px solid #cbd5e1',
        borderRadius: 8,
        padding: 8,
        width: 220,
      },
    }));
    const rfEdges: Edge[] = hops.slice(0, -1).map((h, i) => ({
      id: `e${i}`,
      source: `${h.nodeId}-${i}`,
      target: `${hops[i + 1].nodeId}-${i + 1}`,
      label: hops[i + 1].edgeType,
      labelStyle: { fontSize: 9 },
      style: { stroke: HOP_COLORS[hops[i + 1].edgeType] ?? '#94a3b8', strokeWidth: 1.5 },
      markerEnd: { type: MarkerType.ArrowClosed, color: HOP_COLORS[hops[i + 1].edgeType] ?? '#94a3b8' },
      animated: true,
    }));
    return { rfNodes, rfEdges };
  }, [path]);

  if (isLoading) {
    return <div className="p-6 text-sm text-gray-500">Loading attack path…</div>;
  }
  if (!path) {
    return (
      <div className="p-6">
        <Link to="/identity-graph" className="text-blue-600 text-sm inline-flex items-center gap-1">
          <ArrowLeft size={14} /> Back to Identity Graph
        </Link>
        <div className="mt-4 text-sm text-gray-500">Attack path not found.</div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <Link to="/identity-graph" className="text-blue-600 text-sm inline-flex items-center gap-1">
          <ArrowLeft size={14} /> Back to Identity Graph
        </Link>
      </div>

      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <Shield className="text-purple-600" size={24} />
            Attack Path — {path.kind.replace(/_/g, ' ')}
          </h1>
          <p className="text-sm text-gray-600 mt-2">{path.summary}</p>
        </div>
        <div className="flex gap-2 items-center">
          <span className="px-2 py-0.5 rounded-md text-xs font-semibold bg-red-100 text-red-800 ring-1 ring-red-200">
            {path.severity}
          </span>
          <span className="px-2 py-0.5 rounded-md text-xs ring-1 bg-gray-50 text-gray-700 ring-gray-200">
            {path.status}
          </span>
        </div>
      </div>

      <Card title="Path visualization">
        <div style={{ height: 360 }}>
          {rfNodes.length === 0 ? (
            <div className="h-full flex items-center justify-center text-gray-500 text-sm">No path data</div>
          ) : (
            <ReactFlow nodes={rfNodes} edges={rfEdges} fitView minZoom={0.4} maxZoom={1.5}>
              <Background gap={20} />
              <Controls />
            </ReactFlow>
          )}
        </div>
      </Card>

      <Card title="Hop-by-hop breakdown">
        <div className="space-y-3">
          {(path.pathJson as AttackPathHop[]).map((h, i) => (
            <div key={i} className="flex items-start gap-3">
              <div className="flex-none w-8 h-8 rounded-full bg-blue-50 text-blue-700 text-sm font-semibold flex items-center justify-center">
                {i + 1}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span
                    className="text-xs px-1.5 py-0.5 rounded font-mono"
                    style={{
                      backgroundColor: (HOP_COLORS[h.edgeType] ?? '#94a3b8') + '22',
                      color: HOP_COLORS[h.edgeType] ?? '#94a3b8',
                    }}
                  >
                    {h.edgeType}
                  </span>
                  <span className="font-semibold text-sm">{h.label}</span>
                </div>
                <div className="text-xs text-gray-600 mt-1">{h.detail}</div>
              </div>
              {i < (path.pathJson as AttackPathHop[]).length - 1 && (
                <ChevronRight className="text-gray-300 mt-1" size={20} />
              )}
            </div>
          ))}
        </div>
      </Card>

      <Card title="Notes">
        <div className="text-sm text-gray-600">{path.notes ?? '—'}</div>
      </Card>

      <Card title="Timeline">
        <div className="text-xs text-gray-600 space-y-1">
          <div className="flex items-center gap-2">
            <Globe size={12} /> First seen: {new Date(path.firstSeenAt).toLocaleString()}
          </div>
          <div className="flex items-center gap-2">
            <Globe size={12} /> Last seen:  {new Date(path.lastSeenAt).toLocaleString()}
          </div>
        </div>
      </Card>
    </div>
  );
}

export default AttackPathDetail;

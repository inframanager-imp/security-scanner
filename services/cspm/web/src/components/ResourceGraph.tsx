/**
 * ResourceGraph — pure-SVG radial relationship graph for a single resource.
 *
 * Layout:
 *   - Focal resource: centre
 *   - "Depends On" resources: left arc  (angles 120°–240°)
 *   - "Used By"    resources: right arc (angles -60°–60°)
 *
 * No external graph library required.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Network, ExternalLink, Info } from 'lucide-react';
import { resourceInventoryApi } from '../api/resourceInventory';
import type { DependencyType, ResourceDetail } from '../types';

// ─── Constants ────────────────────────────────────────────────────────────────

const W  = 720;
const H  = 430;
const CX = W / 2;
const CY = H / 2;
const RADIUS = 165;

const FOCAL_R = 26;
const NODE_R  = 20;

const PROVIDER_STYLE: Record<string, { fill: string; stroke: string; badge: string; text: string }> = {
  AWS:   { fill: '#fff7ed', stroke: '#ea580c', badge: '#fed7aa', text: '#9a3412' },
  AZURE: { fill: '#eff6ff', stroke: '#2563eb', badge: '#bfdbfe', text: '#1e40af' },
  GCP:   { fill: '#f0fdf4', stroke: '#16a34a', badge: '#bbf7d0', text: '#14532d' },
};

const DEP_COLOR: Record<DependencyType, string> = {
  NETWORK:  '#3b82f6',
  IAM:      '#7c3aed',
  STORAGE:  '#d97706',
  COMPUTE:  '#16a34a',
  DATABASE: '#dc2626',
  OTHER:    '#6b7280',
};

const DEP_LABEL: Record<DependencyType, string> = {
  NETWORK:  'Network',
  IAM:      'IAM',
  STORAGE:  'Storage',
  COMPUTE:  'Compute',
  DATABASE: 'Database',
  OTHER:    'Other',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function truncate(s: string, max: number) {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function nodeLabel(name: string | null | undefined, nativeId: string) {
  const s = name ?? (nativeId.includes('/') ? nativeId.split('/').pop()! : nativeId);
  return truncate(s, 15);
}

function typeLabel(rt: string) {
  const s = rt
    .replace(/^AWS::/, '')
    .replace(/^Microsoft\./, '')
    .replace(/\.googleapis\.com/, '')
    .replace(/\//g, '/')
    .replace(/::/g, '/');
  const parts = s.split('/');
  return truncate(parts[parts.length - 1] ?? s, 14);
}

// ─── Layout builder ───────────────────────────────────────────────────────────

interface GNode {
  id:       string;
  label:    string;
  sub:      string;
  provider: string;
  state:    string;
  isFocal:  boolean;
  x:        number;
  y:        number;
}

interface GEdge {
  id:      string;
  fromId:  string;
  toId:    string;
  depType: DependencyType;
}

function buildLayout(
  resource: ResourceDetail,
  dependsOn: { id: string; depType: DependencyType; resource: { id: string; resourceType: string; resourceName?: string | null; nativeId: string; provider: string; state: string } }[],
  usedBy:    { id: string; depType: DependencyType; resource: { id: string; resourceType: string; resourceName?: string | null; nativeId: string; provider: string; state: string } }[],
): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];

  // Focal node
  nodes.push({
    id:       resource.id,
    label:    nodeLabel(resource.resourceName, resource.nativeId),
    sub:      typeLabel(resource.resourceType),
    provider: resource.provider,
    state:    resource.state,
    isFocal:  true,
    x:        CX,
    y:        CY,
  });

  // dependsOn → left arc 120°..240°
  const doN = dependsOn.length;
  dependsOn.forEach((edge, i) => {
    const angle = doN === 1
      ? Math.PI
      : (2 * Math.PI / 3) + (Math.PI / 3) * 2 * (i / (doN - 1));
    nodes.push({
      id:       edge.resource.id,
      label:    nodeLabel(edge.resource.resourceName, edge.resource.nativeId),
      sub:      typeLabel(edge.resource.resourceType),
      provider: edge.resource.provider,
      state:    edge.resource.state,
      isFocal:  false,
      x:        CX + RADIUS * Math.cos(angle),
      y:        CY + RADIUS * Math.sin(angle),
    });
    edges.push({ id: edge.id, fromId: resource.id, toId: edge.resource.id, depType: edge.depType });
  });

  // usedBy → right arc -60°..60°
  const ubN = usedBy.length;
  usedBy.forEach((edge, i) => {
    const angle = ubN === 1
      ? 0
      : (-Math.PI / 3) + (2 * Math.PI / 3) * (i / (ubN - 1));
    nodes.push({
      id:       edge.resource.id,
      label:    nodeLabel(edge.resource.resourceName, edge.resource.nativeId),
      sub:      typeLabel(edge.resource.resourceType),
      provider: edge.resource.provider,
      state:    edge.resource.state,
      isFocal:  false,
      x:        CX + RADIUS * Math.cos(angle),
      y:        CY + RADIUS * Math.sin(angle),
    });
    // edge direction: usedBy resource → focal
    edges.push({ id: edge.id, fromId: edge.resource.id, toId: resource.id, depType: edge.depType });
  });

  return { nodes, edges };
}

// ─── SVG helpers ──────────────────────────────────────────────────────────────

/** Arrow marker defs — one per dep type colour */
function Markers() {
  return (
    <defs>
      {(Object.entries(DEP_COLOR) as [DependencyType, string][]).map(([t, c]) => (
        <marker
          key={t}
          id={`arr-${t}`}
          markerWidth="7" markerHeight="7"
          refX="5.5" refY="3.5"
          orient="auto"
        >
          <path d="M0,0.5 L0,6.5 L7,3.5 z" fill={c} />
        </marker>
      ))}
    </defs>
  );
}

/** A single edge: straight line with arrow + centre type label */
function SvgEdge({ edge, nodes }: { edge: GEdge; nodes: GNode[] }) {
  const from = nodes.find((n) => n.id === edge.fromId)!;
  const to   = nodes.find((n) => n.id === edge.toId)!;
  if (!from || !to) return null;

  const color = DEP_COLOR[edge.depType];
  const fromR = from.isFocal ? FOCAL_R : NODE_R;
  const toR   = to.isFocal   ? FOCAL_R : NODE_R;

  const dx  = to.x - from.x;
  const dy  = to.y - from.y;
  const len = Math.hypot(dx, dy);
  if (len < 1) return null;

  const ux = dx / len, uy = dy / len;
  const sx = from.x + ux * fromR;
  const sy = from.y + uy * fromR;
  const ex = to.x   - ux * (toR + 5);
  const ey = to.y   - uy * (toR + 5);
  const mx = (sx + ex) / 2;
  const my = (sy + ey) / 2;

  return (
    <g>
      <line
        x1={sx} y1={sy} x2={ex} y2={ey}
        stroke={color} strokeWidth={1.5} strokeOpacity={0.65}
        markerEnd={`url(#arr-${edge.depType})`}
      />
      {/* pill label */}
      <rect x={mx - 23} y={my - 7} width={46} height={14} rx={4}
        fill="white" fillOpacity={0.9} stroke={color} strokeWidth={0.6} strokeOpacity={0.5} />
      <text x={mx} y={my + 4} textAnchor="middle"
        fontSize={8} fontWeight="600" fill={color}>
        {DEP_LABEL[edge.depType]}
      </text>
    </g>
  );
}

/** A single node: circle + label + sub-label + provider badge */
function SvgNode({
  node,
  isHovered,
  onEnter,
  onLeave,
  onClick,
}: {
  node:      GNode;
  isHovered: boolean;
  onEnter:   () => void;
  onLeave:   () => void;
  onClick:   () => void;
}) {
  const style     = PROVIDER_STYLE[node.provider] ?? PROVIDER_STYLE.AWS;
  const r         = node.isFocal ? FOCAL_R : NODE_R;
  const isDeleted = node.state === 'DELETED';

  return (
    <g
      transform={`translate(${node.x},${node.y})`}
      style={{ cursor: node.isFocal ? 'default' : 'pointer' }}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
      onClick={node.isFocal ? undefined : onClick}
    >
      {/* hover glow */}
      {isHovered && !node.isFocal && (
        <circle r={r + 5} fill={style.stroke} fillOpacity={0.12} />
      )}

      {/* main circle */}
      <circle
        r={r}
        fill={isDeleted ? '#f9fafb' : style.fill}
        stroke={isDeleted ? '#9ca3af' : style.stroke}
        strokeWidth={node.isFocal ? 2.5 : 1.5}
        strokeDasharray={isDeleted ? '4,2' : undefined}
      />

      {/* focal inner ring */}
      {node.isFocal && (
        <circle r={r - 5} fill="none" stroke={style.stroke} strokeWidth={0.8} strokeOpacity={0.4} />
      )}

      {/* provider badge above */}
      <rect
        x={-12} y={-(r + 15)} width={24} height={11} rx={3}
        fill={style.badge}
      />
      <text
        y={-(r + 7)} textAnchor="middle"
        fontSize={7} fontWeight="700" fill={style.text}
      >
        {node.provider}
      </text>

      {/* resource name below */}
      <text
        y={r + 12} textAnchor="middle"
        fontSize={9} fontWeight={node.isFocal ? '700' : '500'}
        fill={isDeleted ? '#9ca3af' : '#111827'}
      >
        {node.label}
      </text>

      {/* type sub-label */}
      <text
        y={r + 22} textAnchor="middle"
        fontSize={7.5} fill="#9ca3af"
      >
        {node.sub}
      </text>
    </g>
  );
}

// ─── Public component ─────────────────────────────────────────────────────────

interface ResourceGraphProps {
  resourceId: string;
  resource:   ResourceDetail;
}

export function ResourceGraph({ resourceId, resource }: ResourceGraphProps) {
  const navigate    = useNavigate();
  const [hovered, setHovered] = useState<string | null>(null);

  const { data: deps, isLoading } = useQuery({
    queryKey: ['resource-deps', resourceId],
    queryFn:  () => resourceInventoryApi.getDeps(resourceId),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-56">
        <div className="animate-spin rounded-full h-7 w-7 border-2 border-blue-600 border-t-transparent" />
      </div>
    );
  }

  const dependsOn = deps?.dependsOn ?? [];
  const usedBy    = deps?.usedBy    ?? [];

  if (dependsOn.length === 0 && usedBy.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 gap-3 text-gray-400">
        <Network className="h-10 w-10" />
        <p className="text-sm font-medium">No relationships mapped for this resource.</p>
        <p className="text-xs">Run Resource Discovery to detect dependencies automatically.</p>
      </div>
    );
  }

  const { nodes, edges } = buildLayout(resource, dependsOn, usedBy);
  const usedTypes = [...new Set(edges.map((e) => e.depType))];
  const hoveredNode = hovered ? nodes.find((n) => n.id === hovered) : null;

  return (
    <div className="space-y-3">
      {/* Top bar: legend + direction labels */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-gray-400">Edge types:</span>
        {usedTypes.map((t) => (
          <span
            key={t}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold border"
            style={{
              color:           DEP_COLOR[t],
              borderColor:     DEP_COLOR[t] + '55',
              backgroundColor: DEP_COLOR[t] + '11',
            }}
          >
            {DEP_LABEL[t]}
          </span>
        ))}
        <div className="ml-auto flex items-center gap-4 text-xs text-gray-500">
          <span>
            ← <span className="font-semibold text-gray-700">Depends On</span>
            <span className="text-gray-400 ml-1">({dependsOn.length})</span>
          </span>
          <span>
            <span className="font-semibold text-gray-700">Used By</span> →
            <span className="text-gray-400 ml-1">({usedBy.length})</span>
          </span>
        </div>
      </div>

      {/* SVG graph */}
      <div className="border border-gray-200 rounded-xl bg-white overflow-hidden shadow-sm">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width="100%"
          style={{ display: 'block', maxHeight: `${H}px` }}
          aria-label="Resource relationship graph"
        >
          <Markers />

          {/* dot-grid background */}
          <defs>
            <pattern id="rg-dots" width="22" height="22" patternUnits="userSpaceOnUse">
              <circle cx="11" cy="11" r="0.8" fill="#e5e7eb" />
            </pattern>
          </defs>
          <rect width={W} height={H} fill="url(#rg-dots)" />

          {/* side labels */}
          <text
            x={22} y={CY}
            textAnchor="middle" fontSize={9} fill="#d1d5db" fontWeight="600" letterSpacing="1.5"
            transform={`rotate(-90, 22, ${CY})`}
          >
            DEPENDS ON
          </text>
          <text
            x={W - 22} y={CY}
            textAnchor="middle" fontSize={9} fill="#d1d5db" fontWeight="600" letterSpacing="1.5"
            transform={`rotate(90, ${W - 22}, ${CY})`}
          >
            USED BY
          </text>

          {/* edges (drawn before nodes so nodes sit on top) */}
          {edges.map((e) => <SvgEdge key={e.id} edge={e} nodes={nodes} />)}

          {/* nodes */}
          {nodes.map((n) => (
            <SvgNode
              key={n.id}
              node={n}
              isHovered={hovered === n.id}
              onEnter={() => setHovered(n.id)}
              onLeave={() => setHovered(null)}
              onClick={() => navigate(`/resource-inventory/${n.id}`)}
            />
          ))}
        </svg>
      </div>

      {/* Hover details bar */}
      {hoveredNode && !hoveredNode.isFocal ? (
        <div className="flex items-center justify-between bg-blue-50 border border-blue-200 rounded-lg px-4 py-2.5">
          <div className="flex items-center gap-2 text-sm">
            <span
              className="px-2 py-0.5 rounded-full text-xs font-bold"
              style={{ background: (PROVIDER_STYLE[hoveredNode.provider] ?? PROVIDER_STYLE.AWS).badge, color: (PROVIDER_STYLE[hoveredNode.provider] ?? PROVIDER_STYLE.AWS).text }}
            >
              {hoveredNode.provider}
            </span>
            <span className="font-semibold text-gray-900">{hoveredNode.label}</span>
            <span className="text-gray-400">·</span>
            <span className="text-gray-500 text-xs">{hoveredNode.sub}</span>
            {hoveredNode.state === 'DELETED' && (
              <span className="text-xs text-red-500 font-medium">(deleted)</span>
            )}
          </div>
          <button
            onClick={() => navigate(`/resource-inventory/${hoveredNode.id}`)}
            className="flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-800 font-semibold transition-colors"
          >
            <ExternalLink size={11} /> Open resource
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-1.5 text-xs text-gray-400 px-1">
          <Info size={11} />
          Hover a node to see details · Click to open that resource
        </div>
      )}
    </div>
  );
}

import { api } from './client';

export type DependencyType =
  | 'NETWORK'
  | 'IAM'
  | 'STORAGE'
  | 'COMPUTE'
  | 'DATABASE'
  | 'IDENTITY_ASSUME'
  | 'IDENTITY_PERMITS'
  | 'INTERNET_EXPOSURE'
  | 'ENCRYPTION_KEY'
  | 'CONTAINS_DATA'
  | 'RUNS_ON'
  | 'OTHER';

export type ExposureType = 'PUBLIC_INTERNET' | 'VPN_ONLY' | 'PRIVATE';

export interface GraphNode {
  id: string;
  nativeId: string;
  resourceType: string;
  region: string | null;
  exposureType?: ExposureType | null;
  dataSensitivity?: string | null;
}

export interface GraphEdge {
  fromId: string;
  toId: string;
  depType: DependencyType;
  description: string | null;
  principalArn: string | null;
  actions: string[];
}

export interface NeighborhoodResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ExposedResource {
  id: string;
  resourceInventoryId: string;
  provider: string;
  exposureType: ExposureType;
  pathJson: Array<{
    nodeId: string;
    resourceType: string;
    edgeType: string;
    detail: string;
  }>;
  entryPoint: string | null;
  computedAt: string;
  resource: {
    id: string;
    nativeId: string;
    resourceType: string;
    region: string | null;
    dataSensitivity: string | null;
  };
}

export interface GraphStats {
  nodes: number;
  edgesByType: Array<{ type: DependencyType; count: number }>;
  exposedCount: number;
}

export const graphApi = {
  build: (provider: 'AWS' | 'AZURE' | 'GCP', targetId: string) =>
    api.post<{ jobId: string; status: string }>(
      `/graph/build/${provider}/${targetId}`,
    ),

  neighborhood: (
    resourceId: string,
    opts: { edges?: DependencyType[]; depth?: number; direction?: 'in' | 'out' | 'both' } = {},
  ) => {
    const params = new URLSearchParams();
    if (opts.edges?.length) params.set('edges', opts.edges.join(','));
    if (opts.depth) params.set('depth', String(opts.depth));
    if (opts.direction) params.set('direction', opts.direction);
    const qs = params.toString();
    return api.get<NeighborhoodResponse>(
      `/graph/resource/${resourceId}${qs ? `?${qs}` : ''}`,
    );
  },

  exposure: (provider: 'AWS' | 'AZURE' | 'GCP', targetId: string) =>
    api.get<ExposedResource[]>(`/graph/exposure/${provider}/${targetId}`),

  edgeTypes: () => api.get<DependencyType[]>('/graph/edge-types'),

  stats: (provider: 'AWS' | 'AZURE' | 'GCP', targetId: string) =>
    api.get<GraphStats>(`/graph/stats/${provider}/${targetId}`),
};

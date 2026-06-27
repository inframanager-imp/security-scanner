/**
 * Graph Enrichment Service
 *
 * Builds the unified asset graph that powers CIEM, vulnerability prioritization,
 * and compliance evidence:
 *
 *   1. buildIdentityEdges() — reads ResourceInventory configState for IAM Roles/Users/Policies
 *      and creates IDENTITY_ASSUME + IDENTITY_PERMITS edges into ResourceDependency.
 *
 *   2. buildEncryptionEdges() — links resources to their KMS keys via ENCRYPTION_KEY edges.
 *
 *   3. computeExposurePaths() — walks the graph from internet entry points
 *      (public ALBs, CloudFront distributions, public-IP EC2s, public S3) inward
 *      and materializes one ExposurePath row per (resource, exposureType).
 *
 *   4. queryNeighborhood() — BFS subgraph extraction for the Asset Graph UI and
 *      attack-path detection rules.
 *
 * The service is provider-agnostic at the boundary; internal helpers branch on
 * `provider` for the cloud-specific configState shapes.
 */

import { prisma } from '../config/database';
import { logger } from '../config/logger';
import { DependencyType, ExposureType, Prisma } from '@prisma/client';

type Provider = 'AWS' | 'AZURE' | 'GCP';

interface ResourceLite {
  id: string;
  nativeId: string;
  resourceType: string;
  configState: any;
  region: string | null;
}

const PUBLIC_CIDRS = ['0.0.0.0/0', '::/0'];

// ─── Public entry points ─────────────────────────────────────────────────────

export async function buildGraphForAccount(
  provider: Provider,
  accountId: string,
): Promise<{
  identityEdges: number;
  encryptionEdges: number;
  exposurePaths: number;
}> {
  const startedAt = Date.now();
  logger.info('graphEnrichment.start', { provider, accountId });

  const identityEdges = await buildIdentityEdges(provider, accountId);
  const encryptionEdges = await buildEncryptionEdges(provider, accountId);
  const exposurePaths = await computeExposurePaths(provider, accountId);

  logger.info('graphEnrichment.done', {
    provider,
    accountId,
    identityEdges,
    encryptionEdges,
    exposurePaths,
    elapsedMs: Date.now() - startedAt,
  });

  return { identityEdges, encryptionEdges, exposurePaths };
}

// ─── Identity edges ──────────────────────────────────────────────────────────

export async function buildIdentityEdges(
  provider: Provider,
  accountId: string,
): Promise<number> {
  const resources = await loadResources(provider, accountId);
  const byNativeId = new Map(resources.map((r) => [r.nativeId, r]));

  let edgeCount = 0;
  const edgeBatch: Prisma.ResourceDependencyCreateManyInput[] = [];

  for (const r of resources) {
    // AWS IAM Role: extract trust policy → IDENTITY_ASSUME edges
    if (provider === 'AWS' && r.resourceType === 'AWS::IAM::Role') {
      const trustPolicy = r.configState?.AssumeRolePolicyDocument ?? r.configState?.assumeRolePolicyDocument;
      const statements = normalizeStatements(trustPolicy);
      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;
        const principals = extractPrincipals(stmt.Principal);
        for (const p of principals) {
          const fromResource = byNativeId.get(p.arn);
          if (fromResource) {
            edgeBatch.push({
              fromId: fromResource.id,
              toId: r.id,
              depType: DependencyType.IDENTITY_ASSUME,
              provider,
              principalType: p.type,
              description: `Principal can assume role ${r.nativeId}`,
            });
          } else {
            // Cross-account or service principal not in inventory — still record on the role itself
            edgeBatch.push({
              fromId: r.id,
              toId: r.id,
              depType: DependencyType.IDENTITY_ASSUME,
              provider,
              principalType: p.type,
              principalArn: p.arn,
              description: `External principal ${p.arn} can assume role`,
            });
          }
        }
      }
    }

    // AWS IAM Role/User: attached managed policies create IDENTITY_PERMITS edges
    // configState typically contains AttachedManagedPolicies + Policies (inline)
    if (
      provider === 'AWS' &&
      (r.resourceType === 'AWS::IAM::Role' ||
        r.resourceType === 'AWS::IAM::User' ||
        r.resourceType === 'AWS::IAM::Group')
    ) {
      const attached = r.configState?.AttachedManagedPolicies ?? r.configState?.attachedManagedPolicies ?? [];
      for (const p of attached) {
        const policyArn = p.PolicyArn ?? p.policyArn ?? p.arn;
        if (!policyArn) continue;
        const policyResource = byNativeId.get(policyArn);
        if (policyResource) {
          edgeBatch.push({
            fromId: r.id,
            toId: policyResource.id,
            depType: DependencyType.IDENTITY_PERMITS,
            provider,
            description: `${r.resourceType} attached to policy ${p.PolicyName ?? policyArn}`,
          });
        }
      }
    }

    // Azure: roleAssignments on resources → IDENTITY_PERMITS
    if (provider === 'AZURE') {
      const roleAssignments = r.configState?.roleAssignments ?? [];
      for (const ra of roleAssignments) {
        if (!ra.principalId) continue;
        edgeBatch.push({
          fromId: r.id,
          toId: r.id,
          depType: DependencyType.IDENTITY_PERMITS,
          provider,
          principalArn: ra.principalId,
          principalType: ra.principalType ?? 'SERVICE_PRINCIPAL',
          actions: [ra.roleDefinitionName ?? 'unknown'].filter(Boolean),
          description: `${ra.principalType ?? 'principal'} has ${ra.roleDefinitionName ?? 'role'} on ${r.nativeId}`,
        });
      }
    }

    // GCP: iamPolicy bindings on resource → IDENTITY_PERMITS
    if (provider === 'GCP') {
      const bindings = r.configState?.iamPolicy?.bindings ?? [];
      for (const b of bindings) {
        const role = b.role;
        for (const member of b.members ?? []) {
          edgeBatch.push({
            fromId: r.id,
            toId: r.id,
            depType: DependencyType.IDENTITY_PERMITS,
            provider,
            principalArn: member,
            principalType: classifyGcpMember(member),
            actions: [role].filter(Boolean),
            description: `${member} has ${role} on ${r.nativeId}`,
          });
        }
      }
    }
  }

  // Insert in chunks with skipDuplicates to honor the (fromId,toId,depType) unique index
  for (const chunk of chunked(edgeBatch, 500)) {
    const result = await prisma.resourceDependency.createMany({
      data: chunk,
      skipDuplicates: true,
    });
    edgeCount += result.count;
  }

  return edgeCount;
}

// ─── Encryption edges ────────────────────────────────────────────────────────

export async function buildEncryptionEdges(
  provider: Provider,
  accountId: string,
): Promise<number> {
  const resources = await loadResources(provider, accountId);
  const byNativeId = new Map(resources.map((r) => [r.nativeId, r]));

  const edges: Prisma.ResourceDependencyCreateManyInput[] = [];
  for (const r of resources) {
    const keyId = extractKmsKey(provider, r);
    if (!keyId) continue;
    const key = byNativeId.get(keyId);
    if (!key) continue;
    edges.push({
      fromId: r.id,
      toId: key.id,
      depType: DependencyType.ENCRYPTION_KEY,
      provider,
      description: `${r.resourceType} encrypted with key ${key.nativeId}`,
    });
  }

  let count = 0;
  for (const chunk of chunked(edges, 500)) {
    const result = await prisma.resourceDependency.createMany({
      data: chunk,
      skipDuplicates: true,
    });
    count += result.count;
  }
  return count;
}

function extractKmsKey(provider: Provider, r: ResourceLite): string | null {
  const c = r.configState ?? {};
  if (provider === 'AWS') {
    return (
      c.KmsKeyId ?? c.kmsKeyId ?? c.KmsKeyArn ?? c.KMSKeyArn ?? c.kmsMasterKeyId ?? null
    );
  }
  if (provider === 'AZURE') {
    return c.encryption?.keyVaultProperties?.keyUri ?? c.encryption?.keyVaultKeyUri ?? null;
  }
  if (provider === 'GCP') {
    return c.kmsKeyName ?? c.encryption?.kmsKeyName ?? null;
  }
  return null;
}

// ─── Exposure paths ──────────────────────────────────────────────────────────

interface Hop {
  nodeId: string;
  resourceType: string;
  edgeType: string;
  detail: string;
}

export async function computeExposurePaths(
  provider: Provider,
  accountId: string,
): Promise<number> {
  const resources = await loadResources(provider, accountId);
  if (resources.length === 0) return 0;

  // Build adjacency from existing ResourceDependency rows (all edge types)
  const deps = await prisma.resourceDependency.findMany({
    where: { provider, fromResource: providerFilter(provider, accountId) },
    select: { fromId: true, toId: true, depType: true, description: true },
  });
  const adjacency = new Map<string, { to: string; depType: string; detail: string }[]>();
  for (const d of deps) {
    if (!adjacency.has(d.fromId)) adjacency.set(d.fromId, []);
    adjacency.get(d.fromId)!.push({ to: d.toId, depType: d.depType, detail: d.description ?? '' });
  }

  // Identify entry points: resources directly reachable from internet
  const entryPoints: ResourceLite[] = [];
  for (const r of resources) {
    if (isInternetExposed(provider, r)) entryPoints.push(r);
  }

  // BFS from each entry point; cap depth at 6 hops
  const exposureByResource = new Map<string, Hop[]>();
  for (const entry of entryPoints) {
    const initial: Hop = {
      nodeId: entry.id,
      resourceType: entry.resourceType,
      edgeType: 'INTERNET_EXPOSURE',
      detail: 'Internet-facing entry point',
    };
    if (!exposureByResource.has(entry.id)) {
      exposureByResource.set(entry.id, [initial]);
    }
    bfsExposure(entry.id, adjacency, exposureByResource, initial);
  }

  // Persist ExposurePath rows
  const rows: Prisma.ExposurePathCreateManyInput[] = [];
  for (const [resourceId, path] of exposureByResource) {
    rows.push({
      resourceInventoryId: resourceId,
      provider,
      exposureType: ExposureType.PUBLIC_INTERNET,
      pathJson: path as unknown as Prisma.JsonArray,
      entryPoint: path[0]?.detail ?? null,
    });
  }

  // Wipe stale public-internet paths for this account (we just recomputed)
  await prisma.exposurePath.deleteMany({
    where: {
      provider,
      exposureType: ExposureType.PUBLIC_INTERNET,
      resource: providerFilter(provider, accountId),
    },
  });

  let count = 0;
  for (const chunk of chunked(rows, 500)) {
    const result = await prisma.exposurePath.createMany({
      data: chunk,
      skipDuplicates: true,
    });
    count += result.count;
  }
  return count;
}

function bfsExposure(
  startId: string,
  adjacency: Map<string, { to: string; depType: string; detail: string }[]>,
  exposureByResource: Map<string, Hop[]>,
  startHop: Hop,
): void {
  const queue: { id: string; path: Hop[] }[] = [{ id: startId, path: [startHop] }];
  const visited = new Set<string>([startId]);
  while (queue.length > 0) {
    const { id, path } = queue.shift()!;
    if (path.length > 6) continue;
    const neighbors = adjacency.get(id) ?? [];
    for (const n of neighbors) {
      if (visited.has(n.to)) continue;
      // Only follow edges that represent network reachability or trust
      if (
        n.depType !== DependencyType.NETWORK &&
        n.depType !== DependencyType.IDENTITY_ASSUME &&
        n.depType !== DependencyType.COMPUTE &&
        n.depType !== DependencyType.RUNS_ON
      ) {
        continue;
      }
      visited.add(n.to);
      const nextHop: Hop = {
        nodeId: n.to,
        resourceType: '',
        edgeType: n.depType,
        detail: n.detail,
      };
      const nextPath = [...path, nextHop];
      // Mark this neighbor as exposed if we haven't already recorded a shorter path
      const existing = exposureByResource.get(n.to);
      if (!existing || existing.length > nextPath.length) {
        exposureByResource.set(n.to, nextPath);
      }
      queue.push({ id: n.to, path: nextPath });
    }
  }
}

function isInternetExposed(provider: Provider, r: ResourceLite): boolean {
  const c = r.configState ?? {};
  if (provider === 'AWS') {
    if (r.resourceType === 'AWS::CloudFront::Distribution') return true;
    if (
      r.resourceType === 'AWS::ElasticLoadBalancingV2::LoadBalancer' &&
      (c.Scheme ?? c.scheme) === 'internet-facing'
    ) return true;
    if (r.resourceType === 'AWS::EC2::Instance' && (c.PublicIpAddress || c.publicIpAddress)) return true;
    if (r.resourceType === 'AWS::S3::Bucket') {
      const pab = c.PublicAccessBlock ?? c.publicAccessBlock;
      const blocksAll =
        pab && pab.BlockPublicAcls && pab.BlockPublicPolicy && pab.IgnorePublicAcls && pab.RestrictPublicBuckets;
      if (!blocksAll) return Boolean(c.isPublic ?? c.IsPublic ?? false);
    }
    if (r.resourceType === 'AWS::EC2::SecurityGroup') {
      const ingress = c.IpPermissions ?? c.ipPermissions ?? [];
      for (const rule of ingress) {
        const ranges = (rule.IpRanges ?? rule.ipRanges ?? []).map((x: any) => x.CidrIp ?? x.cidrIp);
        if (ranges.some((cidr: string) => PUBLIC_CIDRS.includes(cidr))) return true;
      }
    }
  }
  if (provider === 'AZURE') {
    if ((c.publicNetworkAccess ?? '').toLowerCase() === 'enabled') return true;
    if (c.publicIpAddress) return true;
    const nsgRules = c.securityRules ?? [];
    for (const rule of nsgRules) {
      if (
        rule.direction === 'Inbound' &&
        rule.access === 'Allow' &&
        (rule.sourceAddressPrefix === '*' || rule.sourceAddressPrefix === 'Internet')
      ) return true;
    }
  }
  if (provider === 'GCP') {
    const ranges = c.sourceRanges ?? [];
    if (ranges.some((r: string) => PUBLIC_CIDRS.includes(r))) return true;
    if (c.iamPolicy?.bindings?.some((b: any) => (b.members ?? []).includes('allUsers'))) return true;
    if (c.networkInterfaces?.some((n: any) => (n.accessConfigs ?? []).length > 0)) return true;
  }
  return false;
}

// ─── Subgraph query for UI / attack-path engine ──────────────────────────────

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

export async function queryNeighborhood(
  resourceInventoryId: string,
  options: { edgeTypes?: DependencyType[]; depth?: number; direction?: 'both' | 'out' | 'in' } = {},
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const depth = Math.min(Math.max(options.depth ?? 2, 1), 5);
  const direction = options.direction ?? 'both';

  const visited = new Set<string>([resourceInventoryId]);
  const frontier = new Set<string>([resourceInventoryId]);
  const allEdges: GraphEdge[] = [];

  for (let i = 0; i < depth; i++) {
    if (frontier.size === 0) break;
    const next = new Set<string>();
    const where: Prisma.ResourceDependencyWhereInput = {
      OR: [],
    };
    if (direction === 'out' || direction === 'both') {
      (where.OR as any[]).push({ fromId: { in: Array.from(frontier) } });
    }
    if (direction === 'in' || direction === 'both') {
      (where.OR as any[]).push({ toId: { in: Array.from(frontier) } });
    }
    if (options.edgeTypes && options.edgeTypes.length > 0) {
      where.depType = { in: options.edgeTypes };
    }

    const edges = await prisma.resourceDependency.findMany({ where });
    for (const e of edges) {
      allEdges.push({
        fromId: e.fromId,
        toId: e.toId,
        depType: e.depType,
        description: e.description,
        principalArn: e.principalArn,
        actions: e.actions,
      });
      for (const id of [e.fromId, e.toId]) {
        if (!visited.has(id)) {
          visited.add(id);
          next.add(id);
        }
      }
    }
    frontier.clear();
    next.forEach((id) => frontier.add(id));
  }

  const nodes = await prisma.resourceInventory.findMany({
    where: { id: { in: Array.from(visited) } },
    select: {
      id: true,
      nativeId: true,
      resourceType: true,
      region: true,
      dataSensitivity: true,
      exposurePaths: {
        select: { exposureType: true },
        take: 1,
      },
    },
  });

  return {
    nodes: nodes.map((n) => ({
      id: n.id,
      nativeId: n.nativeId,
      resourceType: n.resourceType,
      region: n.region,
      dataSensitivity: n.dataSensitivity,
      exposureType: n.exposurePaths[0]?.exposureType ?? null,
    })),
    edges: allEdges,
  };
}

// ─── Internet exposure listing for an account ────────────────────────────────

export async function listExposedResources(provider: Provider, accountId: string) {
  return prisma.exposurePath.findMany({
    where: {
      provider,
      exposureType: ExposureType.PUBLIC_INTERNET,
      resource: providerFilter(provider, accountId),
    },
    include: {
      resource: {
        select: { id: true, nativeId: true, resourceType: true, region: true, dataSensitivity: true },
      },
    },
    orderBy: { computedAt: 'desc' },
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function loadResources(provider: Provider, accountId: string): Promise<ResourceLite[]> {
  const rows = await prisma.resourceInventory.findMany({
    where: { ...providerFilter(provider, accountId), state: 'ACTIVE' },
    select: { id: true, nativeId: true, resourceType: true, configState: true, region: true },
  });
  return rows.map((r) => ({ ...r, configState: r.configState as any }));
}

function providerFilter(provider: Provider, accountId: string): Prisma.ResourceInventoryWhereInput {
  if (provider === 'AWS')   return { awsAccountId: accountId };
  if (provider === 'AZURE') return { azureSubId: accountId };
  return { gcpProjectId: accountId };
}

function normalizeStatements(doc: any): any[] {
  if (!doc) return [];
  const parsed = typeof doc === 'string' ? safeJsonParse(doc) : doc;
  const stmt = parsed?.Statement ?? parsed?.statement;
  if (!stmt) return [];
  return Array.isArray(stmt) ? stmt : [stmt];
}

function safeJsonParse(s: string): any {
  try {
    // AWS sometimes URL-encodes policy documents
    return JSON.parse(decodeURIComponent(s));
  } catch {
    try { return JSON.parse(s); } catch { return null; }
  }
}

function extractPrincipals(p: any): { arn: string; type: string }[] {
  if (!p) return [];
  const out: { arn: string; type: string }[] = [];
  if (typeof p === 'string') {
    out.push({ arn: p, type: classifyArn(p) });
    return out;
  }
  for (const [key, value] of Object.entries(p)) {
    const values = Array.isArray(value) ? value : [value];
    for (const v of values as string[]) {
      if (!v || typeof v !== 'string') continue;
      out.push({ arn: v, type: key.toUpperCase() === 'SERVICE' ? 'SERVICE' : classifyArn(v) });
    }
  }
  return out;
}

function classifyArn(arn: string): string {
  if (arn.endsWith('.amazonaws.com')) return 'SERVICE';
  if (arn.includes(':user/')) return 'USER';
  if (arn.includes(':role/')) return 'ROLE';
  if (arn.includes(':group/')) return 'GROUP';
  if (arn.includes(':federated-user')) return 'FEDERATED';
  if (arn === '*') return 'WILDCARD';
  return 'EXTERNAL_ACCOUNT';
}

function classifyGcpMember(member: string): string {
  if (member.startsWith('serviceAccount:')) return 'SERVICE_ACCOUNT';
  if (member.startsWith('user:')) return 'USER';
  if (member.startsWith('group:')) return 'GROUP';
  if (member === 'allUsers' || member === 'allAuthenticatedUsers') return 'WILDCARD';
  return 'EXTERNAL';
}

function chunked<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

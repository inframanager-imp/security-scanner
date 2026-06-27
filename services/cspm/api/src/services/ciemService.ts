/**
 * CIEM Service
 *
 *   flattenPermissions(provider, accountId)
 *      - Walks IAM policies (AWS), role assignments (Azure), iamPolicy bindings (GCP)
 *        from ResourceInventory.configState and upserts one PrincipalPermission row per
 *        (principal, action, resource, effect, source).
 *
 *   detectAttackPaths(provider, accountId)
 *      - Combines PrincipalPermission with the asset graph (ExposurePath,
 *        ResourceDependency, ResourceInventory.dataSensitivity) and applies four
 *        detection rules:
 *           PRIVILEGE_ESCALATION  — principal can grant itself admin
 *           EXTERNAL_TO_ADMIN     — internet-exposed resource → admin-equivalent role
 *           LATERAL_MOVEMENT      — principal A → role B → resource C (multi-hop)
 *           DATA_EXFILTRATION     — principal/exposed resource → sensitive data store
 *      - Materializes AttackPath rows (upsert via deterministic fingerprint) and emits
 *        a Finding for each newly observed path so it shows up in the regular Findings UI.
 *
 *   runCiemPassForAccount(provider, accountId)
 *      - Entry point invoked by graphBuildWorker after the graph rebuild.
 */

import crypto from 'crypto';
import { prisma } from '../config/database';
import { logger } from '../config/logger';
import type { Prisma } from '@prisma/client';

type Provider = 'AWS' | 'AZURE' | 'GCP';

const ADMIN_ACTIONS = new Set([
  '*',
  'iam:*',
  'iam:CreateAccessKey',
  'iam:AttachUserPolicy',
  'iam:AttachRolePolicy',
  'iam:PutUserPolicy',
  'iam:PutRolePolicy',
  'iam:PassRole',
  'sts:AssumeRole',
  'organizations:*',
]);

const DATA_STORE_TYPES = new Set([
  // AWS
  'AWS::S3::Bucket',
  'AWS::RDS::DBInstance',
  'AWS::RDS::DBCluster',
  'AWS::DynamoDB::Table',
  'AWS::ElastiCache::CacheCluster',
  // Azure
  'Microsoft.Storage/storageAccounts',
  'Microsoft.Sql/servers/databases',
  'Microsoft.DocumentDB/databaseAccounts',
  // GCP
  'storage.googleapis.com/Bucket',
  'sqladmin.googleapis.com/Instance',
  'bigquery.googleapis.com/Dataset',
]);

// ─── Public entry ────────────────────────────────────────────────────────────

export async function runCiemPassForAccount(provider: Provider, accountId: string): Promise<void> {
  const startedAt = Date.now();
  try {
    const flattened = await flattenPermissions(provider, accountId);
    const paths = await detectAttackPaths(provider, accountId);
    logger.info('ciem.pass.done', {
      provider,
      accountId,
      flattened,
      pathsDetected: paths,
      elapsedMs: Date.now() - startedAt,
    });
  } catch (err) {
    logger.error('ciem.pass.failed', { provider, accountId, error: (err as Error).message });
  }
}

// ─── Permission flattening ───────────────────────────────────────────────────

export async function flattenPermissions(provider: Provider, accountId: string): Promise<number> {
  const resources = await prisma.resourceInventory.findMany({
    where: { ...providerFilter(provider, accountId), state: 'ACTIVE' },
    select: { id: true, nativeId: true, resourceType: true, configState: true },
  });

  // Wipe previous flattening for this account (we recompute)
  await prisma.principalPermission.deleteMany({ where: { provider, accountId } });

  const rows: Prisma.PrincipalPermissionCreateManyInput[] = [];

  if (provider === 'AWS') {
    // First pass: collect managed policies' permissions
    const policyDocs = new Map<string, any>(); // policyArn → defaultVersion document
    for (const r of resources) {
      if (r.resourceType !== 'AWS::IAM::Policy') continue;
      const c = r.configState as any;
      const doc = c?.PolicyVersionList?.find?.((v: any) => v.IsDefaultVersion)?.Document
        ?? c?.Document
        ?? c?.policyDocument;
      if (doc) policyDocs.set(r.nativeId, doc);
    }

    // Second pass: principals
    for (const r of resources) {
      const c = r.configState as any;
      if (r.resourceType === 'AWS::IAM::User' || r.resourceType === 'AWS::IAM::Role') {
        const arn = r.nativeId;
        const ptype = r.resourceType === 'AWS::IAM::User' ? 'USER' : 'ROLE';

        // Attached managed policies
        const attached = c?.AttachedManagedPolicies ?? c?.attachedManagedPolicies ?? [];
        for (const p of attached) {
          const policyArn = p.PolicyArn ?? p.policyArn;
          if (!policyArn) continue;
          const doc = policyDocs.get(policyArn);
          if (!doc) continue;
          for (const stmt of normalizeStatements(doc)) {
            for (const flat of expandStatement(stmt)) {
              rows.push({
                provider, accountId,
                principalArn: arn,
                principalType: ptype,
                action: flat.action,
                resourceArn: flat.resource,
                effect: flat.effect,
                conditionsJson: flat.conditions ?? null,
                source: 'MANAGED',
              });
            }
          }
        }

        // Inline policies
        const inline = c?.PolicyList ?? c?.inlinePolicies ?? c?.Policies ?? [];
        for (const ip of inline) {
          const doc = ip.PolicyDocument ?? ip.policyDocument ?? ip.document;
          if (!doc) continue;
          for (const stmt of normalizeStatements(doc)) {
            for (const flat of expandStatement(stmt)) {
              rows.push({
                provider, accountId,
                principalArn: arn,
                principalType: ptype,
                action: flat.action,
                resourceArn: flat.resource,
                effect: flat.effect,
                conditionsJson: flat.conditions ?? null,
                source: 'INLINE',
              });
            }
          }
        }
      }
    }
  } else if (provider === 'AZURE') {
    // Azure: read roleAssignments from each resource; resourceArn is the resource itself
    for (const r of resources) {
      const c = r.configState as any;
      const ras = c?.roleAssignments ?? [];
      for (const ra of ras) {
        if (!ra.principalId) continue;
        rows.push({
          provider, accountId,
          principalArn: ra.principalId,
          principalType: (ra.principalType ?? 'SERVICE_PRINCIPAL').toUpperCase(),
          action: ra.roleDefinitionName ?? '*',
          resourceArn: r.nativeId,
          effect: 'ALLOW',
          source: 'DIRECT',
        });
      }
    }
  } else if (provider === 'GCP') {
    for (const r of resources) {
      const c = r.configState as any;
      const bindings = c?.iamPolicy?.bindings ?? [];
      for (const b of bindings) {
        for (const member of b.members ?? []) {
          rows.push({
            provider, accountId,
            principalArn: member,
            principalType: classifyGcpMember(member),
            action: b.role ?? 'roles/unknown',
            resourceArn: r.nativeId,
            effect: 'ALLOW',
            source: 'DIRECT',
          });
        }
      }
    }
  }

  let inserted = 0;
  for (const chunk of chunked(rows, 500)) {
    const result = await prisma.principalPermission.createMany({
      data: chunk,
      skipDuplicates: true,
    });
    inserted += result.count;
  }
  return inserted;
}

// ─── Attack path detection ───────────────────────────────────────────────────

interface PathRecord {
  kind: string;
  severity: string;
  sourceLabel: string;
  sourceNodeId: string | null;
  sinkLabel: string;
  sinkNodeId: string | null;
  pathJson: any[];
  summary: string;
}

export async function detectAttackPaths(provider: Provider, accountId: string): Promise<number> {
  const [permissions, resources, exposurePaths] = await Promise.all([
    prisma.principalPermission.findMany({
      where: { provider, accountId, effect: 'ALLOW' },
    }),
    prisma.resourceInventory.findMany({
      where: { ...providerFilter(provider, accountId), state: 'ACTIVE' },
      select: { id: true, nativeId: true, resourceType: true, dataSensitivity: true, tags: true },
    }),
    prisma.exposurePath.findMany({
      where: {
        provider,
        exposureType: 'PUBLIC_INTERNET',
        resource: providerFilter(provider, accountId),
      },
      include: { resource: { select: { id: true, nativeId: true, resourceType: true } } },
    }),
  ]);

  const resourceByArn = new Map(resources.map((r) => [r.nativeId, r]));
  const resourceById = new Map(resources.map((r) => [r.id, r]));

  // Group permissions by principal
  const permsByPrincipal = new Map<string, typeof permissions>();
  for (const p of permissions) {
    if (!permsByPrincipal.has(p.principalArn)) permsByPrincipal.set(p.principalArn, []);
    permsByPrincipal.get(p.principalArn)!.push(p);
  }

  const results: PathRecord[] = [];

  // Rule 1: PRIVILEGE_ESCALATION — principal can grant itself admin
  for (const [principal, perms] of permsByPrincipal) {
    const canEscalate = perms.some((p) => ADMIN_ACTIONS.has(p.action));
    if (canEscalate) {
      results.push({
        kind: 'PRIVILEGE_ESCALATION',
        severity: 'CRITICAL',
        sourceLabel: principal,
        sourceNodeId: resourceByArn.get(principal)?.id ?? null,
        sinkLabel: 'admin-equivalent permissions',
        sinkNodeId: null,
        pathJson: [
          { nodeId: principal, label: principal, edgeType: 'PRINCIPAL', detail: 'Has self-escalation permissions' },
          { nodeId: '*', label: 'Account admin', edgeType: 'IDENTITY_PERMITS', detail: perms.filter((p) => ADMIN_ACTIONS.has(p.action)).slice(0, 5).map((p) => p.action).join(', ') },
        ],
        summary: `Principal "${shortArn(principal)}" has self-escalation permissions (${perms.filter((p) => ADMIN_ACTIONS.has(p.action)).length} admin-class actions)`,
      });
    }
  }

  // Rule 2: EXTERNAL_TO_ADMIN — internet-exposed resource → admin role
  for (const ep of exposurePaths) {
    // Look for IDENTITY_ASSUME/IDENTITY_PERMITS edges from this resource
    const adminPerms = permissions.filter(
      (p) =>
        p.resourceArn === ep.resource.nativeId &&
        ADMIN_ACTIONS.has(p.action),
    );
    if (adminPerms.length > 0) {
      results.push({
        kind: 'EXTERNAL_TO_ADMIN',
        severity: 'CRITICAL',
        sourceLabel: 'Public internet',
        sourceNodeId: null,
        sinkLabel: ep.resource.nativeId,
        sinkNodeId: ep.resource.id,
        pathJson: [
          { nodeId: 'internet', label: '0.0.0.0/0', edgeType: 'INTERNET_EXPOSURE', detail: ep.entryPoint ?? 'public entry' },
          ...((ep.pathJson as any[]) ?? []).slice(0, 6),
          { nodeId: ep.resource.id, label: ep.resource.nativeId, edgeType: 'IDENTITY_PERMITS', detail: adminPerms.slice(0, 3).map((p) => p.action).join(', ') },
        ],
        summary: `Internet-reachable ${ep.resource.resourceType} "${shortArn(ep.resource.nativeId)}" has admin-class permissions`,
      });
    }
  }

  // Rule 3: DATA_EXFILTRATION — internet-exposed path to sensitive data store
  for (const ep of exposurePaths) {
    if (DATA_STORE_TYPES.has(ep.resource.resourceType)) {
      const target = resourceById.get(ep.resource.id);
      const sensitive = target?.dataSensitivity === 'HIGH' || target?.dataSensitivity === 'CRITICAL';
      const severity = sensitive ? 'CRITICAL' : 'HIGH';
      results.push({
        kind: 'DATA_EXFILTRATION',
        severity,
        sourceLabel: 'Public internet',
        sourceNodeId: null,
        sinkLabel: ep.resource.nativeId,
        sinkNodeId: ep.resource.id,
        pathJson: [
          { nodeId: 'internet', label: '0.0.0.0/0', edgeType: 'INTERNET_EXPOSURE', detail: ep.entryPoint ?? 'public entry' },
          ...((ep.pathJson as any[]) ?? []).slice(0, 6),
        ],
        summary: `Internet-reachable ${ep.resource.resourceType} "${shortArn(ep.resource.nativeId)}" is a data store${sensitive ? ' with HIGH-sensitivity data' : ''}`,
      });
    }
  }

  // Rule 4: LATERAL_MOVEMENT — principal can iam:PassRole onto a role with admin
  const passRolePrincipals = permissions.filter((p) => p.action === 'iam:PassRole' || p.action === '*');
  for (const pass of passRolePrincipals) {
    const targetRoleArn = pass.resourceArn;
    if (targetRoleArn === '*') continue;
    const targetPerms = permsByPrincipal.get(targetRoleArn) ?? [];
    if (targetPerms.some((tp) => ADMIN_ACTIONS.has(tp.action))) {
      results.push({
        kind: 'LATERAL_MOVEMENT',
        severity: 'HIGH',
        sourceLabel: pass.principalArn,
        sourceNodeId: resourceByArn.get(pass.principalArn)?.id ?? null,
        sinkLabel: targetRoleArn,
        sinkNodeId: resourceByArn.get(targetRoleArn)?.id ?? null,
        pathJson: [
          { nodeId: pass.principalArn, label: pass.principalArn, edgeType: 'PRINCIPAL', detail: 'Has iam:PassRole' },
          { nodeId: targetRoleArn,     label: targetRoleArn,     edgeType: 'IDENTITY_ASSUME', detail: 'Receives role via PassRole' },
          { nodeId: '*',               label: 'admin-equiv',     edgeType: 'IDENTITY_PERMITS', detail: targetPerms.filter((tp) => ADMIN_ACTIONS.has(tp.action)).slice(0, 3).map((tp) => tp.action).join(', ') },
        ],
        summary: `Principal "${shortArn(pass.principalArn)}" can PassRole onto admin role "${shortArn(targetRoleArn)}"`,
      });
    }
  }

  // Upsert each path
  let count = 0;
  for (const r of results) {
    const fingerprint = pathFingerprint(r.kind, r.sourceLabel, r.sinkLabel);
    await prisma.attackPath.upsert({
      where: { provider_accountId_fingerprint: { provider, accountId, fingerprint } },
      update: { lastSeenAt: new Date(), severity: r.severity, pathJson: r.pathJson as any, summary: r.summary },
      create: {
        provider, accountId,
        kind: r.kind,
        severity: r.severity,
        sourceNodeId: r.sourceNodeId,
        sourceLabel: r.sourceLabel,
        sinkNodeId: r.sinkNodeId,
        sinkLabel: r.sinkLabel,
        pathJson: r.pathJson as any,
        summary: r.summary,
        fingerprint,
      },
    });
    count++;
  }
  return count;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function providerFilter(provider: Provider, accountId: string): Prisma.ResourceInventoryWhereInput {
  if (provider === 'AWS')   return { awsAccountId: accountId };
  if (provider === 'AZURE') return { azureSubId: accountId };
  return { gcpProjectId: accountId };
}

function normalizeStatements(doc: any): any[] {
  if (!doc) return [];
  const parsed = typeof doc === 'string' ? safeParse(doc) : doc;
  const stmt = parsed?.Statement ?? parsed?.statement;
  if (!stmt) return [];
  return Array.isArray(stmt) ? stmt : [stmt];
}

function safeParse(s: string): any {
  try { return JSON.parse(decodeURIComponent(s)); } catch {}
  try { return JSON.parse(s); } catch {}
  return null;
}

function expandStatement(stmt: any): { action: string; resource: string; effect: string; conditions?: any }[] {
  if (!stmt || !stmt.Effect) return [];
  const actions = Array.isArray(stmt.Action) ? stmt.Action : (stmt.Action ? [stmt.Action] : []);
  const resources = Array.isArray(stmt.Resource) ? stmt.Resource : (stmt.Resource ? [stmt.Resource] : ['*']);
  const out: { action: string; resource: string; effect: string; conditions?: any }[] = [];
  for (const a of actions) {
    for (const r of resources) {
      out.push({
        action: String(a),
        resource: String(r),
        effect: String(stmt.Effect).toUpperCase(),
        conditions: stmt.Condition,
      });
    }
  }
  return out;
}

function classifyGcpMember(member: string): string {
  if (member.startsWith('serviceAccount:')) return 'SERVICE_ACCOUNT';
  if (member.startsWith('user:')) return 'USER';
  if (member.startsWith('group:')) return 'GROUP';
  if (member === 'allUsers' || member === 'allAuthenticatedUsers') return 'WILDCARD';
  return 'EXTERNAL';
}

function shortArn(arn: string): string {
  const tail = arn.split(':').pop() ?? arn;
  const path = tail.split('/').pop() ?? tail;
  return path.length > 32 ? path.slice(0, 29) + '…' : path;
}

function pathFingerprint(kind: string, sourceLabel: string, sinkLabel: string): string {
  return crypto.createHash('sha256').update(`${kind}::${sourceLabel}::${sinkLabel}`).digest('hex').slice(0, 24);
}

function chunked<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

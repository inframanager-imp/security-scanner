import { Prisma, PrismaClient } from '@prisma/client';
import { getTenantContext } from './tenantContext';

/**
 * Prisma client with the tenant extension.
 *
 * Every domain model carries `orgId` (= Tenant.id). This extension:
 *   - on create/createMany/upsert: injects `orgId` from the tenant context
 *     into the row and into any nested relation writes,
 *   - on every read/update/delete: adds `orgId = <current tenant>` to `where`,
 *   - in system context (`runAsSystem`): applies no filter, and requires the
 *     caller to pass `orgId` explicitly on creates,
 *   - with no context at all: throws, so forgotten wrappers fail closed.
 *
 * Models without `orgId` (User, Session, Tenant, TenantMembership) pass through.
 */

const TENANT_MODELS = new Set<string>(
  Prisma.dmmf.datamodel.models.filter((m) => m.fields.some((f) => f.name === 'orgId')).map((m) => m.name)
);

/** relation field name -> target model, per model, from the DMMF. */
const RELATION_TARGET = new Map<string, Map<string, string>>();
for (const m of Prisma.dmmf.datamodel.models) {
  const rels = new Map<string, string>();
  for (const f of m.fields) if (f.kind === 'object') rels.set(f.name, f.type);
  RELATION_TARGET.set(m.name, rels);
}

const ORG_NULLABLE = new Set(['AuditLog']);

const UNIQUE_WHERE_OPS = new Set(['findUnique', 'findUniqueOrThrow', 'update', 'delete', 'upsert']);
const LIST_WHERE_OPS = new Set([
  'findMany', 'findFirst', 'findFirstOrThrow', 'count', 'aggregate', 'groupBy', 'updateMany', 'deleteMany',
]);

type AnyRecord = Record<string, unknown>;

function resolveOrg(model: string): { orgId: string } | { system: true } {
  const ctx = getTenantContext();
  if (!ctx) {
    throw new Error(
      `[tenant] ${model} accessed outside a tenant context. Wrap the call in runWithTenant()/runAsSystem().`
    );
  }
  if (ctx.system || !ctx.tenantId) return { system: true };
  return { orgId: ctx.tenantId };
}

/** Recursively stamp orgId onto nested create/createMany/connectOrCreate payloads. */
function stampNested(model: string, data: unknown, orgId: string): unknown {
  if (Array.isArray(data)) return data.map((d) => stampNested(model, d, orgId));
  if (!data || typeof data !== 'object') return data;
  const rels = RELATION_TARGET.get(model);
  const out: AnyRecord = { ...(data as AnyRecord) };
  if (TENANT_MODELS.has(model) && out.orgId === undefined) out.orgId = orgId;
  if (!rels) return out;
  for (const [field, target] of rels) {
    const v = out[field];
    if (!v || typeof v !== 'object') continue;
    const rel = { ...(v as AnyRecord) };
    if (rel.create !== undefined) rel.create = stampNested(target, rel.create, orgId);
    if (rel.createMany && typeof rel.createMany === 'object') {
      const cm = { ...(rel.createMany as AnyRecord) };
      cm.data = stampNested(target, cm.data, orgId);
      rel.createMany = cm;
    }
    if (rel.connectOrCreate !== undefined) {
      const coc = rel.connectOrCreate;
      rel.connectOrCreate = Array.isArray(coc)
        ? coc.map((c) => ({ ...(c as AnyRecord), create: stampNested(target, (c as AnyRecord).create, orgId) }))
        : { ...(coc as AnyRecord), create: stampNested(target, (coc as AnyRecord).create, orgId) };
    }
    if (rel.upsert !== undefined) {
      const up = rel.upsert;
      rel.upsert = Array.isArray(up)
        ? up.map((u) => ({ ...(u as AnyRecord), create: stampNested(target, (u as AnyRecord).create, orgId) }))
        : { ...(up as AnyRecord), create: stampNested(target, (up as AnyRecord).create, orgId) };
    }
    out[field] = rel;
  }
  return out;
}

function assertExplicitOrg(model: string, data: unknown, operation: string): void {
  if (ORG_NULLABLE.has(model)) return;
  const rows = Array.isArray(data) ? data : [data];
  for (const r of rows) {
    if (!r || typeof r !== 'object' || (r as AnyRecord).orgId === undefined) {
      throw new Error(
        `[tenant] ${model}.${operation} in system context must set orgId explicitly (or run inside runWithTenant()).`
      );
    }
  }
}

function scopedWhere(where: unknown, orgId: string, unique: boolean): AnyRecord {
  const w = (where ?? {}) as AnyRecord;
  if (unique) return { ...w, orgId };
  return { AND: [w, { orgId }] };
}

const base = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
});

function withTenantExtension(client: PrismaClient) {
  return client.$extends({
    name: 'tenantScope',
    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }) {
          if (!TENANT_MODELS.has(model)) return query(args);
          const org = resolveOrg(model);
          const a = (args ?? {}) as AnyRecord;

          if ('system' in org) {
            if (operation === 'create') assertExplicitOrg(model, a.data, operation);
            if (operation === 'createMany') assertExplicitOrg(model, a.data, operation);
            if (operation === 'upsert') assertExplicitOrg(model, a.create, operation);
            return query(args);
          }

          const { orgId } = org;
          switch (operation) {
            case 'create':
              return query({ ...a, data: stampNested(model, a.data, orgId) } as typeof args);
            case 'createMany':
              return query({ ...a, data: stampNested(model, a.data, orgId) } as typeof args);
            case 'upsert':
              return query({
                ...a,
                where: scopedWhere(a.where, orgId, true),
                create: stampNested(model, a.create, orgId),
                update: stampNested(model, a.update, orgId),
              } as typeof args);
            default:
              if (UNIQUE_WHERE_OPS.has(operation)) {
                const next: AnyRecord = { ...a, where: scopedWhere(a.where, orgId, true) };
                if (operation === 'update') next.data = stampNested(model, a.data, orgId);
                return query(next as typeof args);
              }
              if (LIST_WHERE_OPS.has(operation)) {
                return query({ ...a, where: scopedWhere(a.where, orgId, false) } as typeof args);
              }
              return query(args);
          }
        },
      },
    },
  });
}

export type TenantPrismaClient = ReturnType<typeof withTenantExtension>;

const globalForPrisma = globalThis as unknown as { prisma: TenantPrismaClient | undefined };

export const prisma: TenantPrismaClient = globalForPrisma.prisma ?? withTenantExtension(base);

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

/** Models that carry orgId; exported for tests and tooling. */
export const tenantModels = TENANT_MODELS;

/** Pure helpers exposed for unit tests only. */
export const __tenantInternals = { stampNested, scopedWhere, assertExplicitOrg, resolveOrg };

export default prisma;

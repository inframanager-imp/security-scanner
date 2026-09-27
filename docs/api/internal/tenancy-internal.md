# Multi-tenancy — Internal Notes

Companion to `docs/api/tenants.md` and `docs/api/auth.md`. This explains how
organization isolation is implemented, what it guarantees, and the rules for
writing new code.

## Vocabulary

- **Tenant** = organization. Model `Tenant`, API path `/api/tenants`.
- **orgId** = the column on every domain row holding `Tenant.id`. It is
  deliberately not called `tenantId`, because `AzureSubscription.tenantId`
  and `AzureCredential.encryptedTenantId` already mean the Azure AD tenant.
- **Tenant context** = the ambient "which organization am I acting for",
  stored in `AsyncLocalStorage` (`src/config/tenantContext.ts`).
- **System context** = no organization; used for identity operations and
  cross-tenant housekeeping.

## Pieces

| Piece | Path |
|---|---|
| Schema: `Tenant`, `TenantMembership`, `User.isSuperAdmin/lastTenantId/isActive`, `orgId` on 46 models | `services/cspm/api/prisma/schema.prisma` |
| Migration + backfill into the default organization | `prisma/migrations/20260927000002_multi_tenancy/migration.sql` |
| Context (`runWithTenant`, `runAsSystem`, `requireTenantId`) | `src/config/tenantContext.ts` |
| Prisma extension (inject + enforce `orgId`) | `src/config/database.ts` |
| Background helpers (`runForTarget`, `runForScan`, `forEachTenant`) | `src/config/tenantJobs.ts` |
| Token claims `tid`/`sa`, tenant resolution | `src/services/authService.ts`, `src/services/tenantService.ts` |
| Request entry: opens the context | `src/middleware/authenticate.ts` |
| Routes | `src/routes/auth.ts`, `src/routes/tenants.ts` |
| Seed (default org, super admin, orphan memberships) | `src/seed.ts` |
| ASPM scoping | `services/aspm/backend/{auth,database,main}.py` |
| Tests | `api/tests/unit/tenantExtension.test.ts` |

## Request flow

```
Bearer token --> authenticate: verify JWT, req.user = {id, role, tenantId, isSuperAdmin}
             --> tid present:  runWithTenant(tid, next)
                 super admin without tid: runAsSystem(next)
                 otherwise: 403 "No active tenant"
             --> rbacPolicy --> route --> prisma.* (extension applies scope)
```

Because the context is opened once in `authenticate`, no route needs
tenant-specific code. A route that queries `prisma.finding.findMany()` gets
only the active organization's findings.

## What the Prisma extension does

For every model that has an `orgId` field (discovered from the DMMF at
startup; identity models `User`, `Session`, `Tenant`, `TenantMembership` are
untouched):

| Operation | In tenant context | In system context |
|---|---|---|
| `create`, `createMany` | stamps `orgId`, including nested `create`/`createMany`/`connectOrCreate`/`upsert` payloads | requires `orgId` to be set explicitly, else throws |
| `upsert` | stamps `create` and `update`, scopes `where` | requires `orgId` on `create` |
| `findUnique`, `update`, `delete` | adds `orgId` to the unique `where` (Prisma 5 extended-where-unique) | unscoped |
| `findMany`, `findFirst`, `count`, `aggregate`, `groupBy`, `updateMany`, `deleteMany` | `where: { AND: [userWhere, { orgId }] }` | unscoped |
| no context at all | throws `[tenant] … accessed outside a tenant context` | |

`AuditLog.orgId` is nullable so login attempts (no tenant yet) can be
recorded; it is stamped whenever a context exists.

### Why the schema default is `""`

Prisma's generated create types would otherwise require `orgId` on every
call site. The default makes the type optional. At the database, a CHECK
constraint (`orgId <> ''`) rejects any row that reached it unstamped, so the
default can never produce a real row.

### Known holes, by design

- **Raw SQL** bypasses the extension. The three existing `$queryRaw` sites
  (anomaly trend, config-change timeline, posture summary) add an explicit
  `"orgId" = …` predicate from `getTenantContext()`. Any new raw query must
  do the same.
- **Cross-tenant unique constraints**: `Account.awsAccountId`,
  `AzureSubscription.subscriptionId` and `GcpProject.projectId` are globally
  unique, so the same cloud account cannot be onboarded by two organizations.
  Relax to `@@unique([orgId, …])` if that becomes a requirement.
- **`include`d relations are not filtered.** They are children of a scoped
  parent, which is safe today. Do not `include` a relation that could point
  across organizations.
- **BullMQ job ids** are not namespaced by organization. Job payloads carry
  target ids that are unique across organizations, so collisions cannot
  happen, but `forEachTenant` runs sequentially to keep per-tenant load
  predictable.

## Background work

Workers never receive a tenant. Each processor is wrapped:

```ts
async function processScanJob(job) {
  return runForTarget('AWS', job.data.accountId, () => processScanJobUnscoped(job));
}
```

`runForTarget` looks up the target's `orgId` in system context and throws
if the target is gone, so a job can never run unscoped. Schedulers in
`app.ts` (drift scan, posture score, scheduled reports, approval expiry,
discovery) fan out with `forEachTenant(label, fn)`. Housekeeping that only
deletes (config-sync run retention) runs in `runAsSystem`.

Rule for new background code: **decide the organization first, then do
work**. If you find yourself needing `runAsSystem` for reads, the code is
probably iterating targets and should use `forEachTenant` instead.

## Roles and the super admin

- Membership role (`TenantMembership.role`) is what goes into the token and
  what `rbacPolicy` checks. `User.role` is legacy: it seeds the membership
  role for auto-provisioned users and is otherwise unused for access.
- `isSuperAdmin` users may act inside any organization (they get `ADMIN`
  there) and may use platform context with `tid = null`. In platform context
  reads are unscoped and creates must carry `orgId`; the only intended use
  is `/api/tenants` administration.
- The `ADMIN_EMAIL` account is promoted to super admin by the seed on every
  start.

## Migration and rollout

1. `20260927000002_multi_tenancy` creates the tables, adds `orgId` as
   nullable, inserts the default organization
   (`00000000-0000-4000-8000-000000000001`), backfills every existing row
   and membership, then sets `NOT NULL` + CHECK. It is safe on an empty
   database.
2. The seed runs after migrations and is idempotent.
3. Existing sessions remain valid until refresh; the refresh re-resolves the
   membership and issues a token with `tid`.
4. The ASPM `targets` table gains `tenant_id`. Existing targets have
   `NULL`, which only a super admin can see. Backfill with
   `UPDATE targets SET tenant_id = '00000000-0000-4000-8000-000000000001' WHERE tenant_id IS NULL;`
   on the ASPM database after deploying.

## Testing

```bash
cd services/cspm
npx jest --config api/jest.config.js api/tests/unit/tenantExtension.test.ts
```

Covers model discovery, where-scoping, nested create stamping, the
system-context guard and the context helpers. Integration coverage against a
real database (two organizations, cross-tenant 404s) is the next step in
Phase 1.

## Phase 1 remaining work

- 1B user groups and per-resource grants (group -> cloud accounts)
- 1C admin UI for organizations and members
- 1D OIDC login (Entra ID) with just-in-time provisioning, mapping the IdP
  tenant/domain to an organization
- integration tests for isolation

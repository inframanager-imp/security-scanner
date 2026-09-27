# Role-Based Access Control (CSPM API)

Every request under `/api` (except the public exceptions below) is authenticated
and then checked against a central policy before it reaches a route handler.
The policy lives in `services/cspm/api/src/middleware/rbac.ts` and is enforced in
`app.ts`, so a router that forgets its own `authenticate` call can no longer
expose an endpoint.

## Roles

Roles are held **per organization** (`TenantMembership.role`); the access
token carries the role for the active organization. A platform super admin
(`isSuperAdmin`) is treated as `ADMIN` inside every organization and is the
only account that can manage organizations at `/api/tenants` (see
`docs/api/tenants.md`).

| Role | Can read | Can operate | Can administer |
|---|---|---|---|
| `VIEWER` | yes | no | no |
| `ANALYST` | yes | yes | no |
| `ADMIN` | yes | yes | yes |

- **Read** = `GET`/`HEAD`/`OPTIONS` on any endpoint except the audit log.
- **Operate** = day-to-day security work: run scans, triage findings, manage
  baselines and drift, create risk items, collect evidence, cancel approval
  requests, run scheduled reports on demand, start/stop threat monitors,
  build graphs, discover inventory.
- **Administer** = anything that changes credentials, onboarding, platform
  configuration, scheduling, decides approvals, deletes data, or reads the
  audit log.

## Public endpoints (no token)

| Endpoint | Why |
|---|---|
| `GET /api/health` | Liveness probe |
| `POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/logout` | Session lifecycle |
| `POST /api/config-sync/webhook/:provider/:targetId` | Authenticates with its own per-target secret |

## Admin-only endpoints

| Method | Path | Purpose |
|---|---|---|
| `*` | `/api/audit-logs/**` | Audit log (reads included) |
| `POST`,`PATCH`,`DELETE` | `/api/tenants/**` | Organizations and members (super admin for platform-level routes) |
| `POST` | `/api/accounts/setup` | Initial AWS setup |
| `POST` | `/api/accounts`, `/api/azure/subscriptions`, `/api/gcp/projects` | Onboard a cloud target |
| `PUT`, `DELETE` | `/api/{accounts\|azure/subscriptions\|gcp/projects}/:id` | Edit or remove a target |
| `*` | `/api/{accounts\|azure/subscriptions\|gcp/projects}/:id/credentials/**` | Manage cloud credentials |
| `DELETE` | `/api/scans/:id` | Delete a scan and its findings |
| `POST` | `/api/findings/deduplicate` | Destructive cleanup |
| `DELETE` | `/api/azure/scans/findings/cleanup-scanner-errors` | Destructive cleanup |
| `POST`,`PUT`,`PATCH`,`DELETE` | `/api/integrations/**`, `/api/alerts/**`, `/api/freeze-windows/**` | Platform configuration |
| `POST`,`PUT`,`DELETE` | `/api/report-schedules/**` (except `/:id/run`) | Manage schedules |
| `POST` | `/api/approvals/:id/approve`, `/api/approvals/:id/reject` | Decide approvals |
| `DELETE` | `/api/approvals/:id` | Delete an approval request |
| `DELETE` | `/api/baselines/:id` | Delete a baseline |
| `POST` | `/api/baselines/:id/drift/:driftId/revert` | Auto-revert live cloud config |
| `DELETE` | `/api/compliance/evidence/:id` | Delete evidence |
| `DELETE`, `POST` | `/api/anomaly/baselines`, `/api/anomaly/baselines/seed` | Reset or seed anomaly baselines |

Everything else follows the default: reads for every role, writes for
`ANALYST` and `ADMIN`.

## Responses

| Status | Body | Meaning |
|---|---|---|
| `401` | `{ "error": "No token provided" }` or `{ "error": "Invalid or expired token" }` | Not authenticated |
| `403` | `{ "error": "Forbidden", "detail": "Role VIEWER may not POST /scans" }` | Authenticated but not allowed |

Denied requests are recorded in the audit log with outcome `DENIED`.

## Changing the policy

1. Edit the `POLICY_RULES` table in `rbac.ts`. Rules are evaluated top-down and
   the first match wins, so put specific rules (for example `/:id/run`) before
   broad ones (`/report-schedules/**`).
2. Add the case to `services/cspm/api/tests/unit/rbac.test.ts`.
3. Update the table above.

## ASPM and Agent services

The Python services validate the same JWT and read the `role` claim from it.
Setting `ASPM_AUTH_REQUIRED=false` disables auth for local development only;
when `APP_ENV` or `NODE_ENV` is `production` the flag is ignored and auth stays
on. `docker-compose.yml` sets `APP_ENV=production` for both services.

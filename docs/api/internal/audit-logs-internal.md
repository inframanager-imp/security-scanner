# Audit Log — Internal Notes

Companion to the user-facing `docs/api/audit-logs.md`. This file covers how
the audit trail is produced, what it deliberately does not do, and how to
extend it.

## Where it lives

| Piece | Path |
|---|---|
| Capture middleware | `services/cspm/api/src/middleware/auditLog.ts` |
| Read API (ADMIN) | `services/cspm/api/src/routes/auditLogs.ts` |
| Prisma model | `AuditLog` in `services/cspm/api/prisma/schema.prisma` |
| Migration | `prisma/migrations/20260927000001_add_audit_log/migration.sql` |
| Wiring | `services/cspm/api/src/app.ts` — mounted on `/api` before the auth gate |
| Unit tests | `services/cspm/api/tests/unit/auditLog.test.ts` |
| UI | `web/src/pages/AuditLogs.tsx`, `web/src/api/auditLogs.ts` |

## Capture flow

```
request --> auditLog (registers res 'finish' listener)
        --> [public path?] --> route
        --> authenticate --> rbacPolicy --> route
response finish --> listener decides whether to record --> prisma.auditLog.create (fire and forget)
```

- The middleware is mounted **before** `authenticate` so failed logins and
  401/403 responses are captured. `req.user` is read inside the `finish`
  listener, by which time downstream middleware has populated it.
- Recorded: any `POST`/`PUT`/`PATCH`/`DELETE`, plus any response with status
  `401` or `403`. Successful `POST /auth/refresh` is skipped because it is
  automatic token churn, not a user action; failed refreshes are kept.
- The insert is not awaited. A failure logs a warning and never affects the
  user's response. There is no retry.

## Redaction

`redact()` walks the body recursively (max depth 6) and replaces the value of
any key matching:

```
password | passwd | secret | token | apikey | api_key | accesskey | access_key |
privatekey | private_key | credential | clientsecret | client_secret |
authorization | serviceaccountkey
```

Matching is case-insensitive and substring-based, so `secretAccessKey`,
`clientSecret`, `refreshToken` and `serviceAccountKeyJson` are all covered.
Values are replaced, keys are kept, so the shape of the request remains
readable. The serialized body is truncated to 4,000 characters.

Query strings are stored through the same redaction. Headers are not stored
except `User-Agent`.

## Action naming

`deriveAction(method, path)` produces `<resource>.<verb>`:

| Path shape | Result |
|---|---|
| `POST /accounts` | `accounts.create` |
| `PUT` / `PATCH /accounts/:id` | `accounts.update` |
| `DELETE /accounts/:id` | `accounts.delete` |
| `POST /approvals/:id/approve` | `approvals.approve` |
| `POST /baselines/:id/drift/:driftId/revert` | `baselines.revert` |
| `POST /auth/login` | `auth.login` |
| `POST /azure/subscriptions/:id/scan` | `azure.scan` |

A trailing word counts as a sub-action when it follows an id (odd segment
count) or is in `COLLECTION_VERBS` (`login`, `setup`, `deduplicate`, `sync`,
`compute`, …). Add to that set when you introduce a new collection-level verb
route, otherwise the entry falls back to the generic method verb.

## Performance and storage

- One insert per mutating request, off the response path. At typical UI
  traffic this is negligible; bulk operations (for example
  `POST /config-changes/bulk-status`) still produce one row each.
- Indexes: `createdAt desc`, `(userId, createdAt desc)`, `action`, `outcome`.
  The list endpoint filters map onto these.
- `requestBody` is `TEXT`, capped at 4 KB per row. Estimate roughly 1 KB per
  row on average.
- No retention job exists. If volume becomes a problem, add a scheduled
  delete of rows older than N days in `app.ts` alongside the other periodic
  jobs, and document the retention window in the user-facing doc.

## Security properties

- The read API is behind `authenticate` + `authorize('ADMIN')` in its own
  router **and** the central `rbacPolicy` rule for `/audit-logs/**`, so it
  stays admin-only even if one layer is edited.
- Rows are never updated or deleted by application code. Deleting a `User`
  sets `userId` to `NULL` (`ON DELETE SET NULL`) rather than removing rows.
- The log is written by the API process with its normal DB role. Tamper
  resistance beyond that (append-only DB grants, shipping to an external
  SIEM) is out of scope here.

## Testing

```bash
cd services/cspm
npx jest --config api/jest.config.js api/tests/unit/auditLog.test.ts api/tests/unit/rbac.test.ts
```

Tests cover redaction and action naming. The middleware itself is exercised
by any route test that sends a mutating request, since `prisma.auditLog` is
mocked in the test setup.

## Extending

- **New route with a verb suffix** (`/foo/verify`): add `verify` to
  `COLLECTION_VERBS` if it is collection-level; id-level verbs need nothing.
- **New sensitive field name**: extend the `REDACT_KEYS` regex and add a case
  to the redact test.
- **Record reads for a specific resource**: add a path check before the
  `MUTATING` guard in the `finish` listener. Keep it narrow; recording all
  reads would multiply row volume by an order of magnitude.

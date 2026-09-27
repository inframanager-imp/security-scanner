# Organizations (Tenants) API

The platform is multi-tenant. An **organization** (tenant) is a customer or
business unit whose cloud accounts, findings, settings, users and reports are
fully isolated from every other organization. A user can belong to several
organizations, with a different role in each, and works inside one **active
organization** at a time.

Two administrative levels exist:

| Level | Who | Can |
|---|---|---|
| Platform super admin | The operator account (`ADMIN_EMAIL`) and anyone flagged `isSuperAdmin` | Create and manage organizations, act inside any organization |
| Organization admin | A member with role `ADMIN` in that organization | Manage that organization's members and everything inside it |

**Base URL:** `/api/tenants` (behind the gateway: `/api/cspm/tenants`)

**Auth:** `Authorization: Bearer <access token>`

---

## Platform level (super admin only)

### List organizations

```
GET /api/tenants
```

```json
{
  "data": [
    { "id": "…", "slug": "acme", "name": "Acme Corp", "isActive": true, "settings": {}, "memberCount": 7, "createdAt": "…", "updatedAt": "…" }
  ]
}
```

### Create an organization

```
POST /api/tenants
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Display name |
| `slug` | string | no | URL handle, lowercase letters, digits, dashes. Generated from the name when omitted. |
| `admin.email` | string | no | First administrator. Created if the user does not exist. |
| `admin.password` | string | no | Password for a newly created admin. When omitted, a temporary password is generated and returned once. |

```json
{
  "data": {
    "tenant": { "id": "…", "slug": "acme", "name": "Acme Corp", … },
    "admin": { "id": "…", "email": "owner@acme.example", "temporaryPassword": "Xk9…" }
  }
}
```

### Update an organization

```
PATCH /api/tenants/:id
```

Body may contain `name`, `isActive`, `settings`. Deactivating an organization
blocks logins into it and stops its scheduled jobs.

---

## Organization level (organization admin or super admin)

### Current organization

```
GET /api/tenants/current
```

Returns the active organization, or `null` for a super admin working in
platform context.

### List members

```
GET /api/tenants/current/members
```

```json
{
  "data": [
    { "userId": "…", "email": "ana@acme.example", "role": "ANALYST", "isActive": true, "isSuperAdmin": false, "joinedAt": "…" }
  ]
}
```

### Add a member

```
POST /api/tenants/current/members
```

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | string | yes | Existing user, or a new user to create |
| `role` | `ADMIN` `ANALYST` `VIEWER` | no | Defaults to `VIEWER` |
| `password` | string | no | Only used when the user is created. Otherwise a temporary password is generated and returned once. |

Returns `201` with the member and, for a newly created user,
`temporaryPassword`. Returns `409` if the user is already a member.

### Change a member's role

```
PATCH /api/tenants/current/members/:userId
```

Body: `{ "role": "ANALYST" }`. You cannot demote yourself.

### Remove a member

```
DELETE /api/tenants/current/members/:userId
```

Returns `204`. The removed user's sessions are revoked immediately. You cannot
remove yourself, and the last administrator cannot be removed.

---

## How isolation works for API clients

- Every access token is issued for one active organization. All data
  endpoints (`/api/accounts`, `/api/findings`, `/api/reports`, `/api/aspm/*`
  and so on) return only that organization's data, without any extra
  parameter.
- To work in another organization, call `POST /api/auth/switch-tenant`
  (see `docs/api/auth.md`) and use the new tokens.
- Objects from another organization behave as if they do not exist
  (`404`), never as `403`, so ids cannot be probed.

## Errors

| Status | Meaning |
|---|---|
| `400` | Validation error, or an action on yourself that is not allowed |
| `403` | Not a super admin / not an organization admin |
| `404` | Organization or member not found |
| `409` | Already a member |

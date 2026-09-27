# Authentication API

Sessions use a short-lived JWT access token plus a rotating refresh token.
Every access token is bound to one **active organization**; see
`docs/api/tenants.md` for what an organization is.

**Base URL:** `/api/auth` (behind the gateway: `/api/cspm/auth`)

---

## Log in

```
POST /api/auth/login
```

| Field | Type | Required | Description |
|---|---|---|---|
| `email` | string | yes | |
| `password` | string | yes | |
| `tenantId` | string | no | Organization to start in. Defaults to the one used last, then the first membership. |

### Response `200`

```json
{
  "data": {
    "accessToken": "eyJ…",
    "refreshToken": "eyJ…",
    "user": {
      "id": "…",
      "email": "ana@acme.example",
      "role": "ANALYST",
      "isSuperAdmin": false,
      "tenant": { "id": "…", "slug": "acme", "name": "Acme Corp" },
      "memberships": [
        { "tenantId": "…", "slug": "acme", "name": "Acme Corp", "role": "ANALYST" },
        { "tenantId": "…", "slug": "globex", "name": "Globex", "role": "VIEWER" }
      ]
    }
  }
}
```

`role` is the user's role **in the active organization**. `tenant` is `null`
only for a platform super admin who has no memberships.

### Errors

| Status | Body | Meaning |
|---|---|---|
| `401` | `Invalid email or password` | Bad credentials or deactivated user |
| `403` | `Your account is not a member of any organization yet.` | Ask an administrator to add you |
| `429` | | Too many attempts; try later |

---

## Refresh tokens

```
POST /api/auth/refresh
```

Body: `{ "refreshToken": "…" }`. Returns new `accessToken`, `refreshToken`
and the current `user` object (same shape as login). The active organization
is preserved. If your membership in it was removed in the meantime, the
response is `403` and you must log in again.

---

## Switch organization

```
POST /api/auth/switch-tenant
```

Headers: `Authorization: Bearer <access token>`

Body: `{ "tenantId": "…", "refreshToken": "…" }`

Returns a fresh token pair and `user` for the requested organization. The
previous refresh token is revoked. Returns `403` if you are not a member.

Clients must discard all cached data after switching; nothing from the
previous organization is valid in the new one.

---

## Current user

```
GET /api/auth/me
```

Returns the `user` object described under login.

---

## Log out

```
POST /api/auth/logout
```

Body: `{ "refreshToken": "…" }`. Revokes that refresh token. Always returns
`200`, even if the access token has already expired.

---

## Token contents

Access tokens are signed JWTs (HS256) valid for 15 minutes by default. They
carry:

| Claim | Meaning |
|---|---|
| `sub` | User id |
| `role` | Role in the active organization |
| `tid` | Active organization id, or `null` for a super admin in platform context |
| `sa` | `true` for a platform super admin |
| `type` | `access` |

The ASPM and agent services accept the same token and apply the same
organization scope.

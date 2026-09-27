# Audit Log API

The audit log records who did what on the platform. Every request that
changes state (`POST`, `PUT`, `PATCH`, `DELETE`) and every request that was
denied (`401`/`403`) is stored with the acting user, the action, the outcome,
the client IP and a copy of the request body with secrets removed.

Read requests are not recorded, except when they are denied.

**Access:** `ADMIN` role only. Other roles receive `403 Forbidden`.

**Base URL:** `/api/audit-logs` (behind the gateway: `/api/cspm/audit-logs`)

**Auth:** `Authorization: Bearer <access token>`

---

## List entries

```
GET /api/audit-logs
```

Returns entries newest first, paginated.

### Query parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `page` | integer ≥ 1 | `1` | Page number |
| `limit` | integer 1–200 | `50` | Page size |
| `email` | string | | Case-insensitive substring match on the user's email |
| `userId` | string | | Exact user id |
| `action` | string | | Case-insensitive substring match, e.g. `approvals` |
| `method` | `GET` `POST` `PUT` `PATCH` `DELETE` | | HTTP method |
| `outcome` | `SUCCESS` `FAILED` `DENIED` | | Result class |
| `path` | string | | Case-insensitive substring match on the request path |
| `from` | ISO 8601 date-time | | Entries at or after this time |
| `to` | ISO 8601 date-time | | Entries at or before this time |

### Response `200`

```json
{
  "data": [
    {
      "id": "3f6d2c1e-…",
      "createdAt": "2026-09-27T09:41:12.318Z",
      "userId": "fc01c927-…",
      "userEmail": "admin@example.com",
      "userRole": "ADMIN",
      "action": "approvals.approve",
      "method": "POST",
      "path": "/api/approvals/7a1b…/approve",
      "statusCode": 200,
      "outcome": "SUCCESS",
      "ip": "203.0.113.10",
      "durationMs": 84
    }
  ],
  "page": 1,
  "limit": 50,
  "total": 1342,
  "totalPages": 27
}
```

### Example

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://sec-plat.example.com/api/cspm/audit-logs?outcome=DENIED&from=2026-09-01T00:00:00Z"
```

---

## List action names

```
GET /api/audit-logs/actions
```

Distinct `action` values seen so far, sorted. Useful for filter dropdowns.

### Response `200`

```json
{ "data": ["accounts.create", "accounts.delete", "approvals.approve", "auth.login", "scans.create"] }
```

---

## Get one entry

```
GET /api/audit-logs/:id
```

Returns the full entry, including the redacted request body.

### Response `200`

```json
{
  "data": {
    "id": "3f6d2c1e-…",
    "createdAt": "2026-09-27T09:41:12.318Z",
    "userId": "fc01c927-…",
    "userEmail": "admin@example.com",
    "actorEmail": null,
    "userRole": "ADMIN",
    "action": "accounts.create",
    "method": "POST",
    "path": "/api/accounts",
    "query": null,
    "statusCode": 201,
    "outcome": "SUCCESS",
    "ip": "203.0.113.10",
    "userAgent": "Mozilla/5.0 …",
    "requestBody": "{\"name\":\"prod\",\"accessKeyId\":\"[REDACTED]\",\"secretAccessKey\":\"[REDACTED]\"}",
    "durationMs": 312
  }
}
```

### Errors

| Status | Body |
|---|---|
| `404` | `{ "error": "Audit entry not found" }` |

---

## Field reference

| Field | Description |
|---|---|
| `action` | `<resource>.<verb>`, e.g. `accounts.create`, `findings.update`, `azure.scan`, `auth.login`. Sub-actions such as `approve`, `run`, `revert` replace the generic verb. |
| `outcome` | `SUCCESS` for 2xx/3xx, `DENIED` for 401/403, `FAILED` for any other 4xx/5xx |
| `userEmail` | The user's current email, or the email typed at login for failed login attempts |
| `userRole` | Role at the time of the request |
| `requestBody` | JSON string. Keys that look like secrets (password, token, key, credential, …) are replaced with `[REDACTED]`. Truncated at 4,000 characters. |
| `ip` | First address in `X-Forwarded-For`, else the socket address |

## Retention

Entries are kept indefinitely. If a user is deleted, their entries remain with
`userId` set to `null`.

## In the UI

Administrators find the log under **Operations → Audit Log**. Rows open a
detail panel with the redacted request body.

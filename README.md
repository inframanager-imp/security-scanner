# VAPT Cloud Scanner — Unified Platform

CSPM (cloud posture, Node) **+** ASPM/VA-PT (app & web scanning, Python) merged into
one product: **one URL, one login, one PostgreSQL database**.

```
Browser ──► nginx (web :8080) ──┬─ /                → React SPA (CSPM shell + ASPM)
                                ├─ /api/cspm/*  ───► cspm-api  (Node/Express)  :3001
                                ├─ /socket.io/* ───► cspm-api  (Socket.IO)
                                └─ /api/aspm/*  ───► aspm-api  (Python/FastAPI) :8000

cspm-api ─► Redis (BullMQ)            ┌──────────────────────────────┐
cspm-api ─► Postgres schema "cspm"    │   PostgreSQL  (db: vapt)      │
aspm-api ─► Postgres schema "aspm"    │   schema cspm  (Prisma, 46)   │
                                      │   schema aspm  (psycopg, 7)   │
                                      └──────────────────────────────┘
```

## Run

```bash
docker compose up -d --build
```

Open **http://localhost:8080** — login `admin@example.com` / `Admin@123456`.
The former AEGIS SEC app lives under the **"Application Security"** item in the sidebar.

Stop / reset:
```bash
docker compose down            # stop, keep data
docker compose down -v         # stop + wipe Postgres/Redis volumes
```

## Layout

```
vapt-cloud-scanner/
├── docker-compose.yml          # postgres + redis + cspm-api + aspm-api + web
├── infra/db/init.sql           # creates schemas cspm + aspm
├── web/                        # unified React app (CSPM shell) + nginx gateway
│   ├── src/aspm/components/    # ASPM views, calls rewritten to /api/aspm
│   ├── src/aspm/aspm-theme.css # cyber theme, scoped to .aspm-root
│   ├── src/pages/AspmWorkspace.tsx
│   └── nginx.conf              # serves SPA + proxies both APIs
└── services/
    ├── cspm/                   # Node service (api/ + src/); Prisma → schema cspm
    └── aspm/                   # Python FastAPI; psycopg → schema aspm
```

## How the merge works
- **DB:** one Postgres `vapt`. CSPM uses `?schema=cspm` in `DATABASE_URL` (`prisma db push`);
  ASPM connects with `search_path=aspm` (`DB_SCHEMA=aspm`), tables auto-created on boot.
  va-tool's SQLite is gone — it now uses Postgres via `psycopg`.
- **Frontend:** CSPM React app is the host shell (login, layout, routing). ASPM views are
  rendered inside it; their `/api/...` calls were rewritten to `/api/aspm/...`. The ASPM
  cyber theme is scoped to `.aspm-root` so it doesn't bleed into CSPM pages.
- **Gateway:** the `web` nginx serves the SPA and reverse-proxies `/api/cspm`, `/api/aspm`
  (SSE-friendly) and `/socket.io` to the right backend.

## Security before distributing
Change in `docker-compose.yml` (cspm-api env): `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`,
`CREDENTIAL_ENCRYPTION_KEY` (64 hex), `ADMIN_PASSWORD`, and the Postgres password.

## Unified auth (done)
One login authorizes both backends. The ASPM (Python) API validates the CSPM-issued
JWT (`services/aspm/backend/auth.py`, shared `JWT_ACCESS_SECRET`, applied globally).
The frontend sends it via `web/src/aspm/aspmClient.ts` (`Authorization: Bearer`, or a
`?token=` query param for download links). Set `ASPM_AUTH_REQUIRED=false` on aspm-api
to disable auth for local dev.

## Not yet done (future)
- Per-target deep-linking from the CSPM shell into specific ASPM scans.
- Role-based checks on ASPM (currently any valid CSPM user is allowed).

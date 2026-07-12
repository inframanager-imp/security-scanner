# VAPT Cloud Scanner — Unified Platform

CSPM (cloud posture, Node) **+** ASPM/VA-PT (app & web scanning, Python) merged into
one product: **one URL, one login, one PostgreSQL database**.

```
Browser ──► nginx (web :8080) ──┬─ /                → React SPA (CSPM shell + ASPM)
                                ├─ /api/cspm/*  ───► cspm-api  (Node/Express)  :3001
                                ├─ /socket.io/* ───► cspm-api  (Socket.IO)
                                └─ /api/aspm/*  ───► aspm-api  (Python/FastAPI) :8000

cspm-api ─► Redis (BullMQ, in-stack container)
cspm-api ─► PostgreSQL schema "cspm"   ┌──────────────────────────────────────────┐
aspm-api ─► PostgreSQL schema "aspm"   │  EXTERNAL PostgreSQL  (database: vapt)    │
                                       │  provisioned & managed by DevOps —        │
                                       │  NOT shipped as a container in this stack  │
                                       │    schema cspm  (Prisma)                  │
                                       │    schema aspm  (psycopg)                 │
                                       └──────────────────────────────────────────┘
```

## Deployment checklist (DevOps)
What the deployment team has to do, in order — details in the sections below.

1. **Provision PostgreSQL 14+** reachable from the Docker host (managed service or a server).
2. **Create the database objects:** run `infra/db/setup-local-db.sql` against it, using a
   strong DB password (see [Database setup](#1-database-setup-devops--do-this-first)).
3. **Provision a Docker host** with outbound internet for the build, and put this repo on it.
4. **Configure `.env`** — `cp .env.example .env`, then set the DB connection (`DB_*`),
   secrets (`JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `CREDENTIAL_ENCRYPTION_KEY`),
   `CORS_ORIGIN`, `ADMIN_PASSWORD`, `TZ` (see [Configure](#2-configure-env)).
5. **Build & start:** `docker compose up -d --build` (first build is large — see [Deploy](#3-deploy)).
6. **Terminate TLS in front** of the `web` container for production
   (see [Production hardening](#production-hardening)).
7. **Verify** (log in, run one test scan) and **set up database backups**.

## Prerequisites
- **Docker** + Docker Compose on the deployment host.
- An **external PostgreSQL 14+** reachable from the Docker host — a managed service
  (RDS / Cloud SQL / Azure Database for PostgreSQL) or a dedicated server. This stack does
  **not** ship a database container by default; DevOps provisions and configures it.
  - On a local dev box, your machine's native PostgreSQL on `localhost:5432` works — the
    containers reach it via `host.docker.internal` (already set in `docker-compose.yml`).
- Outbound internet on the **build** host: the `aspm-api` image pulls real scanner tooling
  and vulnerability databases at build time (see [Deploy](#3-deploy)).

## 1. Database setup (DevOps — do this first)
The platform uses one database `vapt` with two schemas (`cspm`, `aspm`) owned by a login
role. Create them once on the target PostgreSQL instance:

```bash
# Run as a PostgreSQL superuser, against the target DB instance:
psql -U <superuser> -h <db-host> -f infra/db/setup-local-db.sql
```

This creates the `scanner` role, the `vapt` database, and the `cspm` + `aspm` schemas
(see [infra/db/setup-local-db.sql](infra/db/setup-local-db.sql)). **Change the role name /
password** in that file — and match them in `.env` (`DB_USER` / `DB_PASSWORD`) — for any
non-local deployment. The backends auto-create their own tables on first boot — CSPM via
`prisma db push`, ASPM via `init_db()` — so no migrations to run by hand.

## 2. Configure (`.env`)
All deploy-specific config is read from a **`.env`** file in the repo root (`docker compose`
loads it automatically). Copy the template and edit it — never commit the real `.env`:

```bash
cp .env.example .env
```

| `.env` variable | Notes |
|-----------------|-------|
| `DB_USER`, `DB_PASSWORD` | PostgreSQL login role (from step 1). URL-encode the password if it has `@ : / ?`. |
| `DB_HOST`, `DB_PORT`, `DB_NAME` | `host.docker.internal` for a DB on the Docker host, else the managed DB's hostname; port `5432`; db `vapt`. |
| `JWT_ACCESS_SECRET` | shared login secret — used to **sign and verify** the JWT across both backends. |
| `JWT_REFRESH_SECRET` | refresh-token secret. |
| `CREDENTIAL_ENCRYPTION_KEY` | exactly **64 hex** characters. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | first-login admin account. |
| `WEB_PORT` | host port for the UI (default `8080`). |
| `CORS_ORIGIN` | the public URL users hit (`https://…` in production). |
| `TZ` | timezone for report timestamps (default `Asia/Kolkata`). |

The two backends build their `DATABASE_URL`s from `DB_*` (cspm adds `?schema=cspm`, aspm uses
`DB_SCHEMA=aspm`), so both always point at the **same** `vapt` database. The compose file has
`${VAR:-default}` fallbacks, so it still runs if `.env` is missing — but `.env` is the intended
place to configure a deployment.

Generate strong secrets (don't ship the defaults):
```bash
openssl rand -hex 32   # JWT_ACCESS_SECRET
openssl rand -hex 32   # JWT_REFRESH_SECRET
openssl rand -hex 32   # CREDENTIAL_ENCRYPTION_KEY  (64 hex chars)
```

> Optional: to run Postgres *inside* the stack for a self-contained dev deploy instead of an
> external DB, uncomment the `postgres` service in `docker-compose.yml` and set `DB_HOST=postgres`
> in `.env` (this path uses `infra/db/init.sql`).

## 3. Deploy

```bash
docker compose up -d --build
```

The first build is **large and network-heavy**: `aspm-api` ships real scanner binaries
(nmap, nuclei, gobuster, trivy, semgrep, …) and **bakes in Trivy's vulnerability + Java DBs
(~2.6 GB)** so the first SCA scan doesn't have to download them. Allow build time, disk, and
outbound internet on the build host.

Open **http://localhost:8080** (or your `CORS_ORIGIN`) — login `admin@example.com` /
`Admin@123456` (or your configured admin). The former AEGIS SEC app lives under the
**"Application Security"** item in the sidebar.

Stop / reset:
```bash
docker compose down            # stop containers; the external DB is untouched
docker compose down -v         # also wipe the Redis volume (the external DB is NOT wiped)
```

## Production hardening
- **TLS / reverse proxy:** the `web` container serves plain HTTP on `:8080`. In production put
  it behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik, or a cloud load balancer)
  and set `CORS_ORIGIN` (cspm-api) to the public `https://` URL. Don't expose `:8080` publicly.
- **Secrets:** never deploy the default `JWT_*`, `CREDENTIAL_ENCRYPTION_KEY`, `ADMIN_PASSWORD`,
  or DB password. Keep them in a secrets manager or an untracked `.env`, not in git.
- **Database:** it lives outside the stack, so DevOps owns **backups, HA, and patching**.
  Restrict network access so only the Docker host can reach port `5432`.
- **Restart on boot:** services use `restart: unless-stopped`; make sure the Docker daemon
  starts on host boot so the stack comes back after a reboot.
- **Host sizing:** scans run real tools (OWASP ZAP, nuclei, trivy, semgrep). Give the host
  enough CPU/RAM/disk — the `aspm-api` image alone is several GB (it bundles the scanners and
  Trivy's vulnerability databases).
- **Egress:** the build and the scanners need outbound internet (tool feeds, package
  registries, target hosts). Allow it, or pre-mirror the feeds in an air-gapped setup.

## Layout

```
vapt-cloud-scanner/
├── docker-compose.yml          # redis + cspm-api + aspm-api + web   (PostgreSQL is EXTERNAL)
├── infra/db/setup-local-db.sql # one-time: scanner role + vapt db + cspm/aspm schemas
├── infra/db/init.sql           # only used if you enable the optional in-stack postgres service
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
- **DB:** one external Postgres `vapt`. CSPM uses `?schema=cspm` in `DATABASE_URL`
  (`prisma db push`); ASPM connects with `search_path=aspm` (`DB_SCHEMA=aspm`), tables
  auto-created on boot. va-tool's SQLite is gone — it now uses Postgres via `psycopg`.
- **Frontend:** CSPM React app is the host shell (login, layout, routing). ASPM views are
  rendered inside it; their `/api/...` calls were rewritten to `/api/aspm/...`. The ASPM
  cyber theme is scoped to `.aspm-root` so it doesn't bleed into CSPM pages.
- **Gateway:** the `web` nginx serves the SPA and reverse-proxies `/api/cspm`, `/api/aspm`
  (SSE-friendly) and `/socket.io` to the right backend.

## Security before distributing
Everything sensitive lives in **`.env`** (see [Configure](#2-configure-env)) — change the
defaults before any real deployment: `DB_USER` / `DB_PASSWORD`, `JWT_ACCESS_SECRET` (identical
for both services) + `JWT_REFRESH_SECRET`, `CREDENTIAL_ENCRYPTION_KEY` (64 hex), `CORS_ORIGIN`,
and `ADMIN_PASSWORD`. Change the DB role password in `infra/db/setup-local-db.sql` to match,
and keep the real `.env` out of git (it is already `.gitignore`d; commit only `.env.example`).

## Unified auth (done)
One login authorizes both backends. The ASPM (Python) API validates the CSPM-issued
JWT (`services/aspm/backend/auth.py`, shared `JWT_ACCESS_SECRET`, applied globally).
The frontend sends it via `web/src/aspm/aspmClient.ts` (`Authorization: Bearer`, or a
`?token=` query param for download links). Set `ASPM_AUTH_REQUIRED=false` on aspm-api
to disable auth for local dev.

## Not yet done (future)
- Per-target deep-linking from the CSPM shell into specific ASPM scans.
- Role-based checks on ASPM (currently any valid CSPM user is allowed).
```

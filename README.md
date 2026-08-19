# VAPT Cloud Scanner — Unified Platform

CSPM (cloud posture, Node) **+** ASPM/VA-PT (app & web scanning, Python) merged into
one product: **one URL, one login, one PostgreSQL database**.

```
Browser ──► nginx (web :8080) ──┬─ /                → React SPA (CSPM shell + ASPM)
                                ├─ /api/cspm/*  ───► cspm-api    (Node/Express)     :3001
                                ├─ /socket.io/* ───► cspm-api    (Socket.IO)
                                ├─ /api/aspm/*  ───► aspm-api    (Python/FastAPI)   :8000
                                └─ /api/agent/* ───► agent-api   (LangGraph triage) :8100

cspm-api ─► postgres (schema "cspm", Prisma)   ┐
aspm-api ─► postgres (schema "aspm", psycopg)  ├─► one Postgres 16 "vapt" database,
cspm-api ─► redis (BullMQ job queues)          │   redis, and a ZAP daemon all run
aspm-api ─► zap (OWASP ZAP daemon, DAST)       ┘   as containers in this same stack
```

All seven containers (`postgres`, `redis`, `zap`, `cspm-api`, `aspm-api`, `agent-api`, `web`)
are defined in one `docker-compose.yml` — `docker compose up -d --build` is the entire
deployment. Each app-stack container has a Docker healthcheck, and `web`/`aspm-api` wait for
their dependencies to report healthy before starting.

## Features

### Cloud Security (CSPM) — AWS / Azure / GCP
- Multi-account/subscription posture scanning across all three major clouds, with
  Prowler-parity check coverage on the AWS and Azure registries
- Resource inventory, dependency graph, exposure-path computation, and config-change
  tracking with baseline/drift detection and an approval workflow before remediation
- **Prioritized Risks** — findings scored by `severity × network reachability × business
  context × exploit maturity`, not severity alone, so a CRITICAL finding on an internet-facing
  production resource ranks above the same CVE on an isolated dev box
- **CIEM** (identity/attack-path graph, self-escalation and PassRole detection),
  **DSPM** (S3/data-store exposure and sensitivity classification),
  **CWPP** (agent-based workload vulnerability scanning via SSM-managed hosts),
  **IAM Privilege Escalation** detection and an IAM users inventory
- Anomaly detection, threat/CloudTrail monitoring, compliance scoring against standard
  frameworks, freeze-window controls, and a manually-curated risk register
- Scheduled and on-demand VAPT/executive reports (PDF), config-sync via cloud-native
  event triggers (EventBridge/Event Grid/Pub-Sub) with a periodic-poll fallback

### Application Security (ASPM) — Vulnerability Pipeline
An 11-stage pipeline per onboarded Git target, each stage independently resumable:

1. **Repo Ingestion & Stack Detection** — clone, language/framework detection
2. **SAST** (Semgrep), **Secret Detection** (GitLeaks), **Dependency Scan** (pip-audit)
3. **Blind-Spot Sweep** — adversarial single-file LLM review of every source file no other
   scanner flagged at all, so coverage isn't limited to what pattern-matching rules catch
4. **AI Triage** — RAG-grounded (structure-aware chunking with overlap, confidence-thresholded
   retrieval, cosine + keyword reranking, per-chunk citations) and **CVE-aware** (live NVD
   lookup by CWE, cached per finding class) exploitability verdicts
5. **Fix Generation** — AI-proposed remediation, cached by CWE + semantic similarity to avoid
   redundant LLM calls for recurring finding classes
6. **Human-in-the-loop approval gate** — the pipeline pauses after the fix plan is generated
   and waits for explicit approval before anything is written to the repo
7. **Apply Patches** — patches are **re-scan verified** (the same SAST rule is re-run against
   the patched file) before being committed; a patch that doesn't actually clear the finding
   is reverted, not shipped
8. **Build & Compile Check**
9. **Push Branch & Open Pull Request** — GitHub, GitLab, Bitbucket, Gitee, and GitCode supported

### Attack-Chain Synthesis
Computes, on demand, whether a target's open findings could plausibly combine into a
multi-step attack — findings are classified by vulnerability role (code execution, file
access, information theft, access escalation, auth bypass) and chained via graph transitive
closure, deduplicated so rotations of the same underlying finding cluster aren't reported as
separate chains.

### Taint Analysis (Phase 1 — preview)
Real static analysis infrastructure — AST parsing, call-graph construction, and
source/sink/sanitizer tagging (Python source) — surfaced as a read-only diagnostic report.
Deliberately not yet wired into findings: it tags where sources and sinks *are*, not yet
whether a source provably *reaches* a sink (taint propagation is a planned follow-up phase).

### Multi-LLM with Automatic Fallback
Primary provider is configurable (OpenAI, Anthropic, or Groq); if a call fails specifically
due to a credits/quota/rate-limit error, it transparently retries once against a local Ollama
model instead of failing the pipeline stage outright. Any other kind of error still surfaces
normally.

### Triage Benchmark Suite
A labeled dataset of known-vulnerable and known-safe code findings, scored against the live
triage/judge pipeline for precision, recall, and F1 — so changes to prompts, retrieval, or
reranking can be measured against a fixed baseline instead of judged by spot-checks. Run
history is tracked over time (`services/agent-api/benchmark.py`).

## Deployment checklist (DevOps)
What the deployment team has to do, in order — details in the sections below.

1. **Provision a Docker host** with outbound internet for the build, and put this repo on it.
2. **Generate secrets and configure** `docker-compose.yml` / `.env` (see [Configure](#2-configure)):
   `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `ZAP_API_KEY`, the shared `JWT_ACCESS_SECRET`,
   `JWT_REFRESH_SECRET`, `CREDENTIAL_ENCRYPTION_KEY`, `CORS_ORIGIN`, `ADMIN_PASSWORD`, `TZ`.
3. **Build & start:** `docker compose up -d --build` (first build is large — see [Deploy](#3-deploy)).
   Postgres, Redis, and ZAP come up as part of the same stack — no separate provisioning step.
4. **Terminate TLS in front** of the `web` container for production
   (see [Production hardening](#production-hardening)).
5. **Verify** (log in, run one test scan) and **set up database backups** (see
   [Production hardening](#production-hardening) — this is still a manual DevOps step).

## Prerequisites
- **Docker** + Docker Compose on the deployment host. That's it — Postgres, Redis, and ZAP
  all run as containers in this same `docker-compose.yml`, no external database to provision.
- Outbound internet on the **build** host: the `aspm-api` image pulls real scanner tooling
  and vulnerability databases at build time (see [Deploy](#3-deploy)).

## 1. Database setup
No manual step needed for a fresh deploy — the `postgres` service in `docker-compose.yml`
creates the `vapt` database on first boot, and both backends auto-create their own tables on
first boot (CSPM via `prisma db push`, ASPM via `init_db()`). `infra/db/init.sql` seeds the
`cspm` + `aspm` schemas via Postgres's `docker-entrypoint-initdb.d` mechanism.

If you're instead pointing at a database you provisioned yourself (managed Postgres, a
dedicated server), run `infra/db/setup-local-db.sql` against it once as a superuser — see
[infra/db/setup-local-db.sql](infra/db/setup-local-db.sql) — and remove the `postgres` service
from `docker-compose.yml` in favor of pointing `DATABASE_URL`/`ASPM_DATABASE_URL` at that host.

## 2. Configure
Secrets live in `.env` (gitignored) next to `docker-compose.yml`, which reads it automatically:

| Service  | Variable                | Value / notes |
|----------|-------------------------|---------------|
| postgres | `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | credentials for the bundled Postgres container |
| redis    | `REDIS_PASSWORD`        | password for the bundled Redis container |
| —        | `DATABASE_URL`          | `postgresql://<user>:<pass>@vapt-db:5432/vapt?schema=cspm` (must match the postgres credentials above) |
| —        | `ASPM_DATABASE_URL`     | `postgresql+psycopg://<user>:<pass>@vapt-db:5432/vapt` |
| —        | `REDIS_URL`             | `redis://:<pass>@vapt-redis:6379` (must match `REDIS_PASSWORD`) |
| —        | `ZAP_API_KEY`, `ZAP_PROXY` | API key for the bundled ZAP container; `ZAP_PROXY=http://vapt-zap:8090` |
| both     | `JWT_ACCESS_SECRET`     | long random value — **must be identical** on cspm-api and aspm-api (shared login) |
| cspm-api | `JWT_REFRESH_SECRET`    | long random value |
| cspm-api | `CREDENTIAL_ENCRYPTION_KEY` | 64 hex characters |
| cspm-api | `CORS_ORIGIN`           | the public URL users hit (e.g. `https://scanner.example.com`) |
| cspm-api | `ADMIN_EMAIL`, `ADMIN_PASSWORD` | first-login admin account |
| aspm-api | `TZ`                    | timezone for report timestamps (default `Asia/Kolkata`) |
| agent-api | `LLM_PROVIDER`, `AGENT_MODEL`, `*_API_KEY` | triage LLM — `ollama` (local), `anthropic`, `openai`, or `groq` |

The container names (`vapt-db`, `vapt-redis`, `vapt-zap`) are fixed by `docker-compose.yml`'s
`container_name:` entries — the connection strings above work as-is against the bundled
services without editing `docker-compose.yml` itself.

Generate strong secrets (don't ship the defaults):
```bash
openssl rand -hex 32   # JWT_ACCESS_SECRET   (set the SAME value on cspm-api AND aspm-api)
openssl rand -hex 32   # JWT_REFRESH_SECRET
openssl rand -hex 32   # CREDENTIAL_ENCRYPTION_KEY  (must be 64 hex chars)
```

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

**API docs:** `aspm-api` and `agent-api` (both FastAPI) auto-generate interactive Swagger UI —
`http://localhost:8080/api/aspm/docs` and `http://localhost:8080/api/agent/docs` (ReDoc at
`/redoc`, raw spec at `/openapi.json` on each). `cspm-api` (Express) has no equivalent — no
OpenAPI spec is generated for it currently.

Stop / reset:
```bash
docker compose down            # stop containers; named volumes (postgres/redis data) untouched
docker compose down -v         # also wipe postgres + redis data — destructive, dev use only
```

## Production hardening
- **TLS / reverse proxy:** the `web` container serves plain HTTP on `:8080`. In production put
  it behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik, or a cloud load balancer)
  and set `CORS_ORIGIN` (cspm-api) to the public `https://` URL. Don't expose `:8080` publicly.
- **Secrets:** never deploy the default `JWT_*`, `CREDENTIAL_ENCRYPTION_KEY`, `ADMIN_PASSWORD`,
  or DB/Redis passwords. Keep them in `.env` (gitignored) or a secrets manager, never in git —
  see [Security before distributing](#security-before-distributing) below.
- **Database backups:** `infra/db/backup.sh` runs `pg_dump` (custom format, compressed) inside
  the `vapt-db` container to `infra/db/backups/` (gitignored) and prunes anything older than
  `RETENTION_DAYS` (default 14). On the Linux deployment host, run
  `./infra/db/install-cron.sh` once to schedule it daily at 2am (`BACKUP_HOUR=N` to change the
  hour) — idempotent, safe to re-run, logs to `infra/db/backups/backup.log`.
  `infra/db/restore.sh <backup-file>` restores one: stops the app containers, `pg_restore
  --clean` into `vapt-db`, restarts them. **Destructive** — drops and recreates every table
  first — so it prompts for confirmation unless run with `-y`/`--yes`. All three scripts have
  been run end-to-end against a live database (1342 findings, 162 vulnerabilities, restored
  with an exact row-count match; the cron installer verified idempotent against a mock
  crontab).
- **Restart on boot:** services use `restart: unless-stopped`; make sure the Docker daemon
  starts on host boot so the stack comes back after a reboot.
- **Host sizing:** scans run real tools (OWASP ZAP, nuclei, trivy, semgrep). Give the host
  enough CPU/RAM/disk — the `aspm-api` image alone is several GB (it bundles the scanners and
  Trivy's vulnerability databases). ZAP's JVM heap is capped at 1GB (`-Xmx1024m`) with a 1.5GB
  container memory limit to prevent it auto-sizing to a quarter of the *host's* total RAM.
- **Egress:** the build and the scanners need outbound internet (tool feeds, package
  registries, target hosts). Allow it, or pre-mirror the feeds in an air-gapped setup.
- **Rate limiting:** nginx applies a 15 req/s (burst 30) limit to `/api/aspm/` and
  `/api/agent/` at the edge — `cspm-api` self-limits via `express-rate-limit` instead.
- **Monitoring/alerting:** `infra/monitoring/watchdog.sh` checks each app-stack container's
  Docker health status plus its HTTP health endpoint through nginx, and posts to a
  Slack-compatible webhook (`WEBHOOK_URL` in `infra/monitoring/.env`, gitignored) only on a
  state *transition* (healthy→failing or failing→healthy) after `FAIL_THRESHOLD` consecutive
  failures (default 2, to absorb a single transient blip without paging anyone) — not on every
  run, so a down service doesn't spam the channel every 5 minutes it stays down.
  `./infra/monitoring/install-cron.sh` schedules it (every 5 minutes by default) on the Linux
  deployment host, idempotent like the backup cron installer. Verified end-to-end against a
  mock webhook receiver: down-detection, debounced alerting, and the recovery notice all fire
  correctly. Without `WEBHOOK_URL` set, alerts still land in `infra/monitoring/watchdog.log`
  (also gitignored) — an external uptime monitor (UptimeRobot, Healthchecks.io) hitting the
  same health endpoints is a reasonable alternative/addition if you'd rather not self-host this.

## Layout

```
vapt-cloud-scanner/
├── docker-compose.yml          # postgres + redis + zap + cspm-api + aspm-api + agent-api + web
├── infra/db/init.sql           # seeds the cspm/aspm schemas on the bundled postgres container's first boot
├── infra/db/setup-local-db.sql # one-time script for a self-provisioned (non-bundled) Postgres instance
├── web/                        # unified React app (CSPM shell) + nginx gateway
│   ├── src/aspm/components/    # ASPM views, calls rewritten to /api/aspm
│   ├── src/aspm/aspm-theme.css # cyber theme, scoped to .aspm-root
│   ├── src/pages/AspmWorkspace.tsx
│   └── nginx.conf              # serves SPA + proxies /api/cspm, /api/aspm, /api/agent
└── services/
    ├── cspm/                   # Node service (api/ + src/); Prisma → schema cspm
    ├── aspm/                   # Python FastAPI; psycopg → schema aspm; bundles real scanner tooling
    └── agent-api/              # LangGraph triage/remediation agent (SAST/SCA/DAST findings)
```

## How the merge works
- **DB:** one Postgres `vapt` database, bundled as the `postgres` service in this stack. CSPM
  uses `?schema=cspm` in `DATABASE_URL` (`prisma db push`); ASPM connects with
  `search_path=aspm` (`DB_SCHEMA=aspm`), tables auto-created on boot.
- **Frontend:** CSPM React app is the host shell (login, layout, routing). ASPM views are
  rendered inside it; their `/api/...` calls were rewritten to `/api/aspm/...`. The ASPM
  cyber theme is scoped to `.aspm-root` so it doesn't bleed into CSPM pages.
- **Gateway:** the `web` nginx serves the SPA and reverse-proxies `/api/cspm`, `/api/aspm`
  (SSE-friendly), `/api/agent`, and `/socket.io` to the right backend.
- **AI triage agent:** `agent-api` (LangGraph) does exploitability triage, judge verification,
  and remediation-diff generation for ASPM findings, called by `aspm-api` over HTTP. Falls back
  to the scanner's own heuristic verdict if `agent-api` is unreachable/unconfigured, and can
  fall back from a paid provider (OpenAI/Anthropic/Groq) to local Ollama on a quota/credit error.

## Security before distributing
Set in `.env` (gitignored, next to `docker-compose.yml`): `POSTGRES_PASSWORD`,
`REDIS_PASSWORD`, `ZAP_API_KEY`, `JWT_ACCESS_SECRET` (matching on both services) +
`JWT_REFRESH_SECRET`, `CREDENTIAL_ENCRYPTION_KEY` (64 hex), `CORS_ORIGIN`, `ADMIN_PASSWORD`.
`aspm-api`'s CORS is restricted to `CORS_ORIGIN` (not a wildcard) — a wildcard combined with
credentialed requests would let any origin make authenticated calls.

## Unified auth (done)
One login authorizes both backends. The ASPM (Python) API validates the CSPM-issued
JWT (`services/aspm/backend/auth.py`, shared `JWT_ACCESS_SECRET`, applied globally).
The frontend sends it via `web/src/aspm/aspmClient.ts` (`Authorization: Bearer`, or a
`?token=` query param for download links). Set `ASPM_AUTH_REQUIRED=false` on aspm-api
to disable auth for local dev.

## Not yet done (future)
- **Alert delivery still needs a real webhook URL configured** — `infra/monitoring/watchdog.sh`
  and its cron installer exist and are verified working, but `WEBHOOK_URL` is unset by default;
  set it in `infra/monitoring/.env` before relying on this in production.
- **SCA patch generation** — `Apply Patches` can't yet auto-fix dependency/lockfile findings the
  way it can source-code findings (a version bump has no single "vulnerable line" to diff
  against), so these are triaged and reported but not auto-remediated.
- Per-target deep-linking from the CSPM shell into specific ASPM scans.
- Role-based checks on ASPM (currently any valid CSPM user is allowed).
- Per-pipeline-run code mirroring — each ASPM pipeline stage does its own fresh shallow clone
  rather than sharing one pinned checkout, so a target repo that changes mid-run can (rarely)
  cause a later stage's line numbers to drift from an earlier stage's.

# Running the CSPM platform with Docker

Fully self-contained: Postgres, Redis, the API (with all background workers) and the
web UI all run in containers. No Node, Postgres or Redis needs to be installed on the
host — only Docker.

## Quick start

```bash
cd cloud-scanner-sam/aws-scanner
docker compose up -d --build
```

Open **http://localhost:8080** and log in with:

- email: `admin@example.com`
- password: `Admin@123456`

Stop / reset:

```bash
docker compose down            # stop, keep data
docker compose down -v         # stop and delete the DB + Redis volumes
```

## What runs

| Service    | Image / build      | Port (host) | Notes |
|------------|--------------------|-------------|-------|
| `web`      | `Dockerfile.web`   | **8080→80** | nginx serves the React build, proxies `/api` + `/socket.io` to the API |
| `api`      | `Dockerfile.api`   | (internal 3001) | Express + Prisma + **all 11 BullMQ workers** + Socket.IO; runs migrations + admin seed on boot |
| `postgres` | `postgres:16`      | 5432 | data in `postgres_data` volume |
| `redis`    | `redis:7`          | 6379 | BullMQ queue, `redis_data` volume |

The API image includes the root `src/` scanner engine (the API imports it via
`../../../src/...`), so scanning works inside the container.

## Before distributing / going to production

Edit the `api` service `environment:` block in `docker-compose.yml`:

- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` — random ≥32-char strings
- `CREDENTIAL_ENCRYPTION_KEY` — exactly 64 hex chars (`node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`)
- `ADMIN_PASSWORD` — strong password
- `CORS_ORIGIN` — the public URL the UI is served from

Cloud credentials (AWS/Azure/GCP) are **not** baked into the image — they are added
at runtime through the UI and stored encrypted in Postgres.

## CLI-only usage (no UI)

The same image can run the standalone scanner CLI:

```bash
docker build -f Dockerfile.api -t cspm-cli .
docker run --rm -e AWS_REGION=us-east-1 cspm-cli \
  npx ts-node --transpile-only src/cli/index.ts scan --help
```

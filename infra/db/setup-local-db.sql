-- ─────────────────────────────────────────────────────────────────────────────
-- One-time setup for using your MACHINE's native PostgreSQL with the platform.
-- Run once as a PostgreSQL SUPERUSER (usually the "postgres" user):
--
--   psql -U postgres -h localhost -f infra/db/setup-local-db.sql
--
-- After this, the app's backends auto-create their tables on boot
-- (CSPM via `prisma db push`, ASPM via init_db()).
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. Login role used by both services (matches the DATABASE_URL in docker-compose.yml)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'scanner') THEN
    CREATE ROLE scanner WITH LOGIN PASSWORD 'scanner_pass';
  END IF;
END $$;

-- 2. Database (idempotent — CREATE DATABASE can't run in a DO block)
SELECT 'CREATE DATABASE vapt OWNER scanner'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'vapt')\gexec

-- 3. Schemas inside the vapt database
\connect vapt
CREATE SCHEMA IF NOT EXISTS cspm AUTHORIZATION scanner;
CREATE SCHEMA IF NOT EXISTS aspm AUTHORIZATION scanner;
GRANT ALL ON SCHEMA cspm TO scanner;
GRANT ALL ON SCHEMA aspm TO scanner;

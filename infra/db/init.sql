-- Runs once on first Postgres startup (mounted into /docker-entrypoint-initdb.d).
-- One database, two schemas: CSPM (Prisma) and ASPM (the former va-tool).
CREATE SCHEMA IF NOT EXISTS cspm;
CREATE SCHEMA IF NOT EXISTS aspm;

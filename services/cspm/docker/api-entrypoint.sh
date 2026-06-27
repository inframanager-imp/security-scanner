#!/bin/sh
set -e

echo "[entrypoint] Syncing database schema..."
# Use `db push` instead of `migrate deploy`: the project's committed migrations are
# incomplete (schema.prisma defines columns like inventoryStatus / lastDiscoveryAt
# that no migration creates). db push forces the DB to match schema.prisma exactly,
# which is what a self-contained distributable needs.
npx prisma db push --schema=api/prisma/schema.prisma --skip-generate --accept-data-loss

echo "[entrypoint] Starting API server + workers..."
# transpile-only skips type-checking so the service always boots; the API imports
# the scanner from ../../../src which is why we run from the repo root with ts-node.
exec npx ts-node --transpile-only --project api/tsconfig.json api/src/server.ts

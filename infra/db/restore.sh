#!/usr/bin/env bash
# ── Postgres restore for the bundled "postgres" container (vapt-db) ──────────
# DESTRUCTIVE: drops and recreates every object in the target database before
# restoring. Always confirms interactively unless -y/--yes is passed (for
# scripted/CI use — pass it deliberately, not by habit).
#
# Usage:
#   ./infra/db/restore.sh infra/db/backups/vapt_20260819_020000.dump
#   ./infra/db/restore.sh --yes infra/db/backups/vapt_20260819_020000.dump
set -euo pipefail

CONTAINER="${POSTGRES_CONTAINER:-vapt-db}"
DB_NAME="${POSTGRES_DB:-vapt}"
DB_USER="${POSTGRES_USER:-scanner}"

ASSUME_YES=false
if [ "${1:-}" = "-y" ] || [ "${1:-}" = "--yes" ]; then
  ASSUME_YES=true
  shift
fi

BACKUP_FILE="${1:-}"
if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 [-y|--yes] <path-to-backup.dump>" >&2
  exit 1
fi
if [ ! -f "$BACKUP_FILE" ]; then
  echo "[!] Backup file not found: $BACKUP_FILE" >&2
  exit 1
fi

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "[!] Container '$CONTAINER' not found or not running. Is the stack up?" >&2
  exit 1
fi

echo "[!] This will DROP and recreate every object in database '$DB_NAME' on container '$CONTAINER',"
echo "    then restore it from: $BACKUP_FILE"
echo "    Both the cspm and aspm schemas will be replaced -- all current data is lost."
if [ "$ASSUME_YES" != true ]; then
  read -r -p "Type 'restore' to proceed: " CONFIRM
  if [ "$CONFIRM" != "restore" ]; then
    echo "Aborted."
    exit 1
  fi
fi

echo "[*] Stopping app services so nothing writes mid-restore (postgres/redis/zap stay up)..."
# No "|| true" here deliberately: if this fails, app containers may still be
# writing to the DB during the restore below -- that's a silent-corruption
# risk, not something to shrug off and continue past.
if ! docker compose stop cspm-api aspm-api agent-api web 2>&1 | sed 's/^/    /'; then
  echo "[!] Failed to stop app services. Aborting before touching the database." >&2
  echo "    (If this is an env-var resolution issue, restore your shell session's" >&2
  echo "    environment -- e.g. re-source docker-compose.yml's required vars -- and retry.)" >&2
  exit 1
fi

echo "[*] Restoring $BACKUP_FILE into '$DB_NAME'..."
docker exec -i "$CONTAINER" pg_restore -U "$DB_USER" -d "$DB_NAME" --clean --if-exists --no-owner < "$BACKUP_FILE"

echo "[+] Restore complete. Restarting app services..."
docker compose start cspm-api aspm-api agent-api web 2>&1 | sed 's/^/    /'

echo "[+] Done. Verify with: docker compose ps"

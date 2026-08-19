#!/usr/bin/env bash
# ── Postgres backup for the bundled "postgres" container (vapt-db) ───────────
# Runs pg_dump *inside* the container (no local psql/pg_dump needed on the
# host) in custom format (-Fc), which is compressed and supports selective
# restore via pg_restore -- a plain SQL dump doesn't.
#
# Usage:
#   ./infra/db/backup.sh                 # backup now, default retention (14 days)
#   RETENTION_DAYS=30 ./infra/db/backup.sh
#
# Cron example (daily at 2am, from the repo root):
#   0 2 * * * cd /path/to/security-scanner-dev && ./infra/db/backup.sh >> infra/db/backups/backup.log 2>&1
set -euo pipefail

CONTAINER="${POSTGRES_CONTAINER:-vapt-db}"
DB_NAME="${POSTGRES_DB:-vapt}"
DB_USER="${POSTGRES_USER:-scanner}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$SCRIPT_DIR/backups}"
mkdir -p "$BACKUP_DIR"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "[!] Container '$CONTAINER' not found or not running. Is the stack up?" >&2
  exit 1
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_FILE="$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.dump"

echo "[*] Backing up database '$DB_NAME' from container '$CONTAINER' to $OUT_FILE ..."
docker exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$OUT_FILE"

SIZE="$(du -h "$OUT_FILE" | cut -f1)"
echo "[+] Backup complete: $OUT_FILE ($SIZE)"

# Prune backups older than RETENTION_DAYS so this directory doesn't grow
# unbounded on an unattended cron schedule.
DELETED=0
while IFS= read -r -d '' old; do
  rm -f "$old"
  DELETED=$((DELETED + 1))
done < <(find "$BACKUP_DIR" -name "${DB_NAME}_*.dump" -mtime "+${RETENTION_DAYS}" -print0)

if [ "$DELETED" -gt 0 ]; then
  echo "[*] Pruned $DELETED backup(s) older than ${RETENTION_DAYS} days."
fi

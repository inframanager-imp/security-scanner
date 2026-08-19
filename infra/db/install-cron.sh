#!/usr/bin/env bash
# ── Installs the daily backup.sh cron job on a Linux deployment host ─────────
# Run this ONCE on the host that runs `docker compose up` for this stack.
# Idempotent: safe to re-run (replaces any existing entry for this repo path
# instead of duplicating it).
#
# Usage:
#   ./infra/db/install-cron.sh                # daily at 2am
#   BACKUP_HOUR=3 ./infra/db/install-cron.sh   # daily at 3am
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKUP_HOUR="${BACKUP_HOUR:-2}"

MARKER="# vapt-cloud-scanner db backup ($REPO_ROOT)"
CRON_LINE="0 ${BACKUP_HOUR} * * * cd $REPO_ROOT && ./infra/db/backup.sh >> $REPO_ROOT/infra/db/backups/backup.log 2>&1 $MARKER"

mkdir -p "$REPO_ROOT/infra/db/backups"

# Rebuild the crontab: keep every existing line that isn't this repo's own
# marker, then append the (possibly updated) entry -- this is what makes
# re-running the script idempotent instead of appending duplicates.
EXISTING="$(crontab -l 2>/dev/null | grep -vF "$MARKER" || true)"
{
  if [ -n "$EXISTING" ]; then
    printf '%s\n' "$EXISTING"
  fi
  printf '%s\n' "$CRON_LINE"
} | crontab -

echo "[+] Installed cron job: daily backup at ${BACKUP_HOUR}:00, logging to infra/db/backups/backup.log"
echo "[*] Verify with: crontab -l"

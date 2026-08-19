#!/usr/bin/env bash
# ── Installs the watchdog.sh cron job on a Linux deployment host ─────────────
# Run this ONCE on the host that runs `docker compose up` for this stack.
# Idempotent: safe to re-run (replaces any existing entry for this repo path
# instead of duplicating it). Same pattern as infra/db/install-cron.sh.
#
# Usage:
#   ./infra/monitoring/install-cron.sh                    # every 5 minutes
#   WATCHDOG_INTERVAL_MIN=10 ./infra/monitoring/install-cron.sh
#
# Set WEBHOOK_URL in infra/monitoring/.env (gitignored) before running this,
# or alerts will only be logged locally, never delivered anywhere:
#   echo 'WEBHOOK_URL=https://hooks.slack.com/services/...' > infra/monitoring/.env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INTERVAL="${WATCHDOG_INTERVAL_MIN:-5}"

MARKER="# vapt-cloud-scanner watchdog ($REPO_ROOT)"
CRON_LINE="*/${INTERVAL} * * * * cd $REPO_ROOT && ./infra/monitoring/watchdog.sh >> $REPO_ROOT/infra/monitoring/watchdog.log 2>&1 $MARKER"

EXISTING="$(crontab -l 2>/dev/null | grep -vF "$MARKER" || true)"
{
  if [ -n "$EXISTING" ]; then
    printf '%s\n' "$EXISTING"
  fi
  printf '%s\n' "$CRON_LINE"
} | crontab -

echo "[+] Installed cron job: watchdog every ${INTERVAL} minute(s), logging to infra/monitoring/watchdog.log"
if [ ! -f "$SCRIPT_DIR/.env" ] || ! grep -q "^WEBHOOK_URL=" "$SCRIPT_DIR/.env" 2>/dev/null; then
  echo "[!] No WEBHOOK_URL set in infra/monitoring/.env -- alerts will be logged locally only, not delivered anywhere."
fi
echo "[*] Verify with: crontab -l"

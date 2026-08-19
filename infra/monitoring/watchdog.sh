#!/usr/bin/env bash
# ── Platform-failure watchdog ─────────────────────────────────────────────────
# Checks each app-stack container's Docker health status (stronger than a bare
# HTTP check -- catches restart loops even between two healthy curl probes)
# plus each backend's HTTP health endpoint through the same nginx path a real
# browser uses. Alerts only on a STATE TRANSITION (healthy->failing or
# failing->healthy), not on every run, so a 5-minute cron doesn't spam the
# channel every 5 minutes while something stays down -- and re-notifies once
# when it recovers.
#
# Usage:
#   ./infra/monitoring/watchdog.sh
#
# Config (env vars, or put them in infra/monitoring/.env -- gitignored):
#   WEBHOOK_URL       Slack-compatible incoming-webhook URL (posts {"text": ...}).
#                      Discord: use a Discord webhook URL and see the note below.
#   BASE_URL          Where nginx is reachable (default: http://localhost:8080)
#   FAIL_THRESHOLD    Consecutive failing runs before alerting (default: 2 --
#                      absorbs one transient blip without paging anyone)
#
# Cron example (every 5 minutes):
#   */5 * * * * cd /path/to/security-scanner-dev && ./infra/monitoring/watchdog.sh >> infra/monitoring/watchdog.log 2>&1
set -uo pipefail  # deliberately NOT -e: one failed check must not abort the rest

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SCRIPT_DIR/.env" ] && source "$SCRIPT_DIR/.env"

BASE_URL="${BASE_URL:-http://localhost:8080}"
FAIL_THRESHOLD="${FAIL_THRESHOLD:-2}"
STATE_FILE="$SCRIPT_DIR/.state"
touch "$STATE_FILE"

# name -> check command. Container health checks use `docker inspect`;
# HTTP checks go through nginx the same way a real user's browser would.
declare -A CHECKS=(
  [container:vapt-db]="docker inspect --format '{{.State.Health.Status}}' vapt-db"
  [container:vapt-redis]="docker inspect --format '{{.State.Health.Status}}' vapt-redis"
  [container:vapt-zap]="docker inspect --format '{{.State.Health.Status}}' vapt-zap"
  [container:vapt-cspm-api]="docker inspect --format '{{.State.Health.Status}}' vapt-cspm-api"
  [container:vapt-aspm-api]="docker inspect --format '{{.State.Health.Status}}' vapt-aspm-api"
  [container:vapt-agent-api]="docker inspect --format '{{.State.Health.Status}}' vapt-agent-api"
  [container:vapt-web]="docker inspect --format '{{.State.Health.Status}}' vapt-web"
  [http:cspm-api]="curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 $BASE_URL/api/cspm/health"
  [http:aspm-api]="curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 $BASE_URL/api/aspm/health"
  [http:agent-api]="curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 $BASE_URL/api/agent/health"
)

get_state() { grep "^$1=" "$STATE_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || echo "unknown:0"; }
set_state() {
  grep -v "^$1=" "$STATE_FILE" > "$STATE_FILE.tmp" 2>/dev/null || true
  echo "$1=$2" >> "$STATE_FILE.tmp"
  mv "$STATE_FILE.tmp" "$STATE_FILE"
}

notify() {
  local text="$1"
  echo "[ALERT] $text"
  if [ -n "${WEBHOOK_URL:-}" ]; then
    # Escape backslash and double-quote for a valid JSON string -- every
    # message this script generates is built from fixed templates plus
    # timestamps/service-names/status-codes, so that's the full set of JSON
    # metacharacters that can actually appear; no python/jq dependency
    # needed on the host for that.
    local escaped="${text//\\/\\\\}"
    escaped="${escaped//\"/\\\"}"
    # Slack/Mattermost-compatible {"text": ...} payload. For Discord, change
    # the key to "content" (Discord webhooks reject "text").
    curl -fsS -X POST -H 'Content-Type: application/json' \
      -d "{\"text\": \"$escaped\"}" \
      "$WEBHOOK_URL" >/dev/null 2>&1 \
      || echo "[!] Failed to POST to WEBHOOK_URL (alert still logged above/to file)"
  fi
}

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ANY_TRANSITION=0

for name in "${!CHECKS[@]}"; do
  cmd="${CHECKS[$name]}"
  result="$(eval "$cmd" 2>/dev/null || echo "unreachable")"

  case "$name" in
    container:*) ok=$([ "$result" = "healthy" ] && echo 1 || echo 0) ;;
    http:*)      ok=$([ "$result" = "200" ] && echo 1 || echo 0) ;;
    *)           ok=0 ;;
  esac

  prev="$(get_state "$name")"
  prev_status="${prev%%:*}"
  prev_fails="${prev##*:}"

  if [ "$ok" = "1" ]; then
    if [ "$prev_status" = "failing" ]; then
      notify "[$TS] RECOVERED: $name is healthy again (was: $prev_fails consecutive failure(s))."
      ANY_TRANSITION=1
    fi
    set_state "$name" "healthy:0"
  else
    new_fails=$((prev_fails + 1))
    if [ "$new_fails" -ge "$FAIL_THRESHOLD" ] && [ "$prev_status" != "failing" ]; then
      notify "[$TS] DOWN: $name check failed (result: $result), $new_fails consecutive failure(s) >= threshold ($FAIL_THRESHOLD)."
      set_state "$name" "failing:$new_fails"
      ANY_TRANSITION=1
    elif [ "$prev_status" = "failing" ]; then
      set_state "$name" "failing:$new_fails"
    else
      set_state "$name" "pending:$new_fails"
    fi
  fi
done

if [ "$ANY_TRANSITION" = "0" ]; then
  echo "[$TS] No state changes. $(grep -c '^' "$STATE_FILE") checks tracked."
fi

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$SCRIPT_DIR/../deploy"

if [[ -f "$DEPLOY_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$DEPLOY_DIR/.env"
  set +a
fi

API_BASE="${API_BASE:-http://localhost:8080}"
# Ensure compose receives a deterministic static bearer token for this smoke
# run so privileged API operations don't depend on open-dev auth behavior.
API_BEARER_TOKEN="${API_BEARER_TOKEN:-change-me-automation-token}"
export API_BEARER_TOKEN
TOKEN="$API_BEARER_TOKEN"
DB_USER="${POSTGRES_USER:-privacy}"
DB_NAME="${POSTGRES_DB:-privacy_scrubber}"
TEST_PREFIX="${SMOKE_TEST_PREFIX:-lifecycle}"
RUN_SUFFIX="${SMOKE_RUN_ID:-${GITHUB_RUN_ID:-$(date +%s)}}"
RUN_ATTEMPT="${SMOKE_RUN_ATTEMPT:-${GITHUB_RUN_ATTEMPT:-1}}"
RUN_KEY="${RUN_SUFFIX}_${RUN_ATTEMPT}"
KEEP_FIXTURES="${SMOKE_KEEP_FIXTURES:-false}"

OWNER_ID=""
PROFILE_ID=""
PROVIDER_ID=""
ADAPTER_ID=""
OWNER_EMAIL="${TEST_PREFIX}+${RUN_KEY}@example.com"
PROVIDER_KEY="${TEST_PREFIX}_provider_${RUN_KEY}"
ADAPTER_KEY="${TEST_PREFIX}_adapter_${RUN_KEY}"

cd "$DEPLOY_DIR"

psql_exec() {
  docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME" "$@"
}

cleanup_test_fixtures() {
  echo "Cleaning test fixtures for prefix '$TEST_PREFIX'..."
  psql_exec <<SQL
delete from providers where key like '${TEST_PREFIX}_provider_%';
delete from adapters where key like '${TEST_PREFIX}_adapter_%';
delete from users where email like '${TEST_PREFIX}+%@example.com';
SQL
}

cleanup_on_exit() {
  local exit_code=$?
  if [[ "${KEEP_FIXTURES,,}" == "true" ]]; then
    echo "SMOKE_KEEP_FIXTURES=true; skipping cleanup."
    return "$exit_code"
  fi
  cleanup_test_fixtures || true
  return "$exit_code"
}

trap cleanup_on_exit EXIT

echo "Ensuring services are up..."
docker compose up -d postgres migrate api worker >/dev/null

echo "Waiting for API health..."
for i in $(seq 1 60); do
  if curl -fsS "$API_BASE/health" >/dev/null; then
    break
  fi
  sleep 2
done
curl -fsS "$API_BASE/health" >/dev/null

cleanup_test_fixtures

echo "Creating owner user fixture..."
OWNER_ID="$(psql_exec -Atc \
  "insert into users(email,password_hash,role,mfa_enabled) values('$OWNER_EMAIL','devhash','owner',false) returning id;")"

echo "Creating profile..."
PROFILE_RESP="$(curl -sS -X POST "$API_BASE/v1/profiles" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"owner_user_id\":\"$OWNER_ID\",\"display_name\":\"Lifecycle Demo $RUN_KEY\",\"region_code\":\"US-CA\"}")"
PROFILE_ID="$(python3 - <<'PY' "$PROFILE_RESP"
import json,sys
print(json.loads(sys.argv[1])["id"])
PY
)"

echo "Creating provider..."
PROVIDER_RESP="$(curl -sS -X POST "$API_BASE/v1/providers" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"$PROVIDER_KEY\",\"kind\":\"search_provider\",\"enabled\":true,\"config\":{\"endpoint\":\"https://example.test\"}}")"
PROVIDER_ID="$(python3 - <<'PY' "$PROVIDER_RESP"
import json,sys
print(json.loads(sys.argv[1])["id"])
PY
)"

echo "Updating provider..."
curl -sS -X PATCH "$API_BASE/v1/providers/$PROVIDER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":false,"config":{"endpoint":"https://example2.test"}}' >/dev/null

echo "Creating adapter..."
ADAPTER_RESP="$(curl -sS -X POST "$API_BASE/v1/adapters" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"key\":\"$ADAPTER_KEY\",\"display_name\":\"Demo Adapter\",\"domain\":\"example.test\",\"flow\":\"manual\",\"adapter_version\":\"1.0.0\",\"enabled\":true,\"metadata\":{\"source\":\"smoke\"}}")"
ADAPTER_ID="$(python3 - <<'PY' "$ADAPTER_RESP"
import json,sys
print(json.loads(sys.argv[1])["id"])
PY
)"

echo "Updating adapter..."
curl -sS -X PATCH "$API_BASE/v1/adapters/$ADAPTER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":false,"last_verified_at":"2026-01-01T00:00:00Z"}' >/dev/null

echo "Creating findings/tasks/reminders fixtures..."
for i in 1 2 3; do
  FINDING_RESP="$(curl -sS -X POST "$API_BASE/v1/findings" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"profile_id\":\"$PROFILE_ID\",\"source_domain\":\"example$i.test\",\"source_url\":\"https://example$i.test/profile/$RUN_KEY\",\"risk_score\":$((40+i)),\"matched_identifiers\":[\"full_name\"],\"exposed_fields\":[\"name\"],\"notes\":\"fixture-$i-$RUN_KEY\"}")"
  FINDING_ID="$(python3 - <<'PY' "$FINDING_RESP"
import json,sys
print(json.loads(sys.argv[1])["id"])
PY
)"

  curl -sS -X PATCH "$API_BASE/v1/findings/$FINDING_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"status":"triaged"}' >/dev/null

  TASK_RESP="$(curl -sS -X POST "$API_BASE/v1/tasks" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"finding_id\":\"$FINDING_ID\"}")"
  TASK_ID="$(python3 - <<'PY' "$TASK_RESP"
import json,sys
print(json.loads(sys.argv[1])["id"])
PY
)"

  curl -sS -X PATCH "$API_BASE/v1/tasks/$TASK_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"status":"in_progress","result_summary":"queued for review"}' >/dev/null

  NEXT_RUN="$(python3 - <<PY
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc)+timedelta(days=$i)).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"
  REMINDER_RESP="$(curl -sS -X POST "$API_BASE/v1/reminders" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"profile_id\":\"$PROFILE_ID\",\"finding_id\":\"$FINDING_ID\",\"reminder_type\":\"monthly_recheck\",\"next_run_at\":\"$NEXT_RUN\",\"interval_days\":30,\"enabled\":true,\"metadata\":{\"fixture\":$i}}")"
  REMINDER_ID="$(python3 - <<'PY' "$REMINDER_RESP"
import json,sys
print(json.loads(sys.argv[1])["id"])
PY
)"
  if [[ "$i" -eq 3 ]]; then
    curl -sS -X PATCH "$API_BASE/v1/reminders/$REMINDER_ID" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"enabled":false}' >/dev/null
  fi
done

echo
echo "Cursor pagination checks (limit=2):"
for path in "providers" "adapters" "findings?profile_id=$PROFILE_ID" "tasks" "reminders?profile_id=$PROFILE_ID" "audit-log" "adapter-runs" "jobs"; do
  URL="$API_BASE/v1/$path"
  SEP='?'
  [[ "$URL" == *\?* ]] && SEP='&'
  FIRST="$(curl -sS -H "Authorization: Bearer $TOKEN" "${URL}${SEP}limit=2")"
  CURSOR="$(python3 - <<'PY' "$FIRST"
import json,sys
d=json.loads(sys.argv[1])
print(d.get("next_cursor") or "")
PY
)"
  COUNT1="$(python3 - <<'PY' "$FIRST"
import json,sys
d=json.loads(sys.argv[1])
print(len(d.get("items",[])))
PY
)"
  if [[ -n "$CURSOR" ]]; then
    SECOND="$(curl -sS -H "Authorization: Bearer $TOKEN" "${URL}${SEP}limit=2&cursor=$CURSOR")"
    COUNT2="$(python3 - <<'PY' "$SECOND"
import json,sys
d=json.loads(sys.argv[1])
print(len(d.get("items",[])))
PY
)"
    echo "  - $path: page1=$COUNT1 page2=$COUNT2 cursor=ok"
  else
    echo "  - $path: page1=$COUNT1 cursor=<none>"
  fi
done

echo
echo "Smoke lifecycle complete for run key: $RUN_KEY"

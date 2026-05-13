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
TOKEN="${API_BEARER_TOKEN:-change-me-automation-token}"
DB_USER="${DB_USER:-privacy}"
DB_NAME="${DB_NAME:-privacy_scrubber}"

cd "$DEPLOY_DIR"

OWNER_ID=$(docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" -Atc "insert into users(email,password_hash,role,mfa_enabled) values('owner+$(date +%s)@example.com','devhash','owner',false) returning id;")

echo "owner_id=$OWNER_ID"

PROFILE_ID=$(curl -sS -X POST "$API_BASE/v1/profiles" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"owner_user_id\":\"$OWNER_ID\",\"display_name\":\"Demo Person\",\"region_code\":\"US-CA\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

echo "profile_id=$PROFILE_ID"

FINDING_ID=$(curl -sS -X POST "$API_BASE/v1/findings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"profile_id\":\"$PROFILE_ID\",\"source_domain\":\"example.com\",\"source_url\":\"https://example.com/profile/demo\",\"risk_score\":55,\"matched_identifiers\":[\"full_name\"],\"exposed_fields\":[\"name\",\"city\"],\"notes\":\"smoke test\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

echo "finding_id=$FINDING_ID"

TASK_ID=$(curl -sS -X POST "$API_BASE/v1/tasks" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"finding_id\":\"$FINDING_ID\",\"adapter_key\":\"example_people_search\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')

echo "task_id=$TASK_ID"

curl -sS -X POST "$API_BASE/v1/tasks/$TASK_ID/queue-adapter-run" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"adapter_key":"example_people_search","action":"submit_opt_out"}'

echo "\nQueued adapter run. Waiting for worker..."
sleep 5

echo "\nJobs:"
curl -sS -H "Authorization: Bearer $TOKEN" "$API_BASE/v1/jobs" | python3 -m json.tool

echo "\nAdapter runs:"
curl -sS -H "Authorization: Bearer $TOKEN" "$API_BASE/v1/adapter-runs" | python3 -m json.tool

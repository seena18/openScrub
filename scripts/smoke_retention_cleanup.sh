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

DB_USER="${POSTGRES_USER:-privacy}"
DB_NAME="${POSTGRES_DB:-privacy_scrubber}"

cd "$DEPLOY_DIR"

echo "Ensuring required services are up..."
docker compose up -d postgres migrate worker >/dev/null

echo "Running retention cleanup smoke check in dry-run mode..."
docker compose exec -T \
  -e RETENTION_CLEANUP_DRY_RUN=true \
  -e RETENTION_CLEANUP_INCLUDE_ADAPTER_ARTIFACTS=false \
  worker python - <<'PY'
import json
from workers.runner import run_retention_cleanup, write_worker_audit_log

result = run_retention_cleanup()
write_worker_audit_log("retention.cleanup.run.manual_smoke", result)
print(json.dumps(result, indent=2))
PY

echo "Latest retention audit events:"
docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" -Atc \
  "select action || ' ' || created_at::text from audit_log where action like 'retention.cleanup.%' order by created_at desc limit 5;"

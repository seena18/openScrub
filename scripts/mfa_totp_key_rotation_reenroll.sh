#!/usr/bin/env bash
set -euo pipefail

# Controlled TOTP key-rotation helper.
# Default mode is dry-run and non-destructive.

MODE="${1:-dry-run}" # dry-run | apply
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="${DEPLOY_DIR:-$ROOT_DIR/deploy}"
ENV_FILE="$DEPLOY_DIR/.env"
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.yml"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  exit 1
fi
if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "Missing compose file: $COMPOSE_FILE" >&2
  exit 1
fi

DB_USER="$(awk -F= '/^POSTGRES_USER=/{print $2}' "$ENV_FILE" | tail -n1)"
DB_NAME="$(awk -F= '/^POSTGRES_DB=/{print $2}' "$ENV_FILE" | tail -n1)"
DB_USER="${DB_USER:-privacy}"
DB_NAME="${DB_NAME:-privacy_scrubber}"

PSQL=(docker compose -f "$COMPOSE_FILE" exec -T postgres psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME")

echo "Using database: $DB_NAME (user: $DB_USER)"
echo
echo "Users with enrolled TOTP credentials:"
"${PSQL[@]}" -P pager=off -c "
select
  u.email,
  u.role,
  u.mfa_enabled,
  c.enabled as totp_enabled,
  c.verified_at
from mfa_totp_credentials c
join users u on u.id = c.user_id
order by u.email;
"

if [[ "$MODE" == "dry-run" ]]; then
  echo
  echo "Dry-run complete. No changes made."
  echo "If rotating MFA_TOTP_ENCRYPTION_KEY, run:"
  echo "  $0 apply"
  exit 0
fi

if [[ "$MODE" != "apply" ]]; then
  echo "Unknown mode: $MODE (expected dry-run or apply)" >&2
  exit 1
fi

echo
echo "Applying controlled re-enrollment reset:"
echo "- revoke active refresh sessions for users with TOTP credentials"
echo "- set users.mfa_enabled=false for those users"
echo "- delete mfa_totp_credentials rows"

"${PSQL[@]}" -P pager=off -c "
begin;
update auth_refresh_tokens
set revoked_at = now()
where revoked_at is null
  and user_id in (select user_id from mfa_totp_credentials);

update users
set mfa_enabled = false
where id in (select user_id from mfa_totp_credentials);

delete from mfa_totp_credentials
where user_id in (select user_id from users);
commit;
"

echo
echo "Post-change verification:"
"${PSQL[@]}" -P pager=off -c "
select
  u.email,
  u.role,
  u.mfa_enabled,
  c.user_id is not null as has_totp
from users u
left join mfa_totp_credentials c on c.user_id = u.id
where u.email not like 'pytest+%'
order by u.email;
"

echo
echo "Done. Users must re-enroll TOTP with the new MFA_TOTP_ENCRYPTION_KEY."

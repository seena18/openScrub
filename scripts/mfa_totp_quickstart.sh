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

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <email>"
  exit 1
fi

EMAIL="$1"

read -r -s -p "Password for ${EMAIL}: " PASSWORD
echo

echo "Logging in..."
LOGIN_RESP="$(curl -sS -X POST "$API_BASE/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"

ACCESS_TOKEN="$(python3 - <<'PY' "$LOGIN_RESP"
import json,sys
try:
    data=json.loads(sys.argv[1])
except Exception:
    print("")
    raise SystemExit(0)
print(data.get("access_token",""))
PY
)"

if [[ -z "$ACCESS_TOKEN" ]]; then
  echo "Login failed or account already requires MFA. Response:"
  echo "$LOGIN_RESP"
  exit 1
fi

echo "Starting TOTP setup..."
SETUP_RESP="$(curl -sS -X POST "$API_BASE/v1/auth/mfa/totp/setup" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json")"

SECRET="$(python3 - <<'PY' "$SETUP_RESP"
import json,sys
try:
    data=json.loads(sys.argv[1])
except Exception:
    print("")
    raise SystemExit(0)
print(data.get("secret",""))
PY
)"

OTP_URI="$(python3 - <<'PY' "$SETUP_RESP"
import json,sys
try:
    data=json.loads(sys.argv[1])
except Exception:
    print("")
    raise SystemExit(0)
print(data.get("otpauth_uri",""))
PY
)"

if [[ -z "$SECRET" || -z "$OTP_URI" ]]; then
  echo "TOTP setup failed. Response:"
  echo "$SETUP_RESP"
  exit 1
fi

echo
echo "Add this TOTP to your authenticator app:"
echo "Secret: $SECRET"
echo "URI:    $OTP_URI"
echo
read -r -p "Enter current 6-digit MFA code from app: " MFA_CODE

VERIFY_RESP="$(curl -sS -X POST "$API_BASE/v1/auth/mfa/totp/verify-setup" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"$MFA_CODE\"}")"

MFA_ENABLED="$(python3 - <<'PY' "$VERIFY_RESP"
import json,sys
try:
    data=json.loads(sys.argv[1])
except Exception:
    print("false")
    raise SystemExit(0)
print(str(bool(data.get("mfa_enabled", False))).lower())
PY
)"

if [[ "$MFA_ENABLED" != "true" ]]; then
  echo "TOTP verification failed. Response:"
  echo "$VERIFY_RESP"
  exit 1
fi

echo "TOTP enabled. Testing MFA login..."
TEST_LOGIN="$(curl -sS -X POST "$API_BASE/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"mfa_code\":\"$MFA_CODE\"}")"

TEST_TOKEN="$(python3 - <<'PY' "$TEST_LOGIN"
import json,sys
try:
    data=json.loads(sys.argv[1])
except Exception:
    print("")
    raise SystemExit(0)
print(data.get("access_token",""))
PY
)"

if [[ -z "$TEST_TOKEN" ]]; then
  echo "MFA login test failed. Response:"
  echo "$TEST_LOGIN"
  exit 1
fi

echo "Success: TOTP enrollment + MFA login verified."

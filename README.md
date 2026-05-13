# Privacy Scrubber

Portable privacy-ops tool for finding, tracking, and reducing personal exposure on people-search/data-broker sites.

## Current State

Runnable self-host baseline with:
- `postgres` + `minio`
- `migrate` bootstrap/migration service
- `api` service (FastAPI)
- `worker` service (queue + adapter runner)
- adapter-run artifact upload to S3-compatible storage
- auth: JWT access + refresh tokens, managed API keys, and optional static bearer fallback
- RBAC role checks
- encrypted identifier storage endpoint
- built-in `/ui` operator panel now includes API key create/list/rotate/revoke controls

## Quickstart

Canonical guide: [docs/quickstart.md](docs/quickstart.md)

```bash
cd privacy-scrubber/deploy
cp .env.example .env
# edit .env
docker compose up -d --build
```

Generate an `IDENTIFIER_ENCRYPTION_KEY` (Fernet key) and put it in `.env`:

```bash
python3 - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

Validate:

```bash
curl http://localhost:8080/health
```

Open built-in operator UI:

```text
http://localhost:8080/ui
```

Run UI smoke tests (Playwright, mocked API wiring):

```bash
cd privacy-scrubber/tests/ui
npm install
npx playwright install --with-deps chromium
PLAYWRIGHT_BASE_URL=http://127.0.0.1:8080 npm test
```

## Auth Modes

- JWT mode:
  - `POST /v1/auth/register`
  - `POST /v1/auth/login`
  - `POST /v1/auth/refresh`
  - `POST /v1/auth/logout`
  - `POST /v1/auth/change-password`
  - `POST /v1/auth/request-password-reset`
  - `POST /v1/auth/reset-password`
  - `GET /v1/auth/me`
- Managed API key mode:
  - `POST /v1/api-keys` (returns plaintext key once)
  - `GET /v1/api-keys`
  - `POST /v1/api-keys/{api_key_id}/rotate` (returns new plaintext key once)
  - `POST /v1/api-keys/{api_key_id}/revoke`
  - Call protected endpoints with `Authorization: Bearer <api_key>`
  - Optional `allowed_path_prefixes` can scope key access to endpoint families (prefix match)
- Static automation token mode (legacy fallback):
  - Set `API_BEARER_TOKEN` and call protected endpoints with `Authorization: Bearer <token>`

If neither `API_BEARER_TOKEN` nor `JWT_SECRET` is set, API runs in open dev mode.

## Roles

- `owner`, `admin`: full control
- `operator`: can create/update operational records and queue runs
- `reviewer`: read monitoring/queue state
- `viewer`: basic read-only profile access
- `system`: static automation token role

## Main Protected Endpoints

- `GET /v1/stats`
- `GET /v1/version`
- `GET /v1/users`
- `PATCH /v1/users/{user_id}/mfa`
- `PATCH /v1/users/{user_id}/role`
- `DELETE /v1/users/{user_id}`
- `POST /v1/api-keys`
- `GET /v1/api-keys`
- `POST /v1/api-keys/{api_key_id}/rotate`
- `POST /v1/api-keys/{api_key_id}/revoke`
- `GET /v1/auth/mfa/totp/status`
- `POST /v1/auth/mfa/totp/setup`
- `POST /v1/auth/mfa/totp/verify-setup`
- `POST /v1/auth/mfa/totp/disable`
- `GET /v1/auth/mfa/webauthn/credentials`
- `POST /v1/auth/mfa/webauthn/setup`
- `POST /v1/auth/mfa/webauthn/verify-setup`
- `DELETE /v1/auth/mfa/webauthn/credentials/{credential_id}`
- `POST /v1/auth/mfa/webauthn/authenticate/start`
- `POST /v1/auth/mfa/webauthn/authenticate/finish`
- `GET /v1/audit-log`
- `GET /v1/profiles`
- `POST /v1/profiles`
- `POST /v1/identifiers`
- `GET /v1/profiles/{profile_id}/identifiers`
- `GET /v1/providers`
- `POST /v1/providers`
- `PATCH /v1/providers/{provider_id}`
- `GET /v1/adapters`
- `POST /v1/adapters`
- `PATCH /v1/adapters/{adapter_id}`
- `POST /v1/findings`
- `GET /v1/findings`
- `PATCH /v1/findings/{finding_id}`
- `POST /v1/tasks`
- `GET /v1/tasks`
- `PATCH /v1/tasks/{task_id}`
- `POST /v1/tasks/{task_id}/queue-adapter-run`
- `GET /v1/reminders`
- `POST /v1/reminders`
- `PATCH /v1/reminders/{reminder_id}`
- `GET /v1/adapter-runs`
- `GET /v1/jobs`

## MFA Policy (Optional, OSS-Friendly)

MFA policy is configurable and defaults to off:

- `MFA_POLICY_MODE=off|report|enforce` (default `off`)
- `MFA_PRIVILEGED_ROLES=owner,admin` (comma-separated)

Behavior:
- `off`: no MFA policy checks
- `report`: allow login/refresh, but emit audit event if privileged user has `mfa_enabled=false`
- `enforce`: block login/refresh for privileged users with `mfa_enabled=false`

Admin can manage user MFA flag:

- `PATCH /v1/users/{user_id}/mfa` with `{ "mfa_enabled": true|false }`

TOTP config:
- `MFA_TOTP_ISSUER` (default `Privacy Scrubber`)
- `MFA_TOTP_VALID_WINDOW` (default `1`)
- `MFA_TOTP_DISABLE_REQUIRES_CODE` (default `true`)
- `MFA_TOTP_ENCRYPTION_KEY` (optional; falls back to `IDENTIFIER_ENCRYPTION_KEY`)
- `RATE_LIMIT_WEBAUTHN_VERIFY_SETUP_MAX_ATTEMPTS` (default `10`)
- `RATE_LIMIT_WEBAUTHN_VERIFY_SETUP_WINDOW_SECONDS` (default `300`)
- `RATE_LIMIT_WEBAUTHN_FINISH_MAX_ATTEMPTS` (default `10`)
- `RATE_LIMIT_WEBAUTHN_FINISH_WINDOW_SECONDS` (default `300`)

WebAuthn config:
- `MFA_WEBAUTHN_RP_ID` (default `localhost`)
- `MFA_WEBAUTHN_RP_NAME` (default `Privacy Scrubber`)
- `MFA_WEBAUTHN_ORIGINS` (comma-separated, default `https://localhost`)
- `MFA_WEBAUTHN_CHALLENGE_TTL_SECONDS` (default `300`)
- `MFA_WEBAUTHN_TIMEOUT_MS` (default `60000`)

TOTP flow:
1. `POST /v1/auth/mfa/totp/setup`
2. Add returned `secret`/`otpauth_uri` to authenticator app
3. `POST /v1/auth/mfa/totp/verify-setup` with a code
4. Login with `mfa_code` when `mfa_enabled=true`

WebAuthn flow:
1. Authenticated user calls `POST /v1/auth/mfa/webauthn/setup`
2. Browser uses returned `public_key` options with WebAuthn API
3. Submit browser credential to `POST /v1/auth/mfa/webauthn/verify-setup`
4. For MFA login, call `POST /v1/auth/mfa/webauthn/authenticate/start` with email/password
5. Submit assertion to `POST /v1/auth/mfa/webauthn/authenticate/finish` to receive JWTs

Interactive quickstart helper:

```bash
cd privacy-scrubber
chmod +x scripts/mfa_totp_quickstart.sh
./scripts/mfa_totp_quickstart.sh you@example.com
```

Admin override:
- `PATCH /v1/users/{user_id}/mfa`
  - enabling requires verified TOTP credential present
  - disabling clears stored TOTP credential and revokes refresh sessions

Important:
- TOTP and WebAuthn second-factor challenges are both implemented.
- `POST /v1/auth/login` supports TOTP (`mfa_code`) directly.
- WebAuthn login uses the dedicated `authenticate/start` + `authenticate/finish` endpoints.
- For internet-exposed deployments, still pair with external controls (VPN, SSO proxy, or IdP MFA).

Safe rollout:
1. Set `MFA_POLICY_MODE=report` first.
2. Enable MFA flags for all privileged accounts.
3. Switch to `MFA_POLICY_MODE=enforce`.

TOTP key handling:
- Keep `MFA_TOTP_ENCRYPTION_KEY` stable across normal restarts/redeploys.
- If you rotate it, plan a controlled TOTP re-enrollment event.
- Helper script: `scripts/mfa_totp_key_rotation_reenroll.sh` (`dry-run` or `apply`)

## JWT Quick Example

Register first user:

```bash
curl -X POST http://localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"ChangeMeSuperLong123!","role":"owner"}'
```

Login:

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"ChangeMeSuperLong123!"}'
```

Use returned `access_token` as bearer for protected endpoints and `refresh_token` for session renewal.

If TOTP is enabled on the account:

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"ChangeMeSuperLong123!","mfa_code":"123456"}'
```

## Workflow Lifecycle API

Useful operator flows:

- findings list/filter: `GET /v1/findings?profile_id=<uuid>&status=new&limit=100`
- findings update status/risk: `PATCH /v1/findings/{finding_id}`
- tasks list/filter: `GET /v1/tasks?status=in_progress&finding_id=<uuid>&limit=100`
- tasks update status/assignee/result: `PATCH /v1/tasks/{task_id}`
- queue adapter run: `POST /v1/tasks/{task_id}/queue-adapter-run`
- reminders list/filter: `GET /v1/reminders?profile_id=<uuid>&enabled=true`
- reminders schedule CRUD: `POST /v1/reminders`, `PATCH /v1/reminders/{reminder_id}`

Idempotent create support:
- `POST /v1/providers`
- `POST /v1/adapters`
- `POST /v1/findings`
- `POST /v1/tasks`
- `POST /v1/reminders`

Provide `Idempotency-Key: <unique-key>` header.
- same key + same payload: returns stored response (`Idempotency-Replayed: true`)
- same key + different payload: `409 conflict`

Cursor pagination:
- high-volume list endpoints return `next_cursor`
- pass it back as `?cursor=<next_cursor>` to fetch the next page
- supported on `findings`, `tasks`, `reminders`, `audit-log`, `adapter-runs`, `jobs`, `providers`, `adapters`

API versioning contract:
- Route contract is path-prefixed: `/v1/...`
- Responses include:
  - `X-API-Contract-Version` (currently `v1`)
  - `X-API-Versioning-Strategy` (currently `path-prefix`)
  - `X-API-Implementation-Version` (server build/runtime version)
- `GET /v1/version` returns the same version metadata in JSON for automation clients.

## Password Reset (Dev)

Set in `.env` for local testing only:

```text
ENABLE_INSECURE_RESET_TOKEN_RESPONSE=true
```

Then request reset token:

```bash
curl -X POST http://localhost:8080/v1/auth/request-password-reset \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com"}'
```

Use returned token with:

```bash
curl -X POST http://localhost:8080/v1/auth/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"token":"<reset-token>","new_password":"NewLongPassword123!"}'
```

## Demo Adapter Run

Example adapter key: `example_people_search`.

```bash
cd privacy-scrubber
./scripts/smoke_api_flow.sh
```

This script creates test records, queues an adapter run, and prints `jobs` + `adapter-runs`.

## Adapter Quality Gate

Run adapter validation before committing adapter changes:

```bash
cd privacy-scrubber
python3 scripts/validate_adapters.py
```

Strict mode fails on warnings too:

```bash
python3 scripts/validate_adapters.py --strict-warnings
```

What it checks:
- manifest schema and required fields
- semver + key naming conventions
- flow-specific requirements (`runner`, `playbook.md`)
- runner path safety and local file existence
- rate-limit safety bounds (`maxRunsPerHour`, `minDelayMs`)

## CI + Pre-Commit Gate

GitHub Actions workflow:
- [`.github/workflows/adapter-quality-gate.yml`](.github/workflows/adapter-quality-gate.yml)
- runs adapter validation in a containerized Python runner (`python:3.12-slim`) with `python3 scripts/validate_adapters.py --strict-warnings`
- [`.github/workflows/backend-lifecycle-smoke.yml`](.github/workflows/backend-lifecycle-smoke.yml)
- runs `./scripts/smoke_backend_lifecycle.sh` on backend API/deploy PR/push changes
- [`.github/workflows/backend-pytest.yml`](.github/workflows/backend-pytest.yml)
- runs integration tests in a dedicated Docker test-runner container (`tests/Dockerfile`) with MFA policy matrix: `off`, `report`, `enforce`
- executes `docker compose run --rm integration-tests` (not host Python) for consistent dependency/runtime behavior
- includes `webauthn-rate-limit-check` job:
  - runs only WebAuthn rate-limit tests in the same containerized runner (`tests/integration/test_webauthn_security.py -k rate_limited`)
  - forces low thresholds in CI (`RATE_LIMIT_WEBAUTHN_VERIFY_SETUP_MAX_ATTEMPTS=3`, `RATE_LIMIT_WEBAUTHN_FINISH_MAX_ATTEMPTS=3`)
  - purpose: deterministically validate `429` protections for repeated WebAuthn verify/auth-finish failures
- [`.github/workflows/ui-playwright-smoke.yml`](.github/workflows/ui-playwright-smoke.yml)
- runs mocked `/ui` Playwright smoke and uploads traces/screenshots/videos on failure
- env-file cryptographic key generation in UI workflow uses Node (`crypto.randomBytes`) to avoid host Python dependency
- [`.github/workflows/ci-sanity-gate.yml`](.github/workflows/ci-sanity-gate.yml)
- fail-fast CI plumbing check:
  - validates `docker compose config`
  - builds `api`, `migrate`, and `integration-tests` images
  - starts a minimal stack and verifies `/health` within a short timeout
  - uploads compose logs/ps artifacts if the gate fails

## Branch Protection Required Checks

Use these as required status checks on `main`:

1. `CI Sanity Gate / sanity-gate`
2. `Backend Pytest / backend-pytest (off)`
3. `Backend Pytest / backend-pytest (report)`
4. `Backend Pytest / backend-pytest (enforce)`
5. `Backend Pytest / webauthn-rate-limit-check`
6. `Adapter Quality Gate / validate-adapters`
7. `Backend Lifecycle Smoke / backend-lifecycle-smoke`
8. `Retention Smoke / retention-smoke`
9. `UI Playwright Smoke / ui-playwright-smoke`

Notes:
- If GitHub displays slightly different labels, match by workflow name + job id shown above.
- Keep the matrix-backed `backend-pytest` variants (`off`, `report`, `enforce`) all required.

Local pre-commit hook installer:

```bash
cd privacy-scrubber
chmod +x scripts/install_git_hook.sh
./scripts/install_git_hook.sh
```

The hook runs:

```bash
scripts/pre-commit-adapter-gate.sh
```

## Contracts

- Contributor Guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security Policy: [SECURITY.md](SECURITY.md)
- License: [LICENSE](LICENSE)
- Issue Templates: [.github/ISSUE_TEMPLATE](.github/ISSUE_TEMPLATE)
- PR Template: [.github/pull_request_template.md](.github/pull_request_template.md)
- Architecture: [docs/architecture.md](docs/architecture.md)
- DB Schema: [docs/database-schema.sql](docs/database-schema.sql)
- Adapter Interface: [docs/adapter-interface.md](docs/adapter-interface.md)
- Standards Baseline: [docs/STANDARDS.md](docs/STANDARDS.md)
- Release Policy: [docs/release-policy.md](docs/release-policy.md)
- Quickstart Guide: [docs/quickstart.md](docs/quickstart.md)
- Production Hardening: [docs/production-hardening.md](docs/production-hardening.md)

## Audit Logging

Sensitive actions now write to `audit_log`, including:
- auth events (`register`, `login`, `refresh`, `logout`, password change/reset)
- user admin events (role change, delete)
- data operations (profile/identifier/finding/task create, adapter queue)

Review recent events with:

```bash
curl -H "Authorization: Bearer <token>" "http://localhost:8080/v1/audit-log?limit=100"
```

## Auth Rate Limits

Auth endpoints are rate-limited and return `429` with `Retry-After` when exceeded.

Rate limiting is Redis-backed when `REDIS_URL` is configured (recommended for persistence and multi-instance correctness). If Redis is unavailable, API falls back to in-memory limits.

Tune via `.env`:
- `REDIS_URL`, `RATE_LIMIT_REDIS_PREFIX`
- `RATE_LIMIT_REGISTER_MAX_ATTEMPTS`, `RATE_LIMIT_REGISTER_WINDOW_SECONDS`
- `RATE_LIMIT_LOGIN_MAX_ATTEMPTS`, `RATE_LIMIT_LOGIN_WINDOW_SECONDS`
- `RATE_LIMIT_WEBAUTHN_VERIFY_SETUP_MAX_ATTEMPTS`, `RATE_LIMIT_WEBAUTHN_VERIFY_SETUP_WINDOW_SECONDS`
- `RATE_LIMIT_WEBAUTHN_FINISH_MAX_ATTEMPTS`, `RATE_LIMIT_WEBAUTHN_FINISH_WINDOW_SECONDS`
- `RATE_LIMIT_REFRESH_MAX_ATTEMPTS`, `RATE_LIMIT_REFRESH_WINDOW_SECONDS`
- `RATE_LIMIT_LOGOUT_MAX_ATTEMPTS`, `RATE_LIMIT_LOGOUT_WINDOW_SECONDS`
- `RATE_LIMIT_CHANGE_PASSWORD_MAX_ATTEMPTS`, `RATE_LIMIT_CHANGE_PASSWORD_WINDOW_SECONDS`
- `RATE_LIMIT_PASSWORD_RESET_REQUEST_MAX_ATTEMPTS`, `RATE_LIMIT_PASSWORD_RESET_REQUEST_WINDOW_SECONDS`
- `RATE_LIMIT_PASSWORD_RESET_MAX_ATTEMPTS`, `RATE_LIMIT_PASSWORD_RESET_WINDOW_SECONDS`

## Retention Cleanup Automation

Worker includes scheduled retention cleanup for auth/session data.

Cleans:
- expired or used `password_reset_tokens`
- expired/revoked `auth_refresh_tokens` (revoked grace window configurable)
- optional old adapter artifacts metadata + object deletion
- old `idempotency_keys` records

Main env controls:
- `RETENTION_CLEANUP_ENABLED` (default `true`)
- `RETENTION_CLEANUP_INTERVAL_SECONDS` (default `3600`)
- `RETENTION_CLEANUP_DRY_RUN` (default `true`)
- `RETENTION_CLEANUP_REVOKED_REFRESH_GRACE_DAYS` (default `7`)
- `RETENTION_CLEANUP_INCLUDE_ADAPTER_ARTIFACTS` (default `false`)
- `RETENTION_CLEANUP_ADAPTER_ARTIFACT_MAX_AGE_DAYS` (default `30`)
- `RETENTION_CLEANUP_INCLUDE_IDEMPOTENCY_KEYS` (default `true`)
- `RETENTION_CLEANUP_IDEMPOTENCY_MAX_AGE_DAYS` (default `30`)

Suggested idempotency TTL by environment:
- dev: `3` days
- staging: `7` days
- production: `30` days (adjust for retry windows and incident replay needs)

Every run writes an audit event:
- `retention.cleanup.run` (scheduled)
- `retention.cleanup.run.manual_smoke` (scripted smoke run)

Smoke test (dry-run):

```bash
cd privacy-scrubber
chmod +x scripts/smoke_retention_cleanup.sh
./scripts/smoke_retention_cleanup.sh
```

Backend lifecycle smoke:

```bash
cd privacy-scrubber
chmod +x scripts/smoke_backend_lifecycle.sh
./scripts/smoke_backend_lifecycle.sh
```

Behavior:
- pre-run cleanup removes previous smoke fixtures by prefix
- post-run cleanup runs automatically (set `SMOKE_KEEP_FIXTURES=true` to keep data)

Pytest integration suite:

```bash
cd privacy-scrubber
pytest -q tests/integration
```

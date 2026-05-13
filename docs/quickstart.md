# Quickstart

This guide gets a single-node local deployment running with the minimum secure settings.

## Prerequisites

- Docker + Docker Compose plugin
- `curl`
- `python3`

## 1. Configure Environment

```bash
cd privacy-scrubber/deploy
cp .env.example .env
```

Generate a Fernet key for `IDENTIFIER_ENCRYPTION_KEY`:

```bash
python3 - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

Set these in `deploy/.env` before first startup:

- `IDENTIFIER_ENCRYPTION_KEY=<generated-key>`
- `JWT_SECRET=<long-random-secret>`
- `MFA_TOTP_ENCRYPTION_KEY=<generated-key>` (recommended dedicated key)
- `ALLOW_SELF_REGISTER=true` (bootstrap only)
- `API_BEARER_TOKEN=` (leave empty unless explicitly needed)

Important:
- Treat `MFA_TOTP_ENCRYPTION_KEY` as persistent secret state.
- Do not change it across normal restarts/redeploys.
- Back up `deploy/.env` (or your secret-manager values) before upgrades.

## 2. Start Stack

```bash
docker compose up -d --build
```

Health check:

```bash
curl http://localhost:8080/health
```

Open UI:

```text
http://localhost:8080/ui
```

## 3. Bootstrap First User

Register first account (owner):

```bash
curl -X POST http://localhost:8080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"ChangeMeLongRandom123!","role":"owner"}'
```

After first account creation, disable open registration:

- Set `ALLOW_SELF_REGISTER=false` in `deploy/.env`
- Restart API:

```bash
docker compose up -d api
```

## 4. Verify Auth

Login:

```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"ChangeMeLongRandom123!"}'
```

Use returned `access_token` for protected endpoints.

## 5. Enable MFA (Recommended)

Run helper:

```bash
cd privacy-scrubber
chmod +x scripts/mfa_totp_quickstart.sh
./scripts/mfa_totp_quickstart.sh you@example.com
```

Then set policy to enforce for privileged roles:

- `MFA_POLICY_MODE=enforce`
- `MFA_PRIVILEGED_ROLES=owner,admin`

## 6. Smoke Tests

Backend lifecycle smoke:

```bash
cd privacy-scrubber
./scripts/smoke_backend_lifecycle.sh
```

Retention smoke:

```bash
./scripts/smoke_retention_cleanup.sh
```

## 7. Next Steps

- Read [Production Hardening](./production-hardening.md)
- Apply CI + branch protection from [README](../README.md#branch-protection-required-checks)
- Configure backups for `deploy/.env` secrets and persistent volumes

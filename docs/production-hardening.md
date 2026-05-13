# Production Hardening

This checklist is for internet-accessible or shared-team deployments.

## Identity and Access

- Set `ALLOW_SELF_REGISTER=false` after bootstrap.
- Set strong `JWT_SECRET` (32+ random bytes).
- Enable MFA policy:
  - `MFA_POLICY_MODE=enforce`
  - `MFA_PRIVILEGED_ROLES=owner,admin`
- Create only required users and least-privilege roles (`viewer`, `reviewer`, `operator`, `admin`, `owner`).
- Use managed API keys for automation and scope with `allowed_path_prefixes`.
- Revoke unused API keys and user sessions regularly.

## Network and Exposure

- Keep API behind VPN and/or trusted reverse proxy.
- Restrict direct container port exposure to only required services.
- Enforce HTTPS at edge (reverse proxy/LB).
- Restrict admin/UI access by source network where possible.

## Secrets and Configuration

- Generate and protect:
  - `IDENTIFIER_ENCRYPTION_KEY`
  - `JWT_SECRET`
  - `MFA_TOTP_ENCRYPTION_KEY` (or explicit fallback policy)
- Store secrets in a secret manager or encrypted vault, not in plaintext repo files.
- Rotate secrets on compromise or operator turnover.
- Keep `ENABLE_INSECURE_RESET_TOKEN_RESPONSE=false` in production.

### TOTP Key Stability Rule

- Keep `MFA_TOTP_ENCRYPTION_KEY` stable across restarts/redeploys.
- If unset, the app falls back to `IDENTIFIER_ENCRYPTION_KEY`; choose one policy and keep it stable.
- Unplanned key changes will break decryption of stored TOTP secrets and block MFA login.

## Data Protection

- Encrypt disks/volumes at rest (host-level).
- Keep database backups encrypted and access-controlled.
- Validate that MinIO/S3 buckets are private and scoped.
- Review retention settings and minimize sensitive data lifetime.

## Rate Limits and Abuse Control

- Configure Redis for distributed/persistent rate limiting:
  - `REDIS_URL`
  - `RATE_LIMIT_REDIS_PREFIX`
- Keep auth and WebAuthn rate limits enabled and tuned for expected traffic.
- Monitor repeated failed auth attempts and trigger alerts.

## Logging, Auditing, Monitoring

- Enable centralized logs (API + worker + proxy).
- Retain and monitor `audit_log` events for:
  - auth events
  - role changes
  - API key lifecycle operations
  - retention cleanup runs
- Add health and synthetic monitors for:
  - `/health`
  - critical auth endpoints
  - worker queue processing

## Backup and Recovery

- Back up at minimum:
  - PostgreSQL data
  - object storage data + metadata
  - deployment configs (`deploy/.env`, compose overrides)
- Test restore monthly with a documented drill.
- Define RPO/RTO and confirm backup schedule meets it.

## Release and Change Control

- Require branch protection checks on `main`.
- Require at least one external reviewer for protected branches.
- Keep CI gates green before merge.
- Tag releases and maintain changelog entries.

## Controlled TOTP Key Rotation

If you must rotate `MFA_TOTP_ENCRYPTION_KEY`, do it as a planned re-enrollment event:

1. Announce maintenance window and expected MFA re-enrollment.
2. Set `MFA_POLICY_MODE=report` temporarily.
3. Update `MFA_TOTP_ENCRYPTION_KEY` to the new value.
4. Run:
   - `scripts/mfa_totp_key_rotation_reenroll.sh dry-run`
   - `scripts/mfa_totp_key_rotation_reenroll.sh apply`
5. Have privileged users re-enroll TOTP.
6. Restore `MFA_POLICY_MODE=enforce`.

## Operational Verification

Run after config changes:

```bash
cd privacy-scrubber
./scripts/smoke_backend_lifecycle.sh
./scripts/smoke_retention_cleanup.sh
pytest -q tests/integration
```

## Minimum Production Profile

Use this baseline:

- `ALLOW_SELF_REGISTER=false`
- `MFA_POLICY_MODE=enforce`
- `MFA_PRIVILEGED_ROLES=owner,admin`
- `ENABLE_INSECURE_RESET_TOKEN_RESPONSE=false`
- Redis-backed rate limits enabled
- Encrypted backups with verified restore drill cadence

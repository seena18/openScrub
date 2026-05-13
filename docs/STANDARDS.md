# Privacy Scrubber Standards

This document is the canonical standards baseline for Privacy Scrubber.

Use RFC-style language:
- `MUST`: mandatory
- `SHOULD`: recommended unless documented exception
- `MAY`: optional

## 1. Scope And Objectives

These standards apply to:
- backend API (`core/api`)
- workers (`workers`)
- adapters (`adapters`)
- deployment (`deploy`)
- operational automation (`scripts`)
- documentation (`docs`)

Primary objectives:
- protect sensitive identity data
- provide auditability and reproducibility
- keep adapter behavior safe and predictable
- remain portable across self-hosted environments

## 2. Security Standards

### 2.1 Authentication And Authorization

- Protected endpoints `MUST` require authenticated identity.
- Role checks `MUST` enforce least privilege (`owner/admin/operator/reviewer/viewer/system`).
- Static automation token mode (`API_BEARER_TOKEN`) `MUST` be treated as high-risk and rotated periodically.
- JWT mode `MUST` use a strong `JWT_SECRET` and configured expiry windows.
- Production deployments `MUST NOT` run in open dev mode (no auth configured).
- `ALLOW_SELF_REGISTER` `MUST` remain `false` except controlled bootstrap windows.

### 2.2 Session And Credential Controls

- Passwords `MUST` be hashed (never encrypted-only or plaintext).
- Refresh tokens `MUST` be revocable and tracked server-side.
- Password reset tokens `MUST` be short-lived and single-use.
- `ENABLE_INSECURE_RESET_TOKEN_RESPONSE` `MUST` remain `false` outside local development.

### 2.3 Rate Limiting

- Auth endpoints `MUST` be rate-limited.
- Redis-backed limiter `SHOULD` be used in multi-instance or long-running environments.
- In-memory rate limiting `MAY` be used only for local/dev.
- Any rate-limit override `MUST` be documented in deployment notes.

### 2.4 Data Encryption And Minimization

- Identifier values `MUST` be encrypted at rest with `IDENTIFIER_ENCRYPTION_KEY`.
- Identifier searchability `MUST` use hash/index strategy, not plaintext mirrors.
- Only minimum required identifier set for a workflow `SHOULD` be stored.
- Sensitive fields `MUST NOT` be written to logs.

### 2.5 Secrets Management

- Secrets `MUST NOT` be committed to source control.
- `.env.example` `MUST` include placeholders only.
- Production secrets `SHOULD` come from secret manager or host-level secret injection.
- Secret rotation events `SHOULD` be captured in ops logs/changelog.

### 2.6 Network And Access Boundary

- Public exposure `MUST` be intentional and documented.
- Admin surfaces `SHOULD` be behind VPN, Zero Trust access, or LAN-only controls.
- If internet-exposed, TLS `MUST` be enabled end-to-end.
- Access paths and DNS expectations `SHOULD` be documented per deployment.

## 3. Data Governance Standards

### 3.1 Data Classification

- Treat identifiers, findings, evidence metadata, and audit payloads as sensitive.
- Evidence artifacts with personal data `MUST` be considered high sensitivity.
- Raw adapter outputs `SHOULD` be reviewed for unnecessary PII retention.

### 3.2 Retention

- Retention policy `MUST` be defined per deployment (for profiles/findings/evidence/audit).
- Deleted profiles `MUST` cascade-delete dependent records unless legal hold applies.
- Offsite retention windows `SHOULD` match storage budget and threat model.

### 3.3 Auditability

- Sensitive operations `MUST` produce audit log events.
- Audit events `MUST` include actor, action, object reference, and timestamp.
- Manual security exceptions `SHOULD` be documented with rationale.

## 4. Adapter Standards

### 4.1 Manifest Contract

- Each adapter `MUST` have one `*.adapter.json` manifest.
- `key` `MUST` be unique and match `^[a-z0-9_]+$`.
- `version` `MUST` follow semantic versioning.
- `flowType` `MUST` be one of `manual`, `semi_auto`, `auto`.
- `optOutUrl` `MUST` be HTTPS.

### 4.2 Files And Layout

- `runner` is `MUST` for `semi_auto` and `auto`.
- `playbook.md` is `MUST` for `manual` and `semi_auto`.
- Runner path `MUST` be relative and remain inside adapter directory.

### 4.3 Runtime Behavior

- Runners `MUST` emit exactly one JSON object to stdout.
- Runner status `MUST` use allowed values only:
  - `completed`
  - `waiting_manual`
  - `waiting_email_verification`
  - `failed`
  - `not_applicable`
- Runners `MUST NOT` brute force captcha/login/verification flows.
- Runners `SHOULD` return operator-usable summaries and artifacts.

### 4.4 Safety And Legal Controls

- Adapter actions `MUST` comply with local law and target-site terms as applicable.
- Outbound submissions `SHOULD` require explicit user/system intent.
- Any high-risk automation behavior `MUST` be clearly documented before merge.

### 4.5 Adapter Quality Gate

- `python3 scripts/validate_adapters.py --strict-warnings` `MUST` pass before merge.
- Adapter validation `MUST` run in CI (`.github/workflows/adapter-quality-gate.yml`).
- Local teams `SHOULD` install pre-commit gate (`./scripts/install_git_hook.sh`).

## 5. API Standards

### 5.1 Endpoint Design

- Health endpoint `MUST` exist and stay lightweight.
- Protected resources `MUST` return consistent auth errors (`401/403`).
- Mutations `SHOULD` be auditable.
- Create mutations `SHOULD` support idempotency keys for retry safety.
- JSON request/response shapes `SHOULD` stay stable or be versioned.

### 5.2 Error Handling

- API errors `MUST` avoid secret leakage.
- Validation errors `SHOULD` be actionable.
- Transient dependency failures `SHOULD` surface retry-safe guidance where possible.

### 5.3 Backward Compatibility

- Breaking API changes `MUST` be documented before release.
- If breaking changes are unavoidable, route versioning `SHOULD` be introduced.

## 6. Worker And Queue Standards

### 6.1 Job Execution

- Workers `MUST` claim queue jobs with concurrency-safe locking semantics.
- Job status transitions `MUST` be explicit (`queued` → `running` → terminal state).
- Task status `SHOULD` map deterministically from adapter-run status.

### 6.2 Timeouts And Retries

- Adapter execution `MUST` have timeout guard (`ADAPTER_RUN_TIMEOUT_SECONDS`).
- Retry strategy `SHOULD` distinguish permanent vs transient failures.
- Retry loops `MUST` have bounded attempts.

### 6.3 Artifact Handling

- Artifact uploads `MUST` be optional and fail-safe.
- Storage keying `SHOULD` preserve run traceability (`adapter-runs/<run_id>/<key>/...`).
- Missing artifact files `SHOULD` degrade gracefully with clear error summary.

## 7. Database And Migration Standards

### 7.1 Schema Integrity

- Tables `MUST` define primary keys and referential integrity.
- State enums `SHOULD` be used for lifecycle fields with finite states.
- Timestamps `MUST` use timezone-aware types.

### 7.2 Migrations

- Migrations `MUST` be idempotent where possible.
- Destructive migrations `MUST` include rollback/restore procedure.
- Schema changes `MUST` be reflected in `docs/database-schema.sql`.

### 7.3 Query Safety

- SQL execution `MUST` use parameterized queries.
- Privileged SQL operations `SHOULD` be minimized in API handlers.

## 8. Deployment Standards

### 8.1 Compose Baseline

- `deploy/docker-compose.yml` `MUST` remain runnable from clean checkout.
- `.env.example` `MUST` include all required env keys.
- Default credentials in examples `MUST` be changed before shared environments.

### 8.2 Environment Profiles

- Dev profile `MAY` prioritize speed over hardening.
- Staging profile `SHOULD` mirror production auth and storage behavior.
- Production profile `MUST` use persistent volumes and durable backups.

### 8.3 Portability

- Service dependencies `SHOULD` remain standard OSS components.
- Deployment assumptions `MUST` be documented (ports, DNS, storage, networking).

## 9. Observability And Operations Standards

### 9.1 Logging

- Services `MUST` emit timestamped logs.
- Log lines `SHOULD` include enough context to correlate run/task/user.
- Logs `MUST NOT` expose secrets or raw sensitive identifiers.

### 9.2 Monitoring

- Availability checks `SHOULD` cover API, DB, queue health, and worker heartbeat.
- Alerting `SHOULD` include at least:
  - API down
  - worker stalled
  - repeated adapter failures
  - backup/export failures

### 9.3 Backups And Restore Readiness

- Backup scope `MUST` include:
  - database
  - object storage artifacts (or explicit exclusion policy)
  - deployment configuration needed to restore
- Restore drill `SHOULD` run on a recurring schedule (monthly recommended).
- Restore outcomes `MUST` be documented with success/failure and follow-up actions.

## 10. Change Management Standards

### 10.1 Code Review

- Security-impacting changes `MUST` be reviewed before merge.
- Adapter additions/updates `MUST` pass quality gate in CI.
- Operational runbook/documentation changes `SHOULD` accompany behavior changes.

### 10.2 Release Notes

- Each release `SHOULD` summarize:
  - new features
  - security-impacting changes
  - breaking changes
  - migration requirements
- Release process `MUST` follow `docs/release-policy.md` (version bump rules + release checklist).

### 10.3 Incident Handling

- Security incidents `MUST` trigger token/secret rotation where relevant.
- Post-incident review `SHOULD` capture root cause and preventive controls.

## 11. Documentation Standards

### 11.1 Source Of Truth

- README `MUST` document quickstart and operator-critical workflows.
- `docs/adapter-interface.md` `MUST` reflect actual adapter contract behavior.
- `docs/database-schema.sql` `MUST` reflect deployed schema intent.
- This standards document `MUST` be updated when policy changes.

### 11.2 Documentation Quality

- Commands `SHOULD` be copy-pasteable.
- Defaults and assumptions `SHOULD` be explicit.
- Docs `SHOULD` prefer concrete examples over abstract guidance.

## 12. Compliance And Ethical Use Standards

- Users `MUST` ensure lawful use in their jurisdiction.
- Data collection `MUST` be proportional to legitimate privacy-removal objectives.
- Adapters `MUST NOT` be used for harassment, doxxing, or unauthorized surveillance.

## 13. Acceptance Checklists

### 13.1 New Adapter Checklist

- Manifest validates in strict mode.
- Runner/playbook presence matches flow type.
- Rate limits are sane and justified.
- Evidence outputs and summaries are actionable.
- Legal/safety considerations reviewed.

### 13.2 Release Checklist

- Adapter gate passing in CI.
- Auth and security env values reviewed.
- Migrations applied in test/staging path.
- Backup and restore path verified.
- Docs updated for behavior changes.

### 13.3 Production Readiness Checklist

- No default credentials in use.
- TLS and access boundary configured.
- Monitoring and alerting active.
- Backup automation active.
- Restore drill performed and recorded.

## 14. Current Baseline Mapping (As Of 2026-05-12)

Implemented baseline in repository:
- API auth (JWT + refresh + static bearer)
- RBAC-enforced protected endpoints
- Explicit API version contract (`/v1` path strategy + response version headers + `/v1/version`)
- Auth rate limiting with Redis option + in-memory fallback
- MFA policy controls (`off/report/enforce`) for privileged roles
- Native TOTP MFA enrollment + login challenge flow
- Native WebAuthn/passkey MFA enrollment + challenge flow
- Encrypted identifier storage and hash index strategy
- Audit log events for sensitive flows
- Adapter queue + worker execution path
- Adapter manifest validation script + CI + pre-commit integration
- Worker-driven retention cleanup (tokens, idempotency keys, optional artifacts) with dry-run mode and audit trail

Outstanding hardening areas to track:
- Data retention policy tuning per tenant/deployment profile
- End-to-end disaster recovery automation for all deployment modes
- Expanded test coverage and formal API deprecation policy

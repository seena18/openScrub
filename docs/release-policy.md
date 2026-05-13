# Privacy Scrubber Release Policy

This document defines versioning and release standards for maintainers.

## 1. Versioning Model

Project releases `MUST` follow semantic versioning (`MAJOR.MINOR.PATCH`).

1. `PATCH`:
- bug fixes
- security hardening without contract changes
- internal refactors with no behavior/contract change

2. `MINOR`:
- backward-compatible feature additions
- new endpoints that do not break existing clients
- additive schema changes that do not break existing deployments

3. `MAJOR`:
- breaking API contract changes
- removed/renamed endpoints or fields used by existing clients
- incompatible auth, migration, or runtime changes requiring operator action

## 2. API Contract Bump Rules

API contract is currently path-versioned with `/v1` and version headers.

1. Backward-compatible changes:
- keep `API_CONTRACT_VERSION` unchanged
- bump implementation version (`app.version`) using semver rules above

2. Breaking contract changes:
- bump path contract version (for example `/v2`)
- provide migration notes and deprecation timeline for `/v1`
- bump `MAJOR` release version

## 3. Pre-Release Checklist

All items `MUST` pass before tagging a release.

1. CI checks are green:
- `CI Sanity Gate / sanity-gate`
- `Backend Pytest / backend-pytest (off)`
- `Backend Pytest / backend-pytest (report)`
- `Backend Pytest / backend-pytest (enforce)`
- `Backend Pytest / webauthn-rate-limit-check`
- `Adapter Quality Gate / validate-adapters`
- `Backend Lifecycle Smoke / backend-lifecycle-smoke`
- `Retention Smoke / retention-smoke`
- `UI Playwright Smoke / ui-playwright-smoke`

2. Database and migration checks:
- migration path is idempotent for existing installs
- new schema changes are reflected in `docs/database-schema.sql`
- destructive changes include explicit rollback/restore steps

3. Security and auth checks:
- no secrets committed
- auth mode behavior unchanged unless explicitly documented
- API key/JWT behavior validated for impacted endpoints

4. Docs and ops checks:
- `README.md` updated for user-visible changes
- `docs/STANDARDS.md` and related runbooks updated where relevant
- release notes drafted (features, fixes, breaking changes, migration notes)

## 4. Release Procedure

1. Choose next version according to this policy.
2. Update implementation version in `core/api/main.py` (`app.version`).
3. Merge release changes to `main` with all required checks passing.
4. Tag the release (`vMAJOR.MINOR.PATCH`).
5. Publish release notes with:
- highlights
- security-impacting changes
- migrations
- known issues

## 5. Post-Release Verification

1. Deploy to staging (or local verification stack) and verify `/health`.
2. Validate auth/login + protected endpoint access.
3. Validate one full integration test run via containerized runner.
4. Confirm no critical errors in logs during first smoke window.

## 6. Rollback Policy

Every release `SHOULD` include rollback guidance.

1. If no destructive migration:
- roll back to previous image tag
- restart stack

2. If destructive migration exists:
- restore from known-good backup
- execute documented restore drill steps

3. Incident follow-up:
- log root cause
- patch with new release
- update this policy/checklist if process gaps were found

## 7. Breaking Change PR Template

Use this section in PR descriptions whenever a change is potentially breaking.

```md
## Breaking Change Assessment

### Is this change breaking?
- [ ] No
- [ ] Yes (details below)

### Affected Surface
- API endpoints:
- Request/response fields:
- Auth/session behavior:
- DB schema/migrations:
- Deployment/runtime assumptions:

### Required Operator Action
1.
2.
3.

### Backward Compatibility Plan
- Compatibility window:
- Deprecation notice:
- Fallback path:

### Test Coverage
- Added/updated tests:
- Manual validation steps:
```

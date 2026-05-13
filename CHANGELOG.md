# Changelog

All notable changes to this project are documented in this file.

## [v0.1.0] - 2026-05-13

### Added
- Initial open-source release of `openScrub` as a portable self-hosted privacy operations platform.
- Core API, worker, adapter scaffold, and deploy stack (`postgres`, `minio`, `redis`, migration service).
- Authentication foundations:
  - JWT login/refresh/logout
  - managed API keys (create/list/rotate/revoke)
  - role-based authorization
  - optional MFA policy modes (`off`, `report`, `enforce`)
- MFA capabilities:
  - TOTP setup/verify/disable flows
  - WebAuthn setup and authentication challenge flows
- Operational UI at `/ui` for basic operator workflows and API key management.
- Adapter quality controls:
  - strict adapter schema validation script
  - pre-commit adapter gate support
- CI baselines:
  - sanity gate
  - backend integration pytest (policy matrix)
  - WebAuthn rate-limit checks
  - adapter quality gate
  - lifecycle and retention smoke tests
  - UI Playwright smoke workflow
- Governance/project hygiene:
  - contribution guide
  - issue templates
  - pull request template
  - release policy and standards docs
  - MIT `LICENSE`
  - `SECURITY.md` private disclosure policy

### Notes
- This is the first public baseline release and may evolve quickly.
- Branch protection with required checks is expected for all future changes on `main`.

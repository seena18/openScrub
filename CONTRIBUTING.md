# Contributing To Privacy Scrubber

Thanks for contributing.

This project is self-hosted-first and security-sensitive. Use this guide for local setup, testing, and pull requests.

## 1. Development Prerequisites

Required:
- Docker + Docker Compose
- Git
- Node.js 20+ (only for UI Playwright tests)

Recommended:
- `curl`, `jq`

## 2. Local Setup

1. Start from repo root:

```bash
cd privacy-scrubber
```

2. Create env file:

```bash
cp deploy/.env.example deploy/.env
```

3. Set required secrets in `deploy/.env`:
- `IDENTIFIER_ENCRYPTION_KEY`
- `JWT_SECRET`
- other non-default secrets for non-local environments

4. Start stack:

```bash
cd deploy
docker compose up -d --build
```

5. Verify:

```bash
curl http://localhost:8080/health
```

## 3. Preferred Test Workflow (Containerized)

Run backend integration tests through the test-runner container:

```bash
cd privacy-scrubber/deploy
docker compose build integration-tests
docker compose run --rm integration-tests
```

Run only API key tests:

```bash
docker compose run --rm integration-tests pytest -q tests/integration/test_api_keys.py
```

Run WebAuthn rate-limit subset:

```bash
docker compose run --rm integration-tests pytest -q tests/integration/test_webauthn_security.py -k rate_limited
```

## 4. UI Smoke Tests

```bash
cd privacy-scrubber/tests/ui
npm ci
npx playwright install --with-deps chromium
PLAYWRIGHT_BASE_URL=http://127.0.0.1:8080 npm test
```

## 5. Adapter Changes

Adapter changes MUST pass strict validation:

```bash
cd privacy-scrubber
python3 scripts/validate_adapters.py --strict-warnings
```

Install local pre-commit hook:

```bash
chmod +x scripts/install_git_hook.sh
./scripts/install_git_hook.sh
```

## 6. Pull Request Requirements

Every PR should include:

1. Clear problem statement and scope.
2. Test evidence (commands + output summary).
3. Doc updates for behavior/API/deploy changes.
4. Migration notes for schema or runtime-impacting changes.

Required CI checks are documented in `README.md` under "Branch Protection Required Checks".

Issue intake and PR structure:
- use GitHub issue forms under `.github/ISSUE_TEMPLATE/`
- use the repository PR template (`.github/pull_request_template.md`) and fill all sections

## 7. Breaking Changes

If your PR may break compatibility:
- follow `docs/release-policy.md`
- include the "Breaking Change Assessment" template from that doc in your PR description

Breaking API changes require:
- explicit migration guidance
- versioning plan (`/v1` compatibility or `/v2` introduction)

## 8. Security Expectations

- Never commit secrets, tokens, or real user data.
- Keep `.env.example` placeholder-only.
- Treat auth/session/identifier code paths as high-risk and test thoroughly.
- Avoid logging sensitive values.

If you discover a security issue, do not publish exploit details in issues/PRs. Share a minimal private report with maintainers first.
See `SECURITY.md` for the reporting path and response expectations.

## 9. Standards And Source Of Truth

Before opening a PR, review:
- `docs/STANDARDS.md`
- `docs/release-policy.md`
- `docs/adapter-interface.md`
- `docs/database-schema.sql` (if schema-related)

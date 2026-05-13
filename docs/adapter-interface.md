# Adapter Interface (v1)

Adapters encapsulate site-specific logic for discovery hints and opt-out workflows.
Use `adapters/examples/` as the reference baseline for new provider implementations.

## Goals

- Standardize broker integrations
- Support manual, semi-automatic, and automatic workflows
- Preserve evidence and auditability for every run

## Adapter Package Layout

```text
adapters/
  <adapter-key>/
    <adapter-key>.adapter.json
    runner.(py|js)          # optional but recommended for semi_auto/auto
    selectors.json          # optional
    playbook.md             # required for manual/semi-auto
```

## `adapter.json` Manifest

```json
{
  "key": "example_people_search",
  "displayName": "Example People Search",
  "domain": "example.com",
  "flowType": "semi_auto",
  "version": "1.1.0",
  "owner": "community",
  "optOutUrl": "https://example.com/optout",
  "requires": {
    "captcha": true,
    "emailVerification": true,
    "phoneVerification": false,
    "login": false
  },
  "inputs": ["full_name", "city", "email"],
  "rateLimit": {
    "maxRunsPerHour": 10,
    "minDelayMs": 2000
  },
  "capabilities": {
    "discovery": true,
    "submitOptOut": true,
    "verifyRemoval": true
  },
  "runner": {
    "path": "runner.py",
    "args": []
  }
}
```

## Runner Contract

Runner is invoked by worker with JSON on stdin. It must print exactly one JSON object to stdout.

### Input Payload

```json
{
  "taskId": "uuid",
  "findingId": "uuid",
  "profile": {
    "id": "uuid",
    "regionCode": "US-CA"
  },
  "identifiers": [
    {"type": "full_name", "value": "..."}
  ],
  "finding": {
    "url": "https://example.com/profile/123",
    "sourceDomain": "example.com"
  },
  "adapter": {
    "key": "example_people_search",
    "version": "1.1.0",
    "flowType": "semi_auto"
  },
  "action": "submit_opt_out",
  "workDir": "/tmp/adapter-run-abc123"
}
```

`identifiers[].value` is currently base64-encoded encrypted data from DB in this scaffold.

### Output Payload

```json
{
  "status": "waiting_email_verification",
  "summary": "Submission completed, email confirmation required",
  "artifacts": [
    {
      "type": "screenshot",
      "path": "./submission.png",
      "label": "submission_confirmation",
      "contentType": "image/png"
    }
  ],
  "nextStep": {
    "type": "manual",
    "instructions": "Open mailbox and click verification link within 24h"
  },
  "raw": {
    "ticket": "ABC-123"
  }
}
```

## Artifact Upload Behavior

Worker uploads artifact files to object storage when configured:
- bucket from `OBJECT_STORAGE_BUCKET`
- key pattern: `adapter-runs/<adapter_run_id>/<adapter_key>/<filename>`

Worker then enriches each artifact object with:
- `storage_uri` (`s3://bucket/key`)
- `bucket`
- `key`
- optional `url` when `OBJECT_STORAGE_PUBLIC_BASE_URL` is set

## Allowed Status Values

- `completed`
- `waiting_manual`
- `waiting_email_verification`
- `failed`
- `not_applicable`

## Flow Types

- `manual`: adapter supplies playbook only; no browser automation required.
- `semi_auto`: automation for navigable steps; human checkpoint for captcha/email.
- `auto`: end-to-end when legally/technically feasible.

## Safety Rules

- Respect site terms and robots where applicable.
- Enforce per-adapter rate limits.
- Never brute-force protected flows.
- Require explicit user approval before outbound submission actions in v1.

## Versioning

- Semantic versioning for adapter manifest (`version`).
- Breaking changes in input/output contract require major version bump.

## Validation Gate

Before merge/deploy, run:

```bash
python3 scripts/validate_adapters.py
```

Validator coverage:
- required manifest fields + types
- allowed `flowType` values
- `runner.path` traversal/existence checks
- `playbook.md` requirement for `manual` and `semi_auto`
- `rateLimit.maxRunsPerHour` upper bound and `rateLimit.minDelayMs` lower bound
- duplicate adapter key detection across manifests

Strict mode:

```bash
python3 scripts/validate_adapters.py --strict-warnings
```

Automation options:
- CI: `.github/workflows/adapter-quality-gate.yml`
- Local pre-commit install: `./scripts/install_git_hook.sh`

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
KEY_RE = re.compile(r"^[a-z0-9_]+$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

ALLOWED_FLOW_TYPES = {"manual", "semi_auto", "auto"}
REQUIRES_KEYS = {"captcha", "emailVerification", "phoneVerification", "login"}
CAPABILITIES_KEYS = {"discovery", "submitOptOut", "verifyRemoval"}


@dataclass
class LintIssue:
    level: str
    path: Path
    message: str

    def render(self) -> str:
        return f"{self.level.upper()}: {self.path} - {self.message}"


def is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_https_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    return parsed.scheme == "https" and bool(parsed.netloc)


def add_error(issues: list[LintIssue], path: Path, message: str) -> None:
    issues.append(LintIssue(level="error", path=path, message=message))


def add_warning(issues: list[LintIssue], path: Path, message: str) -> None:
    issues.append(LintIssue(level="warning", path=path, message=message))


def validate_manifest(
    manifest_path: Path,
    adapters_root: Path,
    args: argparse.Namespace,
) -> tuple[list[LintIssue], str | None]:
    issues: list[LintIssue] = []

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        add_error(issues, manifest_path, f"invalid JSON: {exc}")
        return issues, None
    except OSError as exc:
        add_error(issues, manifest_path, f"cannot read file: {exc}")
        return issues, None

    if not isinstance(manifest, dict):
        add_error(issues, manifest_path, "manifest root must be a JSON object")
        return issues, None

    key = manifest.get("key")
    if not is_non_empty_string(key):
        add_error(issues, manifest_path, "missing required string field: key")
        key = None
    elif not KEY_RE.fullmatch(key):
        add_error(
            issues,
            manifest_path,
            "key must match ^[a-z0-9_]+$",
        )

    if is_non_empty_string(key):
        expected_name = f"{key}.adapter.json"
        if manifest_path.name != expected_name:
            add_error(
                issues,
                manifest_path,
                f"file name must be {expected_name} to match key",
            )

    display_name = manifest.get("displayName")
    if not is_non_empty_string(display_name):
        add_error(issues, manifest_path, "missing required string field: displayName")

    domain = manifest.get("domain")
    if not is_non_empty_string(domain):
        add_error(issues, manifest_path, "missing required string field: domain")
    elif "://" in domain or "/" in domain:
        add_error(issues, manifest_path, "domain must be a bare host (no scheme/path)")
    elif not DOMAIN_RE.fullmatch(domain):
        add_warning(
            issues,
            manifest_path,
            "domain format looks unusual",
        )

    flow_type = manifest.get("flowType")
    if flow_type not in ALLOWED_FLOW_TYPES:
        add_error(
            issues,
            manifest_path,
            f"flowType must be one of {sorted(ALLOWED_FLOW_TYPES)}",
        )

    version = manifest.get("version")
    if not is_non_empty_string(version):
        add_error(issues, manifest_path, "missing required string field: version")
    elif not SEMVER_RE.fullmatch(version):
        add_error(issues, manifest_path, "version must be valid semantic version (semver)")

    owner = manifest.get("owner")
    if not is_non_empty_string(owner):
        add_error(issues, manifest_path, "missing required string field: owner")

    opt_out_url = manifest.get("optOutUrl")
    if not is_non_empty_string(opt_out_url):
        add_error(issues, manifest_path, "missing required string field: optOutUrl")
    elif not is_https_url(opt_out_url):
        add_error(issues, manifest_path, "optOutUrl must be an https URL")

    requires = manifest.get("requires")
    if not isinstance(requires, dict):
        add_error(issues, manifest_path, "requires must be an object")
    else:
        missing = sorted(REQUIRES_KEYS - set(requires.keys()))
        for item in missing:
            add_error(issues, manifest_path, f"requires.{item} is required")
        extra = sorted(set(requires.keys()) - REQUIRES_KEYS)
        for item in extra:
            add_warning(issues, manifest_path, f"requires.{item} is not recognized")
        for item in REQUIRES_KEYS:
            if item in requires and not isinstance(requires[item], bool):
                add_error(issues, manifest_path, f"requires.{item} must be boolean")

    inputs = manifest.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        add_error(issues, manifest_path, "inputs must be a non-empty array of strings")
    else:
        seen_inputs: set[str] = set()
        for idx, item in enumerate(inputs):
            if not is_non_empty_string(item):
                add_error(issues, manifest_path, f"inputs[{idx}] must be a non-empty string")
                continue
            if item in seen_inputs:
                add_error(issues, manifest_path, f"inputs contains duplicate: {item}")
            seen_inputs.add(item)

    rate_limit = manifest.get("rateLimit")
    if not isinstance(rate_limit, dict):
        add_error(issues, manifest_path, "rateLimit must be an object")
    else:
        max_runs = rate_limit.get("maxRunsPerHour")
        min_delay = rate_limit.get("minDelayMs")
        if not isinstance(max_runs, int) or max_runs <= 0:
            add_error(issues, manifest_path, "rateLimit.maxRunsPerHour must be a positive integer")
        elif max_runs > args.max_runs_per_hour_limit:
            add_error(
                issues,
                manifest_path,
                "rateLimit.maxRunsPerHour exceeds safety limit "
                f"({max_runs} > {args.max_runs_per_hour_limit})",
            )

        if not isinstance(min_delay, int) or min_delay < 0:
            add_error(issues, manifest_path, "rateLimit.minDelayMs must be an integer >= 0")
        elif min_delay < args.min_delay_ms_floor:
            add_error(
                issues,
                manifest_path,
                "rateLimit.minDelayMs below safety floor "
                f"({min_delay} < {args.min_delay_ms_floor})",
            )

    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        add_error(issues, manifest_path, "capabilities must be an object")
    else:
        missing = sorted(CAPABILITIES_KEYS - set(capabilities.keys()))
        for item in missing:
            add_error(issues, manifest_path, f"capabilities.{item} is required")
        extra = sorted(set(capabilities.keys()) - CAPABILITIES_KEYS)
        for item in extra:
            add_warning(issues, manifest_path, f"capabilities.{item} is not recognized")
        for item in CAPABILITIES_KEYS:
            if item in capabilities and not isinstance(capabilities[item], bool):
                add_error(issues, manifest_path, f"capabilities.{item} must be boolean")

    runner = manifest.get("runner")
    runner_required = flow_type in {"semi_auto", "auto"}
    if runner_required and not isinstance(runner, dict):
        add_error(issues, manifest_path, "runner is required for semi_auto/auto adapters")

    if isinstance(runner, dict):
        runner_path = runner.get("path")
        if not is_non_empty_string(runner_path):
            add_error(issues, manifest_path, "runner.path must be a non-empty string")
        else:
            rel = Path(runner_path)
            if rel.is_absolute():
                add_error(issues, manifest_path, "runner.path must be relative")
            else:
                resolved = (manifest_path.parent / rel).resolve()
                try:
                    resolved.relative_to(manifest_path.parent.resolve())
                except ValueError:
                    add_error(
                        issues,
                        manifest_path,
                        "runner.path must stay within adapter directory",
                    )
                else:
                    if not resolved.exists():
                        add_error(
                            issues,
                            manifest_path,
                            f"runner.path does not exist: {runner_path}",
                        )
                    elif not resolved.is_file():
                        add_error(
                            issues,
                            manifest_path,
                            f"runner.path is not a file: {runner_path}",
                        )

        runner_args = runner.get("args", [])
        if not isinstance(runner_args, list):
            add_error(issues, manifest_path, "runner.args must be an array of strings")
        else:
            for idx, arg in enumerate(runner_args):
                if not isinstance(arg, str):
                    add_error(issues, manifest_path, f"runner.args[{idx}] must be a string")

    playbook_path = manifest_path.parent / "playbook.md"
    if flow_type in {"manual", "semi_auto"} and not playbook_path.exists():
        add_error(
            issues,
            manifest_path,
            "playbook.md is required for manual/semi_auto adapters",
        )
    if flow_type == "auto" and not playbook_path.exists():
        add_warning(
            issues,
            manifest_path,
            "playbook.md missing for auto adapter; recommended for ops fallback",
        )

    if is_non_empty_string(domain) and is_non_empty_string(opt_out_url) and is_https_url(opt_out_url):
        parsed = urlparse(opt_out_url)
        if parsed.hostname and parsed.hostname != domain:
            add_warning(
                issues,
                manifest_path,
                f"optOutUrl host ({parsed.hostname}) differs from domain ({domain})",
            )

    if is_non_empty_string(key):
        adapter_dir_name = manifest_path.parent.name
        if adapter_dir_name != "examples" and adapter_dir_name != key:
            add_warning(
                issues,
                manifest_path,
                "adapter directory name does not match key; this can reduce portability",
            )

    try:
        manifest_path.relative_to(adapters_root.resolve())
    except ValueError:
        add_error(issues, manifest_path, "manifest path is outside adapters root")

    return issues, key if is_non_empty_string(key) else None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate privacy-scrubber adapter manifests and local assets.",
    )
    parser.add_argument(
        "--adapters-dir",
        default="adapters",
        help="Path to adapters root (default: adapters)",
    )
    parser.add_argument(
        "--max-runs-per-hour-limit",
        type=int,
        default=60,
        help="Safety upper bound for rateLimit.maxRunsPerHour (default: 60)",
    )
    parser.add_argument(
        "--min-delay-ms-floor",
        type=int,
        default=500,
        help="Safety lower bound for rateLimit.minDelayMs (default: 500)",
    )
    parser.add_argument(
        "--strict-warnings",
        action="store_true",
        help="Fail when warnings are present",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.adapters_dir).resolve()

    if not root.exists() or not root.is_dir():
        print(f"ERROR: adapters dir not found: {root}")
        return 2

    manifest_paths = sorted(root.rglob("*.adapter.json"))
    if not manifest_paths:
        print(f"ERROR: no adapter manifests found under: {root}")
        return 2

    issues: list[LintIssue] = []
    key_to_file: dict[str, Path] = {}

    for manifest_path in manifest_paths:
        manifest_issues, key = validate_manifest(manifest_path, root, args)
        issues.extend(manifest_issues)
        if key:
            prev = key_to_file.get(key)
            if prev is not None:
                add_error(
                    issues,
                    manifest_path,
                    f"duplicate adapter key '{key}' also found in {prev}",
                )
            else:
                key_to_file[key] = manifest_path

    error_count = sum(1 for issue in issues if issue.level == "error")
    warning_count = sum(1 for issue in issues if issue.level == "warning")

    for issue in issues:
        print(issue.render())

    print(
        f"\nChecked {len(manifest_paths)} adapter manifest(s): "
        f"{error_count} error(s), {warning_count} warning(s)"
    )

    if error_count > 0:
        return 1
    if args.strict_warnings and warning_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

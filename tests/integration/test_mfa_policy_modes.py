from __future__ import annotations

import os

import pytest


def _register_user(api, *, email: str, password: str, role: str) -> str:
    resp = api.request(
        "POST",
        "/v1/auth/register",
        json={"email": email, "password": password, "role": role},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return body["user"]["id"]


def _login_raw(api, *, email: str, password: str):
    return api.request(
        "POST",
        "/v1/auth/login",
        json={"email": email, "password": password},
    )


def test_mfa_policy_report_mode_emits_audit(api, run_key: str):
    if os.environ.get("MFA_POLICY_MODE_TEST", "").strip().lower() != "report":
        pytest.skip("MFA_POLICY_MODE_TEST!=report")

    email = f"pytest+mfa-report-{run_key}@example.com"
    password = "VeryStrongPassw0rd!Report"
    user_id = _register_user(api, email=email, password=password, role="owner")

    login = _login_raw(api, email=email, password=password)
    assert login.status_code == 200, login.text

    audit = api.json("GET", "/v1/audit-log", params={"limit": 500}, expected_status=200)
    matches = [
        item
        for item in audit["items"]
        if item.get("action") == "auth.mfa_policy.report" and item.get("object_id") == user_id
    ]
    assert matches, "expected auth.mfa_policy.report audit event in report mode"


def test_mfa_policy_enforce_mode_blocks_privileged_login(api, run_key: str):
    if os.environ.get("MFA_POLICY_MODE_TEST", "").strip().lower() != "enforce":
        pytest.skip("MFA_POLICY_MODE_TEST!=enforce")

    email = f"pytest+mfa-enforce-{run_key}@example.com"
    password = "VeryStrongPassw0rd!Enforce"
    user_id = _register_user(api, email=email, password=password, role="owner")

    login = _login_raw(api, email=email, password=password)
    assert login.status_code == 403, login.text
    assert "mfa required for privileged role by policy" in login.text.lower()

    audit = api.json("GET", "/v1/audit-log", params={"limit": 500}, expected_status=200)
    matches = [
        item
        for item in audit["items"]
        if item.get("action") == "auth.mfa_policy.block" and item.get("object_id") == user_id
    ]
    assert matches, "expected auth.mfa_policy.block audit event in enforce mode"

from __future__ import annotations

import os

import requests
import pytest


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _db_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql://privacy:privacy_change_me@localhost:5432/privacy_scrubber",
    )


def _insert_user(email: str, password: str, role: str) -> None:
    psycopg2 = pytest.importorskip("psycopg2")
    passlib_context = pytest.importorskip("passlib.context")
    pwd_context = passlib_context.CryptContext(schemes=["bcrypt"], deprecated="auto")
    password_hash = pwd_context.hash(password)
    with psycopg2.connect(_db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into users(email, password_hash, role, mfa_enabled)
                values (%s, %s, %s, false)
                on conflict (email) do nothing;
                """,
                (email, password_hash, role),
            )
        conn.commit()


def test_invalid_status_and_flow_validation(api, owner_user_id: str, run_key: str):
    profile = api.json(
        "POST",
        "/v1/profiles",
        json={
            "owner_user_id": owner_user_id,
            "display_name": f"Pytest Negative {run_key}",
            "region_code": "US-CA",
        },
        expected_status=200,
    )
    finding = api.json(
        "POST",
        "/v1/findings",
        json={
            "profile_id": profile["id"],
            "source_domain": "invalid-status.example.test",
            "source_url": f"https://invalid-status.example.test/{run_key}",
            "risk_score": 42,
            "matched_identifiers": ["full_name"],
            "exposed_fields": ["name"],
            "notes": "negative-path",
        },
        expected_status=200,
    )
    task = api.json(
        "POST",
        "/v1/tasks",
        json={"finding_id": finding["id"]},
        expected_status=200,
    )

    bad_finding = api.request(
        "PATCH",
        f"/v1/findings/{finding['id']}",
        json={"status": "not_a_real_status"},
    )
    assert bad_finding.status_code == 400
    assert "invalid finding status" in bad_finding.text.lower()

    bad_task = api.request(
        "PATCH",
        f"/v1/tasks/{task['id']}",
        json={"status": "definitely_invalid"},
    )
    assert bad_task.status_code == 400
    assert "invalid task status" in bad_task.text.lower()

    bad_adapter = api.request(
        "POST",
        "/v1/adapters",
        json={
            "key": f"pytest_adapter_bad_flow_{run_key}",
            "display_name": "Bad Flow",
            "domain": "example.test",
            "flow": "super_auto_mode",
            "adapter_version": "1.0.0",
            "enabled": True,
            "metadata": {},
        },
    )
    assert bad_adapter.status_code == 400
    assert "invalid flow type" in bad_adapter.text.lower()


def test_invalid_cursor_rejected(api):
    bad_cursor = "definitely-not-a-valid-cursor"
    for path in [
        "/v1/findings",
        "/v1/tasks",
        "/v1/reminders",
        "/v1/audit-log",
        "/v1/adapter-runs",
        "/v1/jobs",
        "/v1/providers",
        "/v1/adapters",
    ]:
        resp = api.request("GET", path, params={"cursor": bad_cursor})
        assert resp.status_code == 400, f"{path} returned {resp.status_code}: {resp.text}"
        assert "invalid cursor" in resp.text.lower()


def test_viewer_forbidden_on_privileged_endpoints(api, run_key: str):
    viewer_email = f"pytest+viewer_{run_key}@example.com"
    viewer_password = "VeryStrongPassw0rd!123"

    _insert_user(viewer_email, viewer_password, "viewer")

    login = requests.post(
        f"{api.base_url}/v1/auth/login",
        json={"email": viewer_email, "password": viewer_password},
        timeout=30,
    )
    assert login.status_code == 200, login.text
    viewer_token = login.json()["access_token"]

    # Viewer should be blocked from provider creation.
    forbidden = requests.post(
        f"{api.base_url}/v1/providers",
        headers=_auth_headers(viewer_token),
        json={
            "key": f"pytest_provider_forbidden_{run_key}",
            "kind": "search_provider",
            "enabled": True,
            "config": {"endpoint": "https://forbidden.example"},
        },
        timeout=30,
    )
    assert forbidden.status_code == 403, forbidden.text

    # Ensure forbidden attempt did not create a provider-create audit event for this key.
    audit = api.json("GET", "/v1/audit-log", params={"limit": 500}, expected_status=200)
    matching = [
        item
        for item in audit["items"]
        if item.get("action") == "providers.create"
        and (item.get("payload", {}) or {}).get("key") == f"pytest_provider_forbidden_{run_key}"
    ]
    assert not matching, "forbidden provider create should not emit providers.create audit event"


def test_idempotency_key_replay_and_conflict(api, owner_user_id: str, run_key: str):
    assert owner_user_id
    idem_key = f"pytest-idem-{run_key}"
    provider_key = f"pytest_provider_idem_{run_key}"
    body = {
        "key": provider_key,
        "kind": "search_provider",
        "enabled": True,
        "config": {"endpoint": "https://idem.example"},
    }

    first = api.request(
        "POST",
        "/v1/providers",
        headers={"Idempotency-Key": idem_key},
        json=body,
    )
    assert first.status_code == 200, first.text
    first_body = first.json()

    replay = api.request(
        "POST",
        "/v1/providers",
        headers={"Idempotency-Key": idem_key},
        json=body,
    )
    assert replay.status_code == 200, replay.text
    assert replay.headers.get("Idempotency-Replayed") == "true"
    replay_body = replay.json()
    assert replay_body["id"] == first_body["id"]
    assert replay_body["key"] == first_body["key"]

    conflict = api.request(
        "POST",
        "/v1/providers",
        headers={"Idempotency-Key": idem_key},
        json={
            **body,
            "config": {"endpoint": "https://different.example"},
        },
    )
    assert conflict.status_code == 409, conflict.text
    assert "idempotency-key" in conflict.text.lower()


def test_api_version_contract_metadata(api):
    health = api.request("GET", "/health")
    assert health.status_code == 200, health.text
    assert health.headers.get("X-API-Contract-Version") == "v1"
    assert health.headers.get("X-API-Versioning-Strategy") == "path-prefix"
    assert health.headers.get("X-API-Implementation-Version")

    version = api.json("GET", "/v1/version", expected_status=200)
    assert version["contract_version"] == "v1"
    assert version["versioning_strategy"] == "path-prefix"
    assert version["implementation_version"]

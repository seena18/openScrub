from __future__ import annotations

import requests


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def test_api_key_lifecycle_scope_and_audit(api, run_key: str):
    key_name = f"pytest_api_key_lifecycle_{run_key}"

    created = api.json(
        "POST",
        "/v1/api-keys",
        json={
            "name": key_name,
            "role": "system",
            "allowed_path_prefixes": ["v1/version"],  # exercise prefix normalization
        },
        expected_status=200,
    )
    api_key = created["api_key"]
    item = created["item"]
    assert api_key.startswith("psk_")
    assert item["name"] == key_name
    assert item["role"] == "system"
    assert item["allowed_path_prefixes"] == ["/v1/version"]
    assert item["enabled"] is True

    listed = api.json("GET", "/v1/api-keys", expected_status=200)
    matching = [x for x in listed["items"] if x["id"] == item["id"]]
    assert len(matching) == 1
    assert "api_key" not in matching[0]

    ok = requests.get(f"{api.base_url}/v1/version", headers=_auth_headers(api_key), timeout=30)
    assert ok.status_code == 200, ok.text

    denied = requests.get(f"{api.base_url}/v1/users", headers=_auth_headers(api_key), timeout=30)
    assert denied.status_code == 401, denied.text

    rotated = api.json("POST", f"/v1/api-keys/{item['id']}/rotate", expected_status=200)
    rotated_key = rotated["api_key"]
    assert rotated["item"]["id"] == item["id"]
    assert rotated_key.startswith("psk_")
    assert rotated_key != api_key

    old_key_after_rotate = requests.get(f"{api.base_url}/v1/version", headers=_auth_headers(api_key), timeout=30)
    assert old_key_after_rotate.status_code == 401, old_key_after_rotate.text

    new_key_after_rotate = requests.get(f"{api.base_url}/v1/version", headers=_auth_headers(rotated_key), timeout=30)
    assert new_key_after_rotate.status_code == 200, new_key_after_rotate.text

    revoked = api.json("POST", f"/v1/api-keys/{item['id']}/revoke", expected_status=200)
    assert revoked["enabled"] is False

    denied_after_revoke = requests.get(f"{api.base_url}/v1/version", headers=_auth_headers(rotated_key), timeout=30)
    assert denied_after_revoke.status_code == 401, denied_after_revoke.text

    audit = api.json("GET", "/v1/audit-log", params={"limit": 300}, expected_status=200)
    item_actions = [x for x in audit["items"] if x.get("object_id") == item["id"]]
    action_names = {x.get("action") for x in item_actions}
    assert "api_keys.create" in action_names
    assert "api_keys.rotate" in action_names
    assert "api_keys.revoke" in action_names
    assert "api_keys.scope_denied" in action_names


def test_expired_api_key_rejected(api, run_key: str):
    key_name = f"pytest_api_key_expired_{run_key}"
    created = api.json(
        "POST",
        "/v1/api-keys",
        json={
            "name": key_name,
            "role": "viewer",
            "allowed_path_prefixes": ["/v1/version"],
            "expires_at": "2000-01-01T00:00:00Z",
        },
        expected_status=200,
    )
    api_key = created["api_key"]
    key_id = created["item"]["id"]

    denied = requests.get(f"{api.base_url}/v1/version", headers=_auth_headers(api_key), timeout=30)
    assert denied.status_code == 401, denied.text

    audit = api.json("GET", "/v1/audit-log", params={"limit": 300}, expected_status=200)
    denied_events = [
        x
        for x in audit["items"]
        if x.get("object_id") == key_id
        and x.get("action") == "api_keys.auth_denied"
        and (x.get("payload") or {}).get("reason") == "expired"
    ]
    assert denied_events, "expected api_keys.auth_denied audit event for expired key"

from __future__ import annotations

import uuid

import pytest
import requests


def _db_url() -> str:
    import os

    return os.environ.get(
        "DATABASE_URL",
        "postgresql://privacy:privacy_change_me@localhost:5432/privacy_scrubber",
    )


def _insert_webauthn_challenge(user_id: str, *, purpose: str, challenge: str, expired: bool = False) -> str:
    psycopg2 = pytest.importorskip("psycopg2")
    with psycopg2.connect(_db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            if expired:
                cur.execute(
                    """
                    insert into mfa_webauthn_challenges (user_id, purpose, challenge, expires_at)
                    values (%s::uuid, %s, %s, now() - interval '1 minute')
                    returning id::text;
                    """,
                    (user_id, purpose, challenge),
                )
            else:
                cur.execute(
                    """
                    insert into mfa_webauthn_challenges (user_id, purpose, challenge, expires_at)
                    values (%s::uuid, %s, %s, now() + interval '10 minutes')
                    returning id::text;
                    """,
                    (user_id, purpose, challenge),
                )
            row = cur.fetchone()
        conn.commit()
    return row[0]


def _insert_webauthn_credential(user_id: str, credential_id: str) -> None:
    psycopg2 = pytest.importorskip("psycopg2")
    with psycopg2.connect(_db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into mfa_webauthn_credentials (
                  user_id, credential_id, public_key, sign_count, enabled, verified_at
                )
                values (%s::uuid, %s, %s, 0, true, now())
                on conflict (credential_id) do update
                  set user_id = excluded.user_id,
                      enabled = true,
                      updated_at = now();
                """,
                (user_id, credential_id, "dummy_pubkey"),
            )
        conn.commit()


def test_webauthn_challenge_replay_and_expiry(jwt_api):
    me = jwt_api.json("GET", "/v1/auth/me", expected_status=200)
    user_id = me.get("user_id")
    assert user_id, "expected JWT user principal for test fixture"

    # Replay behavior: first bad verify consumes challenge, second attempt is rejected as invalid/expired.
    challenge_id = _insert_webauthn_challenge(
        user_id,
        purpose="register",
        challenge="replay-challenge-value",
        expired=False,
    )
    first = jwt_api.request(
        "POST",
        "/v1/auth/mfa/webauthn/verify-setup",
        json={"challenge_id": challenge_id, "credential": {}},
    )
    assert first.status_code == 400, first.text
    assert "webauthn registration verify failed" in first.text.lower()

    second = jwt_api.request(
        "POST",
        "/v1/auth/mfa/webauthn/verify-setup",
        json={"challenge_id": challenge_id, "credential": {}},
    )
    assert second.status_code == 400, second.text
    assert "invalid or expired webauthn challenge" in second.text.lower()

    # Expiry behavior: expired challenge cannot be consumed.
    expired_id = _insert_webauthn_challenge(
        user_id,
        purpose="register",
        challenge="expired-challenge-value",
        expired=True,
    )
    expired_resp = jwt_api.request(
        "POST",
        "/v1/auth/mfa/webauthn/verify-setup",
        json={"challenge_id": expired_id, "credential": {}},
    )
    assert expired_resp.status_code == 400, expired_resp.text
    assert "invalid or expired webauthn challenge" in expired_resp.text.lower()


def test_webauthn_delete_revokes_refresh_token(api, run_key: str):
    email = f"pytest+webauthn-revoke-{run_key}@example.com"
    password = "StrongPassw0rd!1234"

    registered = api.json(
        "POST",
        "/v1/auth/register",
        json={"email": email, "password": password, "role": "viewer"},
        expected_status=200,
    )
    refresh_token = registered["refresh_token"]
    access_token = registered["access_token"]
    user_id = registered["user"]["id"]

    credential_id = f"pytest-cred-{uuid.uuid4().hex}"
    _insert_webauthn_credential(user_id, credential_id)

    delete_resp = requests.delete(
        f"{api.base_url}/v1/auth/mfa/webauthn/credentials/{credential_id}",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"current_password": password},
        timeout=30,
    )
    assert delete_resp.status_code == 200, delete_resp.text

    refresh_resp = requests.post(
        f"{api.base_url}/v1/auth/refresh",
        json={"refresh_token": refresh_token},
        timeout=30,
    )
    assert refresh_resp.status_code == 401, refresh_resp.text
    assert "revoked or expired" in refresh_resp.text.lower()


def test_webauthn_auth_finish_rate_limited(api, run_key: str):
    email = f"pytest+webauthn-rate-{run_key}@example.com"
    password = "StrongPassw0rd!1234"

    api.json(
        "POST",
        "/v1/auth/register",
        json={"email": email, "password": password, "role": "viewer"},
        expected_status=200,
    )

    # Keep triggering finish with bad challenge id; after configured limit should become 429.
    last_status = None
    for _ in range(12):
        resp = api.request(
            "POST",
            "/v1/auth/mfa/webauthn/authenticate/finish",
            json={"email": email, "challenge_id": str(uuid.uuid4()), "credential": {}},
        )
        last_status = resp.status_code
        if last_status == 429:
            break

    assert last_status == 429, f"expected 429 rate-limit response, got {last_status}"


def test_webauthn_verify_setup_rate_limited(jwt_api):
    me = jwt_api.json("GET", "/v1/auth/me", expected_status=200)
    user_id = me.get("user_id")
    assert user_id, "expected JWT user principal for test fixture"

    last_status = None
    for i in range(12):
        challenge_id = _insert_webauthn_challenge(
            user_id,
            purpose="register",
            challenge=f"verify-rl-{i}",
            expired=False,
        )
        resp = jwt_api.request(
            "POST",
            "/v1/auth/mfa/webauthn/verify-setup",
            json={"challenge_id": challenge_id, "credential": {}},
        )
        last_status = resp.status_code
        if last_status == 429:
            break

    assert last_status == 429, f"expected 429 rate-limit response, got {last_status}"

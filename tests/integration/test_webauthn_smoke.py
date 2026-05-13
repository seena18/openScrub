from __future__ import annotations


def test_webauthn_setup_start_and_status(api):
    setup = api.json("POST", "/v1/auth/mfa/webauthn/setup", expected_status=200)
    assert setup["status"] == "ok"
    assert setup["challenge_id"]
    assert setup["public_key"]["challenge"]
    assert setup["rp_id"]
    assert setup["origins"]

    status = api.json("GET", "/v1/auth/mfa/totp/status", expected_status=200)
    assert "webauthn_configured" in status
    assert "webauthn_credential_count" in status
    assert isinstance(status["webauthn_credential_count"], int)


def test_webauthn_authenticate_start_requires_mfa_enabled(api, run_key: str):
    email = f"pytest+webauthn-{run_key}@example.com"
    password = "StrongPassw0rd!1234"
    registered = api.json(
        "POST",
        "/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "role": "viewer",
        },
        expected_status=200,
    )
    assert registered["registered"] is True

    auth_start = api.request(
        "POST",
        "/v1/auth/mfa/webauthn/authenticate/start",
        json={"email": email, "password": password},
    )
    assert auth_start.status_code == 400, auth_start.text
    assert "mfa is not enabled" in auth_start.text.lower()

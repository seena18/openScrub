from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any

import pytest
import requests


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


API_BASE = _env("API_BASE", "http://localhost:8080")
API_BEARER_TOKEN = _env("API_BEARER_TOKEN", "change-me-automation-token")
DATABASE_URL = _env(
    "DATABASE_URL",
    "postgresql://privacy:privacy_change_me@localhost:5432/privacy_scrubber",
)


@dataclass
class ApiClient:
    base_url: str
    token: str

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.token}"
        url = f"{self.base_url}{path}"
        response = requests.request(method, url, headers=headers, timeout=30, **kwargs)
        return response

    def json(self, method: str, path: str, expected_status: int = 200, **kwargs: Any) -> dict[str, Any]:
        response = self.request(method, path, **kwargs)
        if response.status_code != expected_status:
            raise AssertionError(
                f"{method} {path} expected {expected_status} got {response.status_code}: {response.text}"
            )
        return response.json()


def _cleanup_test_fixtures() -> None:
    psycopg2 = pytest.importorskip("psycopg2")
    with psycopg2.connect(DATABASE_URL, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("delete from idempotency_keys where idempotency_key like 'pytest-idem-%';")
            cur.execute("delete from api_keys where name like 'pytest_api_key_%';")
            cur.execute("delete from providers where key like 'pytest_provider_%';")
            cur.execute("delete from adapters where key like 'pytest_adapter_%';")
            cur.execute(
                """
                delete from users
                where email like 'pytest+%@example.com'
                  and email not like 'pytest+bootstrap-%@example.com';
                """
            )
        conn.commit()


def _create_owner_user(run_key: str) -> str:
    psycopg2 = pytest.importorskip("psycopg2")
    email = f"pytest+{run_key}@example.com"
    with psycopg2.connect(DATABASE_URL, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into users(email, password_hash, role, mfa_enabled)
                values (%s, 'devhash', 'owner', false)
                returning id::text;
                """,
                (email,),
            )
            user_id = cur.fetchone()[0]
        conn.commit()
    return user_id


def _create_owner_user_with_password(run_key: str, password: str) -> tuple[str, str]:
    psycopg2 = pytest.importorskip("psycopg2")
    passlib_context = pytest.importorskip("passlib.context")
    pwd_context = passlib_context.CryptContext(schemes=["bcrypt"], deprecated="auto")
    email = f"pytest+bootstrap-{run_key}@example.com"
    password_hash = pwd_context.hash(password)
    with psycopg2.connect(DATABASE_URL, connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into users(email, password_hash, role, mfa_enabled)
                values (%s, %s, 'owner', false)
                on conflict (email) do update set password_hash = excluded.password_hash
                returning id::text, email;
                """,
                (email, password_hash),
            )
            row = cur.fetchone()
        conn.commit()
    return row[0], row[1]


def _resolve_working_token(client: ApiClient) -> str:
    probe = client.request("GET", "/v1/auth/me")
    if probe.status_code == 200:
        return client.token

    bootstrap_password = "PytestBootstrapPassw0rd!123"
    _, email = _create_owner_user_with_password(uuid.uuid4().hex[:12], bootstrap_password)
    login = requests.post(
        f"{client.base_url}/v1/auth/login",
        json={"email": email, "password": bootstrap_password},
        timeout=30,
    )
    if login.status_code != 200:
        raise AssertionError(f"unable to bootstrap JWT test user: {login.status_code} {login.text}")
    return login.json()["access_token"]


@pytest.fixture(scope="session")
def api() -> ApiClient:
    client = ApiClient(base_url=API_BASE, token=API_BEARER_TOKEN)
    client.token = _resolve_working_token(client)
    return client


@pytest.fixture()
def run_key() -> str:
    return uuid.uuid4().hex[:12]


@pytest.fixture()
def owner_user_id(run_key: str) -> str:
    _cleanup_test_fixtures()
    user_id = _create_owner_user(run_key)
    yield user_id
    _cleanup_test_fixtures()

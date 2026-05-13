import base64
import hashlib
import json
import os
import secrets
from threading import Lock
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Any, Optional
from uuid import uuid4

import jwt
import psycopg2
import redis
import pyotp
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from psycopg2.extras import Json
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

app = FastAPI(title="Privacy Scrubber API", version="0.5.0")
API_CONTRACT_VERSION = "v1"
API_VERSIONING_STRATEGY = "path-prefix"
STATIC_UI_DIR = Path(__file__).parent / "static"
if STATIC_UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(STATIC_UI_DIR), html=True), name="ui")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

VALID_ROLES = {"owner", "admin", "reviewer", "operator", "viewer", "system"}
IDENTIFIER_TYPES = {
    "full_name",
    "alias",
    "email",
    "phone",
    "address",
    "city",
    "dob_partial",
    "username",
}
FINDING_STATUSES = {
    "new",
    "triaged",
    "task_created",
    "submitted",
    "pending_verification",
    "removed",
    "reappeared",
    "closed_false_positive",
}
TASK_STATUSES = {
    "queued",
    "in_progress",
    "waiting_manual",
    "waiting_email_verification",
    "completed",
    "failed",
    "cancelled",
}
FLOW_TYPES = {"manual", "semi_auto", "auto"}

RATE_LIMIT_LOCK = Lock()
RATE_LIMIT_BUCKETS: dict[str, list[float]] = {}
REDIS_CLIENT = None


@app.middleware("http")
async def add_api_version_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-API-Contract-Version"] = API_CONTRACT_VERSION
    response.headers["X-API-Implementation-Version"] = app.version
    response.headers["X-API-Versioning-Strategy"] = API_VERSIONING_STRATEGY
    return response


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_db_conn():
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://privacy:privacy_change_me@postgres:5432/privacy_scrubber",
    )
    return psycopg2.connect(db_url, connect_timeout=3)


def str_to_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_mfa_policy_mode() -> str:
    mode = os.environ.get("MFA_POLICY_MODE", "off").strip().lower()
    if mode not in {"off", "report", "enforce"}:
        return "off"
    return mode


def get_mfa_privileged_roles() -> set[str]:
    raw = os.environ.get("MFA_PRIVILEGED_ROLES", "owner,admin").strip()
    if not raw:
        return {"owner", "admin"}
    roles = {part.strip().lower() for part in raw.split(",") if part.strip()}
    return roles & VALID_ROLES


def get_bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="invalid authorization header")
    return authorization.removeprefix("Bearer ").strip()


def get_jwt_secret() -> str:
    return os.environ.get("JWT_SECRET", "").strip()


def issue_access_jwt(user_id: str, email: str, role: str) -> tuple[str, int]:
    jwt_secret = get_jwt_secret()
    if not jwt_secret:
        raise HTTPException(status_code=500, detail="JWT_SECRET is not configured")

    expires_minutes = int(os.environ.get("JWT_EXPIRES_MINUTES", "60"))
    now = utc_now()
    exp = now + timedelta(minutes=expires_minutes)

    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "token_type": "access",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, jwt_secret, algorithm="HS256")
    return token, expires_minutes * 60


def issue_refresh_jwt(user_id: str, email: str, role: str) -> tuple[str, str, datetime, int]:
    jwt_secret = get_jwt_secret()
    if not jwt_secret:
        raise HTTPException(status_code=500, detail="JWT_SECRET is not configured")

    expires_minutes = int(os.environ.get("REFRESH_JWT_EXPIRES_MINUTES", "10080"))
    now = utc_now()
    exp = now + timedelta(minutes=expires_minutes)
    jti = str(uuid4())

    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "token_type": "refresh",
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(payload, jwt_secret, algorithm="HS256")
    return token, jti, exp, expires_minutes * 60


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def persist_refresh_token(user_id: str, jti: str, token: str, expires_at: datetime) -> None:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into auth_refresh_tokens (user_id, token_jti, token_hash, expires_at)
                values (%s::uuid, %s, %s, %s::timestamptz);
                """,
                (user_id, jti, hash_token(token), expires_at.isoformat()),
            )
        conn.commit()


def revoke_refresh_token(user_id: str, jti: str, replaced_by_jti: Optional[str] = None) -> None:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update auth_refresh_tokens
                set revoked_at = now(),
                    replaced_by_jti = coalesce(%s, replaced_by_jti)
                where user_id = %s::uuid
                  and token_jti = %s
                  and revoked_at is null;
                """,
                (replaced_by_jti, user_id, jti),
            )
        conn.commit()


def revoke_all_refresh_tokens(user_id: str) -> None:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update auth_refresh_tokens
                set revoked_at = now()
                where user_id = %s::uuid
                  and revoked_at is null;
                """,
                (user_id,),
            )
        conn.commit()


def build_auth_response(user_id: str, email: str, role: str, *, mfa_enabled: Optional[bool] = None) -> dict[str, Any]:
    access_token, access_expires_in = issue_access_jwt(user_id, email, role)
    refresh_token, refresh_jti, refresh_exp, refresh_expires_in = issue_refresh_jwt(user_id, email, role)
    persist_refresh_token(user_id, refresh_jti, refresh_token, refresh_exp)

    user_payload: dict[str, Any] = {
        "id": user_id,
        "email": email,
        "role": role,
    }
    if mfa_enabled is not None:
        user_payload["mfa_enabled"] = mfa_enabled

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": access_expires_in,
        "refresh_token": refresh_token,
        "refresh_expires_in": refresh_expires_in,
        "user": user_payload,
        "refresh_jti": refresh_jti,
    }


def verify_jwt_token(token: str, expected_token_type: str = "access") -> Optional[dict[str, Any]]:
    jwt_secret = get_jwt_secret()
    if not jwt_secret:
        return None

    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except Exception:
        return None

    user_id = payload.get("sub")
    email = payload.get("email")
    role = payload.get("role", "viewer")
    token_type = payload.get("token_type", "access")

    if not user_id or not email:
        return None
    if role not in VALID_ROLES:
        return None
    if token_type != expected_token_type:
        return None

    return {
        "auth_type": "jwt",
        "user_id": user_id,
        "email": email,
        "role": role,
        "token_type": token_type,
        "jti": payload.get("jti"),
    }


def verify_static_token(token: str) -> Optional[dict[str, Any]]:
    expected = os.environ.get("API_BEARER_TOKEN", "").strip()
    if not expected:
        return None
    if token != expected:
        return None
    return {
        "auth_type": "static_token",
        "user_id": None,
        "email": "system@local",
        "role": "system",
        "token_type": "access",
        "jti": None,
    }


def normalize_path_prefixes(values: list[Any]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        item = str(raw or "").strip()
        if not item:
            continue
        if not item.startswith("/"):
            item = f"/{item}"
        item = item.rstrip() or "/"
        if item not in seen:
            seen.add(item)
            normalized.append(item)
    return normalized


def is_path_allowed(request_path: Optional[str], allowed_path_prefixes: list[Any]) -> bool:
    prefixes = normalize_path_prefixes(allowed_path_prefixes)
    if not prefixes:
        return True
    path = (request_path or "/").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"

    for prefix in prefixes:
        if prefix == "/":
            return True

        wildcard = prefix.endswith("*")
        base = prefix[:-1] if wildcard else prefix
        base = base.rstrip("/") or "/"

        if wildcard:
            if path.startswith(base):
                return True
            continue

        if path == base or path.startswith(f"{base}/"):
            return True

    return False


def verify_api_key(token: str, request_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    token_hash = hash_token(token)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text,
                       name,
                       role,
                       allowed_path_prefixes,
                       enabled,
                       expires_at::text,
                       created_by_user_id::text
                from api_keys
                where key_hash = %s;
                """,
                (token_hash,),
            )
            row = cur.fetchone()

            if not row:
                return None

            api_key_id, name, role, allowed_path_prefixes, enabled, expires_at, created_by_user_id = row
            allowed = allowed_path_prefixes if isinstance(allowed_path_prefixes, list) else []

            if role not in VALID_ROLES:
                write_audit_log(
                    "api_keys.auth_denied",
                    "api_key",
                    actor_user_id=created_by_user_id,
                    object_id=api_key_id,
                    payload={"reason": "invalid_role", "role": role},
                )
                return None

            if not enabled:
                write_audit_log(
                    "api_keys.auth_denied",
                    "api_key",
                    actor_user_id=created_by_user_id,
                    object_id=api_key_id,
                    payload={"reason": "disabled"},
                )
                return None

            if expires_at:
                cur.execute("select now() > %s::timestamptz;", (expires_at,))
                is_expired = bool(cur.fetchone()[0])
                if is_expired:
                    write_audit_log(
                        "api_keys.auth_denied",
                        "api_key",
                        actor_user_id=created_by_user_id,
                        object_id=api_key_id,
                        payload={"reason": "expired", "expires_at": expires_at},
                    )
                    return None

            if not is_path_allowed(request_path, allowed):
                write_audit_log(
                    "api_keys.scope_denied",
                    "api_key",
                    actor_user_id=created_by_user_id,
                    object_id=api_key_id,
                    payload={"request_path": request_path, "allowed_path_prefixes": allowed},
                )
                return None

            cur.execute(
                """
                update api_keys
                set last_used_at = now(),
                    updated_at = now()
                where id = %s::uuid;
                """,
                (api_key_id,),
            )
        conn.commit()

    return {
        "auth_type": "api_key",
        "user_id": None,
        "email": f"api-key:{name}",
        "role": role,
        "token_type": "access",
        "jti": None,
        "api_key_id": api_key_id,
        "api_key_name": name,
        "allowed_path_prefixes": allowed,
        "created_by_user_id": created_by_user_id,
    }


def resolve_principal(
    authorization: Optional[str],
    expected_token_type: str = "access",
    request_path: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    token = get_bearer_token(authorization)
    if not token:
        return None

    if expected_token_type == "access":
        principal = verify_api_key(token, request_path=request_path)
        if principal:
            return principal

        principal = verify_static_token(token)
        if principal:
            return principal

    principal = verify_jwt_token(token, expected_token_type=expected_token_type)
    if principal:
        return principal

    return None


def require_auth(request: Request, authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    expected_static = os.environ.get("API_BEARER_TOKEN", "").strip()
    jwt_secret = get_jwt_secret()

    # dev-open mode when no auth config is present
    if not expected_static and not jwt_secret:
        return {
            "auth_type": "dev_open",
            "user_id": None,
            "email": "dev@local",
            "role": "owner",
            "token_type": "access",
            "jti": None,
        }

    principal = resolve_principal(authorization, expected_token_type="access", request_path=request.url.path)
    if not principal:
        raise HTTPException(status_code=401, detail="unauthorized")

    return principal


def require_roles(principal: dict[str, Any], allowed_roles: set[str]) -> None:
    role = principal.get("role")
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="forbidden")


def require_user_principal(principal: dict[str, Any]) -> str:
    user_id = principal.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user principal required")
    return user_id


def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "").strip()
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def parse_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
        if value <= 0:
            return default
        return value
    except Exception:
        return default


def decode_pagination_cursor(cursor: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not cursor:
        return None, None
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
        parsed = json.loads(raw)
        created_at = (parsed.get("created_at") or "").strip()
        item_id = (parsed.get("id") or "").strip()
        if not created_at or not item_id:
            raise ValueError("missing cursor fields")
        return created_at, item_id
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"invalid cursor: {exc}") from exc


def encode_pagination_cursor(created_at: str, item_id: str) -> str:
    payload = json.dumps({"created_at": created_at, "id": item_id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8")


def get_redis_client():
    global REDIS_CLIENT
    if REDIS_CLIENT is not None:
        return REDIS_CLIENT

    redis_url = os.environ.get("REDIS_URL", "").strip()
    if not redis_url:
        return None

    try:
        client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=1)
        client.ping()
        REDIS_CLIENT = client
        return REDIS_CLIENT
    except Exception:
        return None


def enforce_rate_limit(
    action: str,
    key: str,
    *,
    max_attempts: int,
    window_seconds: int,
) -> None:
    now = monotonic()
    redis_client = get_redis_client()
    if redis_client:
        now_epoch = int(datetime.now(timezone.utc).timestamp())
        window_slot = now_epoch // window_seconds
        slot_start = window_slot * window_seconds
        slot_end = slot_start + window_seconds
        retry_after = max(1, slot_end - now_epoch)
        prefix = os.environ.get("RATE_LIMIT_REDIS_PREFIX", "rl").strip() or "rl"
        redis_key = f"{prefix}:{action}:{key}:{window_slot}"
        try:
            count = redis_client.incr(redis_key)
            if count == 1:
                redis_client.expire(redis_key, window_seconds + 5)
            if count > max_attempts:
                raise HTTPException(
                    status_code=429,
                    detail=f"rate limit exceeded for {action}",
                    headers={"Retry-After": str(retry_after)},
                )
            return
        except HTTPException:
            raise
        except Exception:
            # Redis unavailable; continue with in-memory fallback.
            pass

    bucket_key = f"{action}:{key}"
    cutoff = now - window_seconds

    with RATE_LIMIT_LOCK:
        events = RATE_LIMIT_BUCKETS.get(bucket_key, [])
        events = [t for t in events if t >= cutoff]
        if len(events) >= max_attempts:
            retry_after = max(1, int(window_seconds - (now - events[0])))
            raise HTTPException(
                status_code=429,
                detail=f"rate limit exceeded for {action}",
                headers={"Retry-After": str(retry_after)},
            )
        events.append(now)
        RATE_LIMIT_BUCKETS[bucket_key] = events


def write_audit_log(
    action: str,
    object_type: str,
    *,
    actor_user_id: Optional[str] = None,
    object_id: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
) -> None:
    actor = actor_user_id or ""
    obj = object_id or ""
    event_payload = payload or {}
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into audit_log (actor_user_id, action, object_type, object_id, payload)
                    values (nullif(%s, '')::uuid, %s, %s, nullif(%s, '')::uuid, %s::jsonb);
                    """,
                    (actor, action, object_type, obj, Json(event_payload)),
                )
            conn.commit()
    except Exception:
        # Never block primary actions because of audit logging failures.
        pass


def idempotency_scope_key(principal: dict[str, Any]) -> str:
    user_id = (principal.get("user_id") or "").strip() if principal else ""
    if user_id:
        return f"user:{user_id}"
    email = (principal.get("email") or "").strip().lower() if principal else ""
    if email:
        return f"email:{email}"
    role = (principal.get("role") or "unknown").strip().lower() if principal else "unknown"
    return f"role:{role}"


def normalize_idempotency_key(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    key = value.strip()
    if not key:
        return None
    if len(key) > 255:
        raise HTTPException(status_code=400, detail="Idempotency-Key too long (max 255)")
    return key


def hash_idempotency_payload(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def idempotency_replay_if_exists(
    *,
    endpoint: str,
    idempotency_key: Optional[str],
    principal: dict[str, Any],
    request_payload: Any,
) -> Optional[JSONResponse]:
    key = normalize_idempotency_key(idempotency_key)
    if not key:
        return None

    scope = idempotency_scope_key(principal)
    payload_hash = hash_idempotency_payload(request_payload)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select request_hash, response_status, response_body::text
                from idempotency_keys
                where scope_key = %s
                  and endpoint = %s
                  and idempotency_key = %s;
                """,
                (scope, endpoint, key),
            )
            row = cur.fetchone()

    if not row:
        return None

    stored_hash, stored_status, stored_body_text = row
    if stored_hash != payload_hash:
        raise HTTPException(
            status_code=409,
            detail="Idempotency-Key already used with different request payload",
        )
    body = json.loads(stored_body_text)
    return JSONResponse(status_code=int(stored_status), content=body, headers={"Idempotency-Replayed": "true"})


def idempotency_store_response(
    *,
    endpoint: str,
    idempotency_key: Optional[str],
    principal: dict[str, Any],
    request_payload: Any,
    response_status: int,
    response_body: dict[str, Any],
) -> None:
    key = normalize_idempotency_key(idempotency_key)
    if not key:
        return

    scope = idempotency_scope_key(principal)
    payload_hash = hash_idempotency_payload(request_payload)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into idempotency_keys (
                  scope_key, endpoint, idempotency_key, request_hash, response_status, response_body
                )
                values (%s, %s, %s, %s, %s, %s::jsonb)
                on conflict (scope_key, endpoint, idempotency_key) do update
                  set updated_at = now()
                  where idempotency_keys.request_hash = excluded.request_hash
                returning id::text;
                """,
                (scope, endpoint, key, payload_hash, response_status, Json(response_body)),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(
                    status_code=409,
                    detail="Idempotency-Key conflict with different request payload",
                )
        conn.commit()


def enforce_mfa_policy_for_privileged_user(
    *,
    user_id: str,
    email: str,
    role: str,
    mfa_enabled: bool,
    source: str,
) -> None:
    policy_mode = get_mfa_policy_mode()
    if policy_mode == "off":
        return

    privileged_roles = get_mfa_privileged_roles()
    if role not in privileged_roles or mfa_enabled:
        return

    event_payload = {
        "email": email,
        "role": role,
        "mfa_enabled": mfa_enabled,
        "policy_mode": policy_mode,
        "source": source,
    }

    if policy_mode == "report":
        write_audit_log(
            "auth.mfa_policy.report",
            "user",
            actor_user_id=user_id,
            object_id=user_id,
            payload=event_payload,
        )
        return

    write_audit_log(
        "auth.mfa_policy.block",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload=event_payload,
    )
    raise HTTPException(
        status_code=403,
        detail="mfa required for privileged role by policy",
    )


def get_fernet() -> Fernet:
    key = os.environ.get("IDENTIFIER_ENCRYPTION_KEY", "").strip()
    if not key:
        raise HTTPException(status_code=500, detail="IDENTIFIER_ENCRYPTION_KEY is not configured")
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"invalid IDENTIFIER_ENCRYPTION_KEY: {exc}") from exc


def get_mfa_totp_fernet() -> Fernet:
    key = os.environ.get("MFA_TOTP_ENCRYPTION_KEY", "").strip()
    if not key:
        key = os.environ.get("IDENTIFIER_ENCRYPTION_KEY", "").strip()
    if not key:
        raise HTTPException(
            status_code=500,
            detail="MFA_TOTP_ENCRYPTION_KEY (or IDENTIFIER_ENCRYPTION_KEY fallback) is not configured",
        )
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"invalid MFA_TOTP_ENCRYPTION_KEY: {exc}") from exc


def encrypt_totp_secret(secret: str) -> bytes:
    return get_mfa_totp_fernet().encrypt(secret.encode("utf-8"))


def decrypt_totp_secret(secret_encrypted: bytes | memoryview | str) -> str:
    try:
        token: bytes | str
        if isinstance(secret_encrypted, memoryview):
            token = secret_encrypted.tobytes()
        else:
            token = secret_encrypted
        return get_mfa_totp_fernet().decrypt(token).decode("utf-8")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"cannot decrypt TOTP secret: {exc}") from exc


def normalize_totp_code(code: str) -> str:
    return "".join(ch for ch in code if ch.isdigit())


def verify_totp_code(secret: str, code: str) -> bool:
    normalized = normalize_totp_code(code)
    if len(normalized) != 6:
        return False
    valid_window = parse_int_env("MFA_TOTP_VALID_WINDOW", 1)
    if valid_window < 0:
        valid_window = 1
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(normalized, valid_window=valid_window))


def parse_csv_env(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default).strip()
    items = [item.strip() for item in raw.split(",") if item.strip()]
    return items


def get_webauthn_rp_id() -> str:
    rp_id = os.environ.get("MFA_WEBAUTHN_RP_ID", "").strip()
    if not rp_id:
        rp_id = "localhost"
    return rp_id


def get_webauthn_rp_name() -> str:
    return os.environ.get("MFA_WEBAUTHN_RP_NAME", "Privacy Scrubber").strip() or "Privacy Scrubber"


def get_webauthn_origins() -> list[str]:
    rp_id = get_webauthn_rp_id()
    default_origin = f"https://{rp_id}"
    return parse_csv_env("MFA_WEBAUTHN_ORIGINS", default_origin)


def get_webauthn_challenge_ttl_seconds() -> int:
    ttl = parse_int_env("MFA_WEBAUTHN_CHALLENGE_TTL_SECONDS", 300)
    return min(max(ttl, 60), 1800)


def store_webauthn_challenge(*, user_id: str, purpose: str, challenge_b64: str) -> str:
    expires_at = utc_now() + timedelta(seconds=get_webauthn_challenge_ttl_seconds())
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into mfa_webauthn_challenges (user_id, purpose, challenge, expires_at)
                values (%s::uuid, %s, %s, %s::timestamptz)
                returning id::text;
                """,
                (user_id, purpose, challenge_b64, expires_at.isoformat()),
            )
            row = cur.fetchone()
        conn.commit()
    return row[0]


def consume_webauthn_challenge(*, challenge_id: str, user_id: str, expected_purpose: str) -> str:
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select challenge, purpose
                from mfa_webauthn_challenges
                where id = %s::uuid
                  and user_id = %s::uuid
                  and consumed_at is null
                  and expires_at > now();
                """,
                (challenge_id, user_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="invalid or expired webauthn challenge")
            challenge_b64, purpose = row
            if purpose != expected_purpose:
                raise HTTPException(status_code=400, detail="webauthn challenge purpose mismatch")
            cur.execute(
                """
                update mfa_webauthn_challenges
                set consumed_at = now()
                where id = %s::uuid;
                """,
                (challenge_id,),
            )
        conn.commit()
    return challenge_b64


def normalize_identifier(value: str) -> str:
    return value.strip().lower()


def hash_identifier(value: str) -> bytes:
    return hashlib.sha256(normalize_identifier(value).encode("utf-8")).digest()


def encrypt_identifier(value: str) -> bytes:
    return get_fernet().encrypt(value.strip().encode("utf-8"))


def load_adapter_manifest(adapter_key: str) -> dict[str, Any]:
    adapters_root = Path(os.environ.get("ADAPTERS_PATH", "/app/adapters"))
    if not adapters_root.exists():
        raise HTTPException(status_code=500, detail=f"adapters path missing: {adapters_root}")

    for path in adapters_root.rglob("*.adapter.json"):
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if manifest.get("key") == adapter_key:
            return manifest

    raise HTTPException(status_code=404, detail=f"adapter not found: {adapter_key}")


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=10, max_length=256)
    role: str = Field(default="owner", max_length=32)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=256)
    mfa_code: Optional[str] = Field(default=None, min_length=6, max_length=16)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=20)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=10, max_length=256)


class RequestPasswordResetRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=20)
    new_password: str = Field(..., min_length=10, max_length=256)


class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=20)


class UpdateUserRoleRequest(BaseModel):
    role: str = Field(..., min_length=4, max_length=32)


class UpdateUserMfaRequest(BaseModel):
    mfa_enabled: bool


class TotpSetupVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=16)


class TotpDisableRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    code: Optional[str] = Field(default=None, min_length=6, max_length=16)


class WebAuthnSetupFinishRequest(BaseModel):
    challenge_id: str = Field(..., min_length=36, max_length=64)
    credential: dict[str, Any]
    nickname: Optional[str] = Field(default=None, max_length=120)


class WebAuthnAuthStartRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=256)


class WebAuthnAuthFinishRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    challenge_id: str = Field(..., min_length=36, max_length=64)
    credential: dict[str, Any]


class WebAuthnCredentialDeleteRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    role: str = Field(default="system", min_length=2, max_length=32)
    allowed_path_prefixes: list[str] = Field(default_factory=list)
    expires_at: Optional[str] = Field(default=None, max_length=64)


class ProfileCreate(BaseModel):
    owner_user_id: Optional[str] = Field(default=None, description="UUID of the owner user")
    display_name: str = Field(..., min_length=1, max_length=120)
    region_code: Optional[str] = Field(default=None, max_length=16)


class IdentifierCreate(BaseModel):
    profile_id: str
    id_type: str
    value: str = Field(..., min_length=1, max_length=2048)
    is_primary: bool = False


class FindingCreate(BaseModel):
    profile_id: str
    source_domain: str
    source_url: str
    risk_score: int = 0
    matched_identifiers: list[str] = Field(default_factory=list)
    exposed_fields: list[str] = Field(default_factory=list)
    notes: Optional[str] = None


class FindingUpdate(BaseModel):
    status: Optional[str] = Field(default=None, max_length=64)
    risk_score: Optional[int] = None
    notes: Optional[str] = None
    last_seen_at: Optional[str] = None


class TaskCreate(BaseModel):
    finding_id: str
    adapter_key: Optional[str] = None
    due_at: Optional[str] = None


class TaskUpdate(BaseModel):
    status: Optional[str] = Field(default=None, max_length=64)
    due_at: Optional[str] = None
    result_summary: Optional[str] = None
    assigned_user_id: Optional[str] = None


class AdapterRunQueueRequest(BaseModel):
    adapter_key: str
    action: str = Field(default="submit_opt_out")


class ReminderCreate(BaseModel):
    profile_id: str
    finding_id: Optional[str] = None
    reminder_type: str = Field(..., min_length=2, max_length=64)
    next_run_at: str
    interval_days: Optional[int] = None
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReminderUpdate(BaseModel):
    next_run_at: Optional[str] = None
    interval_days: Optional[int] = None
    enabled: Optional[bool] = None
    metadata: Optional[dict[str, Any]] = None


class ProviderCreate(BaseModel):
    key: str = Field(..., min_length=2, max_length=120)
    kind: str = Field(..., min_length=2, max_length=64)
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class ProviderUpdate(BaseModel):
    kind: Optional[str] = Field(default=None, min_length=2, max_length=64)
    config: Optional[dict[str, Any]] = None
    enabled: Optional[bool] = None


class AdapterCreate(BaseModel):
    key: str = Field(..., min_length=2, max_length=120)
    display_name: str = Field(..., min_length=2, max_length=200)
    domain: str = Field(..., min_length=2, max_length=255)
    flow: str = Field(default="manual", min_length=2, max_length=32)
    adapter_version: str = Field(default="0.0.1", min_length=1, max_length=64)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdapterUpdate(BaseModel):
    display_name: Optional[str] = Field(default=None, min_length=2, max_length=200)
    domain: Optional[str] = Field(default=None, min_length=2, max_length=255)
    flow: Optional[str] = Field(default=None, min_length=2, max_length=32)
    adapter_version: Optional[str] = Field(default=None, min_length=1, max_length=64)
    enabled: Optional[bool] = None
    metadata: Optional[dict[str, Any]] = None
    last_verified_at: Optional[str] = None


@app.get("/")
def root():
    return {
        "service": "privacy-scrubber-api",
        "version": app.version,
        "contract_version": API_CONTRACT_VERSION,
        "versioning_strategy": API_VERSIONING_STRATEGY,
    }


@app.get("/health")
def health():
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select 1")
                cur.fetchone()
        return {"status": "ok", "database": "ok"}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"database unavailable: {exc}") from exc


@app.get("/v1/version")
def api_version(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer", "system"})
    return {
        "contract_version": API_CONTRACT_VERSION,
        "implementation_version": app.version,
        "versioning_strategy": API_VERSIONING_STRATEGY,
    }


@app.post("/v1/auth/register")
def register(payload: RegisterRequest, request: Request, authorization: Optional[str] = Header(default=None)):
    enforce_rate_limit(
        "auth.register",
        f"{get_client_ip(request)}:{payload.email.strip().lower()}",
        max_attempts=parse_int_env("RATE_LIMIT_REGISTER_MAX_ATTEMPTS", 8),
        window_seconds=parse_int_env("RATE_LIMIT_REGISTER_WINDOW_SECONDS", 3600),
    )

    email = payload.email.strip().lower()
    role = payload.role.strip().lower()
    if role not in VALID_ROLES - {"system"}:
        raise HTTPException(status_code=400, detail="invalid role")

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select count(*) from users;")
            user_count = cur.fetchone()[0]

    allow_self_register = str_to_bool(os.environ.get("ALLOW_SELF_REGISTER"), default=False)
    if user_count > 0 and not allow_self_register:
        principal = resolve_principal(
            authorization,
            expected_token_type="access",
            request_path=request.url.path,
        )
        if not principal or principal.get("role") not in {"owner", "admin", "system"}:
            raise HTTPException(status_code=403, detail="registration disabled")

    password_hash = pwd_context.hash(payload.password)
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into users (email, password_hash, role, mfa_enabled)
                    values (%s, %s, %s, false)
                    returning id::text, email, role;
                    """,
                    (email, password_hash, role),
                )
                row = cur.fetchone()
            conn.commit()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    token_payload = build_auth_response(row[0], row[1], row[2], mfa_enabled=False)
    token_payload["registered"] = True
    principal = resolve_principal(
        authorization,
        expected_token_type="access",
        request_path=request.url.path,
    )
    write_audit_log(
        "auth.register",
        "user",
        actor_user_id=principal.get("user_id") if principal else None,
        object_id=row[0],
        payload={"email": row[1], "role": row[2]},
    )
    return token_payload


@app.post("/v1/auth/login")
def login(payload: LoginRequest, request: Request):
    enforce_rate_limit(
        "auth.login",
        f"{get_client_ip(request)}:{payload.email.strip().lower()}",
        max_attempts=parse_int_env("RATE_LIMIT_LOGIN_MAX_ATTEMPTS", 10),
        window_seconds=parse_int_env("RATE_LIMIT_LOGIN_WINDOW_SECONDS", 300),
    )

    email = payload.email.strip().lower()

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text, email, password_hash, role, mfa_enabled
                from users
                where lower(email) = %s;
                """,
                (email,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="invalid credentials")

    user_id, user_email, password_hash, role, mfa_enabled = row
    if not pwd_context.verify(payload.password, password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")

    if mfa_enabled:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select secret_encrypted
                    from mfa_totp_credentials
                    where user_id = %s::uuid
                      and enabled = true;
                    """,
                    (user_id,),
                )
                totp_row = cur.fetchone()
                cur.execute(
                    """
                    select count(*)
                    from mfa_webauthn_credentials
                    where user_id = %s::uuid
                      and enabled = true;
                    """,
                    (user_id,),
                )
                webauthn_count = cur.fetchone()[0]

        if payload.mfa_code:
            if not totp_row:
                raise HTTPException(status_code=401, detail="totp mfa is not configured")
            secret = decrypt_totp_secret(totp_row[0])
            if not verify_totp_code(secret, payload.mfa_code):
                raise HTTPException(status_code=401, detail="invalid mfa code")
        else:
            if webauthn_count > 0:
                raise HTTPException(
                    status_code=401,
                    detail="webauthn assertion required; use /v1/auth/mfa/webauthn/authenticate/start",
                )
            if totp_row:
                raise HTTPException(status_code=401, detail="mfa code required")
            raise HTTPException(status_code=403, detail="mfa is enabled but not configured")

    enforce_mfa_policy_for_privileged_user(
        user_id=user_id,
        email=user_email,
        role=role,
        mfa_enabled=bool(mfa_enabled),
        source="login",
    )

    auth = build_auth_response(user_id, user_email, role, mfa_enabled=bool(mfa_enabled))
    write_audit_log(
        "auth.login",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"email": user_email, "role": role, "mfa_enabled": bool(mfa_enabled)},
    )
    return auth


@app.post("/v1/auth/refresh")
def refresh_session(payload: RefreshRequest, request: Request):
    enforce_rate_limit(
        "auth.refresh",
        get_client_ip(request),
        max_attempts=parse_int_env("RATE_LIMIT_REFRESH_MAX_ATTEMPTS", 30),
        window_seconds=parse_int_env("RATE_LIMIT_REFRESH_WINDOW_SECONDS", 300),
    )

    principal = verify_jwt_token(payload.refresh_token, expected_token_type="refresh")
    if not principal:
        raise HTTPException(status_code=401, detail="invalid refresh token")

    user_id = principal["user_id"]
    jti = principal.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail="invalid refresh token")

    token_hash = hash_token(payload.refresh_token)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text
                from auth_refresh_tokens
                where user_id = %s::uuid
                  and token_jti = %s
                  and token_hash = %s
                  and revoked_at is null
                  and expires_at > now();
                """,
                (user_id, jti, token_hash),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="refresh token revoked or expired")

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select email, role, mfa_enabled
                from users
                where id = %s::uuid;
                """,
                (user_id,),
            )
            user_row = cur.fetchone()

    if not user_row:
        raise HTTPException(status_code=401, detail="user not found")

    user_email, user_role, mfa_enabled = user_row
    enforce_mfa_policy_for_privileged_user(
        user_id=user_id,
        email=user_email,
        role=user_role,
        mfa_enabled=bool(mfa_enabled),
        source="refresh",
    )

    auth = build_auth_response(user_id, user_email, user_role, mfa_enabled=bool(mfa_enabled))
    revoke_refresh_token(user_id, jti, replaced_by_jti=auth.get("refresh_jti"))
    write_audit_log(
        "auth.refresh",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"old_refresh_jti": jti, "new_refresh_jti": auth.get("refresh_jti")},
    )
    return auth


@app.post("/v1/auth/logout")
def logout(payload: LogoutRequest, request: Request):
    enforce_rate_limit(
        "auth.logout",
        get_client_ip(request),
        max_attempts=parse_int_env("RATE_LIMIT_LOGOUT_MAX_ATTEMPTS", 60),
        window_seconds=parse_int_env("RATE_LIMIT_LOGOUT_WINDOW_SECONDS", 300),
    )

    principal = verify_jwt_token(payload.refresh_token, expected_token_type="refresh")
    if not principal:
        raise HTTPException(status_code=401, detail="invalid refresh token")

    user_id = principal["user_id"]
    jti = principal.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail="invalid refresh token")

    token_hash = hash_token(payload.refresh_token)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update auth_refresh_tokens
                set revoked_at = now()
                where user_id = %s::uuid
                  and token_jti = %s
                  and token_hash = %s
                  and revoked_at is null;
                """,
                (user_id, jti, token_hash),
            )
            updated = cur.rowcount
        conn.commit()

    resp = {
        "status": "ok",
        "revoked": updated > 0,
    }
    write_audit_log(
        "auth.logout",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"refresh_jti": jti, "revoked": resp["revoked"]},
    )
    return resp


@app.post("/v1/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)
    enforce_rate_limit(
        "auth.change_password",
        f"{get_client_ip(request)}:{user_id}",
        max_attempts=parse_int_env("RATE_LIMIT_CHANGE_PASSWORD_MAX_ATTEMPTS", 10),
        window_seconds=parse_int_env("RATE_LIMIT_CHANGE_PASSWORD_WINDOW_SECONDS", 900),
    )

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select password_hash
                from users
                where id = %s::uuid;
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    current_hash = row[0]
    if not pwd_context.verify(payload.current_password, current_hash):
        raise HTTPException(status_code=401, detail="current password is invalid")

    new_hash = pwd_context.hash(payload.new_password)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update users
                set password_hash = %s
                where id = %s::uuid;
                """,
                (new_hash, user_id),
            )
        conn.commit()

    revoke_all_refresh_tokens(user_id)
    write_audit_log(
        "auth.change_password",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"sessions_revoked": True},
    )
    return {"status": "ok", "message": "password changed and sessions revoked"}


@app.post("/v1/auth/request-password-reset")
def request_password_reset(payload: RequestPasswordResetRequest, request: Request):
    enforce_rate_limit(
        "auth.request_password_reset",
        f"{get_client_ip(request)}:{payload.email.strip().lower()}",
        max_attempts=parse_int_env("RATE_LIMIT_PASSWORD_RESET_REQUEST_MAX_ATTEMPTS", 6),
        window_seconds=parse_int_env("RATE_LIMIT_PASSWORD_RESET_REQUEST_WINDOW_SECONDS", 900),
    )

    email = payload.email.strip().lower()
    token_ttl = int(os.environ.get("PASSWORD_RESET_TOKEN_TTL_MINUTES", "30"))

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text
                from users
                where lower(email) = %s;
                """,
                (email,),
            )
            row = cur.fetchone()

    response: dict[str, Any] = {
        "status": "ok",
        "message": "If the account exists, a reset token has been generated.",
    }

    if not row:
        return response

    user_id = row[0]
    raw_token = secrets.token_urlsafe(48)
    token_hash = hash_token(raw_token)
    expires_at = utc_now() + timedelta(minutes=token_ttl)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into password_reset_tokens (user_id, token_hash, expires_at)
                values (%s::uuid, %s, %s::timestamptz);
                """,
                (user_id, token_hash, expires_at.isoformat()),
            )
        conn.commit()

    if str_to_bool(os.environ.get("ENABLE_INSECURE_RESET_TOKEN_RESPONSE"), default=False):
        response["reset_token"] = raw_token
        response["expires_in_minutes"] = token_ttl

    write_audit_log(
        "auth.request_password_reset",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"ttl_minutes": token_ttl},
    )
    return response


@app.post("/v1/auth/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request):
    enforce_rate_limit(
        "auth.reset_password",
        get_client_ip(request),
        max_attempts=parse_int_env("RATE_LIMIT_PASSWORD_RESET_MAX_ATTEMPTS", 10),
        window_seconds=parse_int_env("RATE_LIMIT_PASSWORD_RESET_WINDOW_SECONDS", 900),
    )

    token_hash = hash_token(payload.token)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text, user_id::text
                from password_reset_tokens
                where token_hash = %s
                  and used_at is null
                  and expires_at > now()
                order by created_at desc
                limit 1;
                """,
                (token_hash,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=400, detail="invalid or expired reset token")

    token_id, user_id = row
    new_hash = pwd_context.hash(payload.new_password)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update users
                set password_hash = %s
                where id = %s::uuid;
                """,
                (new_hash, user_id),
            )
            cur.execute(
                """
                update password_reset_tokens
                set used_at = now()
                where id = %s::uuid;
                """,
                (token_id,),
            )
            cur.execute(
                """
                update password_reset_tokens
                set used_at = now()
                where user_id = %s::uuid
                  and used_at is null;
                """,
                (user_id,),
            )
        conn.commit()

    revoke_all_refresh_tokens(user_id)
    write_audit_log(
        "auth.reset_password",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"sessions_revoked": True},
    )
    return {"status": "ok", "message": "password reset complete and sessions revoked"}


@app.get("/v1/auth/me")
def auth_me(principal: dict[str, Any] = Depends(require_auth)):
    return principal


@app.get("/v1/auth/mfa/totp/status")
def get_totp_status(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select u.email, u.role, u.mfa_enabled,
                       coalesce(c.enabled, false), c.verified_at::text,
                       (
                         select count(*)
                         from mfa_webauthn_credentials w
                         where w.user_id = u.id and w.enabled = true
                       ) as webauthn_count
                from users u
                left join mfa_totp_credentials c on c.user_id = u.id
                where u.id = %s::uuid;
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")
    return {
        "email": row[0],
        "role": row[1],
        "mfa_enabled": bool(row[2]),
        "totp_configured": bool(row[3]),
        "verified_at": row[4],
        "webauthn_configured": int(row[5]) > 0,
        "webauthn_credential_count": int(row[5]),
    }


@app.post("/v1/auth/mfa/totp/setup")
def start_totp_setup(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select email, role
                from users
                where id = %s::uuid;
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    email, role = row
    issuer = os.environ.get("MFA_TOTP_ISSUER", "Privacy Scrubber").strip() or "Privacy Scrubber"
    secret = pyotp.random_base32()
    secret_encrypted = encrypt_totp_secret(secret)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into mfa_totp_credentials (user_id, secret_encrypted, issuer, enabled, verified_at)
                values (%s::uuid, %s, %s, false, null)
                on conflict (user_id) do update
                  set secret_encrypted = excluded.secret_encrypted,
                      issuer = excluded.issuer,
                      enabled = false,
                      verified_at = null,
                      updated_at = now();
                """,
                (user_id, secret_encrypted, issuer),
            )
        conn.commit()

    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
    write_audit_log(
        "auth.mfa.totp.setup_started",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"email": email, "role": role, "issuer": issuer},
    )
    return {
        "status": "ok",
        "issuer": issuer,
        "account_name": email,
        "secret": secret,
        "otpauth_uri": uri,
    }


@app.post("/v1/auth/mfa/totp/verify-setup")
def verify_totp_setup(payload: TotpSetupVerifyRequest, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select u.email, u.role, c.secret_encrypted
                from users u
                join mfa_totp_credentials c on c.user_id = u.id
                where u.id = %s::uuid;
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=400, detail="totp setup not started")

    email, role, secret_encrypted = row
    secret = decrypt_totp_secret(secret_encrypted)
    if not verify_totp_code(secret, payload.code):
        raise HTTPException(status_code=401, detail="invalid mfa code")

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update mfa_totp_credentials
                set enabled = true,
                    verified_at = now()
                where user_id = %s::uuid;
                """,
                (user_id,),
            )
            cur.execute(
                """
                update users
                set mfa_enabled = true
                where id = %s::uuid;
                """,
                (user_id,),
            )
        conn.commit()

    revoke_all_refresh_tokens(user_id)
    write_audit_log(
        "auth.mfa.totp.verified",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"email": email, "role": role, "sessions_revoked": True},
    )
    return {"status": "ok", "mfa_enabled": True}


@app.post("/v1/auth/mfa/totp/disable")
def disable_totp(payload: TotpDisableRequest, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select u.email, u.role, u.password_hash,
                       c.secret_encrypted, c.enabled
                from users u
                left join mfa_totp_credentials c on c.user_id = u.id
                where u.id = %s::uuid;
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="user not found")

    email, role, password_hash, secret_encrypted, cred_enabled = row
    if not pwd_context.verify(payload.current_password, password_hash):
        raise HTTPException(status_code=401, detail="current password is invalid")

    require_code = str_to_bool(os.environ.get("MFA_TOTP_DISABLE_REQUIRES_CODE"), default=True)
    if require_code and cred_enabled:
        if not payload.code:
            raise HTTPException(status_code=401, detail="mfa code required to disable")
        secret = decrypt_totp_secret(secret_encrypted)
        if not verify_totp_code(secret, payload.code):
            raise HTTPException(status_code=401, detail="invalid mfa code")

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("delete from mfa_totp_credentials where user_id = %s::uuid;", (user_id,))
            cur.execute(
                """
                select count(*)
                from mfa_webauthn_credentials
                where user_id = %s::uuid
                  and enabled = true;
                """,
                (user_id,),
            )
            webauthn_count = int(cur.fetchone()[0])
            if webauthn_count == 0:
                cur.execute("update users set mfa_enabled = false where id = %s::uuid;", (user_id,))
        conn.commit()

    revoke_all_refresh_tokens(user_id)
    write_audit_log(
        "auth.mfa.totp.disabled",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"email": email, "role": role, "sessions_revoked": True, "webauthn_remaining": webauthn_count},
    )
    return {"status": "ok", "mfa_enabled": webauthn_count > 0}


@app.get("/v1/auth/mfa/webauthn/credentials")
def list_webauthn_credentials(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select credential_id,
                       coalesce(nickname, ''),
                       sign_count,
                       coalesce(device_type, ''),
                       backup_eligible,
                       backup_state,
                       coalesce(last_used_at::text, ''),
                       verified_at::text,
                       created_at::text
                from mfa_webauthn_credentials
                where user_id = %s::uuid
                  and enabled = true
                order by created_at asc;
                """,
                (user_id,),
            )
            rows = cur.fetchall()
    return {
        "items": [
            {
                "credential_id": r[0],
                "nickname": r[1] or None,
                "sign_count": int(r[2]),
                "device_type": r[3] or None,
                "backup_eligible": bool(r[4]),
                "backup_state": bool(r[5]),
                "last_used_at": r[6] or None,
                "verified_at": r[7],
                "created_at": r[8],
            }
            for r in rows
        ]
    }


@app.post("/v1/auth/mfa/webauthn/setup")
def start_webauthn_setup(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select email
                from users
                where id = %s::uuid;
                """,
                (user_id,),
            )
            user_row = cur.fetchone()
            if not user_row:
                raise HTTPException(status_code=404, detail="user not found")
            email = user_row[0]
            cur.execute(
                """
                select credential_id
                from mfa_webauthn_credentials
                where user_id = %s::uuid
                  and enabled = true;
                """,
                (user_id,),
            )
            existing_ids = [r[0] for r in cur.fetchall()]

    challenge_bytes = secrets.token_bytes(32)
    challenge_b64 = bytes_to_base64url(challenge_bytes)
    challenge_id = store_webauthn_challenge(
        user_id=user_id,
        purpose="register",
        challenge_b64=challenge_b64,
    )
    options = generate_registration_options(
        rp_id=get_webauthn_rp_id(),
        rp_name=get_webauthn_rp_name(),
        user_name=email,
        user_display_name=email,
        user_id=user_id.encode("utf-8"),
        challenge=challenge_bytes,
        timeout=parse_int_env("MFA_WEBAUTHN_TIMEOUT_MS", 60000),
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
            for cred_id in existing_ids
        ],
    )
    write_audit_log(
        "auth.mfa.webauthn.setup_started",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"challenge_id": challenge_id, "exclude_count": len(existing_ids)},
    )
    return {
        "status": "ok",
        "challenge_id": challenge_id,
        "public_key": json.loads(options_to_json(options)),
        "rp_id": get_webauthn_rp_id(),
        "origins": get_webauthn_origins(),
    }


@app.post("/v1/auth/mfa/webauthn/verify-setup")
def finish_webauthn_setup(
    payload: WebAuthnSetupFinishRequest,
    request: Request,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)
    enforce_rate_limit(
        "auth.webauthn.verify_setup",
        f"{get_client_ip(request)}:{user_id}",
        max_attempts=parse_int_env("RATE_LIMIT_WEBAUTHN_VERIFY_SETUP_MAX_ATTEMPTS", 10),
        window_seconds=parse_int_env("RATE_LIMIT_WEBAUTHN_VERIFY_SETUP_WINDOW_SECONDS", 300),
    )
    challenge_b64 = consume_webauthn_challenge(
        challenge_id=payload.challenge_id,
        user_id=user_id,
        expected_purpose="register",
    )
    try:
        verified = verify_registration_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=get_webauthn_rp_id(),
            expected_origin=get_webauthn_origins(),
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"webauthn registration verify failed: {exc}") from exc

    credential_id = bytes_to_base64url(verified.credential_id)
    credential_public_key = bytes_to_base64url(verified.credential_public_key)
    nickname = payload.nickname.strip() if payload.nickname else None
    if nickname == "":
        nickname = None

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into mfa_webauthn_credentials (
                  user_id, credential_id, public_key, sign_count, aaguid,
                  backup_eligible, backup_state, device_type, nickname, enabled, verified_at
                )
                values (
                  %s::uuid, %s, %s, %s, %s,
                  %s, %s, %s, %s, true, now()
                )
                on conflict (credential_id) do update
                  set user_id = excluded.user_id,
                      public_key = excluded.public_key,
                      sign_count = excluded.sign_count,
                      aaguid = excluded.aaguid,
                      backup_eligible = excluded.backup_eligible,
                      backup_state = excluded.backup_state,
                      device_type = excluded.device_type,
                      nickname = coalesce(excluded.nickname, mfa_webauthn_credentials.nickname),
                      enabled = true,
                      verified_at = now(),
                      updated_at = now();
                """,
                (
                    user_id,
                    credential_id,
                    credential_public_key,
                    int(verified.sign_count),
                    verified.aaguid,
                    bool(verified.credential_backed_up),
                    bool(verified.credential_backed_up),
                    str(verified.credential_device_type.value),
                    nickname,
                ),
            )
            cur.execute(
                """
                update users
                set mfa_enabled = true
                where id = %s::uuid;
                """,
                (user_id,),
            )
        conn.commit()

    revoke_all_refresh_tokens(user_id)
    write_audit_log(
        "auth.mfa.webauthn.verified",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"credential_id": credential_id, "sessions_revoked": True},
    )
    return {
        "status": "ok",
        "mfa_enabled": True,
        "credential_id": credential_id,
    }


@app.delete("/v1/auth/mfa/webauthn/credentials/{credential_id}")
def delete_webauthn_credential(
    credential_id: str,
    payload: WebAuthnCredentialDeleteRequest,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer"})
    user_id = require_user_principal(principal)
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select password_hash
                from users
                where id = %s::uuid;
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="user not found")
            if not pwd_context.verify(payload.current_password, row[0]):
                raise HTTPException(status_code=401, detail="current password is invalid")
            cur.execute(
                """
                delete from mfa_webauthn_credentials
                where user_id = %s::uuid
                  and credential_id = %s;
                """,
                (user_id, credential_id),
            )
            deleted = cur.rowcount
            cur.execute(
                """
                select exists(
                    select 1 from mfa_totp_credentials where user_id = %s::uuid and enabled = true
                ),
                exists(
                    select 1 from mfa_webauthn_credentials where user_id = %s::uuid and enabled = true
                );
                """,
                (user_id, user_id),
            )
            has_totp, has_webauthn = cur.fetchone()
            if not has_totp and not has_webauthn:
                cur.execute(
                    """
                    update users set mfa_enabled = false where id = %s::uuid;
                    """,
                    (user_id,),
                )
        conn.commit()
    if deleted == 0:
        raise HTTPException(status_code=404, detail="webauthn credential not found")
    revoke_all_refresh_tokens(user_id)
    write_audit_log(
        "auth.mfa.webauthn.deleted",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"credential_id": credential_id, "sessions_revoked": True},
    )
    return {"status": "ok", "credential_id": credential_id}


@app.post("/v1/auth/mfa/webauthn/authenticate/start")
def start_webauthn_authenticate(payload: WebAuthnAuthStartRequest, request: Request):
    enforce_rate_limit(
        "auth.login",
        f"{get_client_ip(request)}:{payload.email.strip().lower()}",
        max_attempts=parse_int_env("RATE_LIMIT_LOGIN_MAX_ATTEMPTS", 10),
        window_seconds=parse_int_env("RATE_LIMIT_LOGIN_WINDOW_SECONDS", 300),
    )
    email = payload.email.strip().lower()
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text, email, password_hash, role, mfa_enabled
                from users
                where lower(email) = %s;
                """,
                (email,),
            )
            user_row = cur.fetchone()
            if not user_row:
                raise HTTPException(status_code=401, detail="invalid credentials")
            user_id, user_email, password_hash, role, mfa_enabled = user_row
            if not pwd_context.verify(payload.password, password_hash):
                raise HTTPException(status_code=401, detail="invalid credentials")
            if not mfa_enabled:
                raise HTTPException(status_code=400, detail="mfa is not enabled for this account")
            cur.execute(
                """
                select credential_id
                from mfa_webauthn_credentials
                where user_id = %s::uuid
                  and enabled = true;
                """,
                (user_id,),
            )
            ids = [r[0] for r in cur.fetchall()]
    if not ids:
        raise HTTPException(status_code=400, detail="no webauthn credentials configured")

    challenge_bytes = secrets.token_bytes(32)
    challenge_b64 = bytes_to_base64url(challenge_bytes)
    challenge_id = store_webauthn_challenge(
        user_id=user_id,
        purpose="authenticate",
        challenge_b64=challenge_b64,
    )
    options = generate_authentication_options(
        rp_id=get_webauthn_rp_id(),
        challenge=challenge_bytes,
        timeout=parse_int_env("MFA_WEBAUTHN_TIMEOUT_MS", 60000),
        user_verification=UserVerificationRequirement.PREFERRED,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
            for cred_id in ids
        ],
    )
    write_audit_log(
        "auth.mfa.webauthn.auth_start",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"challenge_id": challenge_id, "allow_credentials": len(ids)},
    )
    return {
        "status": "ok",
        "challenge_id": challenge_id,
        "public_key": json.loads(options_to_json(options)),
        "rp_id": get_webauthn_rp_id(),
        "origins": get_webauthn_origins(),
        "email": user_email,
        "role": role,
    }


@app.post("/v1/auth/mfa/webauthn/authenticate/finish")
def finish_webauthn_authenticate(payload: WebAuthnAuthFinishRequest, request: Request):
    enforce_rate_limit(
        "auth.webauthn.finish",
        f"{get_client_ip(request)}:{payload.email.strip().lower()}",
        max_attempts=parse_int_env("RATE_LIMIT_WEBAUTHN_FINISH_MAX_ATTEMPTS", 10),
        window_seconds=parse_int_env("RATE_LIMIT_WEBAUTHN_FINISH_WINDOW_SECONDS", 300),
    )
    email = payload.email.strip().lower()
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text, email, role, mfa_enabled
                from users
                where lower(email) = %s;
                """,
                (email,),
            )
            user_row = cur.fetchone()
            if not user_row:
                raise HTTPException(status_code=401, detail="invalid credentials")
            user_id, user_email, role, mfa_enabled = user_row
            if not mfa_enabled:
                raise HTTPException(status_code=400, detail="mfa is not enabled for this account")

    challenge_b64 = consume_webauthn_challenge(
        challenge_id=payload.challenge_id,
        user_id=user_id,
        expected_purpose="authenticate",
    )
    raw_id = payload.credential.get("id") if isinstance(payload.credential, dict) else None
    if not raw_id:
        raise HTTPException(status_code=400, detail="credential id is required")
    credential_id = str(raw_id).strip()

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select public_key, sign_count
                from mfa_webauthn_credentials
                where user_id = %s::uuid
                  and credential_id = %s
                  and enabled = true;
                """,
                (user_id, credential_id),
            )
            cred_row = cur.fetchone()
    if not cred_row:
        raise HTTPException(status_code=401, detail="webauthn credential not registered")

    credential_public_key, sign_count = cred_row
    try:
        verified = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=get_webauthn_rp_id(),
            expected_origin=get_webauthn_origins(),
            credential_public_key=base64url_to_bytes(credential_public_key),
            credential_current_sign_count=int(sign_count),
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"webauthn authentication verify failed: {exc}") from exc

    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update mfa_webauthn_credentials
                set sign_count = %s,
                    backup_state = %s,
                    device_type = %s,
                    last_used_at = now(),
                    updated_at = now()
                where user_id = %s::uuid
                  and credential_id = %s;
                """,
                (
                    int(verified.new_sign_count),
                    bool(verified.credential_backed_up),
                    str(verified.credential_device_type.value),
                    user_id,
                    credential_id,
                ),
            )
        conn.commit()

    enforce_mfa_policy_for_privileged_user(
        user_id=user_id,
        email=user_email,
        role=role,
        mfa_enabled=bool(mfa_enabled),
        source="webauthn_login",
    )
    auth = build_auth_response(user_id, user_email, role, mfa_enabled=bool(mfa_enabled))
    write_audit_log(
        "auth.mfa.webauthn.auth_finish",
        "user",
        actor_user_id=user_id,
        object_id=user_id,
        payload={"credential_id": credential_id, "new_sign_count": int(verified.new_sign_count)},
    )
    return auth


@app.get("/v1/users")
def list_users(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "system"})
    query = """
        select id::text, email, role, mfa_enabled, created_at::text, updated_at::text
        from users
        order by created_at asc;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        return {
            "items": [
                {
                    "id": r[0],
                    "email": r[1],
                    "role": r[2],
                    "mfa_enabled": r[3],
                    "created_at": r[4],
                    "updated_at": r[5],
                }
                for r in rows
            ]
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.patch("/v1/users/{user_id}/mfa")
def update_user_mfa_status(
    user_id: str,
    payload: UpdateUserMfaRequest,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "system"})
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                if payload.mfa_enabled:
                    cur.execute(
                        """
                        select enabled
                        from mfa_totp_credentials
                        where user_id = %s::uuid;
                        """,
                        (user_id,),
                    )
                    totp_cred = cur.fetchone()
                    cur.execute(
                        """
                        select count(*)
                        from mfa_webauthn_credentials
                        where user_id = %s::uuid
                          and enabled = true;
                        """,
                        (user_id,),
                    )
                    webauthn_count = int(cur.fetchone()[0])
                    has_totp = bool(totp_cred and bool(totp_cred[0]))
                    has_webauthn = webauthn_count > 0
                    if not has_totp and not has_webauthn:
                        raise HTTPException(
                            status_code=400,
                            detail="cannot enable mfa: verified TOTP or WebAuthn credential is missing",
                        )
                else:
                    cur.execute("delete from mfa_totp_credentials where user_id = %s::uuid;", (user_id,))

                cur.execute(
                    """
                    update users
                    set mfa_enabled = %s
                    where id = %s::uuid
                    returning id::text, email, role, mfa_enabled, updated_at::text;
                    """,
                    (payload.mfa_enabled, user_id),
                )
                out = cur.fetchone()
                if not out:
                    raise HTTPException(status_code=404, detail="user not found")
            conn.commit()
        revoke_all_refresh_tokens(user_id)
        write_audit_log(
            "users.update_mfa",
            "user",
            actor_user_id=principal.get("user_id"),
            object_id=user_id,
            payload={"email": out[1], "role": out[2], "mfa_enabled": out[3], "sessions_revoked": True},
        )
        return {
            "id": out[0],
            "email": out[1],
            "role": out[2],
            "mfa_enabled": out[3],
            "updated_at": out[4],
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/v1/users/{user_id}/role")
def update_user_role(
    user_id: str,
    payload: UpdateUserRoleRequest,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "system"})
    new_role = payload.role.strip().lower()
    if new_role not in VALID_ROLES - {"system"}:
        raise HTTPException(status_code=400, detail="invalid role")

    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select role, email, mfa_enabled
                    from users
                    where id = %s::uuid;
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="user not found")
                current_role, target_email, target_mfa_enabled = row

                if current_role == "owner" and new_role != "owner":
                    cur.execute("select count(*) from users where role = 'owner';")
                    owner_count = cur.fetchone()[0]
                    if owner_count <= 1:
                        raise HTTPException(status_code=400, detail="cannot remove last owner")

                enforce_mfa_policy_for_privileged_user(
                    user_id=user_id,
                    email=target_email,
                    role=new_role,
                    mfa_enabled=bool(target_mfa_enabled),
                    source="role_change",
                )

                cur.execute(
                    """
                    update users
                    set role = %s
                    where id = %s::uuid
                    returning id::text, email, role, mfa_enabled, updated_at::text;
                    """,
                    (new_role, user_id),
                )
                out = cur.fetchone()
            conn.commit()
        write_audit_log(
            "users.update_role",
            "user",
            actor_user_id=principal.get("user_id"),
            object_id=user_id,
            payload={"old_role": current_role, "new_role": out[2], "email": out[1]},
        )
        return {
            "id": out[0],
            "email": out[1],
            "role": out[2],
            "mfa_enabled": out[3],
            "updated_at": out[4],
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/v1/users/{user_id}")
def delete_user(user_id: str, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "system"})

    principal_user_id = principal.get("user_id")
    if principal_user_id and principal_user_id == user_id:
        raise HTTPException(status_code=400, detail="refusing to delete currently authenticated user")

    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select role, email
                    from users
                    where id = %s::uuid;
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="user not found")
                role, email = row

                if role == "owner":
                    cur.execute("select count(*) from users where role = 'owner';")
                    owner_count = cur.fetchone()[0]
                    if owner_count <= 1:
                        raise HTTPException(status_code=400, detail="cannot delete last owner")

                cur.execute(
                    """
                    delete from users
                    where id = %s::uuid;
                    """,
                    (user_id,),
                )
            conn.commit()

        write_audit_log(
            "users.delete",
            "user",
            actor_user_id=principal.get("user_id"),
            object_id=user_id,
            payload={"email": email, "role": role},
        )
        return {"status": "ok", "deleted_user_id": user_id, "deleted_email": email}
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/api-keys")
def create_api_key(payload: ApiKeyCreateRequest, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "system"})

    role = payload.role.strip().lower()
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="invalid role")

    if len(payload.allowed_path_prefixes) > 100:
        raise HTTPException(status_code=400, detail="too many allowed_path_prefixes (max 100)")
    allowed_path_prefixes = normalize_path_prefixes(payload.allowed_path_prefixes)

    expires_at = (payload.expires_at or "").strip()
    if expires_at:
        try:
            datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"invalid expires_at: {exc}") from exc

    actor_user_id = principal.get("user_id")
    key_plaintext: Optional[str] = None
    out = None

    for _ in range(3):
        key_plaintext = f"psk_{secrets.token_urlsafe(36)}"
        key_hash = hash_token(key_plaintext)
        try:
            with get_db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        insert into api_keys (name, key_hash, role, allowed_path_prefixes, expires_at, created_by_user_id)
                        values (%s, %s, %s, %s::jsonb, nullif(%s, '')::timestamptz, nullif(%s, '')::uuid)
                        returning id::text,
                                  name,
                                  role,
                                  allowed_path_prefixes,
                                  enabled,
                                  expires_at::text,
                                  last_used_at::text,
                                  created_by_user_id::text,
                                  created_at::text,
                                  updated_at::text;
                        """,
                        (
                            payload.name.strip(),
                            key_hash,
                            role,
                            Json(allowed_path_prefixes),
                            expires_at,
                            actor_user_id or "",
                        ),
                    )
                    out = cur.fetchone()
                conn.commit()
            break
        except Exception as exc:  # noqa: BLE001
            if "duplicate key value violates unique constraint" in str(exc).lower():
                continue
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not out or not key_plaintext:
        raise HTTPException(status_code=500, detail="failed to create api key")

    write_audit_log(
        "api_keys.create",
        "api_key",
        actor_user_id=actor_user_id,
        object_id=out[0],
        payload={
            "name": out[1],
            "role": out[2],
            "allowed_path_prefixes": out[3] if isinstance(out[3], list) else [],
            "expires_at": out[5],
            "enabled": bool(out[4]),
        },
    )

    return {
        "api_key": key_plaintext,
        "item": {
            "id": out[0],
            "name": out[1],
            "role": out[2],
            "allowed_path_prefixes": out[3] if isinstance(out[3], list) else [],
            "enabled": bool(out[4]),
            "expires_at": out[5],
            "last_used_at": out[6],
            "created_by_user_id": out[7],
            "created_at": out[8],
            "updated_at": out[9],
        },
    }


@app.get("/v1/api-keys")
def list_api_keys(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "system"})
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id::text,
                       name,
                       role,
                       allowed_path_prefixes,
                       enabled,
                       expires_at::text,
                       last_used_at::text,
                       created_by_user_id::text,
                       created_at::text,
                       updated_at::text
                from api_keys
                order by created_at desc;
                """
            )
            rows = cur.fetchall()

    return {
        "items": [
            {
                "id": row[0],
                "name": row[1],
                "role": row[2],
                "allowed_path_prefixes": row[3] if isinstance(row[3], list) else [],
                "enabled": bool(row[4]),
                "expires_at": row[5],
                "last_used_at": row[6],
                "created_by_user_id": row[7],
                "created_at": row[8],
                "updated_at": row[9],
            }
            for row in rows
        ]
    }


@app.post("/v1/api-keys/{api_key_id}/revoke")
def revoke_api_key(api_key_id: str, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "system"})
    with get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update api_keys
                set enabled = false,
                    updated_at = now()
                where id = %s::uuid
                returning id::text, name, role, enabled, updated_at::text;
                """,
                (api_key_id,),
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="api key not found")

    write_audit_log(
        "api_keys.revoke",
        "api_key",
        actor_user_id=principal.get("user_id"),
        object_id=row[0],
        payload={"name": row[1], "role": row[2], "enabled": bool(row[3])},
    )
    return {"status": "ok", "id": row[0], "name": row[1], "enabled": bool(row[3]), "updated_at": row[4]}


@app.post("/v1/api-keys/{api_key_id}/rotate")
def rotate_api_key(api_key_id: str, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "system"})

    actor_user_id = principal.get("user_id")
    out = None
    new_key_plaintext: Optional[str] = None

    for _ in range(3):
        new_key_plaintext = f"psk_{secrets.token_urlsafe(36)}"
        new_key_hash = hash_token(new_key_plaintext)
        try:
            with get_db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update api_keys
                        set key_hash = %s,
                            enabled = true,
                            last_used_at = null,
                            updated_at = now()
                        where id = %s::uuid
                        returning id::text,
                                  name,
                                  role,
                                  allowed_path_prefixes,
                                  enabled,
                                  expires_at::text,
                                  last_used_at::text,
                                  created_by_user_id::text,
                                  created_at::text,
                                  updated_at::text;
                        """,
                        (new_key_hash, api_key_id),
                    )
                    out = cur.fetchone()
                conn.commit()
            break
        except Exception as exc:  # noqa: BLE001
            if "duplicate key value violates unique constraint" in str(exc).lower():
                continue
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not out:
        raise HTTPException(status_code=404, detail="api key not found")
    if not new_key_plaintext:
        raise HTTPException(status_code=500, detail="failed to rotate api key")

    write_audit_log(
        "api_keys.rotate",
        "api_key",
        actor_user_id=actor_user_id,
        object_id=out[0],
        payload={
            "name": out[1],
            "role": out[2],
            "allowed_path_prefixes": out[3] if isinstance(out[3], list) else [],
            "expires_at": out[5],
            "enabled": bool(out[4]),
        },
    )

    return {
        "api_key": new_key_plaintext,
        "item": {
            "id": out[0],
            "name": out[1],
            "role": out[2],
            "allowed_path_prefixes": out[3] if isinstance(out[3], list) else [],
            "enabled": bool(out[4]),
            "expires_at": out[5],
            "last_used_at": out[6],
            "created_by_user_id": out[7],
            "created_at": out[8],
            "updated_at": out[9],
        },
    }


@app.get("/v1/stats")
def stats(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "system"})
    query = """
        select
          (select count(*) from profiles) as profiles,
          (select count(*) from findings) as findings,
          (select count(*) from tasks) as tasks,
          (select count(*) from reminders where enabled = true) as reminders_enabled,
          (select count(*) from job_queue where status = 'queued') as jobs_queued,
          (select count(*) from adapter_runs where status in ('queued', 'running')) as adapter_runs_active;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()
        return {
            "profiles": row[0],
            "findings": row[1],
            "tasks": row[2],
            "reminders_enabled": row[3],
            "jobs_queued": row[4],
            "adapter_runs_active": row[5],
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/v1/profiles")
def list_profiles(principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer", "system"})
    query = """
        select id::text, owner_user_id::text, display_name, coalesce(region_code, ''), status::text,
               created_at::text, updated_at::text
        from profiles
        order by created_at desc;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        return {
            "items": [
                {
                    "id": r[0],
                    "owner_user_id": r[1],
                    "display_name": r[2],
                    "region_code": r[3] or None,
                    "status": r[4],
                    "created_at": r[5],
                    "updated_at": r[6],
                }
                for r in rows
            ]
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/profiles")
def create_profile(payload: ProfileCreate, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "operator", "system"})

    owner_user_id = payload.owner_user_id
    if not owner_user_id:
        if principal.get("user_id"):
            owner_user_id = principal["user_id"]
        else:
            raise HTTPException(status_code=400, detail="owner_user_id is required for token/system auth")

    query = """
        insert into profiles (owner_user_id, display_name, region_code)
        values (%s::uuid, %s, nullif(%s, ''))
        returning id::text, owner_user_id::text, display_name, coalesce(region_code, ''), status::text,
                  created_at::text, updated_at::text;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (owner_user_id, payload.display_name, payload.region_code or ""))
                row = cur.fetchone()
            conn.commit()
        response = {
            "id": row[0],
            "owner_user_id": row[1],
            "display_name": row[2],
            "region_code": row[3] or None,
            "status": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }
        write_audit_log(
            "profiles.create",
            "profile",
            actor_user_id=principal.get("user_id"),
            object_id=response["id"],
            payload={"owner_user_id": response["owner_user_id"], "display_name": response["display_name"]},
        )
        return response
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/identifiers")
def create_identifier(payload: IdentifierCreate, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "operator", "system"})

    id_type = payload.id_type.strip()
    if id_type not in IDENTIFIER_TYPES:
        raise HTTPException(status_code=400, detail="invalid identifier type")

    value = payload.value.strip()
    encrypted = encrypt_identifier(value)
    value_hash = hash_identifier(value)

    query = """
        insert into identifiers (profile_id, id_type, value_encrypted, value_hash, is_primary)
        values (%s::uuid, %s::identifier_type, %s::bytea, %s::bytea, %s)
        returning id::text, profile_id::text, id_type::text, is_primary, created_at::text;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (payload.profile_id, id_type, encrypted, value_hash, payload.is_primary),
                )
                row = cur.fetchone()
            conn.commit()

        response = {
            "id": row[0],
            "profile_id": row[1],
            "id_type": row[2],
            "is_primary": row[3],
            "created_at": row[4],
            "hash_prefix": value_hash.hex()[:12],
        }
        write_audit_log(
            "identifiers.create",
            "identifier",
            actor_user_id=principal.get("user_id"),
            object_id=response["id"],
            payload={"profile_id": response["profile_id"], "id_type": response["id_type"], "is_primary": response["is_primary"]},
        )
        return response
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/profiles/{profile_id}/identifiers")
def list_identifiers(profile_id: str, principal: dict[str, Any] = Depends(require_auth)):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "system"})
    query = """
        select id::text, id_type::text, is_primary, encode(value_hash, 'hex'), created_at::text
        from identifiers
        where profile_id = %s::uuid
        order by is_primary desc, created_at asc;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (profile_id,))
                rows = cur.fetchall()
        return {
            "items": [
                {
                    "id": r[0],
                    "id_type": r[1],
                    "is_primary": r[2],
                    "hash_prefix": (r[3] or "")[:12],
                    "created_at": r[4],
                }
                for r in rows
            ]
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/v1/providers")
def list_providers(
    limit: int = 100,
    cursor: Optional[str] = None,
    kind: Optional[str] = None,
    enabled: Optional[bool] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer", "system"})
    safe_limit = min(max(limit, 1), 500)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    enabled_filter = ""
    if enabled is not None:
        enabled_filter = "true" if enabled else "false"

    query = """
        select
          id::text,
          key,
          kind,
          config::text,
          enabled,
          created_at::text
        from providers
        where (%s = '' or lower(kind) = lower(%s))
          and (%s = '' or enabled = %s::boolean)
          and (nullif(%s, '') is null or (created_at, id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by created_at desc, id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        kind or "",
                        kind or "",
                        enabled_filter,
                        enabled_filter or "false",
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()

        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][5], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "key": r[1],
                    "kind": r[2],
                    "config": json.loads(r[3]),
                    "enabled": bool(r[4]),
                    "created_at": r[5],
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/providers")
def create_provider(
    payload: ProviderCreate,
    principal: dict[str, Any] = Depends(require_auth),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    replay = idempotency_replay_if_exists(
        endpoint="providers.create",
        idempotency_key=idempotency_key,
        principal=principal,
        request_payload=payload.model_dump(),
    )
    if replay is not None:
        return replay

    query = """
        insert into providers (key, kind, config, enabled)
        values (%s, %s, %s::jsonb, %s)
        returning id::text, key, kind, config::text, enabled, created_at::text;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        payload.key.strip(),
                        payload.kind.strip(),
                        Json(payload.config),
                        payload.enabled,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        response = {
            "id": row[0],
            "key": row[1],
            "kind": row[2],
            "config": json.loads(row[3]),
            "enabled": bool(row[4]),
            "created_at": row[5],
        }
        write_audit_log(
            "providers.create",
            "provider",
            actor_user_id=principal.get("user_id"),
            object_id=response["id"],
            payload={"key": response["key"], "kind": response["kind"], "enabled": response["enabled"]},
        )
        idempotency_store_response(
            endpoint="providers.create",
            idempotency_key=idempotency_key,
            principal=principal,
            request_payload=payload.model_dump(),
            response_status=200,
            response_body=response,
        )
        return response
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/v1/providers/{provider_id}")
def update_provider(
    provider_id: str,
    payload: ProviderUpdate,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select key, kind, enabled
                    from providers
                    where id = %s::uuid;
                    """,
                    (provider_id,),
                )
                old = cur.fetchone()
                if not old:
                    raise HTTPException(status_code=404, detail="provider not found")

                cur.execute(
                    """
                    update providers
                    set kind = coalesce(%s, kind),
                        config = case when %s::jsonb is null then config else %s::jsonb end,
                        enabled = coalesce(%s, enabled)
                    where id = %s::uuid
                    returning id::text, key, kind, config::text, enabled, created_at::text;
                    """,
                    (
                        payload.kind.strip() if payload.kind else None,
                        Json(payload.config) if payload.config is not None else None,
                        Json(payload.config) if payload.config is not None else None,
                        payload.enabled,
                        provider_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        response = {
            "id": row[0],
            "key": row[1],
            "kind": row[2],
            "config": json.loads(row[3]),
            "enabled": bool(row[4]),
            "created_at": row[5],
        }
        write_audit_log(
            "providers.update",
            "provider",
            actor_user_id=principal.get("user_id"),
            object_id=provider_id,
            payload={"key": old[0], "old_kind": old[1], "new_kind": response["kind"], "old_enabled": bool(old[2]), "new_enabled": response["enabled"]},
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/adapters")
def list_adapters(
    limit: int = 100,
    cursor: Optional[str] = None,
    enabled: Optional[bool] = None,
    key: Optional[str] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer", "system"})
    safe_limit = min(max(limit, 1), 500)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    enabled_filter = ""
    if enabled is not None:
        enabled_filter = "true" if enabled else "false"

    query = """
        select
          id::text,
          key,
          display_name,
          domain,
          flow::text,
          adapter_version,
          coalesce(last_verified_at::text, ''),
          enabled,
          metadata::text,
          created_at::text,
          updated_at::text
        from adapters
        where (%s = '' or lower(key) = lower(%s))
          and (%s = '' or enabled = %s::boolean)
          and (nullif(%s, '') is null or (created_at, id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by created_at desc, id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        key or "",
                        key or "",
                        enabled_filter,
                        enabled_filter or "false",
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()

        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][9], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "key": r[1],
                    "display_name": r[2],
                    "domain": r[3],
                    "flow": r[4],
                    "adapter_version": r[5],
                    "last_verified_at": r[6] or None,
                    "enabled": bool(r[7]),
                    "metadata": json.loads(r[8]),
                    "created_at": r[9],
                    "updated_at": r[10],
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/adapters")
def create_adapter(
    payload: AdapterCreate,
    principal: dict[str, Any] = Depends(require_auth),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    replay = idempotency_replay_if_exists(
        endpoint="adapters.create",
        idempotency_key=idempotency_key,
        principal=principal,
        request_payload=payload.model_dump(),
    )
    if replay is not None:
        return replay

    flow = payload.flow.strip().lower()
    if flow not in FLOW_TYPES:
        raise HTTPException(status_code=400, detail="invalid flow type")

    query = """
        insert into adapters (key, display_name, domain, flow, adapter_version, enabled, metadata)
        values (%s, %s, %s, %s::flow_type, %s, %s, %s::jsonb)
        returning id::text, key, display_name, domain, flow::text, adapter_version,
                  coalesce(last_verified_at::text, ''), enabled, metadata::text, created_at::text, updated_at::text;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        payload.key.strip(),
                        payload.display_name.strip(),
                        payload.domain.strip(),
                        flow,
                        payload.adapter_version.strip(),
                        payload.enabled,
                        Json(payload.metadata),
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        response = {
            "id": row[0],
            "key": row[1],
            "display_name": row[2],
            "domain": row[3],
            "flow": row[4],
            "adapter_version": row[5],
            "last_verified_at": row[6] or None,
            "enabled": bool(row[7]),
            "metadata": json.loads(row[8]),
            "created_at": row[9],
            "updated_at": row[10],
        }
        write_audit_log(
            "adapters.create",
            "adapter",
            actor_user_id=principal.get("user_id"),
            object_id=response["id"],
            payload={"key": response["key"], "flow": response["flow"], "enabled": response["enabled"]},
        )
        idempotency_store_response(
            endpoint="adapters.create",
            idempotency_key=idempotency_key,
            principal=principal,
            request_payload=payload.model_dump(),
            response_status=200,
            response_body=response,
        )
        return response
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/v1/adapters/{adapter_id}")
def update_adapter(
    adapter_id: str,
    payload: AdapterUpdate,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    new_flow = payload.flow.strip().lower() if payload.flow else None
    if new_flow and new_flow not in FLOW_TYPES:
        raise HTTPException(status_code=400, detail="invalid flow type")

    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select key, flow::text, enabled
                    from adapters
                    where id = %s::uuid;
                    """,
                    (adapter_id,),
                )
                old = cur.fetchone()
                if not old:
                    raise HTTPException(status_code=404, detail="adapter not found")

                cur.execute(
                    """
                    update adapters
                    set display_name = coalesce(%s, display_name),
                        domain = coalesce(%s, domain),
                        flow = coalesce(%s::flow_type, flow),
                        adapter_version = coalesce(%s, adapter_version),
                        enabled = coalesce(%s, enabled),
                        metadata = case when %s::jsonb is null then metadata else %s::jsonb end,
                        last_verified_at = coalesce(nullif(%s, '')::timestamptz, last_verified_at)
                    where id = %s::uuid
                    returning id::text, key, display_name, domain, flow::text, adapter_version,
                              coalesce(last_verified_at::text, ''), enabled, metadata::text, created_at::text, updated_at::text;
                    """,
                    (
                        payload.display_name.strip() if payload.display_name else None,
                        payload.domain.strip() if payload.domain else None,
                        new_flow,
                        payload.adapter_version.strip() if payload.adapter_version else None,
                        payload.enabled,
                        Json(payload.metadata) if payload.metadata is not None else None,
                        Json(payload.metadata) if payload.metadata is not None else None,
                        payload.last_verified_at or "",
                        adapter_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()

        response = {
            "id": row[0],
            "key": row[1],
            "display_name": row[2],
            "domain": row[3],
            "flow": row[4],
            "adapter_version": row[5],
            "last_verified_at": row[6] or None,
            "enabled": bool(row[7]),
            "metadata": json.loads(row[8]),
            "created_at": row[9],
            "updated_at": row[10],
        }
        write_audit_log(
            "adapters.update",
            "adapter",
            actor_user_id=principal.get("user_id"),
            object_id=adapter_id,
            payload={"key": old[0], "old_flow": old[1], "new_flow": response["flow"], "old_enabled": bool(old[2]), "new_enabled": response["enabled"]},
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/findings")
def create_finding(
    payload: FindingCreate,
    principal: dict[str, Any] = Depends(require_auth),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    replay = idempotency_replay_if_exists(
        endpoint="findings.create",
        idempotency_key=idempotency_key,
        principal=principal,
        request_payload=payload.model_dump(),
    )
    if replay is not None:
        return replay

    query = """
        insert into findings (
          profile_id, source_domain, source_url, risk_score,
          matched_identifiers, exposed_fields, notes
        )
        values (
          %s::uuid, %s, %s, %s,
          %s::jsonb, %s::jsonb, %s
        )
        returning id::text, status::text, first_seen_at::text;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        payload.profile_id,
                        payload.source_domain,
                        payload.source_url,
                        payload.risk_score,
                        Json(payload.matched_identifiers),
                        Json(payload.exposed_fields),
                        payload.notes,
                    ),
                )
                row = cur.fetchone()
            conn.commit()
        response = {"id": row[0], "status": row[1], "created_at": row[2]}
        write_audit_log(
            "findings.create",
            "finding",
            actor_user_id=principal.get("user_id"),
            object_id=response["id"],
            payload={"profile_id": payload.profile_id, "source_domain": payload.source_domain, "risk_score": payload.risk_score},
        )
        idempotency_store_response(
            endpoint="findings.create",
            idempotency_key=idempotency_key,
            principal=principal,
            request_payload=payload.model_dump(),
            response_status=200,
            response_body=response,
        )
        return response
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/findings")
def list_findings(
    limit: int = 100,
    cursor: Optional[str] = None,
    profile_id: Optional[str] = None,
    status: Optional[str] = None,
    source_domain: Optional[str] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer", "system"})
    safe_limit = min(max(limit, 1), 500)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    status_filter = status.strip().lower() if status else None
    if status_filter and status_filter not in FINDING_STATUSES:
        raise HTTPException(status_code=400, detail="invalid finding status")

    query = """
        select
          id::text,
          profile_id::text,
          coalesce(scan_id::text, ''),
          coalesce(adapter_id::text, ''),
          source_domain,
          source_url,
          matched_identifiers::text,
          exposed_fields::text,
          risk_score,
          status::text,
          first_seen_at::text,
          last_seen_at::text,
          coalesce(removed_at::text, ''),
          coalesce(notes, '')
        from findings
        where (nullif(%s, '') is null or profile_id = nullif(%s, '')::uuid)
          and (%s = '' or status::text = %s)
          and (%s = '' or lower(source_domain) = lower(%s))
          and (nullif(%s, '') is null or (first_seen_at, id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by first_seen_at desc, id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        profile_id or "",
                        profile_id or "",
                        status_filter or "",
                        status_filter or "",
                        source_domain or "",
                        source_domain or "",
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()
        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][10], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "profile_id": r[1],
                    "scan_id": r[2] or None,
                    "adapter_id": r[3] or None,
                    "source_domain": r[4],
                    "source_url": r[5],
                    "matched_identifiers": json.loads(r[6]),
                    "exposed_fields": json.loads(r[7]),
                    "risk_score": r[8],
                    "status": r[9],
                    "first_seen_at": r[10],
                    "last_seen_at": r[11],
                    "removed_at": r[12] or None,
                    "notes": r[13] or None,
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.patch("/v1/findings/{finding_id}")
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    new_status = payload.status.strip().lower() if payload.status else None
    if new_status and new_status not in FINDING_STATUSES:
        raise HTTPException(status_code=400, detail="invalid finding status")

    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select status::text, risk_score, coalesce(notes, '')
                    from findings
                    where id = %s::uuid;
                    """,
                    (finding_id,),
                )
                old = cur.fetchone()
                if not old:
                    raise HTTPException(status_code=404, detail="finding not found")

                cur.execute(
                    """
                    update findings
                    set status = coalesce(%s::finding_status, status),
                        risk_score = coalesce(%s, risk_score),
                        notes = case when %s is null then notes else %s end,
                        last_seen_at = coalesce(nullif(%s, '')::timestamptz, last_seen_at),
                        removed_at = case
                          when coalesce(%s::finding_status, status) = 'removed' then coalesce(removed_at, now())
                          when coalesce(%s::finding_status, status) <> 'removed' then null
                          else removed_at
                        end
                    where id = %s::uuid
                    returning id::text, profile_id::text, status::text, risk_score,
                              first_seen_at::text, last_seen_at::text, coalesce(removed_at::text, ''),
                              coalesce(notes, '');
                    """,
                    (
                        new_status,
                        payload.risk_score,
                        payload.notes,
                        payload.notes,
                        payload.last_seen_at or "",
                        new_status,
                        new_status,
                        finding_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()

        response = {
            "id": row[0],
            "profile_id": row[1],
            "status": row[2],
            "risk_score": row[3],
            "first_seen_at": row[4],
            "last_seen_at": row[5],
            "removed_at": row[6] or None,
            "notes": row[7] or None,
        }
        write_audit_log(
            "findings.update",
            "finding",
            actor_user_id=principal.get("user_id"),
            object_id=finding_id,
            payload={
                "old_status": old[0],
                "new_status": response["status"],
                "old_risk_score": old[1],
                "new_risk_score": response["risk_score"],
            },
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/tasks")
def create_task(
    payload: TaskCreate,
    principal: dict[str, Any] = Depends(require_auth),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    replay = idempotency_replay_if_exists(
        endpoint="tasks.create",
        idempotency_key=idempotency_key,
        principal=principal,
        request_payload=payload.model_dump(),
    )
    if replay is not None:
        return replay

    adapter_id = None
    if payload.adapter_key:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("select id::text from adapters where key = %s", (payload.adapter_key,))
                row = cur.fetchone()
                if row:
                    adapter_id = row[0]

    query = """
        insert into tasks (finding_id, adapter_id, due_at)
        values (%s::uuid, %s::uuid, nullif(%s, '')::timestamptz)
        returning id::text, status::text, created_at::text;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (payload.finding_id, adapter_id, payload.due_at or ""))
                row = cur.fetchone()
            conn.commit()
        response = {"id": row[0], "status": row[1], "created_at": row[2]}
        write_audit_log(
            "tasks.create",
            "task",
            actor_user_id=principal.get("user_id"),
            object_id=response["id"],
            payload={"finding_id": payload.finding_id, "adapter_key": payload.adapter_key},
        )
        idempotency_store_response(
            endpoint="tasks.create",
            idempotency_key=idempotency_key,
            principal=principal,
            request_payload=payload.model_dump(),
            response_status=200,
            response_body=response,
        )
        return response
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/v1/tasks/{task_id}/queue-adapter-run")
def queue_adapter_run(
    task_id: str,
    payload: AdapterRunQueueRequest,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    manifest = load_adapter_manifest(payload.adapter_key)

    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select t.finding_id::text
                    from tasks t
                    where t.id = %s::uuid;
                    """,
                    (task_id,),
                )
                task_row = cur.fetchone()
                if not task_row:
                    raise HTTPException(status_code=404, detail=f"task not found: {task_id}")
                finding_id = task_row[0]

                cur.execute(
                    """
                    insert into adapters (key, display_name, domain, flow, adapter_version, enabled, metadata)
                    values (%s, %s, %s, %s::flow_type, %s, true, %s::jsonb)
                    on conflict (key) do update set
                      display_name = excluded.display_name,
                      domain = excluded.domain,
                      flow = excluded.flow,
                      adapter_version = excluded.adapter_version,
                      enabled = true,
                      metadata = excluded.metadata,
                      updated_at = now();
                    """,
                    (
                        manifest.get("key"),
                        manifest.get("displayName", manifest.get("key")),
                        manifest.get("domain", "unknown"),
                        manifest.get("flowType", "manual"),
                        manifest.get("version", "0.0.0"),
                        Json(manifest),
                    ),
                )

                cur.execute(
                    """
                    insert into adapter_runs (task_id, finding_id, adapter_key, action, status)
                    values (%s::uuid, %s::uuid, %s, %s, 'queued')
                    returning id::text;
                    """,
                    (task_id, finding_id, payload.adapter_key, payload.action),
                )
                adapter_run_id = cur.fetchone()[0]

                cur.execute(
                    """
                    insert into job_queue (job_type, payload, status)
                    values (%s, %s::jsonb, 'queued')
                    returning id::text;
                    """,
                    (
                        "adapter_run",
                        Json(
                            {
                                "adapter_run_id": adapter_run_id,
                                "task_id": task_id,
                                "finding_id": finding_id,
                                "adapter_key": payload.adapter_key,
                                "action": payload.action,
                            }
                        ),
                    ),
                )
                job_id = cur.fetchone()[0]

                cur.execute(
                    """
                    update tasks
                    set status = 'in_progress'::task_status
                    where id = %s::uuid;
                    """,
                    (task_id,),
                )
            conn.commit()

        response = {
            "task_id": task_id,
            "adapter_run_id": adapter_run_id,
            "job_id": job_id,
            "status": "queued",
        }
        write_audit_log(
            "tasks.queue_adapter_run",
            "adapter_run",
            actor_user_id=principal.get("user_id"),
            object_id=adapter_run_id,
            payload={"task_id": task_id, "job_id": job_id, "adapter_key": payload.adapter_key, "action": payload.action},
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/tasks")
def list_tasks(
    limit: int = 100,
    cursor: Optional[str] = None,
    status: Optional[str] = None,
    finding_id: Optional[str] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer", "system"})
    safe_limit = min(max(limit, 1), 500)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    status_filter = status.strip().lower() if status else None
    if status_filter and status_filter not in TASK_STATUSES:
        raise HTTPException(status_code=400, detail="invalid task status")

    query = """
        select
          t.id::text,
          t.finding_id::text,
          coalesce(t.adapter_id::text, ''),
          coalesce(a.key, ''),
          coalesce(t.assigned_user_id::text, ''),
          t.status::text,
          coalesce(t.due_at::text, ''),
          coalesce(t.completed_at::text, ''),
          coalesce(t.result_summary, ''),
          t.metadata::text,
          t.created_at::text,
          t.updated_at::text
        from tasks t
        left join adapters a on a.id = t.adapter_id
        where (%s = '' or t.status::text = %s)
          and (nullif(%s, '') is null or t.finding_id = nullif(%s, '')::uuid)
          and (nullif(%s, '') is null or (t.created_at, t.id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by t.created_at desc, t.id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        status_filter or "",
                        status_filter or "",
                        finding_id or "",
                        finding_id or "",
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()
        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][10], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "finding_id": r[1],
                    "adapter_id": r[2] or None,
                    "adapter_key": r[3] or None,
                    "assigned_user_id": r[4] or None,
                    "status": r[5],
                    "due_at": r[6] or None,
                    "completed_at": r[7] or None,
                    "result_summary": r[8] or None,
                    "metadata": json.loads(r[9]),
                    "created_at": r[10],
                    "updated_at": r[11],
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.patch("/v1/tasks/{task_id}")
def update_task(
    task_id: str,
    payload: TaskUpdate,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    new_status = payload.status.strip().lower() if payload.status else None
    if new_status and new_status not in TASK_STATUSES:
        raise HTTPException(status_code=400, detail="invalid task status")

    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select status::text, coalesce(result_summary, ''), coalesce(assigned_user_id::text, '')
                    from tasks
                    where id = %s::uuid;
                    """,
                    (task_id,),
                )
                old = cur.fetchone()
                if not old:
                    raise HTTPException(status_code=404, detail="task not found")

                cur.execute(
                    """
                    update tasks
                    set status = coalesce(%s::task_status, status),
                        due_at = coalesce(nullif(%s, '')::timestamptz, due_at),
                        result_summary = case when %s is null then result_summary else %s end,
                        assigned_user_id = case
                          when %s is null then assigned_user_id
                          else nullif(%s, '')::uuid
                        end,
                        completed_at = case
                          when coalesce(%s::task_status, status) = 'completed' then coalesce(completed_at, now())
                          when coalesce(%s::task_status, status) <> 'completed' then null
                          else completed_at
                        end
                    where id = %s::uuid
                    returning id::text, finding_id::text, status::text,
                              coalesce(due_at::text, ''), coalesce(completed_at::text, ''),
                              coalesce(result_summary, ''), coalesce(assigned_user_id::text, ''),
                              created_at::text, updated_at::text;
                    """,
                    (
                        new_status,
                        payload.due_at or "",
                        payload.result_summary,
                        payload.result_summary,
                        payload.assigned_user_id,
                        payload.assigned_user_id or "",
                        new_status,
                        new_status,
                        task_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()

        response = {
            "id": row[0],
            "finding_id": row[1],
            "status": row[2],
            "due_at": row[3] or None,
            "completed_at": row[4] or None,
            "result_summary": row[5] or None,
            "assigned_user_id": row[6] or None,
            "created_at": row[7],
            "updated_at": row[8],
        }
        write_audit_log(
            "tasks.update",
            "task",
            actor_user_id=principal.get("user_id"),
            object_id=task_id,
            payload={
                "old_status": old[0],
                "new_status": response["status"],
                "old_assigned_user_id": old[2] or None,
                "new_assigned_user_id": response["assigned_user_id"],
            },
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/reminders")
def list_reminders(
    limit: int = 100,
    cursor: Optional[str] = None,
    profile_id: Optional[str] = None,
    enabled: Optional[bool] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "viewer", "system"})
    safe_limit = min(max(limit, 1), 500)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    enabled_filter = ""
    if enabled is not None:
        enabled_filter = "true" if enabled else "false"

    query = """
        select
          id::text,
          profile_id::text,
          coalesce(finding_id::text, ''),
          reminder_type,
          next_run_at::text,
          coalesce(interval_days, 0),
          enabled,
          metadata::text,
          created_at::text
        from reminders
        where (nullif(%s, '') is null or profile_id = nullif(%s, '')::uuid)
          and (%s = '' or enabled = %s::boolean)
          and (nullif(%s, '') is null or (created_at, id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by created_at desc, id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        profile_id or "",
                        profile_id or "",
                        enabled_filter,
                        enabled_filter or "false",
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()
        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][8], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "profile_id": r[1],
                    "finding_id": r[2] or None,
                    "reminder_type": r[3],
                    "next_run_at": r[4],
                    "interval_days": None if r[5] == 0 else r[5],
                    "enabled": bool(r[6]),
                    "metadata": json.loads(r[7]),
                    "created_at": r[8],
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/reminders")
def create_reminder(
    payload: ReminderCreate,
    principal: dict[str, Any] = Depends(require_auth),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    replay = idempotency_replay_if_exists(
        endpoint="reminders.create",
        idempotency_key=idempotency_key,
        principal=principal,
        request_payload=payload.model_dump(),
    )
    if replay is not None:
        return replay

    query = """
        insert into reminders (profile_id, finding_id, reminder_type, next_run_at, interval_days, enabled, metadata)
        values (%s::uuid, nullif(%s, '')::uuid, %s, %s::timestamptz, %s, %s, %s::jsonb)
        returning id::text, profile_id::text, coalesce(finding_id::text, ''), reminder_type,
                  next_run_at::text, coalesce(interval_days, 0), enabled, metadata::text, created_at::text;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        payload.profile_id,
                        payload.finding_id or "",
                        payload.reminder_type.strip(),
                        payload.next_run_at,
                        payload.interval_days,
                        payload.enabled,
                        Json(payload.metadata),
                    ),
                )
                row = cur.fetchone()
            conn.commit()

        response = {
            "id": row[0],
            "profile_id": row[1],
            "finding_id": row[2] or None,
            "reminder_type": row[3],
            "next_run_at": row[4],
            "interval_days": None if row[5] == 0 else row[5],
            "enabled": bool(row[6]),
            "metadata": json.loads(row[7]),
            "created_at": row[8],
        }
        write_audit_log(
            "reminders.create",
            "reminder",
            actor_user_id=principal.get("user_id"),
            object_id=response["id"],
            payload={
                "profile_id": response["profile_id"],
                "finding_id": response["finding_id"],
                "reminder_type": response["reminder_type"],
                "enabled": response["enabled"],
            },
        )
        idempotency_store_response(
            endpoint="reminders.create",
            idempotency_key=idempotency_key,
            principal=principal,
            request_payload=payload.model_dump(),
            response_status=200,
            response_body=response,
        )
        return response
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/v1/reminders/{reminder_id}")
def update_reminder(
    reminder_id: str,
    payload: ReminderUpdate,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "operator", "system"})
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select reminder_type, enabled
                    from reminders
                    where id = %s::uuid;
                    """,
                    (reminder_id,),
                )
                old = cur.fetchone()
                if not old:
                    raise HTTPException(status_code=404, detail="reminder not found")

                cur.execute(
                    """
                    update reminders
                    set next_run_at = coalesce(nullif(%s, '')::timestamptz, next_run_at),
                        interval_days = coalesce(%s, interval_days),
                        enabled = coalesce(%s, enabled),
                        metadata = case when %s::jsonb is null then metadata else %s::jsonb end
                    where id = %s::uuid
                    returning id::text, profile_id::text, coalesce(finding_id::text, ''), reminder_type,
                              next_run_at::text, coalesce(interval_days, 0), enabled, metadata::text, created_at::text;
                    """,
                    (
                        payload.next_run_at or "",
                        payload.interval_days,
                        payload.enabled,
                        Json(payload.metadata) if payload.metadata is not None else None,
                        Json(payload.metadata) if payload.metadata is not None else None,
                        reminder_id,
                    ),
                )
                row = cur.fetchone()
            conn.commit()

        response = {
            "id": row[0],
            "profile_id": row[1],
            "finding_id": row[2] or None,
            "reminder_type": row[3],
            "next_run_at": row[4],
            "interval_days": None if row[5] == 0 else row[5],
            "enabled": bool(row[6]),
            "metadata": json.loads(row[7]),
            "created_at": row[8],
        }
        write_audit_log(
            "reminders.update",
            "reminder",
            actor_user_id=principal.get("user_id"),
            object_id=reminder_id,
            payload={"old_enabled": bool(old[1]), "new_enabled": response["enabled"], "reminder_type": response["reminder_type"]},
        )
        return response
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/audit-log")
def list_audit_log(
    limit: int = 100,
    cursor: Optional[str] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "system"})
    safe_limit = min(max(limit, 1), 500)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    query = """
        select
          id::text,
          coalesce(actor_user_id::text, ''),
          action,
          object_type,
          coalesce(object_id::text, ''),
          payload::text,
          created_at::text
        from audit_log
        where (nullif(%s, '') is null or (created_at, id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by created_at desc, id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()
        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][6], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "actor_user_id": r[1] or None,
                    "action": r[2],
                    "object_type": r[3],
                    "object_id": r[4] or None,
                    "payload": json.loads(r[5]),
                    "created_at": r[6],
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/v1/adapter-runs")
def list_adapter_runs(
    limit: int = 50,
    cursor: Optional[str] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "system"})
    safe_limit = min(max(limit, 1), 200)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    query = """
        select
          id::text,
          coalesce(task_id::text, ''),
          coalesce(finding_id::text, ''),
          adapter_key,
          action,
          status,
          coalesce(summary, ''),
          coalesce(error_text, ''),
          created_at::text,
          coalesce(started_at::text, ''),
          coalesce(finished_at::text, '')
        from adapter_runs
        where (nullif(%s, '') is null or (created_at, id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by created_at desc, id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()
        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][8], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "task_id": r[1] or None,
                    "finding_id": r[2] or None,
                    "adapter_key": r[3],
                    "action": r[4],
                    "status": r[5],
                    "summary": r[6] or None,
                    "error_text": r[7] or None,
                    "created_at": r[8],
                    "started_at": r[9] or None,
                    "finished_at": r[10] or None,
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/v1/jobs")
def list_jobs(
    limit: int = 50,
    cursor: Optional[str] = None,
    principal: dict[str, Any] = Depends(require_auth),
):
    require_roles(principal, {"owner", "admin", "reviewer", "operator", "system"})
    safe_limit = min(max(limit, 1), 200)
    page_size = safe_limit + 1
    cursor_created_at, cursor_id = decode_pagination_cursor(cursor)
    query = """
        select
          id::text,
          job_type,
          status,
          attempts,
          coalesce(last_error, ''),
          created_at::text,
          coalesce(started_at::text, ''),
          coalesce(finished_at::text, ''),
          payload::text
        from job_queue
        where (nullif(%s, '') is null or (created_at, id) < (nullif(%s, '')::timestamptz, %s::uuid))
        order by created_at desc, id desc
        limit %s;
    """
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        cursor_created_at or "",
                        cursor_created_at or "",
                        cursor_id or "00000000-0000-0000-0000-000000000000",
                        page_size,
                    ),
                )
                rows = cur.fetchall()
        has_more = len(rows) > safe_limit
        rows = rows[:safe_limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_pagination_cursor(rows[-1][5], rows[-1][0])
        return {
            "items": [
                {
                    "id": r[0],
                    "job_type": r[1],
                    "status": r[2],
                    "attempts": r[3],
                    "last_error": r[4] or None,
                    "created_at": r[5],
                    "started_at": r[6] or None,
                    "finished_at": r[7] or None,
                    "payload": json.loads(r[8]),
                }
                for r in rows
            ],
            "next_cursor": next_cursor,
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc

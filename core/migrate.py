import os
from pathlib import Path

import psycopg2

POST_BOOTSTRAP_SQL = """
create table if not exists adapter_runs (
  id uuid primary key default gen_random_uuid(),
  task_id uuid references tasks(id) on delete set null,
  finding_id uuid references findings(id) on delete set null,
  adapter_key text not null,
  action text not null,
  status text not null default 'queued',
  summary text,
  artifacts jsonb not null default '[]'::jsonb,
  raw_result jsonb not null default '{}'::jsonb,
  error_text text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists job_queue (
  id uuid primary key default gen_random_uuid(),
  job_type text not null,
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'queued',
  attempts int not null default 0,
  last_error text,
  available_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists auth_refresh_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  token_jti text not null unique,
  token_hash text not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  replaced_by_jti text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists api_keys (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  key_hash text not null unique,
  role text not null default 'system',
  allowed_path_prefixes jsonb not null default '[]'::jsonb,
  enabled boolean not null default true,
  expires_at timestamptz,
  last_used_at timestamptz,
  created_by_user_id uuid references users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists password_reset_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  token_hash text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists mfa_totp_credentials (
  user_id uuid primary key references users(id) on delete cascade,
  secret_encrypted bytea not null,
  issuer text not null default 'Privacy Scrubber',
  enabled boolean not null default false,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists mfa_webauthn_credentials (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  credential_id text not null unique,
  public_key text not null,
  sign_count bigint not null default 0,
  aaguid text,
  backup_eligible boolean not null default false,
  backup_state boolean not null default false,
  device_type text,
  nickname text,
  enabled boolean not null default true,
  verified_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists mfa_webauthn_challenges (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  purpose text not null,
  challenge text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists idempotency_keys (
  id uuid primary key default gen_random_uuid(),
  scope_key text not null,
  endpoint text not null,
  idempotency_key text not null,
  request_hash text not null,
  response_status int not null,
  response_body jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (scope_key, endpoint, idempotency_key)
);

create index if not exists idx_job_queue_ready
  on job_queue(status, available_at, created_at);

create index if not exists idx_auth_refresh_tokens_user
  on auth_refresh_tokens(user_id, expires_at)
  where revoked_at is null;

create index if not exists idx_api_keys_enabled
  on api_keys(enabled, expires_at, created_at);

create index if not exists idx_password_reset_tokens_user
  on password_reset_tokens(user_id, expires_at)
  where used_at is null;

create index if not exists idx_mfa_webauthn_credentials_user
  on mfa_webauthn_credentials(user_id, enabled, created_at);

create index if not exists idx_mfa_webauthn_challenges_lookup
  on mfa_webauthn_challenges(user_id, purpose, expires_at)
  where consumed_at is null;

drop trigger if exists trg_adapter_runs_updated_at on adapter_runs;
create trigger trg_adapter_runs_updated_at
before update on adapter_runs
for each row execute function set_updated_at();

drop trigger if exists trg_job_queue_updated_at on job_queue;
create trigger trg_job_queue_updated_at
before update on job_queue
for each row execute function set_updated_at();

drop trigger if exists trg_auth_refresh_tokens_updated_at on auth_refresh_tokens;
create trigger trg_auth_refresh_tokens_updated_at
before update on auth_refresh_tokens
for each row execute function set_updated_at();

drop trigger if exists trg_api_keys_updated_at on api_keys;
create trigger trg_api_keys_updated_at
before update on api_keys
for each row execute function set_updated_at();

drop trigger if exists trg_mfa_totp_credentials_updated_at on mfa_totp_credentials;
create trigger trg_mfa_totp_credentials_updated_at
before update on mfa_totp_credentials
for each row execute function set_updated_at();

drop trigger if exists trg_mfa_webauthn_credentials_updated_at on mfa_webauthn_credentials;
create trigger trg_mfa_webauthn_credentials_updated_at
before update on mfa_webauthn_credentials
for each row execute function set_updated_at();

drop trigger if exists trg_idempotency_keys_updated_at on idempotency_keys;
create trigger trg_idempotency_keys_updated_at
before update on idempotency_keys
for each row execute function set_updated_at();
"""


def main() -> None:
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://privacy:privacy_change_me@postgres:5432/privacy_scrubber",
    )
    schema_path = Path(os.environ.get("SCHEMA_PATH", "/app/docs/database-schema.sql"))

    if not schema_path.exists():
        raise SystemExit(f"schema file not found: {schema_path}")

    schema_sql = schema_path.read_text(encoding="utf-8")

    with psycopg2.connect(db_url, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select exists (
                    select 1
                    from information_schema.tables
                    where table_schema = 'public' and table_name = 'users'
                );
                """
            )
            already_bootstrapped = cur.fetchone()[0]

            if not already_bootstrapped:
                print(f"Applying schema from {schema_path} ...")
                cur.execute(schema_sql)
                print("Schema bootstrap complete.")
            else:
                print("Schema already present, skipping bootstrap.")

            print("Applying post-bootstrap migrations ...")
            cur.execute(POST_BOOTSTRAP_SQL)
            conn.commit()

    print("Migrations complete.")


if __name__ == "__main__":
    main()

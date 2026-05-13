-- Privacy Scrubber v1 schema
-- Postgres 15+

create extension if not exists "pgcrypto";

create type profile_status as enum ('active', 'paused', 'archived');
create type finding_status as enum (
  'new',
  'triaged',
  'task_created',
  'submitted',
  'pending_verification',
  'removed',
  'reappeared',
  'closed_false_positive'
);
create type task_status as enum (
  'queued',
  'in_progress',
  'waiting_manual',
  'waiting_email_verification',
  'completed',
  'failed',
  'cancelled'
);
create type flow_type as enum ('manual', 'semi_auto', 'auto');
create type evidence_type as enum ('screenshot', 'html_snapshot', 'pdf_export', 'raw_json');
create type identifier_type as enum ('full_name', 'alias', 'email', 'phone', 'address', 'city', 'dob_partial', 'username');

create table users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  role text not null default 'owner',
  mfa_enabled boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table profiles (
  id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references users(id) on delete cascade,
  display_name text not null,
  region_code text,
  status profile_status not null default 'active',
  consent_record text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table identifiers (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references profiles(id) on delete cascade,
  id_type identifier_type not null,
  value_encrypted bytea not null,
  value_hash bytea not null,
  is_primary boolean not null default false,
  created_at timestamptz not null default now()
);

create index idx_identifiers_profile on identifiers(profile_id);
create index idx_identifiers_hash on identifiers(value_hash);

create table providers (
  id uuid primary key default gen_random_uuid(),
  key text unique not null,
  kind text not null, -- search_provider | broker | evidence
  config jsonb not null default '{}'::jsonb,
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

create table adapters (
  id uuid primary key default gen_random_uuid(),
  key text unique not null,
  display_name text not null,
  domain text not null,
  flow flow_type not null,
  adapter_version text not null,
  last_verified_at timestamptz,
  enabled boolean not null default true,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table scans (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references profiles(id) on delete cascade,
  scan_type text not null, -- discovery | recheck
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  status text not null default 'running',
  query_count int not null default 0,
  result_count int not null default 0,
  metadata jsonb not null default '{}'::jsonb
);

create table findings (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references profiles(id) on delete cascade,
  scan_id uuid references scans(id) on delete set null,
  adapter_id uuid references adapters(id) on delete set null,
  source_domain text not null,
  source_url text not null,
  matched_identifiers jsonb not null default '[]'::jsonb,
  exposed_fields jsonb not null default '[]'::jsonb,
  risk_score int not null default 0,
  status finding_status not null default 'new',
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  removed_at timestamptz,
  notes text
);

create index idx_findings_profile on findings(profile_id);
create index idx_findings_status on findings(status);
create index idx_findings_source_domain on findings(source_domain);

create table evidence (
  id uuid primary key default gen_random_uuid(),
  finding_id uuid not null references findings(id) on delete cascade,
  ev_type evidence_type not null,
  storage_uri text not null,
  content_sha256 text,
  captured_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb
);

create table tasks (
  id uuid primary key default gen_random_uuid(),
  finding_id uuid not null references findings(id) on delete cascade,
  adapter_id uuid references adapters(id) on delete set null,
  assigned_user_id uuid references users(id) on delete set null,
  status task_status not null default 'queued',
  due_at timestamptz,
  completed_at timestamptz,
  result_summary text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index idx_tasks_status on tasks(status);
create index idx_tasks_due_at on tasks(due_at);

create table task_events (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references tasks(id) on delete cascade,
  actor_user_id uuid references users(id) on delete set null,
  event_type text not null,
  event_payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table reminders (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references profiles(id) on delete cascade,
  finding_id uuid references findings(id) on delete cascade,
  reminder_type text not null, -- monthly_recheck | manual_follow_up | email_verify
  next_run_at timestamptz not null,
  interval_days int,
  enabled boolean not null default true,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index idx_reminders_next_run on reminders(next_run_at) where enabled = true;

create table notifications (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid references profiles(id) on delete cascade,
  channel text not null, -- discord | email | webhook
  destination text not null,
  event_filter jsonb not null default '{}'::jsonb,
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

create table audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_user_id uuid references users(id) on delete set null,
  action text not null,
  object_type text not null,
  object_id uuid,
  payload jsonb not null default '{}'::jsonb,
  signature text,
  created_at timestamptz not null default now()
);

-- Basic update trigger helper
create or replace function set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger trg_users_updated_at before update on users
for each row execute function set_updated_at();

create trigger trg_profiles_updated_at before update on profiles
for each row execute function set_updated_at();

create trigger trg_adapters_updated_at before update on adapters
for each row execute function set_updated_at();

create trigger trg_tasks_updated_at before update on tasks
for each row execute function set_updated_at();


-- Phase 2: adapter execution queue
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

create index if not exists idx_job_queue_ready
  on job_queue(status, available_at, created_at);

drop trigger if exists trg_adapter_runs_updated_at on adapter_runs;
create trigger trg_adapter_runs_updated_at before update on adapter_runs
for each row execute function set_updated_at();

drop trigger if exists trg_job_queue_updated_at on job_queue;
create trigger trg_job_queue_updated_at before update on job_queue
for each row execute function set_updated_at();

-- Phase 4: auth session + password reset tables
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

create index if not exists idx_auth_refresh_tokens_user
  on auth_refresh_tokens(user_id, expires_at)
  where revoked_at is null;

create index if not exists idx_api_keys_enabled
  on api_keys(enabled, expires_at, created_at);

create index if not exists idx_mfa_totp_credentials_enabled
  on mfa_totp_credentials(enabled);

create index if not exists idx_mfa_webauthn_credentials_user
  on mfa_webauthn_credentials(user_id, enabled, created_at);

create index if not exists idx_mfa_webauthn_challenges_lookup
  on mfa_webauthn_challenges(user_id, purpose, expires_at)
  where consumed_at is null;

create index if not exists idx_idempotency_keys_lookup
  on idempotency_keys(scope_key, endpoint, idempotency_key);

create index if not exists idx_password_reset_tokens_user
  on password_reset_tokens(user_id, expires_at)
  where used_at is null;

drop trigger if exists trg_auth_refresh_tokens_updated_at on auth_refresh_tokens;
create trigger trg_auth_refresh_tokens_updated_at before update on auth_refresh_tokens
for each row execute function set_updated_at();

drop trigger if exists trg_api_keys_updated_at on api_keys;
create trigger trg_api_keys_updated_at before update on api_keys
for each row execute function set_updated_at();

drop trigger if exists trg_mfa_totp_credentials_updated_at on mfa_totp_credentials;
create trigger trg_mfa_totp_credentials_updated_at before update on mfa_totp_credentials
for each row execute function set_updated_at();

drop trigger if exists trg_mfa_webauthn_credentials_updated_at on mfa_webauthn_credentials;
create trigger trg_mfa_webauthn_credentials_updated_at before update on mfa_webauthn_credentials
for each row execute function set_updated_at();

drop trigger if exists trg_idempotency_keys_updated_at on idempotency_keys;
create trigger trg_idempotency_keys_updated_at before update on idempotency_keys
for each row execute function set_updated_at();

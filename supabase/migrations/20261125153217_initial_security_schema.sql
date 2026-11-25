-- Private application schema. It is intentionally not exposed through Supabase Data API.
create extension if not exists pgcrypto;

create schema if not exists app_private;
revoke all on schema app_private from public, anon, authenticated;

create type app_private.user_role as enum ('user', 'admin');
create type app_private.user_status as enum ('active', 'disabled', 'pending_verification');

create table app_private.users (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  email_normalized text generated always as (lower(btrim(email))) stored,
  password_hash text not null,
  role app_private.user_role not null default 'user',
  status app_private.user_status not null default 'pending_verification',
  email_verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint users_email_length check (char_length(email) between 3 and 254),
  constraint users_email_normalized_unique unique (email_normalized)
);

create table app_private.refresh_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_private.users(id) on delete cascade,
  token_hash char(64) not null unique,
  family_id uuid not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  constraint refresh_tokens_expiry_after_creation check (expires_at > created_at)
);

create table app_private.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_private.users(id) on delete cascade,
  title text not null default '',
  content text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint notes_title_length check (char_length(title) <= 160),
  constraint notes_content_length check (char_length(content) between 1 and 5000)
);

create table app_private.audit_log (
  id bigint generated always as identity primary key,
  user_id uuid references app_private.users(id) on delete set null,
  event_type text not null,
  ip_address inet,
  user_agent text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint audit_event_length check (char_length(event_type) between 1 and 80)
);

create table app_private.password_reset_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_private.users(id) on delete cascade,
  token_hash char(64) not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table app_private.email_verification_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_private.users(id) on delete cascade,
  token_hash char(64) not null unique,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table app_private.mfa_settings (
  user_id uuid primary key references app_private.users(id) on delete cascade,
  encrypted_secret jsonb not null,
  enabled boolean not null default false,
  enabled_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table app_private.mfa_recovery_codes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_private.users(id) on delete cascade,
  code_hash char(64) not null unique,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create table app_private.login_attempts (
  id bigint generated always as identity primary key,
  account_identifier text not null,
  ip_address inet,
  success boolean not null,
  created_at timestamptz not null default now()
);

create index refresh_tokens_user_family_idx on app_private.refresh_tokens (user_id, family_id);
create index refresh_tokens_family_active_idx on app_private.refresh_tokens (family_id) where revoked_at is null;
create index refresh_tokens_expiry_idx on app_private.refresh_tokens (expires_at);
create index notes_user_created_idx on app_private.notes (user_id, created_at desc);
create index audit_log_user_created_idx on app_private.audit_log (user_id, created_at desc);
create index audit_log_event_created_idx on app_private.audit_log (event_type, created_at desc);
create index password_reset_expiry_idx on app_private.password_reset_tokens (expires_at) where used_at is null;
create index email_verification_expiry_idx on app_private.email_verification_tokens (expires_at) where used_at is null;
create index recovery_codes_user_idx on app_private.mfa_recovery_codes (user_id) where used_at is null;
create index login_attempts_identifier_created_idx on app_private.login_attempts (account_identifier, created_at desc);
create index login_attempts_ip_created_idx on app_private.login_attempts (ip_address, created_at desc);

create function app_private.set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = app_private, pg_catalog
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger users_set_updated_at before update on app_private.users
for each row execute function app_private.set_updated_at();
create trigger notes_set_updated_at before update on app_private.notes
for each row execute function app_private.set_updated_at();
create trigger mfa_settings_set_updated_at before update on app_private.mfa_settings
for each row execute function app_private.set_updated_at();

revoke all on all tables in schema app_private from public, anon, authenticated;
revoke all on all sequences in schema app_private from public, anon, authenticated;
revoke all on all functions in schema app_private from public, anon, authenticated;

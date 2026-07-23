create schema if not exists __SCHEMA__;

create table if not exists __SCHEMA__.accounts (
    id uuid primary key,
    email text not null,
    password_hash text not null,
    display_name text null,
    status text not null,
    created_at_epoch bigint not null,
    constraint accounts_status_check
        check (status in ('pending_verification', 'active', 'disabled'))
);

create unique index if not exists accounts_email_key
    on __SCHEMA__.accounts (email);

create table if not exists __SCHEMA__.oidc_clients (
    client_id text primary key,
    client_name text not null,
    redirect_uris_json text not null,
    client_type text not null,
    pkce_required boolean not null,
    client_secret_hash text null,
    created_at_epoch bigint not null,
    constraint oidc_clients_type_check
        check (client_type in ('public_desktop', 'confidential_web'))
);

alter table if exists __SCHEMA__.oidc_clients
    add column if not exists client_secret_hash text;

create table if not exists __SCHEMA__.devices (
    id uuid primary key,
    client_id text not null references __SCHEMA__.oidc_clients(client_id) on delete restrict,
    device_name text not null,
    proof_key_id text null,
    status text not null,
    registered_at_epoch bigint not null,
    last_seen_at_epoch bigint null,
    constraint devices_status_check
        check (status in ('pending', 'active', 'disabled', 'revoked'))
);

create index if not exists devices_client_id_idx
    on __SCHEMA__.devices (client_id);

create index if not exists devices_proof_key_id_idx
    on __SCHEMA__.devices (proof_key_id);

create unique index if not exists devices_proof_key_id_key
    on __SCHEMA__.devices (proof_key_id)
    where proof_key_id is not null;

create table if not exists __SCHEMA__.auth_sessions (
    id uuid primary key,
    account_id uuid not null references __SCHEMA__.accounts(id) on delete restrict,
    client_id text not null references __SCHEMA__.oidc_clients(client_id) on delete restrict,
    device_id uuid null references __SCHEMA__.devices(id) on delete restrict,
    status text not null,
    created_at_epoch bigint not null,
    expires_at_epoch bigint not null,
    refresh_token_version bigint not null,
    constraint auth_sessions_status_check
        check (status in ('pending', 'active', 'revoked', 'expired'))
);

alter table if exists __SCHEMA__.auth_sessions
    add column if not exists device_id uuid null references __SCHEMA__.devices(id) on delete restrict;

create index if not exists auth_sessions_account_id_idx
    on __SCHEMA__.auth_sessions (account_id);

create index if not exists auth_sessions_client_id_idx
    on __SCHEMA__.auth_sessions (client_id);

create index if not exists auth_sessions_device_id_idx
    on __SCHEMA__.auth_sessions (device_id);

create table if not exists __SCHEMA__.account_device_bindings (
    id uuid primary key,
    account_id uuid not null references __SCHEMA__.accounts(id) on delete restrict,
    device_id uuid not null references __SCHEMA__.devices(id) on delete restrict,
    status text not null,
    bound_at_epoch bigint not null,
    unbound_at_epoch bigint null,
    last_authenticated_at_epoch bigint null,
    constraint account_device_bindings_status_check
        check (status in ('active', 'unbound', 'suspended'))
);

create index if not exists account_device_bindings_account_id_idx
    on __SCHEMA__.account_device_bindings (account_id);

create index if not exists account_device_bindings_device_id_idx
    on __SCHEMA__.account_device_bindings (device_id);

create unique index if not exists account_device_bindings_active_key
    on __SCHEMA__.account_device_bindings (account_id, device_id, status);

create table if not exists __SCHEMA__.refresh_tokens (
    id uuid primary key,
    session_id uuid not null references __SCHEMA__.auth_sessions(id) on delete restrict,
    token_value text not null,
    token_version bigint not null,
    issued_at_epoch bigint not null,
    expires_at_epoch bigint not null,
    revoked_at_epoch bigint null
);

alter table if exists __SCHEMA__.refresh_tokens
    add column if not exists token_value text;

create unique index if not exists refresh_tokens_session_version_key
    on __SCHEMA__.refresh_tokens (session_id, token_version);

create unique index if not exists refresh_tokens_token_value_key
    on __SCHEMA__.refresh_tokens (token_value);

create index if not exists refresh_tokens_expires_at_idx
    on __SCHEMA__.refresh_tokens (expires_at_epoch);

create table if not exists __SCHEMA__.authorization_codes (
    code text primary key,
    account_id uuid not null references __SCHEMA__.accounts(id) on delete restrict,
    client_id text not null references __SCHEMA__.oidc_clients(client_id) on delete restrict,
    redirect_uri text not null,
    scope text null,
    nonce text null,
    code_challenge text null,
    code_challenge_method text null,
    created_at_epoch bigint not null,
    expires_at_epoch bigint not null,
    consumed_at_epoch bigint null,
    constraint authorization_codes_challenge_method_check
        check (code_challenge_method in ('plain', 'S256') or code_challenge_method is null)
);

create index if not exists authorization_codes_account_id_idx
    on __SCHEMA__.authorization_codes (account_id);

create index if not exists authorization_codes_client_id_idx
    on __SCHEMA__.authorization_codes (client_id);

create index if not exists authorization_codes_expires_at_idx
    on __SCHEMA__.authorization_codes (expires_at_epoch);

create table if not exists __SCHEMA__.email_verification_codes (
    id uuid primary key,
    account_id uuid not null references __SCHEMA__.accounts(id) on delete restrict,
    email text not null,
    code text not null,
    issued_at_epoch bigint not null,
    expires_at_epoch bigint not null,
    consumed_at_epoch bigint null
);

create index if not exists email_verification_codes_account_id_idx
    on __SCHEMA__.email_verification_codes (account_id);

create index if not exists email_verification_codes_email_code_idx
    on __SCHEMA__.email_verification_codes (email, code, issued_at_epoch desc);

create index if not exists email_verification_codes_expires_at_idx
    on __SCHEMA__.email_verification_codes (expires_at_epoch);

create table if not exists __SCHEMA__.device_nonces (
    id uuid primary key,
    device_id uuid not null references __SCHEMA__.devices(id) on delete restrict,
    challenge text not null,
    issued_at_epoch bigint not null,
    expires_at_epoch bigint not null,
    consumed_at_epoch bigint null
);

create unique index if not exists device_nonces_challenge_key
    on __SCHEMA__.device_nonces (challenge);

create index if not exists device_nonces_expires_at_idx
    on __SCHEMA__.device_nonces (expires_at_epoch);

select pg_advisory_lock(hashtext('__SCHEMA__:embedded-idp-migration'));

create table if not exists __SCHEMA__.schema_versions (
    version text primary key,
    description text not null,
    applied_at_epoch bigint not null
);

insert into __SCHEMA__.schema_versions (version, description, applied_at_epoch)
values ('0001', 'initial embedded idp schema', extract(epoch from clock_timestamp())::bigint)
on conflict (version) do nothing;

create table if not exists __SCHEMA__.device_proof_keys (
    key_id text primary key,
    device_id uuid not null references __SCHEMA__.devices(id) on delete restrict,
    algorithm text not null,
    public_jwk text not null,
    version bigint not null,
    status text not null,
    registered_at_epoch bigint not null,
    retired_at_epoch bigint null,
    constraint device_proof_keys_algorithm_check check (algorithm = 'ed25519'),
    constraint device_proof_keys_version_check check (version > 0),
    constraint device_proof_keys_status_check check (status in ('active', 'retired')),
    constraint device_proof_keys_key_id_length_check check (length(key_id) = 43),
    constraint device_proof_keys_retirement_check check (
        (status = 'active' and retired_at_epoch is null)
        or (status = 'retired' and retired_at_epoch is not null)
    ),
    unique (device_id, version)
);

create unique index if not exists device_proof_keys_one_active_per_device
    on __SCHEMA__.device_proof_keys (device_id)
    where status = 'active';

alter table if exists __SCHEMA__.device_nonces
    add column if not exists purpose text null;

alter table if exists __SCHEMA__.device_nonces
    add column if not exists challenge_digest bytea null;

alter table if exists __SCHEMA__.device_nonces
    alter column challenge drop not null;

create unique index if not exists device_nonces_challenge_digest_key
    on __SCHEMA__.device_nonces (challenge_digest)
    where challenge_digest is not null;

alter table if exists __SCHEMA__.refresh_tokens
    add column if not exists token_digest bytea null;

alter table if exists __SCHEMA__.refresh_tokens
    add column if not exists revocation_reason text null;

alter table if exists __SCHEMA__.refresh_tokens
    alter column token_value drop not null;

create unique index if not exists refresh_tokens_token_digest_key
    on __SCHEMA__.refresh_tokens (token_digest)
    where token_digest is not null;

create index if not exists refresh_tokens_active_family_idx
    on __SCHEMA__.refresh_tokens (session_id, token_version)
    where revoked_at_epoch is null;

create table if not exists __SCHEMA__.security_cutovers (
    cutover_id text primary key,
    completed_at_epoch bigint not null
);

insert into __SCHEMA__.schema_versions (version, description, applied_at_epoch)
values ('0002_expand', 'production security additive schema', extract(epoch from clock_timestamp())::bigint)
on conflict (version) do nothing;

select pg_advisory_unlock(hashtext('__SCHEMA__:embedded-idp-migration'));

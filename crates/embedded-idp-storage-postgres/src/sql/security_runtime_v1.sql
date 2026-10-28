-- Optional runtime extension; explicit installation after security_foundation_v1.
create table __SCHEMA__.security_runtime_state (
    singleton boolean primary key default true check (singleton),
    version text not null check (version = 'security_runtime_v1'),
    authority text not null check (octet_length(authority) between 1 and 128 and authority ~ '^[A-Za-z0-9_.-]+$'),
    tenancy_mode text not null check (tenancy_mode in ('disabled', 'enabled')),
    installed_at_epoch bigint not null check (installed_at_epoch >= 0),
    layout_fingerprint text not null check (layout_fingerprint ~ '^[0-9a-f]{64}$')
);

create table __SCHEMA__.security_receipts (
    purpose text not null check (purpose in ('session_revoke', 'password_change', 'password_recovery')),
    operation_id uuid not null check (operation_id <> '00000000-0000-0000-0000-000000000000'),
    account_id uuid not null check (account_id <> '00000000-0000-0000-0000-000000000000'),
    secret_key_id text not null check (octet_length(secret_key_id) between 1 and 32 and secret_key_id ~ '^[A-Za-z0-9_.-]+$'),
    secret_digest bytea not null check (octet_length(secret_digest) = 32),
    command_key_id text not null check (octet_length(command_key_id) between 1 and 32 and command_key_id ~ '^[A-Za-z0-9_.-]+$'),
    command_digest bytea not null check (octet_length(command_digest) = 32),
    completed_at_epoch bigint not null check (completed_at_epoch >= 0),
    expires_at_epoch bigint not null,
    primary key (purpose, operation_id),
    check (expires_at_epoch > completed_at_epoch and expires_at_epoch - completed_at_epoch <= 86400)
);
create index security_receipts_expiry_idx on __SCHEMA__.security_receipts(expires_at_epoch, purpose, operation_id);
create index security_receipts_account_idx on __SCHEMA__.security_receipts(account_id, completed_at_epoch, operation_id);

create table __SCHEMA__.password_recovery_budgets (
    subject_digest bytea primary key check (octet_length(subject_digest) = 32),
    window_start_epoch bigint not null check (window_start_epoch >= 0),
    start_count integer not null check (start_count between 0 and 3),
    failure_count integer not null check (failure_count between 0 and 10),
    expires_at_epoch bigint not null,
    check (expires_at_epoch > window_start_epoch and expires_at_epoch - window_start_epoch = 3600)
);
create index password_recovery_budgets_expiry_idx on __SCHEMA__.password_recovery_budgets(expires_at_epoch, subject_digest);

create table __SCHEMA__.password_recovery_flows (
    id uuid primary key check (id <> '00000000-0000-0000-0000-000000000000'),
    subject_digest bytea not null check (octet_length(subject_digest) = 32),
    account_id uuid references __SCHEMA__.accounts(id) on delete cascade check (account_id <> '00000000-0000-0000-0000-000000000000'),
    snapshot_credential_version bigint,
    handle_key_id text not null check (octet_length(handle_key_id) between 1 and 32 and handle_key_id ~ '^[A-Za-z0-9_.-]+$'),
    handle_digest bytea not null check (octet_length(handle_digest) = 32),
    code_key_id text not null check (octet_length(code_key_id) between 1 and 32 and code_key_id ~ '^[A-Za-z0-9_.-]+$'),
    code_digest bytea not null check (octet_length(code_digest) = 32),
    created_at_epoch bigint not null check (created_at_epoch >= 0),
    expires_at_epoch bigint not null,
    retained_until_epoch bigint not null,
    state text not null check (state in ('pending', 'consumed', 'invalidated', 'expired')),
    failed_attempts integer not null check (failed_attempts between 0 and 5),
    check ((account_id is null and snapshot_credential_version is null)
        or (account_id is not null and snapshot_credential_version is not null and snapshot_credential_version >= 1)),
    check (expires_at_epoch > created_at_epoch and expires_at_epoch - created_at_epoch <= 900),
    check (retained_until_epoch > created_at_epoch and retained_until_epoch - created_at_epoch = 86400)
);
create index password_recovery_flows_subject_idx on __SCHEMA__.password_recovery_flows(subject_digest, state, created_at_epoch, id);
create index password_recovery_flows_account_idx on __SCHEMA__.password_recovery_flows(account_id, state, id);
create index password_recovery_flows_expiry_idx on __SCHEMA__.password_recovery_flows(retained_until_epoch, id);
create index password_recovery_flows_state_expiry_idx on __SCHEMA__.password_recovery_flows(state, expires_at_epoch, id);

create table __SCHEMA__.password_recovery_start_receipts (
    operation_id uuid primary key check (operation_id <> '00000000-0000-0000-0000-000000000000'),
    flow_id uuid not null unique references __SCHEMA__.password_recovery_flows(id) on delete cascade,
    request_key_id text not null check (octet_length(request_key_id) between 1 and 32 and request_key_id ~ '^[A-Za-z0-9_.-]+$'),
    request_digest bytea not null check (octet_length(request_digest) = 32),
    envelope_key_id text not null check (octet_length(envelope_key_id) between 1 and 32 and envelope_key_id ~ '^[A-Za-z0-9_.-]+$'),
    ciphertext bytea not null check (octet_length(ciphertext) between 28 and 16412),
    created_at_epoch bigint not null check (created_at_epoch >= 0),
    expires_at_epoch bigint not null,
    check (expires_at_epoch > created_at_epoch and expires_at_epoch - created_at_epoch <= 900)
);
create index password_recovery_start_receipts_expiry_idx on __SCHEMA__.password_recovery_start_receipts(expires_at_epoch, operation_id);

create table __SCHEMA__.security_email_outbox (
    id uuid primary key check (id <> '00000000-0000-0000-0000-000000000000'),
    flow_id uuid not null unique references __SCHEMA__.password_recovery_flows(id) on delete cascade,
    envelope_key_id text,
    ciphertext bytea,
    state text not null check (state in ('pending', 'sending', 'accepted', 'rejected', 'unknown', 'cancelled', 'expired')),
    created_at_epoch bigint not null check (created_at_epoch >= 0),
    expires_at_epoch bigint not null,
    next_attempt_at_epoch bigint not null,
    attempts integer not null check (attempts between 0 and 3),
    lease_token uuid check (lease_token <> '00000000-0000-0000-0000-000000000000'),
    lease_until_epoch bigint,
    last_outcome text check (last_outcome in ('accepted', 'rejected', 'unknown', 'not_started')),
    check (expires_at_epoch > created_at_epoch and expires_at_epoch - created_at_epoch <= 900),
    check (next_attempt_at_epoch >= created_at_epoch),
    check ((envelope_key_id is null and ciphertext is null)
        or (envelope_key_id is not null and ciphertext is not null
            and octet_length(envelope_key_id) between 1 and 32 and envelope_key_id ~ '^[A-Za-z0-9_.-]+$'
            and octet_length(ciphertext) between 28 and 16412)),
    check ((state in ('pending', 'sending') and ciphertext is not null)
        or (state not in ('pending', 'sending') and ciphertext is null)),
    check ((state = 'sending' and lease_token is not null and lease_until_epoch is not null
            and lease_until_epoch > created_at_epoch and attempts >= 1)
        or (state <> 'sending' and lease_token is null and lease_until_epoch is null)),
    check (state <> 'pending' or attempts < 3)
);
create index security_email_outbox_claim_idx on __SCHEMA__.security_email_outbox(state, next_attempt_at_epoch, id);
create index security_email_outbox_lease_idx on __SCHEMA__.security_email_outbox(state, lease_until_epoch, id);
create index security_email_outbox_expiry_idx on __SCHEMA__.security_email_outbox(expires_at_epoch, id);

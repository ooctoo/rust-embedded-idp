-- Registration-email foundation. The storage adapter executes this text only
-- inside the explicit foundation transaction after a reviewed inventory.
-- `__SCHEMA__` is replaced with the already prepared tenant_v6 schema name.

alter table __SCHEMA__.accounts
    add column registration_security_revision bigint not null default 0
        check (registration_security_revision >= 0),
    add column registration_invalidated_at bigint not null default 0
        check (registration_invalidated_at >= 0);

alter table __SCHEMA__.access_memberships
    add column registration_invalidated_at bigint not null default 0
        check (registration_invalidated_at >= 0);

-- Existing identity rows keep their UUIDs, password hashes and references;
-- only the agreed trim/domain normalization is changed.
update __SCHEMA__.accounts
set email = case
    when position('@' in btrim(email)) > 0 then
        split_part(btrim(email), '@', 1) || '@' || lower(split_part(btrim(email), '@', 2))
    else btrim(email)
end;

create table __SCHEMA__.registration_email_state (
    authority text primary key check (authority ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    version text not null default 'registration_email_v1'
        check (version = 'registration_email_v1'),
    tenancy_mode text not null check (tenancy_mode in ('disabled', 'enabled')),
    installed_at bigint not null check (installed_at >= 0)
);

create table __SCHEMA__.registration_email_products (
    authority text not null,
    product text not null check (product ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    tenant_id text not null,
    primary key (authority, product),
    foreign key (authority) references __SCHEMA__.registration_email_state(authority),
    foreign key (tenant_id) references __SCHEMA__.access_tenants(id)
);
create index registration_email_products_tenant_idx
    on __SCHEMA__.registration_email_products(tenant_id, authority, product);

create table __SCHEMA__.registration_email_capacity (
    authority text primary key references __SCHEMA__.registration_email_state(authority),
    start_rows bigint not null default 0 check (start_rows >= 0),
    verify_rows bigint not null default 0 check (verify_rows >= 0),
    subjects bigint not null default 0 check (subjects >= 0),
    buckets bigint not null default 0 check (buckets >= 0),
    all_times bigint[] not null default '{}'::bigint[],
    start_times bigint[] not null default '{}'::bigint[],
    last_time bigint not null default 0 check (last_time >= 0),
    check (cardinality(all_times) <= 100000),
    check (cardinality(start_times) <= 100000)
);

create table __SCHEMA__.registration_email_operations (
    authority text not null check (authority ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    product text not null check (product ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    kind text not null check (kind in ('register', 'resend', 'verify')),
    operation_id uuid not null,
    request_digest bytea not null check (octet_length(request_digest) = 32),
    phase text not null check (phase in ('reserved', 'attached', 'cancelled')),
    reserved_rows bigint not null check (reserved_rows >= 0),
    lease_until bigint not null check (lease_until >= 0),
    fence bigint not null check (fence >= 0),
    context_id uuid,
    result text check (result is null or result in ('accepted', 'verified', 'unavailable')),
    accepted_at bigint check (accepted_at is null or accepted_at >= 0),
    retain_until bigint not null check (retain_until >= 0),
    primary key (authority, product, kind, operation_id),
    foreign key (authority, product)
        references __SCHEMA__.registration_email_products(authority, product)
);
create index registration_email_operations_phase_idx
    on __SCHEMA__.registration_email_operations(authority, product, phase, retain_until);
create index registration_email_operations_lease_idx
    on __SCHEMA__.registration_email_operations(lease_until, authority, product)
    where phase = 'reserved';

create table __SCHEMA__.registration_email_subjects (
    authority text not null references __SCHEMA__.registration_email_state(authority),
    subject bytea not null check (octet_length(subject) = 32),
    sends bigint[] not null default '{}'::bigint[],
    wrongs bigint[] not null default '{}'::bigint[],
    blocked_until bigint not null default 0 check (blocked_until >= 0),
    last_time bigint not null default 0 check (last_time >= 0),
    retain_until bigint not null check (retain_until >= 0),
    check (cardinality(sends) <= 100000),
    check (cardinality(wrongs) <= 100000),
    primary key (authority, subject)
);
create index registration_email_subjects_retain_idx
    on __SCHEMA__.registration_email_subjects(retain_until, authority);

create table __SCHEMA__.registration_email_buckets (
    authority text not null,
    product text not null,
    subject bytea not null check (octet_length(subject) = 32),
    sends bigint[] not null default '{}'::bigint[],
    wrongs bigint[] not null default '{}'::bigint[],
    blocked_until bigint not null default 0 check (blocked_until >= 0),
    last_time bigint not null default 0 check (last_time >= 0),
    retain_until bigint not null check (retain_until >= 0),
    check (cardinality(sends) <= 100000),
    check (cardinality(wrongs) <= 100000),
    primary key (authority, product, subject),
    foreign key (authority, product)
        references __SCHEMA__.registration_email_products(authority, product)
);
create index registration_email_buckets_retain_idx
    on __SCHEMA__.registration_email_buckets(retain_until, authority, product);

create table __SCHEMA__.registration_email_contexts (
    id uuid primary key,
    authority text not null,
    product text not null,
    tenant_id text not null,
    subject bytea not null check (octet_length(subject) = 32),
    lookup_digest bytea not null unique check (octet_length(lookup_digest) = 32),
    seed bytea not null check (octet_length(seed) = 32),
    email_cipher bytea not null check (octet_length(email_cipher) > 0),
    -- Verification zeroizes the candidate after activation.
    password_cipher bytea not null,
    accepted_at bigint not null check (accepted_at >= 0),
    expires_at bigint not null check (expires_at > accepted_at),
    deliverable boolean not null,
    wrong_count integer not null default 0 check (wrong_count >= 0),
    accepted_seq bigint not null check (accepted_seq > 0),
    current_seq bigint check (current_seq is null or current_seq > 0),
    prepared boolean not null default false,
    bound_account uuid,
    bound_revision bigint check (bound_revision is null or bound_revision >= 0),
    bound_member_version bigint check (bound_member_version is null or bound_member_version >= 0),
    completed_operation uuid,
    foreign key (authority, product)
        references __SCHEMA__.registration_email_products(authority, product),
    foreign key (tenant_id) references __SCHEMA__.access_tenants(id)
);
create index registration_email_contexts_expiry_idx
    on __SCHEMA__.registration_email_contexts(expires_at, authority, product);

create table __SCHEMA__.registration_email_intents (
    operation_id uuid not null,
    context_id uuid not null references __SCHEMA__.registration_email_contexts(id),
    seq bigint not null check (seq > 0),
    kind text not null check (kind in ('register', 'resend', 'verify')),
    status text not null check (status in ('reserved', 'prepared', 'suppressed', 'superseded', 'expired')),
    created_at bigint not null check (created_at >= 0),
    lease_until bigint check (lease_until is null or lease_until >= created_at),
    claim_token uuid,
    primary key (context_id, seq)
);
create index registration_email_intents_lease_idx
    on __SCHEMA__.registration_email_intents(lease_until, status)
    where lease_until is not null;

create table __SCHEMA__.registration_email_codes (
    context_id uuid not null references __SCHEMA__.registration_email_contexts(id),
    seq bigint not null check (seq > 0),
    digest bytea not null check (octet_length(digest) = 32),
    issued_at bigint not null check (issued_at >= 0),
    expires_at bigint not null check (expires_at > issued_at),
    consumed_at bigint check (consumed_at is null or consumed_at >= issued_at),
    primary key (context_id, seq)
);
create index registration_email_codes_expiry_idx
    on __SCHEMA__.registration_email_codes(expires_at, context_id);

create table __SCHEMA__.registration_email_deliveries (
    id uuid primary key,
    context_id uuid not null,
    seq bigint not null,
    -- Delivery cleanup zeroizes payloads after send/expiry/unknown outcomes.
    payload_cipher bytea not null,
    status text not null check (status in ('reserved', 'claimed', 'sent', 'failed', 'unknown', 'expired')),
    claim_token uuid,
    lease_until bigint check (lease_until is null or lease_until >= 0),
    stop_confirmed boolean not null default false,
    foreign key (context_id, seq)
        references __SCHEMA__.registration_email_codes(context_id, seq)
);
create index registration_email_deliveries_lease_idx
    on __SCHEMA__.registration_email_deliveries(lease_until, status)
    where lease_until is not null;

create table __SCHEMA__.registration_email_events (
    id uuid primary key,
    authority text not null check (authority ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    product text not null check (product ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    operation_id uuid not null,
    kind text not null check (octet_length(kind) between 1 and 64),
    reason text not null check (octet_length(reason) between 1 and 256),
    subject bytea check (subject is null or octet_length(subject) = 32),
    context_id uuid,
    policy_revision text not null check (octet_length(policy_revision) between 1 and 128),
    created_at bigint not null check (created_at >= 0)
);
create index registration_email_events_created_idx
    on __SCHEMA__.registration_email_events(authority, created_at, id);

create table __SCHEMA__.registration_email_tombstones (
    email text primary key check (octet_length(email) between 1 and 254),
    account_id uuid not null,
    revision bigint not null check (revision >= 0),
    invalidated_at bigint not null check (invalidated_at >= 0),
    retain_until bigint not null check (retain_until >= invalidated_at)
);
create index registration_email_tombstones_retain_idx
    on __SCHEMA__.registration_email_tombstones(retain_until, email);

-- Membership tombstones deliberately have no foreign keys.  A deleted
-- membership must keep invalidating a private registration context even when
-- an administrator recreates the account or membership row.
create table __SCHEMA__.registration_email_member_tombstones (
    tenant text not null check (length(btrim(tenant)) between 1 and 128),
    account_id uuid not null,
    invalidated_at bigint not null check (invalidated_at >= 0),
    retain_until bigint not null check (retain_until >= invalidated_at),
    primary key (tenant, account_id)
);
create index registration_email_member_tombstones_retain_idx
    on __SCHEMA__.registration_email_member_tombstones(retain_until, tenant, account_id);

-- Consume all legacy codes before making the old writer fail closed.
update __SCHEMA__.email_verification_codes
set consumed_at_epoch = coalesce(
    consumed_at_epoch,
    floor(extract(epoch from clock_timestamp()))::bigint
);

-- Once the cutover has normalized existing rows, future writes must already
-- satisfy the same narrow core parser identity.  The check covers both
-- INSERT and UPDATE without duplicating a second normalization path.
create function __SCHEMA__.registration_email_is_canonical(value text)
returns boolean language plpgsql immutable as $fn$
declare local_part text;
declare domain_part text;
begin
    if value is null
       or value <> btrim(value, ' ')
       or octet_length(value) > 254
       or value ~ $$[^ -~]$$ then
        return false;
    end if;
    if length(value) - length(replace(value, '@', '')) <> 1 then
        return false;
    end if;
    local_part := split_part(value, '@', 1);
    domain_part := split_part(value, '@', 2);
    if octet_length(local_part) not between 1 and 64
       or local_part !~ $$^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$$
       or left(local_part, 1) = '.'
       or right(local_part, 1) = '.'
       or position('..' in local_part) > 0 then
        return false;
    end if;
    if octet_length(domain_part) = 0
       or octet_length(domain_part) > 253
       or domain_part <> lower(domain_part)
       or domain_part !~ $$^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$$ then
        return false;
    end if;
    return value = local_part || '@' || lower(domain_part);
end;
$fn$;
alter table __SCHEMA__.accounts
    add constraint registration_email_account_email_canonical_ck
    check (__SCHEMA__.registration_email_is_canonical(email));

create function __SCHEMA__.registration_email_write_email_tombstone(
    email_value text,
    target_account uuid,
    target_revision bigint,
    target_invalidated_at bigint
)
returns void language plpgsql as $$
declare canonical_email text;
begin
    canonical_email := case
        when position('@' in btrim(email_value)) > 0 then
            split_part(btrim(email_value), '@', 1) || '@' || lower(split_part(btrim(email_value), '@', 2))
        else btrim(email_value)
    end;
    insert into __SCHEMA__.registration_email_tombstones(
        email, account_id, revision, invalidated_at, retain_until
    )
    values (
        canonical_email,
        target_account,
        target_revision,
        target_invalidated_at,
        target_invalidated_at + 960
    )
    on conflict(email) do update set
        account_id = excluded.account_id,
        revision = greatest(__SCHEMA__.registration_email_tombstones.revision, excluded.revision),
        invalidated_at = greatest(
            __SCHEMA__.registration_email_tombstones.invalidated_at,
            excluded.invalidated_at
        ),
        retain_until = greatest(
            __SCHEMA__.registration_email_tombstones.retain_until,
            excluded.retain_until
        );
end $$;

create function __SCHEMA__.registration_email_account_security_bu()
returns trigger language plpgsql as $$
declare now_epoch bigint;
begin
    if (new.password_hash, new.status, new.email, new.registration_tenant_id)
       is distinct from (old.password_hash, old.status, old.email, old.registration_tenant_id) then
        now_epoch := floor(extract(epoch from clock_timestamp()))::bigint;
        new.registration_security_revision := old.registration_security_revision + 1;
        new.registration_invalidated_at := greatest(
            old.registration_invalidated_at,
            now_epoch
        );
    end if;
    if new.email is distinct from old.email then
        perform __SCHEMA__.registration_email_write_email_tombstone(
            old.email,
            old.id,
            new.registration_security_revision,
            new.registration_invalidated_at
        );
    end if;
    return new;
end $$;
create trigger registration_email_account_security_bu
before update on __SCHEMA__.accounts
for each row execute function __SCHEMA__.registration_email_account_security_bu();

create function __SCHEMA__.registration_email_account_tombstone_bd()
returns trigger language plpgsql as $$
declare now_epoch bigint;
begin
    now_epoch := floor(extract(epoch from clock_timestamp()))::bigint;
    perform __SCHEMA__.registration_email_write_email_tombstone(
        old.email,
        old.id,
        old.registration_security_revision,
        greatest(old.registration_invalidated_at, now_epoch)
    );
    return old;
end $$;
create trigger registration_email_account_tombstone_bd
before delete on __SCHEMA__.accounts
for each row execute function __SCHEMA__.registration_email_account_tombstone_bd();

create function __SCHEMA__.registration_email_member_security_bu()
returns trigger language plpgsql as $$
begin
    if (new.status, new.version, new.joined_at_epoch)
       is distinct from (old.status, old.version, old.joined_at_epoch) then
        new.registration_invalidated_at := greatest(
            old.registration_invalidated_at,
            floor(extract(epoch from clock_timestamp()))::bigint
        );
    end if;
    return new;
end $$;
create trigger registration_email_member_security_bu
before update on __SCHEMA__.access_memberships
for each row execute function __SCHEMA__.registration_email_member_security_bu();

create function __SCHEMA__.registration_email_member_tombstone_bd()
returns trigger language plpgsql as $$
declare now_epoch bigint;
begin
    now_epoch := greatest(
        old.registration_invalidated_at,
        floor(extract(epoch from clock_timestamp()))::bigint
    );
    insert into __SCHEMA__.registration_email_member_tombstones(
        tenant, account_id, invalidated_at, retain_until
    )
    values (old.tenant_id, old.account_id, now_epoch, now_epoch + 960)
    on conflict(tenant, account_id) do update set
        invalidated_at = greatest(
            __SCHEMA__.registration_email_member_tombstones.invalidated_at,
            excluded.invalidated_at
        ),
        retain_until = greatest(
            __SCHEMA__.registration_email_member_tombstones.retain_until,
            excluded.retain_until
        );
    return old;
end $$;
create trigger registration_email_member_tombstone_bd
before delete on __SCHEMA__.access_memberships
for each row execute function __SCHEMA__.registration_email_member_tombstone_bd();

create function __SCHEMA__.registration_email_legacy_code_guard()
returns trigger language plpgsql as $$
begin
    raise exception using errcode='55000',
        message='legacy email verification codes disabled; coordinated registration-email cutover required';
end $$;
create trigger registration_email_legacy_code_guard
before insert or update on __SCHEMA__.email_verification_codes
for each row execute function __SCHEMA__.registration_email_legacy_code_guard();

create function __SCHEMA__.registration_email_state_guard()
returns trigger language plpgsql as $$
begin
    if tg_op = 'DELETE' then
        raise exception using errcode='23514', message='registration-email foundation identity is immutable';
    end if;
    if (new.authority,new.version,new.tenancy_mode)
       is distinct from (old.authority,old.version,old.tenancy_mode) then
        raise exception using errcode='23514', message='registration-email foundation identity is immutable';
    end if;
    return new;
end $$;
create trigger registration_email_state_guard
before update or delete on __SCHEMA__.registration_email_state
for each row execute function __SCHEMA__.registration_email_state_guard();

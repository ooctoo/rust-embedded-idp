-- Optional, explicitly installed security foundation. This is not part of tenant_v6.
alter table __SCHEMA__.accounts
    add column security_credential_version bigint not null default 1;
alter table __SCHEMA__.accounts
    add constraint accounts_security_credential_version_ck
        check (security_credential_version > 0);

create function __SCHEMA__.security_foundation_account_credential_version()
returns trigger language plpgsql as $$
begin
    if tg_op = 'INSERT' then
        if new.security_credential_version is distinct from 1 then
            raise exception using errcode='23514', message='credential version is database managed';
        end if;
        new.security_credential_version := 1;
        return new;
    end if;

    if new.security_credential_version is distinct from old.security_credential_version then
        raise exception using errcode='23514', message='credential version is database managed';
    end if;

    if (new.password_hash, new.status, new.email, new.registration_tenant_id)
       is distinct from (old.password_hash, old.status, old.email, old.registration_tenant_id) then
        new.security_credential_version := old.security_credential_version + 1;
    else
        new.security_credential_version := old.security_credential_version;
    end if;
    return new;
end $$;
create trigger security_foundation_account_credential_version_biu
before insert or update on __SCHEMA__.accounts
for each row execute function __SCHEMA__.security_foundation_account_credential_version();

create table __SCHEMA__.security_state (
    singleton boolean primary key default true check (singleton),
    version text not null check (version = 'security_foundation_v1'),
    authority text not null
        check (octet_length(authority) between 1 and 128
            and authority ~ '^[A-Za-z0-9_.-]+$'),
    tenancy_mode text not null check (tenancy_mode in ('disabled', 'enabled')),
    installed_at_epoch bigint not null check (installed_at_epoch >= 0),
    layout_fingerprint text not null
        check (layout_fingerprint ~ '^[0-9a-f]{64}$')
);

create table __SCHEMA__.security_events (
    id uuid primary key,
    kind text not null check (kind in (
        'password_changed', 'session_revoked', 'recovery_started',
        'recovery_failed', 'recovery_completed', 'email_delivery'
    )),
    outcome text not null check (outcome in ('accepted', 'rejected', 'unknown')),
    account_id uuid,
    operation_id uuid,
    occurred_at_epoch bigint not null check (occurred_at_epoch >= 0)
);
create index security_events_occurred_idx
    on __SCHEMA__.security_events(occurred_at_epoch, id);
create index security_events_account_idx
    on __SCHEMA__.security_events(account_id, occurred_at_epoch, id);

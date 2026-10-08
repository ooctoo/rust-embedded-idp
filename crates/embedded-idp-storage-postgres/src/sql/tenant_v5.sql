-- Tenant model. Applied atomically beside non-conflicting host objects.
create table __SCHEMA__.access_state (
    singleton boolean primary key default true check (singleton),
    tenancy_mode text not null check (tenancy_mode in ('disabled', 'enabled')),
    module_version text not null check (module_version = 'tenant_v5'),
    bootstrap_completed_at_epoch bigint
);
create table __SCHEMA__.access_tenants (
    id text collate "C" primary key check (id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    kind text not null check ((id = '0' and kind = 'system') or (id <> '0' and kind = 'tenant')),
    name text not null check (length(btrim(name)) > 0),
    status text not null check (status in ('active', 'suspended', 'archived')),
    allow_registration boolean not null default false,
    version bigint not null default 1 check (version > 0),
    created_at_epoch bigint not null,
    check (id <> '0' or status = 'active')
);
create table __SCHEMA__.accounts (
    id uuid primary key,
    registration_tenant_id text not null references __SCHEMA__.access_tenants(id),
    email text not null unique check (length(btrim(email)) > 0),
    password_hash text not null check (length(password_hash) > 0),
    display_name text,
    status text not null check (status in ('pending_verification', 'active', 'disabled', 'closed')),
    created_at_epoch bigint not null
);
create table __SCHEMA__.access_memberships (
    tenant_id text not null references __SCHEMA__.access_tenants(id),
    account_id uuid not null references __SCHEMA__.accounts(id),
    status text not null check (status in ('active', 'suspended', 'removed')),
    version bigint not null default 1 check (version > 0),
    joined_at_epoch bigint not null,
    removed_at_epoch bigint,
    primary key (tenant_id, account_id),
    check ((status = 'removed') = (removed_at_epoch is not null))
);
-- Retain the original registration membership row as history, even after removal.
alter table __SCHEMA__.accounts add constraint account_registration_membership
    foreign key (registration_tenant_id, id)
    references __SCHEMA__.access_memberships(tenant_id, account_id)
    deferrable initially deferred;
create index access_memberships_by_account on __SCHEMA__.access_memberships(account_id, tenant_id) include(status);

create table __SCHEMA__.access_permissions (
    tenant_id text not null references __SCHEMA__.access_tenants(id),
    business_id text collate "C" not null check (business_id ~ '^[a-z][a-z0-9_.-]{0,63}$' and (business_id='idp' or business_id not like 'idp.%')),
    resource_type text collate "C" not null check (resource_type ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    action text collate "C" not null check (action ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    category text not null check (category in ('platform', 'tenant', 'business')),
    description text not null,
    enabled boolean not null,
    archived boolean not null default false,
    version bigint not null default 1 check (version > 0),
    primary key(tenant_id, business_id, resource_type, action),
    check (not archived or not enabled),
    check ((business_id = 'idp') = (category in ('platform', 'tenant'))),
    created_at_epoch bigint default floor(extract(epoch from clock_timestamp()))::bigint
);
create table __SCHEMA__.access_roles (
    tenant_id text not null references __SCHEMA__.access_tenants(id),
    business_id text collate "C" not null check (business_id ~ '^[a-z][a-z0-9_.-]{0,63}$' and (business_id='idp' or business_id not like 'idp.%')),
    id uuid not null,
    key text not null check (key ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    name text not null check (length(btrim(name)) > 0 and octet_length(name) <= 256),
    status text not null check (status in ('active', 'disabled')),
    kind text not null check (kind in ('system_admin', 'tenant_security_admin', 'business', 'business_admin')),
    version bigint not null default 1 check (version > 0),
    created_at_epoch bigint not null,
    primary key(tenant_id, id), unique(tenant_id, business_id, id), unique(tenant_id, business_id, key),
    check (kind <> 'system_admin' or (tenant_id = '0' and business_id = 'idp' and key = 'idp_system_admin')),
    check (kind <> 'tenant_security_admin' or (business_id = 'idp' and key = 'idp_tenant_security_admin')),
    check (kind <> 'business_admin' or (business_id <> 'idp' and key = 'business_admin')),
    check (kind <> 'business' or (business_id <> 'idp' and key not in ('system_admin', 'tenant_security_admin', 'idp_system_admin', 'idp_tenant_security_admin', 'business_admin')))
);
create unique index access_protected_role_unique on __SCHEMA__.access_roles(tenant_id, kind) where kind in ('system_admin', 'tenant_security_admin');
create unique index access_business_admin_unique on __SCHEMA__.access_roles(tenant_id, business_id) where kind='business_admin';
create table __SCHEMA__.access_role_permissions (
    tenant_id text not null,
    business_id text collate "C" not null,
    role_id uuid not null,
    resource_type text collate "C" not null,
    action text collate "C" not null,
    primary key(tenant_id, business_id, role_id, resource_type, action),
    foreign key(tenant_id, business_id, role_id) references __SCHEMA__.access_roles(tenant_id, business_id, id),
    foreign key(tenant_id, business_id, resource_type, action) references __SCHEMA__.access_permissions(tenant_id, business_id, resource_type, action)
);
create table __SCHEMA__.access_role_bindings (
    id uuid primary key,
    tenant_id text not null,
    business_id text collate "C" not null,
    account_id uuid not null,
    role_id uuid not null,
    scope_kind text not null check (scope_kind in ('business','type','instance')),
    resource_type text collate "C" check (resource_type ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    resource_id text collate "C" check (resource_id ~ '^[A-Za-z0-9_.-]+$' and octet_length(resource_id) <= 256),
    created_at_epoch bigint not null,
    created_by uuid not null references __SCHEMA__.accounts(id),
    foreign key(tenant_id, account_id) references __SCHEMA__.access_memberships(tenant_id, account_id),
    foreign key(tenant_id, business_id, role_id) references __SCHEMA__.access_roles(tenant_id, business_id, id),
    check ((scope_kind='business' and resource_type is null and resource_id is null)
        or (scope_kind='type' and resource_type is not null and resource_id is null)
        or (scope_kind='instance' and resource_type is not null and resource_id is not null))
);
create unique index access_binding_business_unique on __SCHEMA__.access_role_bindings(tenant_id,business_id,account_id,role_id) where scope_kind='business';
create unique index access_binding_type_unique on __SCHEMA__.access_role_bindings(tenant_id,business_id,account_id,role_id,resource_type) where scope_kind='type';
create unique index access_binding_instance_unique on __SCHEMA__.access_role_bindings(tenant_id,business_id,account_id,role_id,resource_type,resource_id) where scope_kind='instance';
create index access_binding_check on __SCHEMA__.access_role_bindings(tenant_id,business_id,account_id,resource_type,resource_id,role_id) where scope_kind <> 'business';
create index access_binding_subject_page on __SCHEMA__.access_role_bindings(tenant_id,business_id,account_id,id);
create index access_binding_by_role on __SCHEMA__.access_role_bindings(tenant_id,business_id,role_id,account_id);
create index access_binding_by_resource on __SCHEMA__.access_role_bindings(tenant_id,business_id,resource_type,resource_id,id) where scope_kind <> 'business';
create table __SCHEMA__.access_audit_events (
    id uuid primary key,
    occurred_at_epoch bigint not null,
    actor_id uuid not null references __SCHEMA__.accounts(id),
    actor_domain text not null,
    actor_session_id uuid,
    authentication_source text not null,
    target_domain text not null references __SCHEMA__.access_tenants(id),
    target_business_id text collate "C",
    operation text not null,
    request_id text not null,
    change_json jsonb not null,
    device_operation_id uuid,
    device_command_sha256 bytea,
    check ((device_operation_id is null and device_command_sha256 is null) or
        (device_operation_id is not null and octet_length(device_command_sha256)=32)),
    check ((authentication_source = 'offline_bootstrap' and actor_session_id is null and operation = 'access.bootstrap')
        or (authentication_source = 'offline_migration' and actor_session_id is null and operation in ('access.migrate_business_scope','access.migrate_device_lifecycle') and actor_domain='0' and target_domain='0' and target_business_id is null)
        or (authentication_source not in ('offline_bootstrap','offline_migration') and actor_session_id is not null)),
    foreign key(actor_domain, actor_id) references __SCHEMA__.access_memberships(tenant_id, account_id)
);
create index access_audit_domain_page on __SCHEMA__.access_audit_events(target_domain, occurred_at_epoch, id);
create index access_audit_business_page on __SCHEMA__.access_audit_events(target_domain,target_business_id,occurred_at_epoch,id) where target_business_id is not null;
create unique index access_audit_device_operation on __SCHEMA__.access_audit_events(actor_domain,actor_id,target_domain,device_operation_id) where device_operation_id is not null;

create table __SCHEMA__.oidc_clients (
    client_id text collate "C" primary key, client_name text not null, redirect_uris_json text not null,
    client_type text not null check (client_type in ('public_desktop','confidential_web')),
    pkce_required boolean not null, client_secret_hash text, created_at_epoch bigint not null
);
create table __SCHEMA__.devices (
    tenant_id text not null references __SCHEMA__.access_tenants(id), id uuid not null,
    client_id text not null references __SCHEMA__.oidc_clients(client_id), device_name text not null,
    proof_key_id text unique, status text not null check (status in ('pending','active','disabled','revoked')),
    version bigint not null default 1 check (version > 0),
    registered_at_epoch bigint not null, last_seen_at_epoch bigint,
    primary key(tenant_id,id), unique(tenant_id,id,client_id)
);
create index devices_tenant_client_page on __SCHEMA__.devices(tenant_id,client_id,id);
create table __SCHEMA__.auth_sessions (
    purpose text not null default 'business' constraint auth_session_purpose check(purpose in ('business','management')),
    tenant_id text not null, id uuid not null, account_id uuid not null,
    client_id text not null references __SCHEMA__.oidc_clients(client_id), device_id uuid,
    status text not null check (status in ('pending','active','revoked','expired')),
    created_at_epoch bigint not null, expires_at_epoch bigint not null check (expires_at_epoch > created_at_epoch),
    refresh_token_version bigint not null check (refresh_token_version > 0),
    scope text constraint auth_session_scope_length check(scope is null or octet_length(scope)<=1024),
    authenticated_at_epoch bigint not null constraint auth_session_auth_time check(authenticated_at_epoch<=created_at_epoch),
    primary key(tenant_id,id),
    foreign key(tenant_id,account_id) references __SCHEMA__.access_memberships(tenant_id,account_id),
    foreign key(tenant_id,device_id) references __SCHEMA__.devices(tenant_id,id)
);
create index sessions_tenant_account on __SCHEMA__.auth_sessions(tenant_id,account_id,status);
create index sessions_account_scope on __SCHEMA__.auth_sessions(account_id,tenant_id,id);
create table __SCHEMA__.account_device_bindings (
    tenant_id text not null, id uuid not null, account_id uuid not null, device_id uuid not null,
    status text not null check(status in ('active','unbound','suspended')),
    version bigint not null default 1 check (version > 0),
    bound_at_epoch bigint not null, unbound_at_epoch bigint, last_authenticated_at_epoch bigint,
    primary key(tenant_id,id),
    foreign key(tenant_id,account_id) references __SCHEMA__.access_memberships(tenant_id,account_id),
    foreign key(tenant_id,device_id) references __SCHEMA__.devices(tenant_id,id)
);
create unique index device_binding_active_unique on __SCHEMA__.account_device_bindings(tenant_id,account_id,device_id) where status <> 'unbound';
create index device_binding_account on __SCHEMA__.account_device_bindings(tenant_id,account_id,device_id);
create index device_binding_device_page on __SCHEMA__.account_device_bindings(tenant_id,device_id,bound_at_epoch,id);
create table __SCHEMA__.refresh_tokens (
    tenant_id text not null, id uuid not null, session_id uuid not null,
    token_digest bytea not null unique check(octet_length(token_digest)=32), token_version bigint not null check(token_version>0),
    issued_at_epoch bigint not null, expires_at_epoch bigint not null check(expires_at_epoch>issued_at_epoch),
    revoked_at_epoch bigint, revocation_reason text,
    primary key(tenant_id,id), unique(tenant_id,session_id,token_version),
    foreign key(tenant_id,session_id) references __SCHEMA__.auth_sessions(tenant_id,id),
    check ((revoked_at_epoch is null and revocation_reason is null) or
        (revoked_at_epoch is not null and revocation_reason is not null and revocation_reason in ('rotated','reuse_detected','logout','client_revocation','administrative','security_cutover')))
);
create index refresh_active_family on __SCHEMA__.refresh_tokens(tenant_id,session_id,token_version) where revoked_at_epoch is null;
create table __SCHEMA__.authorization_codes (
    tenant_id text not null, code_digest bytea primary key constraint authorization_code_digest_length check(octet_length(code_digest)=32),
    account_id uuid not null, source_session_id uuid not null, login_entry text not null,
    client_id text not null references __SCHEMA__.oidc_clients(client_id), redirect_uri text not null,
    scope text not null, nonce text,
    code_challenge text, code_challenge_method text check(code_challenge_method in ('plain','S256')),
    created_at_epoch bigint not null, expires_at_epoch bigint not null check(expires_at_epoch>created_at_epoch), consumed_at_epoch bigint,
    foreign key(tenant_id,account_id) references __SCHEMA__.access_memberships(tenant_id,account_id),
    constraint authorization_code_source_session foreign key(tenant_id,source_session_id) references __SCHEMA__.auth_sessions(tenant_id,id),
    constraint authorization_code_pkce_pair check((code_challenge is null)=(code_challenge_method is null))
);
create index codes_tenant_account on __SCHEMA__.authorization_codes(tenant_id,account_id);
create index codes_account on __SCHEMA__.authorization_codes(account_id);
create table __SCHEMA__.email_verification_codes (
    tenant_id text not null, id uuid primary key, account_id uuid not null, email text not null, code text not null,
    issued_at_epoch bigint not null, expires_at_epoch bigint not null check(expires_at_epoch>issued_at_epoch), consumed_at_epoch bigint,
    foreign key(tenant_id,account_id) references __SCHEMA__.access_memberships(tenant_id,account_id)
);
create index verification_lookup on __SCHEMA__.email_verification_codes(tenant_id,email,code,issued_at_epoch desc);
create index verification_account on __SCHEMA__.email_verification_codes(account_id);
create table __SCHEMA__.auth_tenant_selections (
    id uuid primary key, ticket_digest bytea not null unique check(octet_length(ticket_digest)=32),
    account_id uuid not null references __SCHEMA__.accounts(id), client_id text not null references __SCHEMA__.oidc_clients(client_id),
    login_entry text not null, purpose text not null, authenticated_at_epoch bigint not null,
    expires_at_epoch bigint not null check(expires_at_epoch>authenticated_at_epoch), consumed_at_epoch bigint, revoked_at_epoch bigint,
    source_tenant_id text, source_session_id uuid,
    check ((source_tenant_id is null) = (source_session_id is null)),
    foreign key(source_tenant_id,source_session_id) references __SCHEMA__.auth_sessions(tenant_id,id)
);
create index selections_account on __SCHEMA__.auth_tenant_selections(account_id);
create index selections_expiry on __SCHEMA__.auth_tenant_selections(expires_at_epoch);
create index selections_active_source on __SCHEMA__.auth_tenant_selections(source_tenant_id,account_id) where revoked_at_epoch is null;
create table __SCHEMA__.device_proof_keys (
    tenant_id text not null, key_id text primary key check(length(key_id)=43), device_id uuid not null,
    algorithm text not null check(algorithm='ed25519'), public_jwk text not null, version bigint not null check(version>0),
    status text not null check(status in ('active','retired')), registered_at_epoch bigint not null, retired_at_epoch bigint,
    foreign key(tenant_id,device_id) references __SCHEMA__.devices(tenant_id,id), unique(tenant_id,device_id,version), unique(tenant_id,device_id,key_id),
    check ((status='active') = (retired_at_epoch is null))
);
create unique index device_key_active on __SCHEMA__.device_proof_keys(tenant_id,device_id) where status='active';
create table __SCHEMA__.device_registrations (
    tenant_id text not null, client_id text not null, registration_scope text collate "C" not null
      check(registration_scope ~ '^[A-Za-z0-9_.-]{1,128}$'),
    registration_request_id uuid not null, device_id uuid not null,
    device_name text not null check(octet_length(device_name) between 1 and 256),
    expected_key_id text not null unique check(length(expected_key_id)=43), public_jwk text not null,
    created_at_epoch bigint not null, expires_at_epoch bigint not null check(expires_at_epoch>created_at_epoch),
    completed_at_epoch bigint check(completed_at_epoch is null or (completed_at_epoch>=created_at_epoch and completed_at_epoch<expires_at_epoch)),
    primary key(tenant_id,client_id,registration_scope,registration_request_id),
    unique(tenant_id,device_id),
    foreign key(tenant_id,device_id,client_id) references __SCHEMA__.devices(tenant_id,id,client_id)
);
alter table __SCHEMA__.devices add constraint device_current_key_tenant
    foreign key(tenant_id,id,proof_key_id) references __SCHEMA__.device_proof_keys(tenant_id,device_id,key_id)
    deferrable initially deferred;
create table __SCHEMA__.device_nonces (
    tenant_id text not null, id uuid primary key, device_id uuid not null,
    purpose text not null check(purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
    challenge_digest bytea not null unique check(octet_length(challenge_digest)=32),
    issued_at_epoch bigint not null, expires_at_epoch bigint not null check(expires_at_epoch>issued_at_epoch), consumed_at_epoch bigint,
    foreign key(tenant_id,device_id) references __SCHEMA__.devices(tenant_id,id),
    check(consumed_at_epoch is null or consumed_at_epoch>=issued_at_epoch)
);
create index nonce_expiry on __SCHEMA__.device_nonces(expires_at_epoch);
create index nonce_tenant_device on __SCHEMA__.device_nonces(tenant_id,device_id);

-- Deferred invariant allows account + first membership to be created atomically.
-- Updating the account row serializes concurrent removals even at stronger
-- isolation (which may return a serialization failure instead of stale success).
create function __SCHEMA__.access_require_membership() returns trigger language plpgsql as $$
declare target uuid; current_status text;
begin
    if TG_TABLE_NAME = 'accounts' then target := NEW.id;
    elsif TG_OP = 'DELETE' then target := OLD.account_id;
    else target := NEW.account_id; end if;
    update __SCHEMA__.accounts set status = status where id = target returning status into current_status;
    if found and current_status <> 'closed' and not exists (
        select 1 from __SCHEMA__.access_memberships where account_id=target and status <> 'removed'
    ) then raise exception using errcode='23514', message='account requires membership'; end if;
    return null;
end $$;
-- Only status transitions run the account trigger; the lock-only UPDATE above
-- must not recursively enqueue another deferred invariant.
create constraint trigger account_requires_membership after insert on __SCHEMA__.accounts
    deferrable initially deferred for each row execute function __SCHEMA__.access_require_membership();
create constraint trigger account_status_requires_membership after update of status on __SCHEMA__.accounts
    deferrable initially deferred for each row
    when (OLD.status is distinct from NEW.status) execute function __SCHEMA__.access_require_membership();
create constraint trigger membership_requires_membership after insert or update or delete on __SCHEMA__.access_memberships
    deferrable initially deferred for each row execute function __SCHEMA__.access_require_membership();

create function __SCHEMA__.access_guard_domain() returns trigger language plpgsql as $$
begin
    if TG_OP = 'DELETE' then
        if OLD.id='0' then raise exception using errcode='23514', message='system domain is required'; end if;
        return OLD;
    end if;
    if TG_OP='UPDATE' and (NEW.id,NEW.kind) is distinct from (OLD.id,OLD.kind) then
        raise exception using errcode='23514', message='domain identity is immutable';
    end if;
    if NEW.id <> '0' and not exists(select 1 from __SCHEMA__.access_state where tenancy_mode='enabled') then
        raise exception using errcode='23514', message='tenancy disabled';
    end if;
    return NEW;
end $$;
create trigger access_domain_guard before insert or update or delete on __SCHEMA__.access_tenants
    for each row execute function __SCHEMA__.access_guard_domain();

create function __SCHEMA__.access_guard_state() returns trigger language plpgsql as $$
begin
    if TG_OP='DELETE' or (NEW.tenancy_mode,NEW.module_version) is distinct from (OLD.tenancy_mode,OLD.module_version) then
        raise exception using errcode='23514', message='deployment mode and version are immutable';
    end if;
    return NEW;
end $$;
create trigger access_state_guard before update or delete on __SCHEMA__.access_state
    for each row execute function __SCHEMA__.access_guard_state();

create function __SCHEMA__.access_guard_membership_identity() returns trigger language plpgsql as $$
begin
    if (NEW.tenant_id,NEW.account_id) is distinct from (OLD.tenant_id,OLD.account_id) then
        raise exception using errcode='23514', message='membership identity is immutable';
    end if;
    return NEW;
end $$;
create trigger membership_identity_guard before update on __SCHEMA__.access_memberships
    for each row execute function __SCHEMA__.access_guard_membership_identity();

create function __SCHEMA__.access_guard_device_identity() returns trigger language plpgsql as $$
begin
    if (NEW.tenant_id,NEW.id) is distinct from (OLD.tenant_id,OLD.id) then
        raise exception using errcode='23514', message='device identity is immutable';
    end if;
    return NEW;
end $$;
create trigger device_identity_guard before update on __SCHEMA__.devices
    for each row execute function __SCHEMA__.access_guard_device_identity();

create function __SCHEMA__.access_guard_role_identity() returns trigger language plpgsql as $$
begin
    if TG_OP='UPDATE' and (NEW.tenant_id,NEW.business_id,NEW.key,NEW.kind) is distinct from (OLD.tenant_id,OLD.business_id,OLD.key,OLD.kind) then
        raise exception using errcode='23514', message='role identity is immutable';
    end if;
    return NEW;
end $$;
create trigger role_identity_guard before update on __SCHEMA__.access_roles
    for each row execute function __SCHEMA__.access_guard_role_identity();

create function __SCHEMA__.access_validate_role_permission() returns trigger language plpgsql as $$
declare role_kind text; permission_category text;
begin
    select kind into role_kind from __SCHEMA__.access_roles where tenant_id=NEW.tenant_id and business_id=NEW.business_id and id=NEW.role_id;
    select category into permission_category from __SCHEMA__.access_permissions where tenant_id=NEW.tenant_id and business_id=NEW.business_id and resource_type=NEW.resource_type and action=NEW.action;
    if role_kind is null or permission_category is null or role_kind='business_admin'
       or (role_kind='business' and permission_category<>'business')
       or (role_kind='system_admin' and permission_category<>'platform')
       or (role_kind='tenant_security_admin' and permission_category<>'tenant') then
        raise exception using errcode='23514', message='role permission category mismatch';
    end if;
    return NEW;
end $$;
create trigger role_permission_guard before insert or update on __SCHEMA__.access_role_permissions
    for each row execute function __SCHEMA__.access_validate_role_permission();

create function __SCHEMA__.access_validate_binding() returns trigger language plpgsql as $$
declare role_kind text;
begin
    select kind into role_kind from __SCHEMA__.access_roles where tenant_id=NEW.tenant_id and business_id=NEW.business_id and id=NEW.role_id;
    if role_kind is null
       or (role_kind='business_admin' and NEW.scope_kind<>'business')
       or (role_kind<>'business_admin' and NEW.scope_kind='business')
       or (role_kind='system_admin' and (NEW.business_id<>'idp' or NEW.resource_type<>'idp.platform' or NEW.scope_kind<>'type'))
       or (role_kind='tenant_security_admin' and (NEW.business_id<>'idp' or NEW.resource_type<>'idp.tenant' or NEW.scope_kind<>'type')) then
        raise exception using errcode='23514', message='role binding scope mismatch';
    end if;
    return NEW;
end $$;
create trigger role_binding_guard before insert or update on __SCHEMA__.access_role_bindings
    for each row execute function __SCHEMA__.access_validate_binding();

-- Ascending B-trees also serve descending keyset scans.
create index access_tenants_time_page on __SCHEMA__.access_tenants(created_at_epoch, id);
create index accounts_time_page on __SCHEMA__.accounts(created_at_epoch, id);
create index access_memberships_time_page on __SCHEMA__.access_memberships(tenant_id, joined_at_epoch, account_id);
create index access_roles_time_page on __SCHEMA__.access_roles(tenant_id,business_id,created_at_epoch,id);
create index access_bindings_time_page on __SCHEMA__.access_role_bindings(tenant_id,business_id,account_id,created_at_epoch,id);
create index access_permissions_time_page on __SCHEMA__.access_permissions(tenant_id,business_id,(coalesce(created_at_epoch,0)),resource_type,action);
create index oidc_clients_time_page on __SCHEMA__.oidc_clients(created_at_epoch, client_id collate "C");
create index devices_time_page on __SCHEMA__.devices(tenant_id, registered_at_epoch, id);
create index sessions_time_page on __SCHEMA__.auth_sessions(tenant_id, created_at_epoch, id);

create table __SCHEMA__.scan_login_grants (
 tenant_id text not null, host_scope text collate "C" not null, entry_id text collate "C" not null, id uuid primary key,
 mode text not null check(mode in ('device_display','phone_display')), target_client_id text not null references __SCHEMA__.oidc_clients(client_id), state text not null check(state in ('waiting_user','waiting_device','awaiting_approval','approved','issued','denied','cancelled','expired','invalidated')), version bigint not null check(version>0), code_digest bytea not null check(octet_length(code_digest)=32),
 source_account_id uuid, source_session_id uuid, source_client_id text, source_authenticated_at_epoch bigint,
 target_device_id uuid, target_key_id text, target_device_version bigint, target_key_version bigint,
 presentation_key_id text, presentation_nonce bytea, presentation_ciphertext bytea, delivery_secret_hash bytea check(delivery_secret_hash is null or octet_length(delivery_secret_hash)=32), confirmation_revision text,
 created_at_epoch bigint not null, expires_at_epoch bigint not null, code_expires_at_epoch bigint not null, approved_until_epoch bigint,
 unique(tenant_id,host_scope,entry_id,code_digest), foreign key(source_account_id) references __SCHEMA__.accounts(id), foreign key(tenant_id,source_session_id) references __SCHEMA__.auth_sessions(tenant_id,id), foreign key(tenant_id,target_device_id,target_client_id) references __SCHEMA__.devices(tenant_id,id,client_id), foreign key(tenant_id,target_device_id,target_key_id) references __SCHEMA__.device_proof_keys(tenant_id,device_id,key_id),
 check ((source_account_id is null) = (source_session_id is null) and (source_account_id is null) = (source_client_id is null) and (source_account_id is null) = (source_authenticated_at_epoch is null)), check ((target_device_id is null) = (target_key_id is null) and (target_device_id is null) = (target_device_version is null) and (target_device_id is null) = (target_key_version is null)), check ((presentation_key_id is null) = (presentation_nonce is null) and (presentation_key_id is null) = (presentation_ciphertext is null)), check(expires_at_epoch>created_at_epoch and code_expires_at_epoch>created_at_epoch and code_expires_at_epoch<=expires_at_epoch), check(approved_until_epoch is null or (approved_until_epoch>created_at_epoch and approved_until_epoch<=expires_at_epoch))
);
create index scan_login_grants_target_pending on __SCHEMA__.scan_login_grants(tenant_id,target_device_id,state,expires_at_epoch);
create index scan_login_grants_source_pending on __SCHEMA__.scan_login_grants(tenant_id,source_session_id,state,expires_at_epoch);
create table __SCHEMA__.scan_login_operations (
 tenant_id text not null, host_scope text collate "C" not null, entry_id text collate "C" not null, actor_id text collate "C" not null, action text collate "C" not null, operation_id text collate "C" not null, fingerprint bytea not null check(octet_length(fingerprint)=32), grant_id uuid not null references __SCHEMA__.scan_login_grants(id), created_at_epoch bigint not null, primary key(tenant_id,host_scope,entry_id,actor_id,action,operation_id)
);
create table __SCHEMA__.scan_login_deliveries (
 tenant_id text not null, grant_id uuid not null references __SCHEMA__.scan_login_grants(id), issuance_operation_id text collate "C" not null, session_id uuid not null, state text not null check(state in ('recoverable','acknowledged','revoked')), binding_id uuid not null, binding_version bigint not null check(binding_version>0), result_key_id text, result_nonce bytea, result_ciphertext bytea, receipt_nonce_hash bytea check(receipt_nonce_hash is null or octet_length(receipt_nonce_hash)=32), recover_until_epoch bigint not null, created_at_epoch bigint not null, release_authorized_at_epoch bigint, acknowledged_at_epoch bigint, revoked_at_epoch bigint, reason text, primary key(tenant_id,grant_id), unique(tenant_id,session_id), unique(tenant_id,grant_id,issuance_operation_id), foreign key(tenant_id,session_id) references __SCHEMA__.auth_sessions(tenant_id,id), foreign key(tenant_id,binding_id) references __SCHEMA__.account_device_bindings(tenant_id,id), check ((result_key_id is null) = (result_nonce is null) and (result_key_id is null) = (result_ciphertext is null)), check(recover_until_epoch>=created_at_epoch)
);
create table __SCHEMA__.scan_login_audit_events (
 id uuid primary key, tenant_id text not null, host_scope text collate "C" not null, grant_id uuid not null references __SCHEMA__.scan_login_grants(id), actor_kind text not null, actor_id text, operation text collate "C" not null, operation_id text collate "C" not null, session_id uuid, decision_id text, occurred_at_epoch bigint not null
);
create index scan_login_audit_grant on __SCHEMA__.scan_login_audit_events(tenant_id,grant_id,occurred_at_epoch);

create index scan_login_grants_expiry on __SCHEMA__.scan_login_grants(host_scope,entry_id,expires_at_epoch,id) where state in ('waiting_user','waiting_device','awaiting_approval','approved');
create index scan_login_deliveries_expiry on __SCHEMA__.scan_login_deliveries(recover_until_epoch,grant_id) where state='recoverable';

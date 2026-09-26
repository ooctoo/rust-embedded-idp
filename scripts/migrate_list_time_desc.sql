-- Explicit tenant_v2 upgrade; run with psql -v schema=YOUR_IDP_SCHEMA -f this-file.
-- Historical permission creation times remain NULL (unknown), behind dated rows.
\set ON_ERROR_STOP on
begin;
set local search_path = :"schema";
select pg_advisory_xact_lock(hashtext(current_schema() || ':embedded-idp-migration'));
do $$
begin
    if not exists (select 1 from access_state where singleton and module_version = 'tenant_v2') then
        raise exception 'requires an existing tenant_v2 IdP schema';
    end if;
end $$;
alter table :"schema".access_permissions add column if not exists created_at_epoch bigint;
alter table :"schema".access_permissions alter column created_at_epoch set default floor(extract(epoch from clock_timestamp()))::bigint;
create index if not exists access_tenants_time_page on :"schema".access_tenants(created_at_epoch, id);
create index if not exists accounts_time_page on :"schema".accounts(created_at_epoch, id);
create index if not exists access_memberships_time_page on :"schema".access_memberships(tenant_id, joined_at_epoch, account_id);
create index if not exists access_roles_time_page on :"schema".access_roles(tenant_id, created_at_epoch, id);
create index if not exists access_bindings_time_page on :"schema".access_role_bindings(tenant_id, account_id, created_at_epoch, id);
create index if not exists access_permissions_time_page on :"schema".access_permissions(tenant_id, (coalesce(created_at_epoch, 0)), resource_type, action);
create index if not exists oidc_clients_time_page on :"schema".oidc_clients(created_at_epoch, client_id collate "C");
create index if not exists devices_time_page on :"schema".devices(tenant_id, registered_at_epoch, id);
create index if not exists sessions_time_page on :"schema".auth_sessions(tenant_id, created_at_epoch, id);
commit;

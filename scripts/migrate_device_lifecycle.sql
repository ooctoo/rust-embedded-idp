\set ON_ERROR_STOP on
-- Stop all IdP writers and verify a backup before --apply. Dry-run uses a
-- repeatable-read snapshot; only --apply takes exclusive table locks.
\if :apply
  begin;
  select pg_advisory_xact_lock(hashtext(:'schema' || ':embedded-idp-migration'));
  lock table :"schema".access_state, :"schema".devices, :"schema".device_proof_keys,
    :"schema".account_device_bindings, :"schema".auth_sessions, :"schema".refresh_tokens,
    :"schema".authorization_codes, :"schema".auth_tenant_selections,
    :"schema".device_nonces, :"schema".access_audit_events in access exclusive mode;
\else
  begin isolation level repeatable read;
\endif
select set_config('embedded_idp.schema', :'schema', true) as schema_setting,
       set_config('embedded_idp.actor_id', :'actor_id', true) as actor_setting \gset
select module_version='tenant_v4' as already_migrated from :"schema".access_state where singleton \gset
\if :already_migrated
  select (select count(*) from information_schema.columns where table_schema=:'schema' and table_name in ('devices','account_device_bindings') and column_name='version' and data_type='bigint' and is_nullable='NO')=2
    and exists(select 1 from information_schema.tables where table_schema=:'schema' and table_name='device_registrations')
    and (select count(*) from information_schema.columns where table_schema=:'schema' and table_name='access_audit_events' and column_name in ('device_operation_id','device_command_sha256'))=2
    and exists(select 1 from pg_indexes where schemaname=:'schema' and indexname='access_audit_device_operation')
    and exists(select 1 from pg_indexes where schemaname=:'schema' and indexname='device_binding_device_page') as valid_layout \gset
  \if :valid_layout
    rollback;
    \echo 'already tenant_v4; no migration was replayed.'
    \quit
  \else
    rollback;
    do $$ begin raise exception 'tenant_v4 layout is incomplete'; end $$;
  \endif
\endif

do $$
declare s text := current_setting('embedded_idp.schema'); actor uuid := current_setting('embedded_idp.actor_id')::uuid; ok boolean; bad boolean;
begin
  execute format('select module_version=''tenant_v3'' and bootstrap_completed_at_epoch is not null from %I.access_state where singleton',s) into ok;
  if not coalesce(ok,false) then raise exception 'bootstrapped tenant_v3 required'; end if;
  execute format($q$select exists(select 1 from %1$I.accounts a join %1$I.access_memberships m on m.account_id=a.id and m.tenant_id='0' join %1$I.access_role_bindings b on b.tenant_id='0' and b.account_id=a.id and b.resource_type='idp.platform' and b.resource_id is null join %1$I.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id and r.status='active' and r.kind='system_admin' where a.id=$1 and a.status='active' and m.status='active' and not exists(select 1 from unnest(array['users.read','users.security','tenants.manage','users.bind','clients.manage','access.manage','audit.read']) required(action) where not exists(select 1 from %1$I.access_permissions p join %1$I.access_role_permissions rp on rp.tenant_id=p.tenant_id and rp.business_id=p.business_id and rp.resource_type=p.resource_type and rp.action=p.action and rp.role_id=r.id where p.tenant_id='0' and p.resource_type='idp.platform' and p.action=required.action and p.category='platform' and p.enabled and not p.archived)))$q$,s) into ok using actor;
  if not coalesce(ok,false) then raise exception 'actor_id is not an effective platform administrator'; end if;
  execute format($q$select exists(select 1 from %1$I.devices d where (d.status='pending' and d.proof_key_id is not null) or (d.status='active' and not exists(select 1 from %1$I.device_proof_keys k where k.tenant_id=d.tenant_id and k.device_id=d.id and k.key_id=d.proof_key_id and k.status='active')) or (d.status='revoked' and (exists(select 1 from %1$I.device_proof_keys k where k.tenant_id=d.tenant_id and k.device_id=d.id and k.status='active') or exists(select 1 from %1$I.account_device_bindings b where b.tenant_id=d.tenant_id and b.device_id=d.id and b.status<>'unbound'))))$q$,s) into bad;
  if bad then raise exception 'invalid legacy device/key/binding state requires manual repair'; end if;
end $$;

create temp table device_cutover on commit drop as
select d.tenant_id,d.id,d.status,1::bigint as old_version,
  (select count(*) from :"schema".auth_sessions x where x.tenant_id=d.tenant_id and x.device_id=d.id and x.status in ('active','pending')) as sessions,
  (select count(*) from :"schema".refresh_tokens f join :"schema".auth_sessions x on x.tenant_id=f.tenant_id and x.id=f.session_id where x.tenant_id=d.tenant_id and x.device_id=d.id and f.revoked_at_epoch is null) as refresh_tokens,
  (select count(*) from :"schema".authorization_codes c join :"schema".auth_sessions x on x.tenant_id=c.tenant_id and x.id=c.source_session_id where x.tenant_id=d.tenant_id and x.device_id=d.id) as authorization_codes,
  (select count(*) from :"schema".auth_tenant_selections t join :"schema".auth_sessions x on x.tenant_id=t.source_tenant_id and x.id=t.source_session_id where x.tenant_id=d.tenant_id and x.device_id=d.id and t.revoked_at_epoch is null) as tenant_selections,
  (select count(*) from :"schema".device_nonces n where n.tenant_id=d.tenant_id and n.device_id=d.id) as nonces,
  (select count(*) from :"schema".account_device_bindings b where b.tenant_id=d.tenant_id and b.device_id=d.id and b.status<>'unbound') as bindings
from :"schema".devices d where d.status='pending' or (d.status='disabled' and d.proof_key_id is null);
-- v3 has no version column. The temporary version is the v4 starting point.
select (select count(*) from :"schema".devices) as total_devices,
       (select count(*) from device_cutover) as identities_to_revoke,
       (select coalesce(sum(sessions),0) from device_cutover) as active_sessions_to_revoke,
       (select coalesce(sum(bindings),0) from device_cutover) as bindings_to_unbind;
select tenant_id,id,status,old_version,sessions,refresh_tokens,authorization_codes,tenant_selections,nonces,bindings from device_cutover order by tenant_id,id;

\if :apply
  alter table :"schema".devices add column version bigint not null default 1 check(version>0);
  alter table :"schema".account_device_bindings add column version bigint not null default 1 check(version>0);
  create index device_binding_device_page on :"schema".account_device_bindings(tenant_id,device_id,bound_at_epoch,id);
  alter table :"schema".access_audit_events add column device_operation_id uuid, add column device_command_sha256 bytea;
  alter table :"schema".access_audit_events add constraint access_audit_device_operation_pair check ((device_operation_id is null and device_command_sha256 is null) or (device_operation_id is not null and octet_length(device_command_sha256)=32));
  create unique index access_audit_device_operation on :"schema".access_audit_events(actor_domain,actor_id,target_domain,device_operation_id) where device_operation_id is not null;
  alter table :"schema".devices add constraint devices_tenant_id_id_client_id_key unique(tenant_id,id,client_id);
  create table :"schema".device_registrations (
    tenant_id text not null, client_id text not null, registration_scope text collate "C" not null check(registration_scope ~ '^[A-Za-z0-9_.-]{1,128}$'),
    registration_request_id uuid not null, device_id uuid not null,
    device_name text not null check(octet_length(device_name) between 1 and 256),
    expected_key_id text not null unique check(length(expected_key_id)=43), public_jwk text not null,
    created_at_epoch bigint not null, expires_at_epoch bigint not null check(expires_at_epoch>created_at_epoch),
    completed_at_epoch bigint check(completed_at_epoch is null or (completed_at_epoch>=created_at_epoch and completed_at_epoch<expires_at_epoch)),
    primary key(tenant_id,client_id,registration_scope,registration_request_id), unique(tenant_id,device_id),
    foreign key(tenant_id,device_id,client_id) references :"schema".devices(tenant_id,id,client_id)
  );
  -- Keep the old v3 audit rows; only extend the offline migration operation.
  select format('alter table %I.access_audit_events drop constraint %I', :'schema', conname)
    from pg_constraint where conrelid=(:'schema'||'.access_audit_events')::regclass
      and contype='c' and pg_get_constraintdef(oid) like '%access.migrate_business_scope%' \gexec
  alter table :"schema".access_audit_events add constraint access_audit_authentication_source_check
    check ((authentication_source='offline_bootstrap' and actor_session_id is null and operation='access.bootstrap')
      or (authentication_source='offline_migration' and actor_session_id is null and operation in ('access.migrate_business_scope','access.migrate_device_lifecycle') and actor_domain='0' and target_domain='0' and target_business_id is null)
      or (authentication_source not in ('offline_bootstrap','offline_migration') and actor_session_id is not null));

  delete from :"schema".authorization_codes c using :"schema".auth_sessions x,device_cutover d
    where c.tenant_id=x.tenant_id and c.source_session_id=x.id and c.account_id=x.account_id and x.tenant_id=d.tenant_id and x.device_id=d.id;
  update :"schema".auth_tenant_selections t set revoked_at_epoch=floor(extract(epoch from clock_timestamp()))::bigint
    from :"schema".auth_sessions x,device_cutover d
    where t.source_tenant_id=x.tenant_id and t.source_session_id=x.id and x.tenant_id=d.tenant_id and x.device_id=d.id and t.revoked_at_epoch is null;
  update :"schema".refresh_tokens f set revoked_at_epoch=floor(extract(epoch from clock_timestamp()))::bigint,revocation_reason='administrative'
    from :"schema".auth_sessions x,device_cutover d
    where f.tenant_id=x.tenant_id and f.session_id=x.id and x.tenant_id=d.tenant_id and x.device_id=d.id and f.revoked_at_epoch is null;
  update :"schema".auth_sessions x set status='revoked' from device_cutover d
    where x.tenant_id=d.tenant_id and x.device_id=d.id and x.status in ('active','pending');
  delete from :"schema".device_nonces n using device_cutover d where n.tenant_id=d.tenant_id and n.device_id=d.id;
  update :"schema".account_device_bindings b set status='unbound',version=version+1,unbound_at_epoch=floor(extract(epoch from clock_timestamp()))::bigint
    from device_cutover d where b.tenant_id=d.tenant_id and b.device_id=d.id and b.status<>'unbound';
  update :"schema".devices x set status='revoked',version=version+1 from device_cutover d
    where x.tenant_id=d.tenant_id and x.id=d.id;
  insert into :"schema".access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,target_business_id,operation,request_id,change_json)
    select md5(random()::text || clock_timestamp()::text || d.id::text)::uuid,
      floor(extract(epoch from clock_timestamp()))::bigint,:'actor_id'::uuid,'0',null,'offline_migration','0',null,
      'access.migrate_device_lifecycle',:'request_id',
      jsonb_build_object('tenant_id',d.tenant_id,'device_id',d.id,'before_status',d.status,'after_status','revoked','before_version',d.old_version,'after_version',d.old_version+1,'active_sessions',d.sessions,'refresh_tokens',d.refresh_tokens,'authorization_codes',d.authorization_codes,'tenant_selections',d.tenant_selections,'nonces',d.nonces,'bindings',d.bindings)
    from device_cutover d;
  insert into :"schema".access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,target_business_id,operation,request_id,change_json)
    values(md5(random()::text || clock_timestamp()::text)::uuid,floor(extract(epoch from clock_timestamp()))::bigint,:'actor_id'::uuid,'0',null,'offline_migration','0',null,'access.migrate_device_lifecycle',:'request_id',
      jsonb_build_object('from','tenant_v3','to','tenant_v4','revoked_device_count',(select count(*) from device_cutover)));
  create or replace function :"schema".access_guard_state() returns trigger language plpgsql as $$ begin if TG_OP='DELETE' then raise exception using errcode='23514', message='deployment mode and version are immutable'; end if; return NEW; end $$;
  alter table :"schema".access_state drop constraint access_state_module_version_check;
  update :"schema".access_state set module_version='tenant_v4' where singleton;
  alter table :"schema".access_state add constraint access_state_module_version_check check(module_version='tenant_v4');
  create or replace function :"schema".access_guard_state() returns trigger language plpgsql as $$ begin if TG_OP='DELETE' or (NEW.tenancy_mode,NEW.module_version) is distinct from (OLD.tenancy_mode,OLD.module_version) then raise exception using errcode='23514', message='deployment mode and version are immutable'; end if; return NEW; end $$;
  commit;
  \echo 'tenant_v4 migration committed.'
\else
  rollback;
  \echo 'dry-run complete; no changes made.'
\endif

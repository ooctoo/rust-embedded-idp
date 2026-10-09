\set ON_ERROR_STOP on
-- This migration never runs implicitly. The shell wrapper defaults to dry-run.
\if :apply
 begin;
 select pg_advisory_xact_lock(hashtext(:'schema' || ':embedded-idp-migration'));
 lock table :"schema".access_state, :"schema".scan_login_grants,
   :"schema".scan_login_operations, :"schema".scan_login_deliveries in access exclusive mode;
\else
 begin isolation level repeatable read;
\endif
select module_version as observed_version from :"schema".access_state where singleton \gset
\if :apply
\else
 select :'observed_version' in ('tenant_v5','tenant_v6') as compatible_source \gset
 \if :compatible_source
 \else
  rollback;
  do $$ begin raise exception 'tenant_v5 source or tenant_v6 target required'; end $$;
 \endif
 rollback;
 \echo 'dry-run complete; no changes made. Source must be tenant_v5; tenant_v6 is verified by the apply idempotence check.'
 \quit
\endif
select set_config('embedded_idp.scan_origin_closure_schema', :'schema', true);
do $$
declare n text:=current_setting('embedded_idp.scan_origin_closure_schema'); v text;
begin
 execute format('select module_version from %I.access_state where singleton',n) into v;
 if v='tenant_v6' then
   if (select count(*) from information_schema.columns where table_schema=n and table_name='scan_login_origin_closures' and column_name in ('tenant_id','host_scope','entry_id','device_id','origin_action','origin_operation_id','delivery_secret_hash','grant_id','closed_by_key_id','closed_at_epoch'))<>10 then raise exception 'tenant_v6 layout is incomplete'; end if;
   if not exists (select 1 from pg_constraint c join pg_class r on r.oid=c.conrelid join pg_namespace s on s.oid=r.relnamespace where s.nspname=n and r.relname='scan_login_origin_closures' and c.convalidated and c.contype='p' and pg_get_constraintdef(c.oid)='PRIMARY KEY (tenant_id, host_scope, entry_id, device_id, origin_action, origin_operation_id)') then raise exception 'tenant_v6 origin closure key is incomplete'; end if;
   if not exists (select 1 from pg_constraint c join pg_class r on r.oid=c.conrelid join pg_namespace s on s.oid=r.relnamespace where s.nspname=n and r.relname='scan_login_origin_closures' and c.convalidated and c.contype='c' and pg_get_constraintdef(c.oid) like '%octet_length%delivery_secret_hash%32%') then raise exception 'tenant_v6 origin closure secret constraint is incomplete'; end if;
   if not exists (select 1 from pg_constraint c join pg_class r on r.oid=c.conrelid join pg_namespace s on s.oid=r.relnamespace where s.nspname=n and r.relname='scan_login_origin_closures' and c.convalidated and c.contype='c' and pg_get_constraintdef(c.oid) like '%origin_action%create%claim%') then raise exception 'tenant_v6 origin closure action constraint is incomplete'; end if;
   return;
 end if;
 if v<>'tenant_v5' then raise exception 'tenant_v5 source required, got %',v; end if;
 execute format($q$create table %I.scan_login_origin_closures (tenant_id text not null,host_scope text collate "C" not null,entry_id text collate "C" not null,device_id uuid not null,origin_action text collate "C" not null check(origin_action in ('create','claim')),origin_operation_id text collate "C" not null,delivery_secret_hash bytea not null check(octet_length(delivery_secret_hash)=32),grant_id uuid,closed_by_key_id text not null,closed_at_epoch bigint not null,primary key(tenant_id,host_scope,entry_id,device_id,origin_action,origin_operation_id))$q$,n);
 execute format('create or replace function %I.access_guard_state() returns trigger language plpgsql as $f$ begin if TG_OP=''DELETE'' then raise exception using errcode=''23514'',message=''deployment mode and version are immutable''; end if; return NEW; end $f$',n);
 execute format('alter table %I.access_state drop constraint access_state_module_version_check',n);
 execute format('update %I.access_state set module_version=''tenant_v6'' where singleton',n);
 execute format('alter table %I.access_state add constraint access_state_module_version_check check(module_version=''tenant_v6'')',n);
 execute format('create or replace function %I.access_guard_state() returns trigger language plpgsql as $f$ begin if TG_OP=''DELETE'' or (NEW.tenancy_mode,NEW.module_version) is distinct from (OLD.tenancy_mode,OLD.module_version) then raise exception using errcode=''23514'',message=''deployment mode and version are immutable''; end if; return NEW; end $f$',n);
end $$;
commit;
\echo 'tenant_v6 migration committed or target layout verified.'

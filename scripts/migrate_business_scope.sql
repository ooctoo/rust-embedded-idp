\set ON_ERROR_STOP on
\if :{?schema}
\else
\echo 'set schema, permission_mapping, role_mapping, actor_id and request_id'
\quit
\endif
\if :{?permission_mapping}
\else
\echo 'permission_mapping must be a TSV: tenant_id,resource_type,action,business_id'
\quit
\endif
\if :{?role_mapping}
\else
\echo 'role_mapping must be a TSV: tenant_id,role_id,business_id'
\quit
\endif
\if :{?actor_id}
\else
\echo 'actor_id must be an effective platform administrator UUID'
\quit
\endif
\if :{?request_id}
\else
\echo 'request_id is required for the offline migration audit event'
\quit
\endif
\if :{?apply}
\else
\set apply false
\endif

-- Run with psql.  It is dry-run by default; use --set=apply=true only after
-- reviewing this run's counts.  The two mapping files make every legacy
-- business object explicit, including orphan permissions and empty roles.
begin;
select pg_advisory_xact_lock(hashtext(:'schema' || ':embedded-idp-business-scope-migration'));
lock table :"schema".access_state, :"schema".access_permissions, :"schema".access_roles, :"schema".access_role_permissions, :"schema".access_role_bindings, :"schema".access_audit_events in access exclusive mode;
select set_config('embedded_idp.schema', :'schema', true), set_config('embedded_idp.actor_id', :'actor_id', true);
select module_version='tenant_v3' as already_migrated from :"schema".access_state where singleton \gset
\if :already_migrated
  select not exists(select 1 from (values ('access_permissions','business_id'),('access_roles','business_id'),('access_role_permissions','business_id'),('access_role_bindings','business_id')) required(table_name,column_name) left join pg_namespace n on n.nspname=:'schema' left join pg_class t on t.relnamespace=n.oid and t.relname=required.table_name left join pg_attribute a on a.attrelid=t.oid and a.attname=required.column_name and a.attnum>0 and not a.attisdropped where a.attname is null or a.atttypid<>'text'::regtype or not a.attnotnull or a.attcollation<>'"C"'::regcollation) and exists(select 1 from pg_attribute a join pg_class t on t.oid=a.attrelid join pg_namespace n on n.oid=t.relnamespace where n.nspname=:'schema' and t.relname='access_role_bindings' and a.attname='scope_kind' and a.attnotnull and a.atttypid='text'::regtype) and exists(select 1 from pg_attribute a join pg_class t on t.oid=a.attrelid join pg_namespace n on n.oid=t.relnamespace where n.nspname=:'schema' and t.relname='access_audit_events' and a.attname='target_business_id' and a.atttypid='text'::regtype and a.attcollation='"C"'::regcollation) and (select count(*) from pg_trigger g join pg_class c on c.oid=g.tgrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=:'schema' and g.tgname in ('role_identity_guard','role_permission_guard','role_binding_guard') and g.tgenabled in ('O','A'))=3 and (select count(*) from pg_class i join pg_namespace n on n.oid=i.relnamespace where n.nspname=:'schema' and i.relkind='i' and i.relname in ('access_business_admin_unique','access_binding_business_unique'))=2 and exists(select 1 from pg_constraint c where c.conrelid=(:'schema'||'.access_role_permissions')::regclass and c.contype='f' and c.convalidated and array_length(c.conkey,1)=3 and c.confrelid=(:'schema'||'.access_roles')::regclass) and exists(select 1 from pg_constraint c where c.conrelid=(:'schema'||'.access_role_permissions')::regclass and c.contype='f' and c.convalidated and array_length(c.conkey,1)=4 and c.confrelid=(:'schema'||'.access_permissions')::regclass) as v3_layout \gset
  \if :v3_layout
  rollback;
  \echo 'already tenant_v3; no migration was replayed.'
  \quit
  \else
  rollback;
  do $$ begin raise exception 'tenant_v3 layout is incomplete'; end $$;
  \endif
\endif
create temp table business_permission_map (
    tenant_id text not null, resource_type text not null, action text not null, business_id text not null,
    primary key(tenant_id,resource_type,action)
) on commit drop;
create temp table business_role_map (
    tenant_id text not null, role_id uuid not null, business_id text not null,
    primary key(tenant_id,role_id)
) on commit drop;
-- The wrapper expands these two COPY paths after restricting them to local
-- ordinary files.  psql itself does not interpolate variables in \copy paths.
\copy business_permission_map from '__PERMISSION_MAPPING__' with (format csv, header true, delimiter E'\t')
\copy business_role_map from '__ROLE_MAPPING__' with (format csv, header true, delimiter E'\t')

do $$
declare state_version text; state_mode text; missing_count bigint; bad_actor boolean;
begin
  execute format('select module_version,tenancy_mode from %I.access_state where singleton', current_setting('embedded_idp.schema')) into state_version,state_mode;
  if state_version is distinct from 'tenant_v2' then raise exception 'expected tenant_v2, found %',state_version; end if;
  execute format('select bootstrap_completed_at_epoch is not null from %I.access_state where singleton', current_setting('embedded_idp.schema')) into bad_actor;
  if not bad_actor then raise exception 'requires a bootstrapped tenant_v2 schema'; end if;
  execute format($q$select not exists(select 1 from %1$I.accounts a join %1$I.access_memberships m on m.account_id=a.id and m.tenant_id='0' join %1$I.access_role_bindings b on b.tenant_id='0' and b.account_id=a.id and b.resource_type='idp.platform' and b.resource_id is null join %1$I.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id and r.status='active' and r.kind='system_admin' where a.id=$1::uuid and a.status='active' and m.status='active' and not exists(select 1 from unnest(array['users.read','users.security','tenants.manage','users.bind','clients.manage','access.manage','audit.read']) required(action) where not exists(select 1 from %1$I.access_permissions p join %1$I.access_role_permissions rp on rp.tenant_id=p.tenant_id and rp.resource_type=p.resource_type and rp.action=p.action and rp.role_id=r.id where p.tenant_id='0' and p.resource_type='idp.platform' and p.action=required.action and p.category='platform' and p.enabled and not p.archived)))$q$, current_setting('embedded_idp.schema')) into bad_actor using current_setting('embedded_idp.actor_id');
  if bad_actor then raise exception 'actor_id is not an effective platform administrator'; end if;
  execute format($q$select count(*) from %1$I.access_permissions p where p.category='business' and not exists(select 1 from business_permission_map m where m.tenant_id=p.tenant_id and m.resource_type=p.resource_type and m.action=p.action)$q$, current_setting('embedded_idp.schema')) into missing_count;
  if missing_count<>0 then raise exception 'permission mapping omits % business permissions',missing_count; end if;
  execute format($q$select exists(select 1 from business_permission_map m left join %1$I.access_permissions p on p.tenant_id=m.tenant_id and p.resource_type=m.resource_type and p.action=m.action where p.category is distinct from 'business')$q$, current_setting('embedded_idp.schema')) into bad_actor;
  if bad_actor then raise exception 'permission mapping contains an unknown or non-business permission'; end if;
  execute format($q$select count(*) from %1$I.access_roles r where r.kind='business' and not exists(select 1 from business_role_map m where m.tenant_id=r.tenant_id and m.role_id=r.id)$q$, current_setting('embedded_idp.schema')) into missing_count;
  if missing_count<>0 then raise exception 'role mapping omits % business roles',missing_count; end if;
  execute format($q$select exists(select 1 from business_role_map m left join %1$I.access_roles r on r.tenant_id=m.tenant_id and r.id=m.role_id where r.kind is distinct from 'business')$q$, current_setting('embedded_idp.schema')) into bad_actor;
  if bad_actor then raise exception 'role mapping contains an unknown or non-business role'; end if;
  if exists(select 1 from business_permission_map where business_id !~ '^[a-z][a-z0-9_.-]{0,63}$' or business_id='idp' or business_id like 'idp.%')
     or exists(select 1 from business_role_map where business_id !~ '^[a-z][a-z0-9_.-]{0,63}$' or business_id='idp' or business_id like 'idp.%') then
    raise exception 'mapping contains a reserved or invalid business id';
  end if;
  execute format($q$select exists(select 1 from %1$I.access_role_permissions rp join business_role_map r on r.tenant_id=rp.tenant_id and r.role_id=rp.role_id join business_permission_map p on p.tenant_id=rp.tenant_id and p.resource_type=rp.resource_type and p.action=rp.action where r.business_id<>p.business_id)$q$, current_setting('embedded_idp.schema')) into bad_actor;
  if bad_actor then raise exception 'role-permission mapping crosses business domains'; end if;
  execute format($q$select exists(select 1 from %1$I.access_roles r where r.kind='business' and r.key in ('system_admin','tenant_security_admin','idp_system_admin','idp_tenant_security_admin','business_admin')) or exists(select 1 from %1$I.access_roles r where r.kind='system_admin' and exists(select 1 from %1$I.access_roles x where x.tenant_id=r.tenant_id and x.key='idp_system_admin' and x.id<>r.id)) or exists(select 1 from %1$I.access_roles r where r.kind='tenant_security_admin' and exists(select 1 from %1$I.access_roles x where x.tenant_id=r.tenant_id and x.key='idp_tenant_security_admin' and x.id<>r.id))$q$, current_setting('embedded_idp.schema')) into bad_actor;
  if bad_actor then raise exception 'reserved role key conflict requires an explicit pre-migration rename'; end if;
end $$;

select
  (select module_version from :"schema".access_state where singleton) as source_version,
  (select tenancy_mode from :"schema".access_state where singleton) as source_mode,
  (select count(*) from :"schema".access_permissions) as permissions,
  (select count(*) from :"schema".access_roles) as roles,
  (select count(*) from :"schema".access_role_permissions) as role_permissions,
  (select count(*) from :"schema".access_role_bindings) as role_bindings,
  (select count(*) from :"schema".access_roles where kind in ('system_admin','tenant_security_admin')) as protected_roles,
  (select coalesce(string_agg(id::text, ',' order by id), '') from :"schema".access_roles where (kind='system_admin' and name='System administrator') or (kind='tenant_security_admin' and name='Tenant security administrator')) as default_name_role_ids,
  (select md5(coalesce(string_agg(conname || ':' || pg_get_constraintdef(oid), '' order by conname), '')) from pg_constraint where connamespace=(:'schema')::regnamespace) as ddl_fingerprint;

  alter table :"schema".access_permissions add column if not exists business_id text;
  alter table :"schema".access_roles add column if not exists business_id text;
  alter table :"schema".access_role_permissions add column if not exists business_id text;
  alter table :"schema".access_role_bindings add column if not exists business_id text;
  alter table :"schema".access_role_bindings add column if not exists scope_kind text;
  alter table :"schema".access_role_bindings alter column resource_type drop not null;
  alter table :"schema".access_audit_events add column if not exists target_business_id text;
  alter table :"schema".access_audit_events alter column target_business_id type text collate "C";

  update :"schema".access_permissions p set business_id=coalesce(m.business_id,'idp') from business_permission_map m
   where p.tenant_id=m.tenant_id and p.resource_type=m.resource_type and p.action=m.action and p.category='business';
  update :"schema".access_permissions set business_id='idp' where category<>'business';
  update :"schema".access_roles r set business_id=coalesce(m.business_id,'idp') from business_role_map m
   where r.tenant_id=m.tenant_id and r.id=m.role_id and r.kind='business';
  update :"schema".access_roles set business_id='idp' where kind<>'business';
  update :"schema".access_role_permissions rp set business_id=r.business_id from :"schema".access_roles r where r.tenant_id=rp.tenant_id and r.id=rp.role_id;
  update :"schema".access_role_bindings b set business_id=r.business_id,scope_kind=case when b.resource_id is null then 'type' else 'instance' end from :"schema".access_roles r where r.tenant_id=b.tenant_id and r.id=b.role_id;
  update :"schema".access_roles set key='idp_system_admin',name=case when name='System administrator' then 'IDP管理员' else name end,version=version+1 where kind='system_admin';
  update :"schema".access_roles set key='idp_tenant_security_admin',name=case when name='Tenant security administrator' then 'IDP租户管理员' else name end,version=version+1 where kind='tenant_security_admin';
  -- Rebuild the access-only keys, FKs and indexes. Existing unrelated host
  -- objects are never enumerated or changed.
  alter table :"schema".access_role_permissions drop constraint access_role_permissions_pkey;
  alter table :"schema".access_role_permissions drop constraint access_role_permissions_tenant_id_role_id_fkey;
  alter table :"schema".access_role_permissions drop constraint access_role_permissions_tenant_id_resource_type_action_fkey;
  alter table :"schema".access_role_bindings drop constraint access_role_bindings_tenant_id_role_id_fkey;
  alter table :"schema".access_permissions drop constraint access_permissions_pkey;
  alter table :"schema".access_roles drop constraint access_roles_tenant_id_key_key;
  alter table :"schema".access_roles drop constraint access_roles_pkey;
  drop index :"schema".access_protected_role_unique;
  drop index :"schema".access_binding_type_unique;
  drop index :"schema".access_binding_instance_unique;
  drop index :"schema".access_binding_check;
  drop index :"schema".access_binding_subject_page;
  drop index :"schema".access_binding_by_role;
  drop index :"schema".access_binding_by_resource;
  drop index :"schema".access_roles_time_page;
  drop index :"schema".access_bindings_time_page;
  drop index :"schema".access_permissions_time_page;
  alter table :"schema".access_permissions alter column business_id set not null;
  alter table :"schema".access_permissions alter column business_id type text collate "C";
  alter table :"schema".access_roles alter column business_id set not null;
  alter table :"schema".access_roles alter column business_id type text collate "C";
  alter table :"schema".access_role_permissions alter column business_id set not null;
  alter table :"schema".access_role_permissions alter column business_id type text collate "C";
  alter table :"schema".access_role_bindings alter column business_id set not null;
  alter table :"schema".access_role_bindings alter column business_id type text collate "C";
  alter table :"schema".access_role_bindings alter column scope_kind set not null;
  select format('alter table %I.access_roles drop constraint %I', :'schema', conname) from pg_constraint where conrelid=(:'schema'||'.access_roles')::regclass and contype='c' \gexec
  select format('alter table %I.access_audit_events drop constraint %I', :'schema', conname) from pg_constraint where conrelid=(:'schema'||'.access_audit_events')::regclass and contype='c' \gexec
  alter table :"schema".access_permissions add primary key(tenant_id,business_id,resource_type,action);
  alter table :"schema".access_roles add primary key(tenant_id,id);
  alter table :"schema".access_roles add unique(tenant_id,business_id,id), add unique(tenant_id,business_id,key);
  alter table :"schema".access_role_permissions add primary key(tenant_id,business_id,role_id,resource_type,action);
  alter table :"schema".access_role_permissions add foreign key(tenant_id,business_id,role_id) references :"schema".access_roles(tenant_id,business_id,id), add foreign key(tenant_id,business_id,resource_type,action) references :"schema".access_permissions(tenant_id,business_id,resource_type,action);
  alter table :"schema".access_role_bindings add foreign key(tenant_id,business_id,role_id) references :"schema".access_roles(tenant_id,business_id,id);
  alter table :"schema".access_role_bindings add check ((scope_kind='business' and resource_type is null and resource_id is null) or (scope_kind='type' and resource_type is not null and resource_id is null) or (scope_kind='instance' and resource_type is not null and resource_id is not null));
  alter table :"schema".access_permissions add check (business_id ~ '^[a-z][a-z0-9_.-]{0,63}$' and (business_id='idp' or business_id not like 'idp.%')), add check ((business_id='idp') = (category in ('platform','tenant')));
  alter table :"schema".access_roles add check (business_id ~ '^[a-z][a-z0-9_.-]{0,63}$' and (business_id='idp' or business_id not like 'idp.%')), add check (key ~ '^[a-z][a-z0-9_.-]{0,63}$'), add check (length(btrim(name)) > 0 and octet_length(name) <= 256), add check (status in ('active','disabled')), add check (version > 0), add check (kind in ('system_admin','tenant_security_admin','business','business_admin')), add check (kind <> 'system_admin' or (tenant_id='0' and business_id='idp' and key='idp_system_admin')), add check (kind <> 'tenant_security_admin' or (business_id='idp' and key='idp_tenant_security_admin')), add check (kind <> 'business_admin' or (business_id<>'idp' and key='business_admin')), add check (kind <> 'business' or (business_id<>'idp' and key not in ('system_admin','tenant_security_admin','idp_system_admin','idp_tenant_security_admin','business_admin')));
  alter table :"schema".access_audit_events add check ((authentication_source='offline_bootstrap' and actor_session_id is null and operation='access.bootstrap') or (authentication_source='offline_migration' and actor_session_id is null and actor_domain='0' and target_domain='0' and target_business_id is null and operation='access.migrate_business_scope') or (authentication_source not in ('offline_bootstrap','offline_migration') and actor_session_id is not null));
  create unique index access_protected_role_unique on :"schema".access_roles(tenant_id,kind) where kind in ('system_admin','tenant_security_admin');
  create unique index access_business_admin_unique on :"schema".access_roles(tenant_id,business_id) where kind='business_admin';
  create unique index access_binding_business_unique on :"schema".access_role_bindings(tenant_id,business_id,account_id,role_id) where scope_kind='business';
  create unique index access_binding_type_unique on :"schema".access_role_bindings(tenant_id,business_id,account_id,role_id,resource_type) where scope_kind='type';
  create unique index access_binding_instance_unique on :"schema".access_role_bindings(tenant_id,business_id,account_id,role_id,resource_type,resource_id) where scope_kind='instance';
  create index access_binding_check on :"schema".access_role_bindings(tenant_id,business_id,account_id,resource_type,resource_id,role_id) where scope_kind<>'business';
  create index access_binding_subject_page on :"schema".access_role_bindings(tenant_id,business_id,account_id,id);
  create index access_binding_by_role on :"schema".access_role_bindings(tenant_id,business_id,role_id,account_id);
  create index access_binding_by_resource on :"schema".access_role_bindings(tenant_id,business_id,resource_type,resource_id,id) where scope_kind<>'business';
  create index access_roles_time_page on :"schema".access_roles(tenant_id,business_id,created_at_epoch,id);
  create index access_bindings_time_page on :"schema".access_role_bindings(tenant_id,business_id,account_id,created_at_epoch,id);
  create index access_permissions_time_page on :"schema".access_permissions(tenant_id,business_id,(coalesce(created_at_epoch,0)),resource_type,action);
  create index access_audit_business_page on :"schema".access_audit_events(target_domain,target_business_id,occurred_at_epoch,id) where target_business_id is not null;
  set local search_path to :"schema",pg_catalog;
  create or replace function access_guard_role_identity() returns trigger language plpgsql set search_path to :"schema", pg_catalog as $$ begin if TG_OP='UPDATE' and (NEW.tenant_id,NEW.business_id,NEW.key,NEW.kind) is distinct from (OLD.tenant_id,OLD.business_id,OLD.key,OLD.kind) then raise exception using errcode='23514', message='role identity is immutable'; end if; return NEW; end $$;
  create trigger role_identity_guard before update on access_roles for each row execute function access_guard_role_identity();
  create or replace function access_validate_role_permission() returns trigger language plpgsql set search_path to :"schema", pg_catalog as $$ declare role_kind text; permission_category text; begin select kind into role_kind from access_roles where tenant_id=NEW.tenant_id and business_id=NEW.business_id and id=NEW.role_id; select category into permission_category from access_permissions where tenant_id=NEW.tenant_id and business_id=NEW.business_id and resource_type=NEW.resource_type and action=NEW.action; if role_kind is null or permission_category is null or role_kind='business_admin' or (role_kind='business' and permission_category<>'business') or (role_kind='system_admin' and permission_category<>'platform') or (role_kind='tenant_security_admin' and permission_category<>'tenant') then raise exception using errcode='23514', message='role permission category mismatch'; end if; return NEW; end $$;
  create trigger role_permission_guard before insert or update on access_role_permissions for each row execute function access_validate_role_permission();
  create or replace function access_validate_binding() returns trigger language plpgsql set search_path to :"schema", pg_catalog as $$ declare role_kind text; begin select kind into role_kind from access_roles where tenant_id=NEW.tenant_id and business_id=NEW.business_id and id=NEW.role_id; if role_kind is null or (role_kind='business_admin' and NEW.scope_kind<>'business') or (role_kind<>'business_admin' and NEW.scope_kind='business') or (role_kind='system_admin' and (NEW.business_id<>'idp' or NEW.resource_type<>'idp.platform' or NEW.scope_kind<>'type')) or (role_kind='tenant_security_admin' and (NEW.business_id<>'idp' or NEW.resource_type<>'idp.tenant' or NEW.scope_kind<>'type')) then raise exception using errcode='23514', message='role binding scope mismatch'; end if; return NEW; end $$;
  create trigger role_binding_guard before insert or update on access_role_bindings for each row execute function access_validate_binding();
  create or replace function :"schema".access_guard_state() returns trigger language plpgsql as $$ begin if TG_OP='DELETE' then raise exception using errcode='23514', message='deployment mode and version are immutable'; end if; return NEW; end $$;
  alter table :"schema".access_state drop constraint access_state_module_version_check;
  update :"schema".access_state set module_version='tenant_v3' where singleton;
  alter table :"schema".access_state add constraint access_state_module_version_check check(module_version='tenant_v3');
  create or replace function :"schema".access_guard_state() returns trigger language plpgsql as $$ begin if TG_OP='DELETE' or (NEW.tenancy_mode,NEW.module_version) is distinct from (OLD.tenancy_mode,OLD.module_version) then raise exception using errcode='23514', message='deployment mode and version are immutable'; end if; return NEW; end $$;
  insert into :"schema".access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,target_business_id,operation,request_id,change_json)
    values((substr(md5(random()::text||clock_timestamp()::text),1,8)||'-'||substr(md5(random()::text),1,4)||'-4'||substr(md5(random()::text),1,3)||'-a'||substr(md5(random()::text),1,3)||'-'||substr(md5(random()::text),1,12))::uuid,floor(extract(epoch from clock_timestamp()))::bigint,:'actor_id'::uuid,'0',null,'offline_migration','0',null,'access.migrate_business_scope',:'request_id',jsonb_build_object('from','tenant_v2','to','tenant_v3','permission_mappings',(select count(*) from business_permission_map),'role_mappings',(select count(*) from business_role_map)));
  select count(*) as mapped_permissions from business_permission_map;
  select count(*) as mapped_roles from business_role_map;
\if :apply
  commit;
  \echo 'tenant_v3 migration committed.'
\else
  rollback;
  \echo 'dry run complete; no schema or data changed.'
\endif

\set ON_ERROR_STOP on
-- This migration never runs implicitly. The shell wrapper defaults to dry-run.
\if :apply
 begin;
 select pg_advisory_xact_lock(hashtext(:'schema' || ':embedded-idp-migration'));
 lock table :"schema".access_state, :"schema".auth_sessions, :"schema".refresh_tokens,
   :"schema".devices, :"schema".device_proof_keys, :"schema".account_device_bindings in access exclusive mode;
\else
 begin isolation level repeatable read;
\endif
select module_version as observed_version from :"schema".access_state where singleton \gset
\if :apply
\else
 select :'observed_version' in ('tenant_v4','tenant_v5') as compatible_source \gset
 \if :compatible_source
 \else
  rollback;
  do $$ begin raise exception 'tenant_v4 source or tenant_v5 target required'; end $$;
 \endif
 rollback;
 \echo 'dry-run complete; no changes made. Source must be tenant_v4; tenant_v5 is verified by the apply idempotence check.'
 \quit
\endif
-- psql conditionals cannot compare variables portably; enforce version in SQL.
select set_config('embedded_idp.scan_schema', :'schema', true);
do $$
declare n text:=current_setting('embedded_idp.scan_schema'); v text;
begin
 execute format('select module_version from %I.access_state where singleton',n) into v;
 if v='tenant_v5' then
   if (select count(*) from information_schema.tables where table_schema=n and table_name in ('scan_login_grants','scan_login_operations','scan_login_deliveries','scan_login_audit_events'))<>4 then raise exception 'tenant_v5 layout is incomplete'; end if;
   return;
 end if;
 if v<>'tenant_v4' then raise exception 'tenant_v4 source required, got %',v; end if;
 execute format($q$create table %1$I.scan_login_grants (tenant_id text not null,host_scope text collate "C" not null,entry_id text collate "C" not null,id uuid primary key,mode text not null check(mode in ('device_display','phone_display')),target_client_id text not null references %1$I.oidc_clients(client_id),state text not null check(state in ('waiting_user','waiting_device','awaiting_approval','approved','issued','denied','cancelled','expired','invalidated')),version bigint not null check(version>0),code_digest bytea not null check(octet_length(code_digest)=32),source_account_id uuid,source_session_id uuid,source_client_id text,source_authenticated_at_epoch bigint,target_device_id uuid,target_key_id text,target_device_version bigint,target_key_version bigint,presentation_key_id text,presentation_nonce bytea,presentation_ciphertext bytea,delivery_secret_hash bytea check(delivery_secret_hash is null or octet_length(delivery_secret_hash)=32),confirmation_revision text,created_at_epoch bigint not null,expires_at_epoch bigint not null,code_expires_at_epoch bigint not null,approved_until_epoch bigint,unique(tenant_id,host_scope,entry_id,code_digest),foreign key(source_account_id) references %1$I.accounts(id),foreign key(tenant_id,source_session_id) references %1$I.auth_sessions(tenant_id,id),foreign key(tenant_id,target_device_id,target_client_id) references %1$I.devices(tenant_id,id,client_id),foreign key(tenant_id,target_device_id,target_key_id) references %1$I.device_proof_keys(tenant_id,device_id,key_id),check ((source_account_id is null)=(source_session_id is null) and (source_account_id is null)=(source_client_id is null) and (source_account_id is null)=(source_authenticated_at_epoch is null)),check ((target_device_id is null)=(target_key_id is null) and (target_device_id is null)=(target_device_version is null) and (target_device_id is null)=(target_key_version is null)),check ((presentation_key_id is null)=(presentation_nonce is null) and (presentation_key_id is null)=(presentation_ciphertext is null)),check(expires_at_epoch>created_at_epoch and code_expires_at_epoch>created_at_epoch and code_expires_at_epoch<=expires_at_epoch),check(approved_until_epoch is null or (approved_until_epoch>created_at_epoch and approved_until_epoch<=expires_at_epoch)))$q$,n);
 execute format('create table %I.scan_login_operations (tenant_id text not null,host_scope text collate "C" not null,entry_id text collate "C" not null,actor_id text collate "C" not null,action text collate "C" not null,operation_id text collate "C" not null,fingerprint bytea not null check(octet_length(fingerprint)=32),grant_id uuid not null references %I.scan_login_grants(id),created_at_epoch bigint not null,primary key(tenant_id,host_scope,entry_id,actor_id,action,operation_id))',n,n);
 execute format('create table %I.scan_login_deliveries (tenant_id text not null,grant_id uuid not null references %I.scan_login_grants(id),issuance_operation_id text collate "C" not null,session_id uuid not null,state text not null check(state in (''recoverable'',''acknowledged'',''revoked'')),binding_id uuid not null,binding_version bigint not null check(binding_version>0),result_key_id text,result_nonce bytea,result_ciphertext bytea,receipt_nonce_hash bytea check(receipt_nonce_hash is null or octet_length(receipt_nonce_hash)=32),recover_until_epoch bigint not null,created_at_epoch bigint not null,release_authorized_at_epoch bigint,acknowledged_at_epoch bigint,revoked_at_epoch bigint,reason text,primary key(tenant_id,grant_id),unique(tenant_id,session_id),unique(tenant_id,grant_id,issuance_operation_id),foreign key(tenant_id,session_id) references %I.auth_sessions(tenant_id,id),foreign key(tenant_id,binding_id) references %I.account_device_bindings(tenant_id,id),check ((result_key_id is null)=(result_nonce is null) and (result_key_id is null)=(result_ciphertext is null)),check(recover_until_epoch>=created_at_epoch))',n,n,n,n);
 execute format('create table %I.scan_login_audit_events (id uuid primary key,tenant_id text not null,host_scope text collate "C" not null,grant_id uuid not null references %I.scan_login_grants(id),actor_kind text not null,actor_id text,operation text collate "C" not null,operation_id text collate "C" not null,session_id uuid,decision_id text,occurred_at_epoch bigint not null)',n,n);
 execute format('create index scan_login_grants_target_pending on %I.scan_login_grants(tenant_id,target_device_id,state,expires_at_epoch)',n);
 execute format('create index scan_login_grants_source_pending on %I.scan_login_grants(tenant_id,source_session_id,state,expires_at_epoch)',n);
 execute format('create index scan_login_grants_expiry on %I.scan_login_grants(host_scope,entry_id,expires_at_epoch,id) where state in (''waiting_user'',''waiting_device'',''awaiting_approval'',''approved'')',n);
 execute format('create index scan_login_deliveries_expiry on %I.scan_login_deliveries(recover_until_epoch,grant_id) where state=''recoverable''',n);
 execute format('create index scan_login_audit_grant on %I.scan_login_audit_events(tenant_id,grant_id,occurred_at_epoch)',n);
 execute format('create or replace function %I.access_guard_state() returns trigger language plpgsql as $f$ begin if TG_OP=''DELETE'' then raise exception using errcode=''23514'',message=''deployment mode and version are immutable''; end if; return NEW; end $f$',n);
 execute format('alter table %I.access_state drop constraint access_state_module_version_check',n);
 execute format('update %I.access_state set module_version=''tenant_v5'' where singleton',n);
 execute format('alter table %I.access_state add constraint access_state_module_version_check check(module_version=''tenant_v5'')',n);
 execute format('create or replace function %I.access_guard_state() returns trigger language plpgsql as $f$ begin if TG_OP=''DELETE'' or (NEW.tenancy_mode,NEW.module_version) is distinct from (OLD.tenancy_mode,OLD.module_version) then raise exception using errcode=''23514'',message=''deployment mode and version are immutable''; end if; return NEW; end $f$',n);
end $$;
commit;
\echo 'tenant_v5 migration committed or target layout verified.'

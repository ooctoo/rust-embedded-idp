#!/usr/bin/env bash
set -euo pipefail

: "${EMBEDDED_IDP_TEST_PG_CONNECTION_URI:?set EMBEDDED_IDP_TEST_PG_CONNECTION_URI}"
export EMBEDDED_IDP_TEST_PG_CONNECTION_URI
command -v psql >/dev/null || { echo 'psql is required' >&2; exit 127; }
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 127; }
root=$(cd "$(dirname "$0")/.." && pwd)
libpq_file=$(mktemp)
if ! python3 - > "$libpq_file" <<'PY'
import os
import sys
from urllib.parse import unquote, urlsplit

uri = urlsplit(os.environ["EMBEDDED_IDP_TEST_PG_CONNECTION_URI"])
if uri.scheme not in ("postgres", "postgresql") or not uri.hostname or not uri.path.strip("/") or uri.query or uri.fragment:
    raise SystemExit("test connection URI must contain host and database without query options")
parts = {"PGHOST": uri.hostname, "PGDATABASE": unquote(uri.path.lstrip("/"))}
if uri.port:
    parts["PGPORT"] = str(uri.port)
if uri.username:
    parts["PGUSER"] = unquote(uri.username)
if uri.password:
    parts["PGPASSWORD"] = unquote(uri.password)
for key, value in parts.items():
    sys.stdout.buffer.write(key.encode() + b"\0" + value.encode() + b"\0")
PY
then
  rm -f "$libpq_file"
  exit 64
fi
while IFS= read -r -d '' key && IFS= read -r -d '' value; do
  export "$key=$value"
done < "$libpq_file"
rm -f "$libpq_file"
prefix="idp_device_migration_test_${RANDOM}_${RANDOM}"
actor=11111111-1111-4111-8111-111111111111
member=22222222-2222-4222-8222-222222222222
role=33333333-3333-4333-8333-333333333333
active=44444444-4444-4444-8444-444444444444
legacy=55555555-5555-4555-8555-555555555555
session=66666666-6666-4666-8666-666666666666
schemas=()
cleanup() {
  for schema in "${schemas[@]}"; do
    psql -X -v ON_ERROR_STOP=1 -c "drop schema if exists ${schema} cascade" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
value() { psql -X -At -v ON_ERROR_STOP=1 -c "$2"; }
assert_eq() { [[ $1 == "$2" ]] || { echo "$3: expected $2, got $1" >&2; exit 1; }; }
fixture() {
  local schema=$1 mode=$2 domain=$3
  schemas+=("$schema")
  psql -X -v ON_ERROR_STOP=1 -c "create schema ${schema}" >/dev/null
  sed "s/__SCHEMA__/${schema}/g" "$root/crates/embedded-idp-storage-postgres/src/sql/tenant_v3.sql" | psql -X -v ON_ERROR_STOP=1 >/dev/null
  psql -X -v ON_ERROR_STOP=1 -v schema="$schema" -v mode="$mode" -v domain="$domain" -v actor="$actor" -v member="$member" -v role="$role" -v active="$active" -v legacy="$legacy" -v session="$session" <<'SQL' >/dev/null
begin;
insert into :"schema".access_state(singleton,tenancy_mode,module_version,bootstrap_completed_at_epoch) values(true,:'mode','tenant_v3',1);
insert into :"schema".access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values('0','system','System','active',false,1);
insert into :"schema".access_tenants(id,kind,name,status,allow_registration,created_at_epoch)
  select :'domain','tenant','Tenant','active',true,1 where :'domain'<>'0';
insert into :"schema".accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch)
  values(:'actor'::uuid,'0','actor@example.test','fixture','active',1),(:'member'::uuid,:'domain','member@example.test','fixture','active',1);
insert into :"schema".access_memberships(tenant_id,account_id,status,joined_at_epoch)
  values('0',:'actor'::uuid,'active',1),(:'domain',:'member'::uuid,'active',1);
insert into :"schema".access_permissions(tenant_id,business_id,resource_type,action,category,description,enabled)
  select '0','idp','idp.platform',action,'platform',action,true
  from unnest(array['users.read','users.security','tenants.manage','users.bind','clients.manage','access.manage','audit.read']) action;
insert into :"schema".access_roles(tenant_id,business_id,id,key,name,status,kind,created_at_epoch)
  values('0','idp',:'role'::uuid,'idp_system_admin','Admin','active','system_admin',1);
insert into :"schema".access_role_permissions(tenant_id,business_id,role_id,resource_type,action)
  select '0','idp',:'role'::uuid,'idp.platform',action from :"schema".access_permissions where tenant_id='0' and business_id='idp';
insert into :"schema".access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,resource_id,created_at_epoch,created_by)
  values('77777777-7777-4777-8777-777777777777','0','idp',:'actor'::uuid,:'role'::uuid,'type','idp.platform',null,1,:'actor'::uuid);
insert into :"schema".oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch)
  values('fixture','Fixture','[]','public_desktop',true,1);
insert into :"schema".devices(tenant_id,id,client_id,device_name,status,registered_at_epoch)
  values(:'domain',:'active'::uuid,'fixture','Active','active',1),(:'domain',:'legacy'::uuid,'fixture','Legacy','disabled',1);
insert into :"schema".device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch)
  values(:'domain',repeat('a',43),:'active'::uuid,'ed25519','fixture',1,'active',1);
update :"schema".devices set proof_key_id=repeat('a',43) where tenant_id=:'domain' and id=:'active'::uuid;
insert into :"schema".account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch)
  values(:'domain','88888888-8888-4888-8888-888888888888',:'member'::uuid,:'legacy'::uuid,'active',1);
insert into :"schema".auth_sessions(tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch)
  values(:'domain',:'session'::uuid,:'member'::uuid,'fixture',:'legacy'::uuid,'active',1,10000000000,1,1);
insert into :"schema".refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch)
  values(:'domain','99999999-9999-4999-8999-999999999999',:'session'::uuid,decode(repeat('ab',32),'hex'),1,1,10000000000);
insert into :"schema".authorization_codes(tenant_id,code_digest,account_id,source_session_id,login_entry,client_id,redirect_uri,scope,created_at_epoch,expires_at_epoch)
  values(:'domain',decode(repeat('cd',32),'hex'),:'member'::uuid,:'session'::uuid,'fixture','fixture','https://example.test','openid',1,10000000000);
insert into :"schema".auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch,source_tenant_id,source_session_id)
  values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',decode(repeat('ef',32),'hex'),:'member'::uuid,'fixture','fixture','tenant_selection',1,10000000000,:'domain',:'session'::uuid);
insert into :"schema".device_nonces(tenant_id,id,device_id,purpose,challenge_digest,issued_at_epoch,expires_at_epoch)
  values(:'domain','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',:'legacy'::uuid,'heartbeat',decode(repeat('12',32),'hex'),1,10000000000);
commit;
SQL
}
for mode in disabled enabled; do
  domain=0
  [[ $mode == enabled ]] && domain=t1
  schema="${prefix}_${mode}"
  fixture "$schema" "$mode" "$domain"
  "$root/scripts/migrate_device_lifecycle.sh" "$schema" "$actor" "dry-${mode}" >/dev/null
  assert_eq "$(value "$schema" "select module_version from ${schema}.access_state")" tenant_v3 'dry-run changed schema'
  assert_eq "$(value "$schema" "select count(*) from ${schema}.access_audit_events")" 0 'dry-run wrote audit'
  "$root/scripts/migrate_device_lifecycle.sh" "$schema" "$actor" "apply-${mode}" --apply >/dev/null
  assert_eq "$(value "$schema" "select module_version from ${schema}.access_state")" tenant_v4 'apply did not advance schema'
  assert_eq "$(value "$schema" "select status from ${schema}.devices where id='${legacy}'")" revoked 'legacy device remained enabled'
  assert_eq "$(value "$schema" "select status from ${schema}.devices where id='${active}'")" active 'valid device was changed'
  assert_eq "$(value "$schema" "select status from ${schema}.auth_sessions where id='${session}'")" revoked 'session was not revoked'
  assert_eq "$(value "$schema" "select count(*) from ${schema}.authorization_codes")" 0 'authorization code survived'
  assert_eq "$(value "$schema" "select count(*) from ${schema}.device_nonces")" 0 'nonce survived'
  assert_eq "$(value "$schema" "select status from ${schema}.account_device_bindings")" unbound 'binding survived'
  assert_eq "$(value "$schema" "select count(*) from ${schema}.access_audit_events where operation='access.migrate_device_lifecycle'")" 2 'missing migration audit'
  "$root/scripts/migrate_device_lifecycle.sh" "$schema" "$actor" "replay-${mode}" --apply >/dev/null
  assert_eq "$(value "$schema" "select count(*) from ${schema}.access_audit_events where operation='access.migrate_device_lifecycle'")" 2 'replay changed audit'
done
invalid="${prefix}_invalid"
fixture "$invalid" enabled t1
psql -X -v ON_ERROR_STOP=1 -c "update ${invalid}.devices set proof_key_id=null where id='${active}'" >/dev/null
if "$root/scripts/migrate_device_lifecycle.sh" "$invalid" "$actor" invalid --apply >/dev/null 2>&1; then
  echo 'invalid active device migrated' >&2; exit 1
fi
assert_eq "$(value "$invalid" "select module_version from ${invalid}.access_state")" tenant_v3 'invalid data changed schema'
assert_eq "$(value "$invalid" "select count(*) from information_schema.columns where table_schema='${invalid}' and table_name='devices' and column_name='version'")" 0 'invalid data added version'
failed_audit="${prefix}_audit_failure"
fixture "$failed_audit" enabled t1
psql -X -v ON_ERROR_STOP=1 -c "create function ${failed_audit}.fail_audit() returns trigger language plpgsql as \$\$ begin raise exception 'injected migration audit failure'; end \$\$; create trigger fail_audit before insert on ${failed_audit}.access_audit_events for each row execute function ${failed_audit}.fail_audit()" >/dev/null
if "$root/scripts/migrate_device_lifecycle.sh" "$failed_audit" "$actor" audit-failure --apply >/dev/null 2>&1; then
  echo 'audit failure did not roll back migration' >&2; exit 1
fi
assert_eq "$(value "$failed_audit" "select module_version from ${failed_audit}.access_state")" tenant_v3 'audit failure changed schema'
assert_eq "$(value "$failed_audit" "select status from ${failed_audit}.devices where id='${legacy}'")" disabled 'audit failure changed device'
echo 'device lifecycle migration verified in both tenancy modes'

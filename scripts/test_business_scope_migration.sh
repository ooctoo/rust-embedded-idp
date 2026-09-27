#!/usr/bin/env bash
set -euo pipefail

: "${EMBEDDED_IDP_TEST_PG_CONNECTION_URI:?set EMBEDDED_IDP_TEST_PG_CONNECTION_URI}"
command -v psql >/dev/null || { echo 'psql is required' >&2; exit 127; }

repo_root=$(cd "$(dirname "$0")/.." && pwd)
uri=$EMBEDDED_IDP_TEST_PG_CONNECTION_URI
work=$(mktemp -d "${TMPDIR:-/tmp}/embedded-idp-business-scope-test.XXXXXX")
prefix="idp_business_scope_test_${RANDOM}_${RANDOM}"
schemas=("${prefix}_ok" "${prefix}_unknown" "${prefix}_cross" "${prefix}_reserved")
actor=11111111-1111-4111-8111-111111111111
member=22222222-2222-4222-8222-222222222222
system_role=33333333-3333-4333-8333-333333333333
business_role=44444444-4444-4444-8444-444444444444
unknown_role=55555555-5555-4555-8555-555555555555

cleanup() {
  for schema in "${schemas[@]}"; do
    psql -X -v ON_ERROR_STOP=1 "$uri" -c "drop schema if exists ${schema} cascade" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

sql() {
  local schema=$1 statement=$2
  psql -X -v ON_ERROR_STOP=1 "$uri" -v schema="$schema" -c "$statement" >/dev/null
}

value() {
  local schema=$1 statement=$2
  psql -X -At -v ON_ERROR_STOP=1 "$uri" -v schema="$schema" -c "$statement"
}

assert_eq() {
  local actual=$1 expected=$2 message=$3
  [[ $actual == "$expected" ]] || { echo "$message: expected $expected, got $actual" >&2; exit 1; }
}

fixture() {
  local schema=$1
  sql "$schema" "create schema ${schema}"
  sed "s/__SCHEMA__/${schema}/g" "$repo_root/crates/embedded-idp-storage-postgres/src/sql/tenant_v2.sql" |
    psql -X -v ON_ERROR_STOP=1 "$uri" >/dev/null
  sql "$schema" "
    insert into ${schema}.access_state(singleton,tenancy_mode,module_version,bootstrap_completed_at_epoch)
      values(true,'enabled','tenant_v2',1);
    insert into ${schema}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch)
      values('0','system','System','active',false,1),('t1','tenant','Tenant 1','active',true,1);
    insert into ${schema}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch)
      values('${actor}','0','actor@example.test','fixture','active',1),
            ('${member}','t1','member@example.test','fixture','active',1);
    insert into ${schema}.access_memberships(tenant_id,account_id,status,joined_at_epoch)
      values('0','${actor}','active',1),('t1','${member}','active',1);
    insert into ${schema}.access_permissions(tenant_id,resource_type,action,category,description,enabled)
      values('0','idp.platform','users.read','platform','Read users',true),
            ('0','idp.platform','users.security','platform','Manage user security',true),
            ('0','idp.platform','tenants.manage','platform','Manage tenants',true),
            ('0','idp.platform','users.bind','platform','Bind users',true),
            ('0','idp.platform','clients.manage','platform','Manage clients',true),
            ('0','idp.platform','access.manage','platform','Manage IDP',true),
            ('0','idp.platform','audit.read','platform','Read audit',true),
            ('t1','report','read','business','Read reports',true);
    insert into ${schema}.access_roles(tenant_id,id,key,name,status,kind,created_at_epoch)
      values('0','${system_role}','system_admin','Custom platform operator','active','system_admin',1),
            ('t1','${business_role}','report_reader','Report reader','active','business',1);
    insert into ${schema}.access_role_permissions(tenant_id,role_id,resource_type,action)
      select '0','${system_role}',resource_type,action from ${schema}.access_permissions where tenant_id='0' and resource_type='idp.platform';
    insert into ${schema}.access_role_permissions(tenant_id,role_id,resource_type,action)
      values('t1','${business_role}','report','read');
    insert into ${schema}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,resource_id,created_at_epoch,created_by)
      values('66666666-6666-4666-8666-666666666666','0','${actor}','${system_role}','idp.platform',null,1,'${actor}'),
            ('77777777-7777-4777-8777-777777777777','t1','${member}','${business_role}','report','report-1',1,'${actor}')"
}

write_maps() {
  local permission_file=$1 role_file=$2 business_id=$3
  cat >"$permission_file" <<EOF
tenant_id	resource_type	action	business_id
t1	report	read	${business_id}
EOF
  cat >"$role_file" <<EOF
tenant_id	role_id	business_id
t1	${business_role}	${business_id}
EOF
}

run_migration() {
  local schema=$1 permissions=$2 roles=$3 request=$4
  shift 4
  "$repo_root/scripts/migrate_business_scope.sh" "$uri" "$schema" "$permissions" "$roles" "$actor" "$request" "$@"
}

ok=${schemas[0]}
fixture "$ok"
permissions="$work/permissions.tsv"
roles="$work/roles.tsv"
write_maps "$permissions" "$roles" f_01

run_migration "$ok" "$permissions" "$roles" dry-run >/dev/null
assert_eq "$(value "$ok" "select module_version from ${ok}.access_state")" tenant_v2 'dry run changed module version'
assert_eq "$(value "$ok" "select count(*) from information_schema.columns where table_schema='${ok}' and table_name='access_roles' and column_name='business_id'")" 0 'dry run changed schema'
assert_eq "$(value "$ok" "select count(*) from ${ok}.access_audit_events")" 0 'dry run wrote audit'

run_migration "$ok" "$permissions" "$roles" apply-1 --apply >/dev/null
assert_eq "$(value "$ok" "select module_version from ${ok}.access_state")" tenant_v3 'apply did not set v3'
assert_eq "$(value "$ok" "select business_id from ${ok}.access_permissions where tenant_id='t1' and resource_type='report' and action='read'")" f_01 'permission business mapping lost'
assert_eq "$(value "$ok" "select business_id from ${ok}.access_roles where id='${business_role}'")" f_01 'role business mapping lost'
assert_eq "$(value "$ok" "select business_id || ':' || scope_kind || ':' || coalesce(resource_id,'') from ${ok}.access_role_bindings where role_id='${business_role}'")" 'f_01:instance:report-1' 'ordinary binding authorization changed'
assert_eq "$(value "$ok" "select key || ':' || name from ${ok}.access_roles where id='${system_role}'")" 'idp_system_admin:Custom platform operator' 'custom IDP role name was not preserved'
assert_eq "$(value "$ok" "select count(*) from ${ok}.access_audit_events where operation='access.migrate_business_scope'")" 1 'apply audit missing'
assert_eq "$(value "$ok" "select collation_name from information_schema.columns where table_schema='${ok}' and table_name='access_audit_events' and column_name='target_business_id'")" C 'audit business collation differs from tenant_v3'
sql "$ok" "
  update ${ok}.access_roles set name='Report reader v2' where id='${business_role}';
  insert into ${ok}.access_roles(tenant_id,business_id,id,key,name,status,kind,created_at_epoch) values('t1','f_01','88888888-8888-4888-8888-888888888888','report_writer','Report writer','active','business',2);
  insert into ${ok}.access_role_permissions(tenant_id,business_id,role_id,resource_type,action) values('t1','f_01','88888888-8888-4888-8888-888888888888','report','read');
  insert into ${ok}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,resource_id,created_at_epoch,created_by) values('99999999-9999-4999-8999-999999999999','t1','f_01','${member}','88888888-8888-4888-8888-888888888888','instance','report','report-2',2,'${actor}')"
if sql "$ok" "insert into ${ok}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,resource_id,created_at_epoch,created_by) values('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','t1','f_01','${member}','88888888-8888-4888-8888-888888888888','business',null,null,3,'${actor}')" >/dev/null 2>&1; then
  echo 'business role accepted a business-wide binding' >&2
  exit 1
fi
run_migration "$ok" "$permissions" "$roles" apply-2 --apply >/dev/null
assert_eq "$(value "$ok" "select count(*) from ${ok}.access_audit_events where operation='access.migrate_business_scope'")" 1 'replay wrote another audit event'

unknown=${schemas[1]}
fixture "$unknown"
unknown_permissions="$work/unknown-permissions.tsv"
unknown_roles="$work/unknown-roles.tsv"
write_maps "$unknown_permissions" "$unknown_roles" f_01
printf 't1\t%s\tf_02\n' "$unknown_role" >>"$unknown_roles"
if run_migration "$unknown" "$unknown_permissions" "$unknown_roles" unknown-role --apply >/dev/null 2>&1; then
  echo 'unknown role mapping unexpectedly migrated' >&2
  exit 1
fi
assert_eq "$(value "$unknown" "select module_version from ${unknown}.access_state")" tenant_v2 'unknown role mapping did not roll back'
assert_eq "$(value "$unknown" "select count(*) from ${unknown}.access_audit_events")" 0 'unknown role mapping wrote audit'

cross=${schemas[2]}
fixture "$cross"
cross_permissions="$work/cross-permissions.tsv"
cross_roles="$work/cross-roles.tsv"
write_maps "$cross_permissions" "$cross_roles" f_02
cat >"$cross_roles" <<EOF
tenant_id	role_id	business_id
t1	${business_role}	f_01
EOF
if run_migration "$cross" "$cross_permissions" "$cross_roles" cross-business --apply >/dev/null 2>&1; then
  echo 'cross-business mapping unexpectedly migrated' >&2
  exit 1
fi
assert_eq "$(value "$cross" "select module_version from ${cross}.access_state")" tenant_v2 'cross-business mapping did not roll back'
assert_eq "$(value "$cross" "select count(*) from ${cross}.access_audit_events")" 0 'cross-business mapping wrote audit'

reserved=${schemas[3]}
fixture "$reserved"
reserved_permissions="$work/reserved-permissions.tsv"
reserved_roles="$work/reserved-roles.tsv"
write_maps "$reserved_permissions" "$reserved_roles" f_01
sql "$reserved" "update ${reserved}.access_roles set key='system_admin' where id='${business_role}'"
reserved_output="$work/reserved.out"
if run_migration "$reserved" "$reserved_permissions" "$reserved_roles" reserved-role --apply >"$reserved_output" 2>&1; then
  echo 'legacy reserved role key unexpectedly migrated' >&2
  exit 1
fi
grep -q 'reserved role key conflict requires an explicit pre-migration rename' "$reserved_output" || {
  echo 'legacy reserved role key did not fail the explicit preflight' >&2
  exit 1
}
assert_eq "$(value "$reserved" "select module_version from ${reserved}.access_state")" tenant_v2 'reserved role key did not roll back'

echo 'business scope migration integration test passed'

#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
wrapper="$root/scripts/migrate_scan_login_origin_closures.sh"
sql="$root/scripts/migrate_scan_login_origin_closures.sql"
ddl="$root/crates/embedded-idp-storage-postgres/src/sql/tenant_v6.sql"

bash -n "$wrapper"
grep -Fq 'mode=${2:-dry-run}' "$wrapper"
grep -Fq 'psql -X -v ON_ERROR_STOP=1' "$wrapper"
if grep -Fq 'psql "$EMBEDDED_IDP_PG_CONNECTION_URI"' "$wrapper"; then
  echo 'migration wrapper passes a URI on the psql command line' >&2
  exit 1
fi
grep -Fq 'PGDATABASE' "$wrapper"
grep -Fq "select :'observed_version' in ('tenant_v5','tenant_v6')" "$sql"
grep -Fq 'tenant_v5 source required' "$sql"
grep -Fq 'scan_login_origin_closures' "$sql"
grep -Fq 'primary key(tenant_id,host_scope,entry_id,device_id,origin_action,origin_operation_id)' "$sql"
grep -Fq 'delivery_secret_hash bytea not null check(octet_length(delivery_secret_hash)=32)' "$sql"
grep -Fq 'scan_login_origin_closures' "$ddl"
grep -Fq 'primary key(tenant_id,host_scope,entry_id,device_id,origin_action,origin_operation_id)' "$ddl"
echo 'scan login origin closure migration wrapper static checks passed'

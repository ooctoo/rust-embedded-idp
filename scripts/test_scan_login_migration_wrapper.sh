#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
wrapper="$root/scripts/migrate_scan_login.sh"
sql="$root/scripts/migrate_scan_login.sql"
ddl="$root/crates/embedded-idp-storage-postgres/src/sql/tenant_v5.sql"

bash -n "$wrapper"
grep -Fq 'mode=${2:-dry-run}' "$wrapper"
grep -Fq 'psql -X -v ON_ERROR_STOP=1' "$wrapper"
if grep -Fq 'psql "$EMBEDDED_IDP_PG_CONNECTION_URI"' "$wrapper"; then
  echo 'migration wrapper passes a URI on the psql command line' >&2
  exit 1
fi
grep -Fq 'PGDATABASE' "$wrapper"
grep -Fq "select :'observed_version' in" "$sql"
grep -Fq 'set PGDATABASE and configure libpq' "$wrapper"
grep -Fq "(source_account_id is null)=(source_session_id is null)" "$sql"
grep -Fq "(target_device_id is null)=(target_key_id is null)" "$sql"
grep -Fq "(presentation_key_id is null)=(presentation_nonce is null)" "$sql"
grep -Fq "(source_account_id is null) = (source_session_id is null)" "$ddl"
grep -Fq "(target_device_id is null) = (target_key_id is null)" "$ddl"
grep -Fq "(presentation_key_id is null) = (presentation_nonce is null)" "$ddl"
echo 'scan login migration wrapper static checks passed'

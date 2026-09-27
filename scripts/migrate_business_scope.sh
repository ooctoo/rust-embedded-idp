#!/usr/bin/env bash
set -euo pipefail

if (($# != 6 && $# != 7)); then
  echo "usage: $0 CONNECTION_URI SCHEMA PERMISSION_MAPPING.tsv ROLE_MAPPING.tsv ACTOR_UUID REQUEST_ID [--apply]" >&2
  exit 64
fi
connection_uri=$1 schema=$2 permission_map=$3 role_map=$4 actor_id=$5 request_id=$6
apply=${7:-}
[[ $schema =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo 'invalid schema' >&2; exit 64; }
[[ $request_id =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || { echo 'invalid request id' >&2; exit 64; }
for file in "$permission_map" "$role_map"; do
  [[ -f $file && $file =~ ^[A-Za-z0-9_./-]+$ ]] || { echo 'mapping must be an ordinary local file path' >&2; exit 64; }
done
[[ -z $apply || $apply == --apply ]] || { echo 'only --apply is accepted' >&2; exit 64; }
tool_dir=$(cd "$(dirname "$0")" && pwd)
temporary=$(mktemp "${TMPDIR:-/tmp}/embedded-idp-business-migration.XXXXXX.sql")
trap 'rm -f "$temporary"' EXIT
sed -e "s|__PERMISSION_MAPPING__|$permission_map|g" -e "s|__ROLE_MAPPING__|$role_map|g" "$tool_dir/migrate_business_scope.sql" > "$temporary"
psql -X --set=ON_ERROR_STOP=1 "$connection_uri" -v schema="$schema" -v permission_mapping="$permission_map" -v role_mapping="$role_map" -v actor_id="$actor_id" -v request_id="$request_id" -v apply=$([[ $apply == --apply ]] && echo true || echo false) -f "$temporary"

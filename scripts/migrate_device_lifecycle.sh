#!/usr/bin/env bash
set -euo pipefail

if (($# != 3 && $# != 4)); then
  echo "usage: PGDATABASE=... $0 SCHEMA ACTOR_UUID REQUEST_ID [--apply]" >&2
  exit 64
fi
: "${PGDATABASE:?set PGDATABASE to the target database name and configure libpq connection variables}"
schema=$1 actor_id=$2 request_id=$3 apply=${4:-}
[[ $schema =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo 'invalid schema' >&2; exit 64; }
[[ $actor_id =~ ^[0-9a-fA-F-]{36}$ ]] || { echo 'invalid actor UUID' >&2; exit 64; }
[[ $request_id =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || { echo 'invalid request id' >&2; exit 64; }
[[ -z $apply || $apply == --apply ]] || { echo 'only --apply is accepted' >&2; exit 64; }
tool_dir=$(cd "$(dirname "$0")" && pwd)
psql -X --set=ON_ERROR_STOP=1 -v schema="$schema" -v actor_id="$actor_id" -v request_id="$request_id" -v apply=$([[ $apply == --apply ]] && echo true || echo false) -f "$tool_dir/migrate_device_lifecycle.sql"

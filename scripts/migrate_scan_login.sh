#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  echo "usage: PGDATABASE=... $0 SCHEMA [--apply]"
  echo 'Configure libpq PGHOST, PGPORT, PGUSER and password file or PGPASSWORD; default is dry-run.'
  exit 0
fi
if (($# < 1 || $# > 2)); then
  echo "usage: PGDATABASE=... $0 SCHEMA [--apply]" >&2
  exit 64
fi
: "${PGDATABASE:?set PGDATABASE and configure libpq connection variables explicitly}"
schema=$1
mode=${2:-dry-run}
[[ $schema =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo 'invalid schema name' >&2; exit 64; }
case "$mode" in (dry-run|--apply) ;; (*) echo 'mode must be dry-run or --apply' >&2; exit 64;; esac
root=$(cd "$(dirname "$0")/.." && pwd)
apply=false; [[ $mode == --apply ]] && apply=true
psql -X -v ON_ERROR_STOP=1 -v schema="$schema" -v apply="$apply" -f "$root/scripts/migrate_scan_login.sql"

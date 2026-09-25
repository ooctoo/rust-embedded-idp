#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/load_dev_env.sh"
load_dev_env "${1:-}"

PG_CONNECTION_URI="${EMBEDDED_IDP_TEST_PG_CONNECTION_URI:-}"

if [[ -z "${PG_CONNECTION_URI}" ]]; then
  echo "missing EMBEDDED_IDP_TEST_PG_CONNECTION_URI"
  exit 1
fi

cd "${MODULE_ROOT}"

echo "running live postgres integration tests"

pnpm --dir web build

EMBEDDED_IDP_TEST_PG_CONNECTION_URI="${PG_CONNECTION_URI}" \
cargo test -p embedded-idp-storage-postgres --locked --test live_postgres --test live_access --test live_access_admin --test live_access_bootstrap --test live_access_tenants --test live_pool --test live_tenant_registration -- --ignored --nocapture

EMBEDDED_IDP_TEST_PG_CONNECTION_URI="${PG_CONNECTION_URI}" \
cargo test -p embedded-idp-app --locked --test live_bootstrap_admin --test live_reference_host -- --ignored --nocapture

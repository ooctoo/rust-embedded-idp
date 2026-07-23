#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${MODULE_ROOT}/.env"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

PG_CONNECTION_URI="${EMBEDDED_IDP_TEST_PG_CONNECTION_URI:-}"

if [[ -z "${PG_CONNECTION_URI}" ]]; then
  echo "missing EMBEDDED_IDP_TEST_PG_CONNECTION_URI"
  exit 1
fi

cd "${MODULE_ROOT}"

echo "running live postgres integration tests"

EMBEDDED_IDP_TEST_PG_CONNECTION_URI="${PG_CONNECTION_URI}" \
cargo test --test live_postgres -- --ignored --nocapture

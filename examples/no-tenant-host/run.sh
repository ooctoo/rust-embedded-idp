#!/usr/bin/env bash
set -euo pipefail
umask 077

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${EXAMPLE_DIR}/../.." && pwd)"
ACTION="${1:-}"
ENV_FILE="${EXAMPLE_DIR}/.env"
if [[ "${ACTION}" == init && $# == 1 ]]; then
  if [[ -e "${ENV_FILE}" ]]; then
    echo "using existing ${ENV_FILE}"
    exit 0
  fi
  (set -o noclobber; cat "${ENV_FILE}.example" > "${ENV_FILE}")
  echo "created ${ENV_FILE}; configure its PostgreSQL connection before continuing"
  exit 0
fi
if [[ "${ACTION}" == build-web && $# == 1 ]]; then
  cd "${ROOT}"
  pnpm --dir web exec tsc --noEmit -p ../examples/no-tenant-host/web/tsconfig.json
  pnpm --dir web exec vite build --config ../examples/no-tenant-host/web/vite.config.mjs
  exit 0
fi
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "missing ${ENV_FILE}; run $0 init" >&2
  exit 1
fi

set -a
# This example's own configuration is trusted Bash input.
source "${ENV_FILE}"
set +a
if [[ "${EMBEDDED_IDP_APP_TENANCY_MODE:-}" != disabled ]]; then
  echo "${ENV_FILE} must set EMBEDDED_IDP_APP_TENANCY_MODE=disabled" >&2
  exit 1
fi
cd "${ROOT}"

case "${ACTION}" in
  key-init)
    [[ $# == 1 ]] || exit 2
    key_file="${EMBEDDED_IDP_APP_SIGNING_KEY_FILE:-examples/no-tenant-host/.local/idp-signing-key.der}"
    if [[ "${key_file}" = /* ]]; then key_path="${key_file}"; else key_path="${ROOT}/${key_file}"; fi
    if [[ -e "${key_path}" ]]; then
      echo "refusing to overwrite existing signing key: ${key_path}" >&2
      exit 1
    fi
    mkdir -p "$(dirname "${key_path}")"
    temp_key="$(mktemp "${key_path}.tmp.XXXXXX")"
    trap 'rm -f -- "${temp_key}"' EXIT
    openssl genrsa 3072 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -outform DER -out "${temp_key}"
    chmod 600 "${temp_key}"
    ln "${temp_key}" "${key_path}"
    rm -f -- "${temp_key}"
    trap - EXIT
    echo "created signing key: ${key_path}"
    ;;
  db-init)
    [[ $# == 1 ]] || exit 2
    exec cargo run --locked -p embedded-idp-no-tenant-host -- db-init
    ;;
  bootstrap-admin)
    shift
    pnpm --dir web build </dev/null
    exec cargo run --locked -p embedded-idp-app -- bootstrap-admin "$@"
    ;;
  management)
    [[ $# == 1 ]] || exit 2
    pnpm --dir web build
    exec cargo run --locked -p embedded-idp-app
    ;;
  serve)
    [[ $# == 1 ]] || exit 2
    "${EXAMPLE_DIR}/run.sh" build-web
    exec cargo run --locked -p embedded-idp-no-tenant-host -- serve
    ;;
  seed-report)
    shift
    exec cargo run --locked -p embedded-idp-no-tenant-host -- seed-report "$@"
    ;;
  *)
    echo "usage: $0 init|build-web|key-init|db-init|bootstrap-admin|management|serve|seed-report" >&2
    exit 2
    ;;
esac

#!/usr/bin/env bash
set -euo pipefail
umask 077

MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
ACTION="${2:-}"
if [[ $# -lt 2 || ! "${MODE}" =~ ^(disabled|enabled)$ ||
      ! "${ACTION}" =~ ^(init|key-init|db-init|bootstrap-admin|start)$ ||
      ( "${ACTION}" != bootstrap-admin && $# != 2 ) ]]; then
  echo "usage: $0 disabled|enabled init|key-init|db-init|start, or bootstrap-admin --email <email> --password-stdin [--display-name <name>]" >&2
  exit 2
fi

ENV_FILE="${EMBEDDED_IDP_APP_ENV_FILE:-${MODULE_ROOT}/.env.${MODE}}"
COMMON_ENV_FILE="${EMBEDDED_IDP_COMMON_ENV_FILE:-${MODULE_ROOT}/.env}"
case "${ACTION}" in
  init)
    if [[ ! -e "${COMMON_ENV_FILE}" ]]; then
      (set -o noclobber; cat "${MODULE_ROOT}/.env.example" > "${COMMON_ENV_FILE}")
      echo "created ${COMMON_ENV_FILE}; configure the shared database connection"
    fi
    # noclobber protects existing local configuration, including concurrent init.
    (set -o noclobber; cat "${MODULE_ROOT}/.env.${MODE}.example" > "${ENV_FILE}")
    echo "created ${ENV_FILE}; review it before starting"
    ;;
  key-init)
    source "${MODULE_ROOT}/scripts/load_dev_env.sh"
    load_dev_env "${MODE}"
    key_file="${EMBEDDED_IDP_APP_SIGNING_KEY_FILE:-.local/idp-signing-key.der}"
    if [[ "${key_file}" = /* ]]; then
      key_path="${key_file}"
    else
      key_path="${MODULE_ROOT}/${key_file}"
    fi
    if [[ -e "${key_path}" ]]; then
      echo "refusing to overwrite existing signing key: ${key_path}" >&2
      exit 1
    fi
    mkdir -p "$(dirname "${key_path}")"
    temp_key="$(mktemp "${key_path}.tmp.XXXXXX")"
    cleanup_key() { rm -f -- "${temp_key}"; }
    trap cleanup_key EXIT
    openssl genrsa 3072 2>/dev/null |
      openssl pkcs8 -topk8 -nocrypt -outform DER -out "${temp_key}"
    chmod 600 "${temp_key}"
    ln "${temp_key}" "${key_path}"
    rm -f -- "${temp_key}"
    trap - EXIT
    echo "created owner-only RSA3072 PKCS#8 DER signing key: ${key_path}"
    ;;
  db-init)
    source "${MODULE_ROOT}/scripts/load_dev_env.sh"
    load_dev_env "${MODE}"
    cd "${MODULE_ROOT}"
    exec cargo run --locked -p embedded-idp-storage-postgres --example bootstrap_local_postgres -- --access-schema
    ;;
  start)
    exec "${MODULE_ROOT}/scripts/run_embedded_idp_app.sh" "${MODE}"
    ;;
  bootstrap-admin)
    source "${MODULE_ROOT}/scripts/load_dev_env.sh"
    load_dev_env "${MODE}"
    shift 2
    cd "${MODULE_ROOT}"
    # Build assets without exposing/consuming the administrator password on stdin.
    pnpm --dir web build </dev/null
    exec cargo run --locked -p embedded-idp-app -- bootstrap-admin "$@"
    ;;
esac

#!/usr/bin/env bash

# Shared by all local entry points; configuration files are trusted Bash input.
load_dev_env() {
  local mode="${1:-}"
  local root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local common_file="${EMBEDDED_IDP_COMMON_ENV_FILE:-${root}/.env}"
  local mode_file="${EMBEDDED_IDP_APP_ENV_FILE:-${root}/.env.${mode}}"
  if [[ ! "${mode}" =~ ^(disabled|enabled)$ ]]; then
    echo "specify a development mode: disabled|enabled" >&2
    return 2
  fi
  if [[ ! -f "${common_file}" || ! -f "${mode_file}" ]]; then
    echo "missing common or mode configuration; run scripts/dev_env.sh ${mode} init" >&2
    return 1
  fi

  set -a
  # shellcheck disable=SC1090
  source "${common_file}"
  # shellcheck disable=SC1090
  source "${mode_file}"
  set +a

  if [[ "${EMBEDDED_IDP_APP_TENANCY_MODE:-}" != "${mode}" ||
        "${EMBEDDED_IDP_APP_PG_SCHEMA:-}" != "embedded_idp_${mode}_v2" ]]; then
    echo "configuration must use mode ${mode} and schema embedded_idp_${mode}_v2" >&2
    return 1
  fi
}

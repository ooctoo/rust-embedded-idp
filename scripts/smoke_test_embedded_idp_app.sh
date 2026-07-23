#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${MODULE_ROOT}/.env"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
else
  echo "missing ${ENV_FILE}"
  echo "copy ${MODULE_ROOT}/.env.example to ${ENV_FILE} and adjust values first"
  exit 1
fi

ISSUER="${EMBEDDED_IDP_APP_ISSUER:-http://127.0.0.1:9100}"
ADMIN_UI_BASE_PATH="${EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH:-/}"
ADMIN_KEY="${EMBEDDED_IDP_APP_ADMIN_API_KEY:-}"

normalize_base_path() {
  local value="${1:-/}"
  if [[ -z "${value}" || "${value}" == "/" ]]; then
    printf '/'
    return
  fi
  value="/${value#/}"
  value="${value%/}"
  printf '%s/' "${value}"
}

UI_BASE_PATH="$(normalize_base_path "${ADMIN_UI_BASE_PATH}")"
STATIC_BASE_PATH="${UI_BASE_PATH%/}/static"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/embedded-idp-smoke.XXXXXX")"
trap 'rm -rf -- "${TEMP_DIR}"' EXIT
UNAUTHORIZED_OUTPUT="${TEMP_DIR}/admin-unauth.json"
AUTHORIZED_OUTPUT="${TEMP_DIR}/admin-auth.json"

echo "smoke check issuer: ${ISSUER}"
echo "smoke check admin ui path: ${UI_BASE_PATH}"
echo "smoke check static path: ${STATIC_BASE_PATH}"

curl -fsS "${ISSUER}${UI_BASE_PATH}" >/dev/null
echo "ok: admin ui shell"

curl -fsS "${ISSUER}${STATIC_BASE_PATH}/admin-app.js" >/dev/null
echo "ok: admin static js"

unauthorized_status="$(curl -s -o "${UNAUTHORIZED_OUTPUT}" -w '%{http_code}' "${ISSUER}/api/admin/accounts?limit=1")"
if [[ "${unauthorized_status}" != "401" ]]; then
  echo "expected 401 from unauthenticated admin API, got ${unauthorized_status}"
  exit 1
fi
echo "ok: admin api rejects missing key"

if [[ -n "${ADMIN_KEY}" ]]; then
  authorized_status="$(curl -s -o "${AUTHORIZED_OUTPUT}" -w '%{http_code}' -H "x-embedded-idp-admin-key: ${ADMIN_KEY}" "${ISSUER}/api/admin/accounts?limit=1")"
  if [[ "${authorized_status}" != "200" ]]; then
    echo "expected 200 from authenticated admin API, got ${authorized_status}"
    exit 1
  fi
  echo "ok: admin api accepts configured key"
else
  echo "skip: EMBEDDED_IDP_APP_ADMIN_API_KEY not set"
fi

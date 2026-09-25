#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/load_dev_env.sh"
load_dev_env "${1:-}"

ISSUER="${EMBEDDED_IDP_APP_ISSUER:-http://127.0.0.1:9100}"
ADMIN_UI_BASE_PATH="${EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH:-/}"

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
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/embedded-idp-smoke.XXXXXX")"
trap 'rm -rf -- "${TEMP_DIR}"' EXIT
INDEX_OUTPUT="${TEMP_DIR}/index.html"

echo "smoke check issuer: ${ISSUER}"
echo "smoke check admin ui path: ${UI_BASE_PATH}"

curl -fsS "${ISSUER}${UI_BASE_PATH}" -o "${INDEX_OUTPUT}"
echo "ok: admin ui shell"

asset_path="$(sed -nE 's/.*(assets\/[^" ]+\.(js|css)).*/\1/p' "${INDEX_OUTPUT}" | head -n 1)"
if [[ -z "${asset_path}" ]]; then
  echo "admin ui shell did not reference a JS or CSS asset"
  exit 1
fi
curl -fsS "${ISSUER}${UI_BASE_PATH}${asset_path}" >/dev/null
echo "ok: admin management asset"

curl -fsS "${ISSUER}/healthz" >/dev/null
echo "ok: healthz"

curl -fsS "${ISSUER}/readyz" >/dev/null
echo "ok: readyz"

curl -fsS "${ISSUER}/auth/access/capabilities" >/dev/null
echo "ok: public login capabilities"

curl -fsS "${ISSUER}/api/admin/auth/capabilities" >/dev/null
echo "ok: management login capabilities"

unauthorized_status="$(curl -s -o /dev/null -w '%{http_code}' "${ISSUER}/api/admin/accounts?limit=1")"
if [[ "${unauthorized_status}" != "401" ]]; then
  echo "expected 401 from unauthenticated admin API, got ${unauthorized_status}"
  exit 1
fi
echo "ok: management api rejects unauthenticated request"

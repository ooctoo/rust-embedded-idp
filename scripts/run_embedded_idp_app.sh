#!/usr/bin/env bash
set -euo pipefail

# Standalone host conventions:
# - admin UI shell defaults to /
# - admin static assets are served from <admin-ui-base-path>/static/*
# - admin APIs are served from /api/admin/*

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

cd "${MODULE_ROOT}"
exec cargo run -p embedded-idp-app "$@"

#!/usr/bin/env bash
set -euo pipefail
umask 077

# Standalone host conventions:
# - admin UI shell defaults to /
# - admin static assets are served from <admin-ui-base-path>/assets/*
# - admin APIs are served from /api/admin/*

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/load_dev_env.sh"
load_dev_env "${1:-}"
shift

cd "${MODULE_ROOT}"
pnpm --dir web build
exec cargo run -p embedded-idp-app "$@"

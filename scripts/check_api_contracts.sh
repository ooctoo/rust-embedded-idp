#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
generated=$(mktemp)
generated_oidc=$(mktemp)
generated_device=$(mktemp)
generated_scan=$(mktemp)
trap 'rm -f "$generated" "$generated_oidc" "$generated_device" "$generated_scan"' EXIT
cargo run --quiet --locked -p embedded-idp-axum --features openapi --example export_openapi > "$generated"
diff -u docs/api/business-openapi.json "$generated"
cargo run --quiet --locked -p embedded-idp-axum --features openapi --example export_shared_oidc > "$generated_oidc"
diff -u docs/api/shared-oidc-openapi.json "$generated_oidc"
cargo run --quiet --locked -p embedded-idp-axum --features openapi --example export_device_openapi > "$generated_device"
diff -u docs/api/device-openapi.json "$generated_device"
cargo run --quiet --locked -p embedded-idp-axum --features openapi --example export_scan_openapi > "$generated_scan"
diff -u docs/api/scan-openapi.json "$generated_scan"
cargo test --locked -p embedded-idp-axum --features openapi --test openapi_contract

node scripts/check_tenant_host_contract.mjs

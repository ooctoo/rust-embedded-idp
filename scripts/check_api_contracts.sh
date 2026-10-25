#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
generated=$(mktemp)
generated_oidc=$(mktemp)
trap 'rm -f "$generated" "$generated_oidc"' EXIT
cargo run --quiet --locked -p embedded-idp-axum --features openapi --example export_openapi > "$generated"
diff -u docs/api/business-openapi.json "$generated"
cargo run --quiet --locked -p embedded-idp-axum --features openapi --example export_shared_oidc > "$generated_oidc"
diff -u docs/api/shared-oidc-openapi.json "$generated_oidc"
cargo test --locked -p embedded-idp-axum --features openapi --test openapi_contract

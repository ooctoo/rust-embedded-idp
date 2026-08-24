# rust-embedded-idp Repository Guide

## Authority and scope

Read `README.md`, `CONTRIBUTING.md`, and the relevant document under `docs/`
before changing behavior. Security work must follow the current production
security and device-proof documents; older v1 material is historical context
unless a current document explicitly references it.

This repository is an embeddable identity module plus a development/reference
host. `embedded-idp-app` is not a production host. Do not treat its development
subject header, empty JWKS behavior, or local security adapters as production
defaults.

## Crate boundaries

- `embedded-idp-core` owns domain models, service rules, store traits, token
  policy, and device-proof behavior. It does not depend on HTTP or databases.
- `embedded-idp-email` owns provider-neutral email contracts.
- `embedded-idp-security` owns production cryptographic adapters.
- `embedded-idp-axum` owns thin Axum routes and HTTP adapters; keep business
  rules and persistence out of handlers.
- `embedded-idp-storage-postgres` is a Postgres infrastructure adapter with
  typed configuration, migrations, and SQL. It is not another domain layer.
- `embedded-idp-app` owns reference-host composition, environment loading,
  migration bootstrap, and route assembly.

Add or change a core service contract before exposing new endpoint behavior.
Hosts must inject trusted subject, access-token validation, client-secret
verification, and other security-boundary dependencies; the module must not
hard-code a host token format or secret lifecycle.

Keep provider configuration nested and typed. Hosts parse environment values
and pass configuration into modules; process-global environment access is not
the primary module boundary.

## Routing and Web assets

Preserve module-local route roots: `/auth`, `/devices`, `/admin`, `/oidc`, and
`/.well-known/openid-configuration`. The embedding host owns any outer prefix.

`embedded-idp-app` embeds `web/dist` at Rust compile time. Build the Web app
before compiling the Rust reference host, and never commit generated `web/dist`
or dependency directories.

## Security and secrets

Keep local `.env` files untracked and permission-restricted. Never place real
credentials, signing keys, access tokens, or production secrets in examples,
tests, logs, or commits. Report vulnerabilities through the private process in
`SECURITY.md`.

## Validation

Use the narrowest relevant check first, then broaden when a change crosses
crate or Web/Rust boundaries. The repository-wide baseline is:

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```

Live Postgres checks are optional and require an explicit
`EMBEDDED_IDP_TEST_PG_CONNECTION_URI`:

```sh
./scripts/run_live_postgres_checks.sh
```

Do not make ordinary offline tests depend on a live database.

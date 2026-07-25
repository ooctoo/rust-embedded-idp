# rust-embedded-idp

`rust-embedded-idp` is an embeddable Rust identity provider focused on:

- local account registration and login
- `Authorization Code + PKCE` for desktop public clients
- confidential client authentication for token/revoke/introspect flows
- `userinfo`, token introspection, and JWKS publication
- device registration and proof verification
- embeddable HTTP routing for host backends

This repository is a standalone Cargo workspace. Project design and implementation
notes live under [docs/](./docs/).

For local development, configuration, host integration, and the complete HTTP
API reference, see [Developer and Integration Guide](./docs/developer-and-integration-guide.md).

## Layout

```text
rust-embedded-idp/
  README.md
  Cargo.toml
  docs/
  crates/
```

## Current Scope

Current module boundary is:

- `embedded-idp-core`: pure service, model, store trait, token, and device proof logic
- `embedded-idp-email`: provider-neutral email contracts and verification message composition
- `embedded-idp-axum`: fixed module-local API paths and HTTP handlers built on `axum`
- `embedded-idp-storage-postgres`: storage adapter crate that implements core store traits, not a third architecture layer
- `embedded-idp-app`: runnable standalone reference host

Storage configuration rule:

- database connection config is resolved by the host application and passed into the storage adapter
- this module should not rely on process-global environment variables as its primary runtime boundary
- provider-specific config should remain nested and typed; do not flatten all backend fields into one shared struct before a second backend exists

Local Postgres workflow:

- bootstrap schema and seed a desktop client with `cargo run -p embedded-idp-storage-postgres --example bootstrap_local_postgres -- <postgres-connection-uri> [schema-name] [client-id]`
- run the full live Postgres checks with [run_live_postgres_checks.sh](./scripts/run_live_postgres_checks.sh)
- set `EMBEDDED_IDP_TEST_PG_CONNECTION_URI` in the repository-root `.env` or process environment

Standalone admin console:

> [!WARNING]
> `embedded-idp-app` is a development/reference host and is not production-ready.
> It uses development-only plaintext, forgeable token issuing and validation, a
> caller-controlled subject header, device proof without signature validation,
> and an empty JWKS. Production hosts must supply cryptographic access-token and
> ID-token issuing and validation, trusted subject/session authentication,
> signature-verifying device proof, and published signing keys.

- `embedded-idp-app` serves the admin UI at `/` by default
- the admin UI base path can be overridden with `EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH`
- static admin assets are exposed under `<admin-ui-base-path>/static/*`
- standalone admin APIs are exposed under `/api/admin/*`
- self-service registration now returns `pending_verification`; accounts must complete `POST /auth/verify-email` before login
- the standalone host also exposes `POST /auth/resend-verification`
- verification delivery defaults to log output; the standalone host can switch to local `sendmail` with `EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE=sendmail`
- the UI source now lives under `web`
- `web/components/*` is the reusable React component layer for hosts
- `web/app.tsx` is the assembled page entry used for static bundling
- `embedded-idp-app` serves `web/dist` output, so the host/runtime side remains a thin static asset adapter
- generated admin assets under `web/dist` are not committed, so build the web workspace before compiling the app
- copy `.env.example` to `.env` in the repository root for local standalone runs
- start the standalone host with [run_embedded_idp_app.sh](./scripts/run_embedded_idp_app.sh)

Mail delivery boundary:

- `embedded-idp-email` defines provider-neutral email contracts such as `EmailSenderProvider` and `VerificationEmailService`
- host crates such as `embedded-idp-app` are responsible for implementing concrete senders and holding SMTP / sendmail credentials
- verification email composition stays reusable, but delivery configuration remains host-owned
- `embedded-idp-app` currently supports `log`, `sendmail`, and generic `smtp` delivery modes for verification emails

## Host API Integration

The HTTP adapter is intended to be nested into a host `axum` router.

The module no longer owns a repository-wide `/api/v1` prefix for auth, device, or admin APIs.
Hosts should decide whether to expose the module at root or nest it under a host-defined prefix.

For `/oidc/authorize`, the host must inject an [`AuthenticatedSubject`](./crates/embedded-idp-axum/src/lib.rs) request extension before the request reaches the embedded router.

For `/oidc/userinfo` and `/oidc/introspect`, the host must provide an `AccessTokenValidator` through core service composition. The module validates refresh tokens itself, but it intentionally does not hardcode host access-token format.

For confidential clients, the host must also provide a `ClientSecretVerifier` and provision `client_secret_hash` into storage. The module enforces when client authentication is required, but it does not own client provisioning or raw secret lifecycle.

See:

- [host-integration-v1.md](./docs/host-integration-v1.md)
- `cargo run -p embedded-idp-axum --example host_integration`

## Git Dependency

Library crates can be consumed directly from the repository tag:

```toml
[dependencies]
embedded-idp-core = { git = "https://github.com/ooctoo/rust-embedded-idp.git", tag = "v0.1.0" }
embedded-idp-axum = { git = "https://github.com/ooctoo/rust-embedded-idp.git", tag = "v0.1.0" }
embedded-idp-email = { git = "https://github.com/ooctoo/rust-embedded-idp.git", tag = "v0.1.0" }
embedded-idp-storage-postgres = { git = "https://github.com/ooctoo/rust-embedded-idp.git", tag = "v0.1.0" }
```

Cargo records the resolved commit in the consuming project's `Cargo.lock`. For a
fully explicit source pin, replace `tag = "v0.1.0"` with the full commit
`rev = "<full-commit-sha>"`. `embedded-idp-app` is a runnable reference host, not
an intended library dependency.

## Build and Test

The app compile-time embeds generated assets from `web/dist`, so build the web
workspace first. Generated admin assets are not committed.

```bash
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```

## Local Standalone Run

> [!WARNING]
> `embedded-idp-app` is a development/reference host and is not production-ready.
> Use it only for local development; production hosts must replace its
> development-only security adapters as described above.

From the repository root:

```bash
cp .env.example .env
./scripts/run_embedded_idp_app.sh
```

The helper sources the repository-root `.env` before starting the reference host.

## Live Postgres Checks

Set only `EMBEDDED_IDP_TEST_PG_CONNECTION_URI`, either in the repository-root
`.env` or in the process environment, then run:

```bash
./scripts/run_live_postgres_checks.sh
```

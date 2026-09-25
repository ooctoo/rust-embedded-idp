# Contributing

## Prerequisites

- Stable Rust toolchain
- Node.js 22
- pnpm 10.30.1

Install web dependencies with:

```bash
pnpm --dir web install --frozen-lockfile
```

## Development Setup

Local `.env` files and `.local/` signing keys may contain secrets; keep them
untracked and restrict them to owner-only permissions.

## Build and Test

Build the web application before building the Rust application. `web/dist` is
embedded into the application at compile time and is intentionally not
committed.

```bash
pnpm --dir web test
pnpm --dir web build
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

The build also produces the independent account-based management entry at
`web/dist/management/index.html`. `pnpm --dir web dev` serves its
source at `127.0.0.1:4179`; the serving host must provide the independent
management authentication API at the same-origin `/api` prefix.

Initialize a local mode with `./scripts/dev_env.sh disabled init`, then prepare
its database and administrator before starting:

```bash
./scripts/dev_env.sh disabled key-init
./scripts/dev_env.sh disabled db-init
./scripts/dev_env.sh disabled bootstrap-admin --email admin@example.test --password-stdin < /path/to/private-password-file
./scripts/dev_env.sh disabled start
```

`key-init` creates one shared RSA3072 PKCS#8 DER signing key at
`.local/idp-signing-key.der`; both modes use that path from the shared `.env`.
The key is created only when absent and is never printed. All local startup and
test scripts require a mode and load `.env` followed by `.env.<mode>`; mode
settings override shared settings. Management APIs use JWT authentication under
`/api/admin`; legacy API-key and subject-header development switches are not
part of the local workflow.

For optional live Postgres coverage, set
`EMBEDDED_IDP_TEST_PG_CONNECTION_URI` to a local test database URI, then run:

```bash
scripts/run_live_postgres_checks.sh disabled
```

## Scope and Crate Boundaries

Keep changes within the owning crate and preserve the existing boundaries:
`embedded-idp-core` contains domain contracts and services;
`embedded-idp-email` provides email delivery; `embedded-idp-axum` provides the
HTTP adapter; `embedded-idp-storage-postgres` provides the Postgres storage
adapter; and `embedded-idp-app` composes the standalone application. Do not
move domain behavior into transport or storage adapters, and keep cross-crate
changes deliberate and narrowly scoped.

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

Local .env files may contain secrets; keep them untracked and restrict them to owner-only permissions.

## Build and Test

Build the web application before building the Rust application. `web/dist` is
embedded into the application at compile time and is intentionally not
committed.

```bash
pnpm --dir web build
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

For optional live Postgres coverage, set
`EMBEDDED_IDP_TEST_PG_CONNECTION_URI` to a local test database URI, then run:

```bash
scripts/run_live_postgres_checks.sh
```

## Scope and Crate Boundaries

Keep changes within the owning crate and preserve the existing boundaries:
`embedded-idp-core` contains domain contracts and services;
`embedded-idp-email` provides email delivery; `embedded-idp-axum` provides the
HTTP adapter; `embedded-idp-storage-postgres` provides the Postgres storage
adapter; and `embedded-idp-app` composes the standalone application. Do not
move domain behavior into transport or storage adapters, and keep cross-crate
changes deliberate and narrowly scoped.

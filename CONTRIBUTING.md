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
The key is created only when absent and is never printed. The reference-host
`scripts/dev_env.sh` and `scripts/run_live_postgres_checks.sh` require a mode
and load `.env` followed by
`.env.<mode>`; mode settings override shared settings. The separate
`examples/no-tenant-host/run.sh` uses only its own example configuration.
Management APIs use JWT authentication under
`/api/admin`; legacy API-key and subject-header development switches are not
part of the local workflow.

For optional live Postgres coverage, set
`EMBEDDED_IDP_TEST_PG_CONNECTION_URI` to a local test database URI, then run:

```bash
scripts/run_live_postgres_checks.sh disabled
```

## CI quality lanes

Ordinary CI preserves build/static checks and UT in `check`, then runs independent
`integration` and `e2e` jobs on Ubuntu 24.04 x64. The latter use disposable
PostgreSQL 18.6 and synthetic identities; no development `.env` is loaded.
Full N2 is temporarily retained as an optional manual diagnostic workflow, not a
PR/release requirement. Its broader role/member/tenant coverage must be accounted
for before retiring the old orchestration; see design section 4. Production configuration,
images and deployment belong to downstream repositories.

After installing Web dependencies, prepare the pinned database image explicitly:

```bash
docker pull postgres:18.6-bookworm
scripts/run_ci_integration.sh --output-dir /tmp/idp-integration-new-run
```

The integration entry builds Web and invokes the existing live Postgres tests
with generated private configuration. It requires all ten live targets to execute
with nonzero passes, no ignored cases and confirmed resource cleanup.

For the six critical browser groups, install the existing locked test tools with
Node 22.23.4 / pnpm 10.30.1, then build the reference host and fixture tool:

```bash
pnpm --dir scripts/n2-ci install --frozen-lockfile --ignore-scripts --config.engine-strict=true
pnpm --dir scripts/n2-ci exec playwright install --with-deps --no-shell chromium
pnpm --dir web build
cargo build -p embedded-idp-app --bin embedded-idp-app --locked
cargo build -p embedded-idp-storage-postgres --example bootstrap_local_postgres --locked
python3 -B scripts/run_ci_e2e.py --image postgres:18.6-bookworm \
  --playwright scripts/n2-ci/node_modules/playwright/index.mjs \
  --output /tmp/idp-e2e-new-run
```

Use a new output directory for each attempt. These entries create and clean only
their own containers, host processes and private fixture data. If cleanup fails,
the command fails and retains private recovery data; do not upload that data.
CI artifacts contain only the result JSON whitelist, retained for 30 days subject
to repository policy. Raw traces, database dumps and fixture credentials are not
uploaded. Local execution does not prove the hosted Linux runner passed.

The [design](docs/ci-quality-design.md), [coverage map](docs/ci-quality-coverage.md)
and [implementation result](docs/ci-quality-implementation-result.md) define scope
and verification limits. No new release trigger or deployment is included.

## Scope and Crate Boundaries

Keep changes within the owning crate and preserve the existing boundaries:
`embedded-idp-core` contains domain contracts and services;
`embedded-idp-email` provides email delivery; `embedded-idp-axum` provides the
HTTP adapter; `embedded-idp-storage-postgres` provides the Postgres storage
adapter; and `embedded-idp-app` composes the standalone application. Do not
move domain behavior into transport or storage adapters, and keep cross-crate
changes deliberate and narrowly scoped.

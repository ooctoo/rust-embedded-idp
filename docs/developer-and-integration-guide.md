# Developer and Integration Guide

This guide covers current local development and reference-host composition.
`embedded-idp-app` is useful for development and integration checks; it is not
a production identity platform. Current route contracts and host boundaries are
maintained in the [host integration guide](host-integration-v1.md).

## Workspace

| Crate | Responsibility |
| --- | --- |
| `embedded-idp-core` | Domain models, service rules, store contracts, token policy, and device-proof behavior |
| `embedded-idp-email` | Provider-neutral email contracts and verification messages |
| `embedded-idp-security` | Production cryptographic adapters |
| `embedded-idp-axum` | Thin Axum routes and HTTP adapters |
| `embedded-idp-storage-postgres` | Typed PostgreSQL adapter, migrations, and SQL |
| `embedded-idp-app` | Reference-host composition, local configuration, offline commands, and embedded management UI |

Build Web assets before compiling the reference host because it embeds
`web/dist/management` at compile time:

```bash
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```

## Local reference runtime

The reference host supports `disabled` and `enabled` modes. Each mode has its
own schema and configuration file, but both use the `tenant_v2` Access layout
and must be prepared offline before startup.

```bash
./scripts/dev_env.sh disabled init
./scripts/dev_env.sh disabled key-init
./scripts/dev_env.sh disabled db-init
./scripts/dev_env.sh disabled bootstrap-admin \
  --email admin@example.test --password-stdin < /path/to/private/admin-password
./scripts/dev_env.sh disabled start
```

Use `enabled` for the corresponding tenant-enabled schema. Scripts load `.env`
first and then `.env.<mode>`; mode settings override shared ones. `init` does
not overwrite existing local configuration.

`db-init` creates only an empty, mode-bound schema. `bootstrap-admin` is a
separate offline operation that creates the first platform administrator. It
requires a pipe or private password file on standard input and rejects a bare
terminal. Neither command starts the service. Online startup does not apply
migrations, bootstrap users, repair data, or otherwise mutate Access state.

The reference runtime requires an owner-only RSA key of at least 3072 bits in
PKCS#8 DER format. `EMBEDDED_IDP_APP_SIGNING_KEY_FILE` defaults to
`.local/idp-signing-key.der`; `key-init` creates it once and refuses to
overwrite it.

The runtime serves the React management UI at
`EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH` (default `/`) and assets under
`<base>/assets/*`. Management APIs are under `/api/admin` and use management
JWT bearer authentication, including login, capability discovery, refresh,
logout, and enabled-mode tenant selection. Business routes remain rooted at
`/auth`, `/devices`, and `/oidc`. Discovery is
`/.well-known/openid-configuration`; `/oidc/jwks` exposes the actual RSA public
keys.

`GET /healthz` is a liveness endpoint. `GET /readyz` runs a read-only database
check of schema layout, mode, bootstrap state, trusted permission catalog, and
an effective platform administrator; it returns `503` when any check fails.

Local startup creates the public `desktop-app` and management `idp-management`
clients only if absent. An optional confidential client follows the same rule.
Existing client configuration and secrets are never overwritten.

Business login configuration is explicit:

- `EMBEDDED_IDP_APP_LOGIN_POLICY=fixed|choose` defaults to `fixed` in Disabled
  mode and `choose` in Enabled mode.
- Disabled fixed login defaults to tenant `0`.
- Enabled fixed login needs a real `EMBEDDED_IDP_APP_LOGIN_TENANT_ID`; choose
  needs it unset. Platform access is fixed to `0`, and tenant choice excludes
  `0`.
- Management login defaults to fixed tenant `0` through
  `EMBEDDED_IDP_APP_MANAGEMENT_LOGIN_POLICY` and
  `EMBEDDED_IDP_APP_MANAGEMENT_TENANT_ID`.

Device proof verification uses Ed25519. Provisioning is denied unless the
reference-only `EMBEDDED_IDP_APP_ALLOW_DEVICE_PROVISIONING=true` is set; a
production host must supply its own admission policy.

The complete local variable reference is in
[`.env.example`](../.env.example),
[disabled mode](../.env.disabled.example), and
[enabled mode](../.env.enabled.example). Keep those local files and
signing keys untracked.

## Embedding in an Axum host

The host owns the outer route prefix, trusted subject/session authentication,
access-token validation, client-secret lifecycle, production signing keys,
JWKS publication, device admission, and operational controls. Keep module
routes rooted at `/auth`, `/devices`, `/admin`, `/oidc`, and
`/.well-known/openid-configuration`; the host may nest the assembled router.

Read the [host integration guide](host-integration-v1.md) before changing
contracts or exposing a route. Its current sections describe the trusted
dependencies, management bearer boundary, tenant policies, and the current
HTTP surface. Older examples that use development subject headers, API keys,
plaintext tokens, automatic migrations, or an empty JWKS are legacy material
and do not describe the current reference runtime.

## Tests

Routine validation:

```bash
pnpm --dir web test
pnpm --dir web build
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test --workspace
```

Live PostgreSQL coverage is opt-in. Set
`EMBEDDED_IDP_TEST_PG_CONNECTION_URI` to a disposable local database and run:

```bash
./scripts/run_live_postgres_checks.sh disabled
```

The live suite uses random disposable schemas. It does not fall back to the
application connection URI.

The reference host still lacks production rate limiting, signing-key rotation,
host-specific device admission, a real business-resource host example, device
self-service UI, and performance acceptance. Those gaps are not removed by
using the reference runtime in Enabled mode.

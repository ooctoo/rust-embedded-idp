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
own schema and configuration file, but both use the current `tenant_v6` Access
layout and must be prepared offline before startup. Existing schemas require
the explicit [device lifecycle upgrade procedure](device-identity-lifecycle-upgrade.md)
and [scan-login upgrade procedure](device-scan-login-upgrade.md); startup never
migrates them.

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

`db-init` creates the mode-bound IdP objects in the selected schema, preserving
unrelated host objects and rejecting IdP name conflicts. `bootstrap-admin` is a
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

The reference host also exposes the generic [two-way device scan-login
contract](device-scan-login-design-v1.md) and the [private-network HTTP
development contract](development-private-http.md). The latter is an explicit
feature-gated debug mode for local RFC1918 HTTP origins; it keeps device proof,
pending delivery, ACK, cancellation and response-recovery rules unchanged.

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
host-specific device admission, device self-service UI, and performance
acceptance. A separate [no-tenant host example](../examples/no-tenant-host/README.md)
demonstrates business-resource authorization, but does not supply those
production controls.

## Business authorization upgrade

Access v3 requires an explicit business identifier for permissions, roles and authorization checks. Existing v2 data requires a stopped-service mapping migration; see [the business authorization design](business-domain-authorization-design-v1.md). Schema directory names do not determine the Access version. Do not rerun bootstrap or silently recreate an existing database. The current reference runtime is tenant_v6; follow the [scan-login upgrade procedure](device-scan-login-upgrade.md) after the earlier business and device lifecycle migrations.

## Host-configured access token lifetime

The embedding host supplies the access lifetime when constructing its services.
Use one trusted value for `AuthConfig.access_token_ttl_secs` and
`ProductionJwtConfig.access_token_ttl_secs`. The Core value bounds every current
tenant-aware login, tenant selection, OIDC code exchange, pending scan issuance,
and refresh. The RS256 issuer also enforces its configured lifetime, so a smaller
issuer value produces a shorter token. Configure both from the same host setting
when the requested lifetime should apply in full.

The reference application's default is 900 seconds. Its existing environment
setting is `EMBEDDED_IDP_APP_ACCESS_TOKEN_TTL_SECS`, and its composition-file
setting is `runtime.auth.access_token_ttl_secs`. The independent tenant-host
example uses `TENANT_HOST_ACCESS_TOKEN_TTL_SECS`. Each host owns configuration
loading. The module accepts typed configuration at construction.

Configuration requires `0 < access TTL < refresh TTL <= session TTL`. RS256 also
requires `clock_skew_secs < access_token_ttl_secs`. Existing JWTs retain their
signed expiration when a host is reconstructed with a new configuration. Existing
sessions retain their stored absolute deadline. At refresh, the next refresh
expiry is the earlier of `now + refresh TTL` and that deadline, and access expiry
is bounded by both `now + access TTL` and the next refresh expiry. A session with
120 seconds left can therefore refresh under a 900-second access policy, receiving
an access token that expires at the session deadline. Access and refresh may
expire together in this final interval.

Custom signing adapters should implement all three bounded methods on the
existing issuer traits, and wrapper adapters should forward them.

- `TokenIssuer::issue_session_tokens_with_access_expiry`
- `AccessTokenIssuer::issue_access_token_with_expiry`
- `ScopedAccessTokenIssuer::issue_scoped_access_token_with_expiry`

The deadline is supplied by trusted Core state. An adapter signs an expiry at or
before it and reports the actual signed expiry. Delegated scope and identity must
be preserved. The default trait implementations call the existing methods and
reject overlong output. They preserve source compatibility, while shortening at
the end of a session requires the adapter to implement the bounded methods.
`Rs256JwtService` implements all three. Its returned expiry and JWT `exp` are the
same whole-second timestamp. Core verifies the reported and validated expiry at
second precision and rejects output exceeding its deadline.

The Web clients derive a fixed refresh time when accepting each token, using at
most 30 seconds or half its remaining lifetime as the advance interval. When an
access token reaches the session deadline, clients use it until expiration.
Cookie lifetime rounds a positive fractional second upward while server-side
session and refresh deadlines remain authoritative. Expired responses are handled
as expired sessions. Network transit can still consume the final available time.

Very short lifetimes also constrain scan delivery. The existing recovery window
ends at least one second before access expiry, and issuance fails if no recovery
window remains. Hosts should select a lifetime that permits their actual delivery
and acknowledgement flow. Restricted development-browser mode continues to use
its dedicated bounded login lifetime and rejects restore and refresh.

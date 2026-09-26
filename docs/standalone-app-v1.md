# Standalone reference host

`embedded-idp-app` is a runnable reference host for local development and
integration checks. It is not a production identity platform. A production host
must own rate limits, signing-key rotation, device-admission policy, deployment
operations, and its other security controls.

## Prepare a local mode

The reference host has two independent local modes, `disabled` and `enabled`.
Both use the `tenant_v2` Access schema and require an offline administrator
bootstrap before they can serve traffic. `init` copies templates only; it never
rewrites an existing `.env` or `.env.<mode>` file.

```bash
./scripts/dev_env.sh disabled init
./scripts/dev_env.sh disabled key-init
./scripts/dev_env.sh disabled db-init
./scripts/dev_env.sh disabled bootstrap-admin \
  --email admin@example.test --password-stdin < /path/to/private/admin-password
./scripts/dev_env.sh disabled start
```

Use `enabled` for the tenant-enabled schema; skip `key-init` when reusing the
already generated shared key. The scripts
load `.env` and then `.env.<mode>`; the mode file overrides shared settings.
They require an explicit mode so the mode and schema cannot be selected by an
incoming request.

`db-init` creates fresh Access objects in its selected schema, or validates an
already prepared matching layout without changing its data. Unrelated host
objects may remain; conflicting IdP names and legacy or incompatible IdP
layouts are rejected. `bootstrap-admin` creates the first
platform administrator in the prepared schema. It does not listen, migrate,
seed clients, or create a session. A repeat only verifies the existing
effective administrator; it is not a repair or password-reset command.

`bootstrap-admin` accepts the password only from non-terminal standard input.
Use a pipe or a private input file; never put a password in a command argument
or environment variable. A bare terminal is rejected to avoid echoed input.

To run both modes on one machine, initialize the other schema and its
administrator, then keep each server in its own terminal:

```bash
./scripts/dev_env.sh enabled init
./scripts/dev_env.sh enabled db-init
./scripts/dev_env.sh enabled bootstrap-admin \
  --email admin@example.test --password-stdin < /path/to/private/admin-password
# Terminal 1
./scripts/dev_env.sh disabled start
# Terminal 2
./scripts/dev_env.sh enabled start
```

Do not repeat `init` for an existing `.env.<mode>`, or `key-init` for an existing
key. The default consoles are `http://127.0.0.1:9100/` (Disabled) and
`http://127.0.0.1:9200/` (Enabled). Their health checks are `/healthz` and
`/readyz`. In Enabled mode, the default management login is fixed to platform
`0`: sign in with the bootstrapped platform administrator, then create a tenant
and its first administrator. To use the same console as a tenant administrator,
stop the Enabled server, set `EMBEDDED_IDP_APP_MANAGEMENT_LOGIN_POLICY=choose`
and remove `EMBEDDED_IDP_APP_MANAGEMENT_TENANT_ID` from `.env.enabled`, then
restart and sign in with the new tenant account. `choose` excludes platform `0`;
restore the fixed platform settings to return to platform management. Disabled
mode has one domain (`0`) and no tenant-management UI. The local profiles share
the PostgreSQL connection from `.env` but use separate schemas and ports.

## Signing key

The reference host requires an RSA key of at least 3072 bits in unencrypted
PKCS#8 DER form. Set `EMBEDDED_IDP_APP_SIGNING_KEY_FILE`; its default is
`.local/idp-signing-key.der`. On Unix, the file must be owner-only (for example,
mode `0600`).

`key-init` generates the default local RSA-3072 PKCS#8 DER key once and refuses
to overwrite an existing file. The key is shared by the local disabled and
enabled modes unless configuration selects another path.

## Online startup and readiness

`start` builds the React management distribution and starts the host. Online
startup only validates the prepared database state before binding a listener:
the Access layout, schema version and selected mode, bootstrap marker, trusted
permission catalog, and an effective platform/system administrator must all be
present. It never creates schema, runs migrations, bootstraps accounts, or
repairs access state.

The host seeds `desktop-app` and `idp-management` only when they are missing.
An optional confidential client is handled the same way. Existing client
settings, redirect URIs, and secrets are never overwritten by
startup configuration.

- `GET /healthz` reports that the process is live.
- `GET /readyz` reruns the read-only database readiness check and returns `503`
  when it fails.

## UI, APIs, and tokens

The built React management application is embedded from `web/dist/management`.
It is served at `EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH` (default `/`), with assets
at `<base>/assets/*`.

Management APIs are rooted at `/api/admin`. They use management JWT bearer
authentication, not an API key or development header:

- `/api/admin/auth/capabilities`
- `/api/admin/auth/login`
- `/api/admin/auth/refresh`
- `/api/admin/auth/logout`
- `/api/admin/auth/session` and the enabled-mode tenant-selection routes

Protected management APIs use the same bearer session. Business authentication,
device, and OIDC routes retain their module roots: `/auth`, `/devices`, and
`/oidc`. Discovery is at `/.well-known/openid-configuration`; `/oidc/jwks`
publishes the real public RSA JWK set. The previous development subject-header,
development-key, plaintext-token, and empty-JWKS conventions are not used by
this reference runtime.

`GET /auth/me/roles` lists only the authenticated business user's roles in the
current tenant, with cursor pagination. The endpoint derives tenant and user
from the access session; management credentials cannot select another subject.

Device proofs are verified with Ed25519. Device provisioning is denied by
default. `EMBEDDED_IDP_APP_ALLOW_DEVICE_PROVISIONING=true` enables the reference
host admission only; a production host must inject its own admission policy.

## Login selection

Business login uses `EMBEDDED_IDP_APP_LOGIN_POLICY=fixed|choose`.

- In Disabled mode, its default is `fixed`, and the default tenant is `0`.
- In Enabled mode, its default is `choose`.
- Enabled `fixed` requires `EMBEDDED_IDP_APP_LOGIN_TENANT_ID` to name a real
  tenant. `choose` requires that variable to be unset.
- Platform access is only fixed tenant `0`; tenant choice excludes `0`.

Management login uses `EMBEDDED_IDP_APP_MANAGEMENT_LOGIN_POLICY`, defaulting to
`fixed`, and `EMBEDDED_IDP_APP_MANAGEMENT_TENANT_ID`, defaulting to `0`.

## Configuration and scope

The local templates document the complete environment-variable set:
[`.env.example`](../.env.example),
[disabled mode](../.env.disabled.example), and
[enabled mode](../.env.enabled.example). Keep local configuration and
keys untracked and owner-readable only.

The current management UI covers login, tenants, roles, permissions, members,
account security, devices, sessions, clients, audit, and diagnostics. A local
React package provides embedded login, self-role and permission-directory components. A real
business-resource host example, embedded device self-service UI, remaining
browser interaction checks, and performance acceptance are still pending.
For API contracts and embedding guidance, use the current
[host integration guide](host-integration-v1.md).

## Browser sessions

The management page now uses the optional same-origin [browser session adapter](browser-session-design.md). The reference host also mounts business browser routes. Set `EMBEDDED_IDP_APP_BROWSER_ORIGIN` to the exact externally visible origin (scheme, host, optional port; no trailing slash) when it differs from the default `http://<bind_addr>`. Non-loopback origins must use HTTPS. The origin is trusted configuration, not inferred from forwarded headers or the token issuer.

Cookies are host-only and named `idp_<bind-port>_business` and `idp_<bind-port>_management`, scoped to `/auth/browser` and `/api/admin/auth/browser`. The port suffix separates the local profiles because cookies themselves are not port-scoped. Production embedding hosts choose their own unique names and external paths. Serving the UI under another base path does not move these API paths. A Vite development reverse proxy must use the page's origin in this configuration.

The original explicit-token login/refresh/logout and device-proof routes remain available. Browser cookies never authenticate ordinary business or management APIs; those still require the appropriate Bearer token.

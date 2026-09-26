# Host Integration v1

> 浏览器 Cookie 接入的新增契约见[浏览器会话设计](browser-session-design.md)。原显式令牌与设备证明接口继续适用；本期不支持跨标签页同时使用不同业务租户。

## Current reference-host composition

The reference host now uses tenant-aware services in both modes. See
[the runnable composition](../crates/embedded-idp-app/src/bootstrap.rs) and
[setup/configuration](standalone-app-v1.md). It mounts the dedicated management
router under `/api`, authenticates with separate RS256 management credentials,
serves `web/dist/management`, and merges tenant registration, device-aware auth,
self-service devices and OIDC routers at their module-local roots. It publishes
real public JWKS. Development subject headers and API keys are no longer mounted.

This is the standalone reference composition. An embedding host chooses whether
to mount the IdP management router and UI, run management separately against
the same IdP database, or expose no management surface. A host console may use
IdP management APIs and reusable UI components; it must preserve the Core
management actor checks. Tenant-scoped business permission-definition CRUD is
available through Core, optional management HTTP routes and the reference host.
The IdP stores tenant-specific keys and management metadata; the host owns
the business meaning and decides which operations check those keys. The same
key in different tenants may have different descriptions or state.

Offline schema initialization and explicit administrator bootstrap precede online
startup. `PostgresAccessStore::check_readiness(&PermissionCatalog)` checks schema,
mode, bootstrap, trusted permission directory and an effective system administrator
without writes; the host also uses it for `/readyz` on the blocking executor.
Existing clients are never overwritten by startup seeding. Both modes have real
reference-process integration tests in `live_reference_host.rs`.

The older single-domain composition examples below describe the legacy crate
surface, not the current reference executable. Use the tenant-aware sections and
the reference composition when implementing new hosts; no old-token or schema
compatibility layer is installed. A minimal, independent [no-tenant host example](../examples/no-tenant-host/README.md)
now demonstrates an actual business-resource check. Embedded device self-service
UI and performance acceptance remain separate work.

## Historical v1 composition example (not the current integration contract)

## Purpose

This document describes how a host Rust service should wire `rust-embedded-idp` into its own composition root.

If a standalone runnable host is preferred, the module workspace also provides `embedded-idp-app` as a thin `axum` composition root.
That crate is a reference host, not an additional business layer.

## Integration Boundary

The module keeps a strict split:

- `embedded-idp-core` owns business contracts and implementations
- `embedded-idp-axum` owns fixed routes and HTTP handlers
- `embedded-idp-storage-postgres` owns the Postgres adapter

The host application owns:

- environment loading
- typed config construction
- database provider selection
- token signing implementation
- whether client provisioning stays host-only or is exposed through trusted admin APIs
- trusted user authentication context before `/oidc/authorize`

## Deployment Topologies

The module supports two composition shapes. In an independent deployment, one
IdP service owns the management surface, public IdP API, and one IdP database.
In an embedded deployment, the management service and the host's IdP-facing
API are separate services, but they share the same IdP database and schema.
The host owns its business tables and may place them in the same schema, a
different schema in that database, or a separate database. Shared-schema
initialization preserves unrelated host objects and rejects conflicting IdP
object names atomically; it does not migrate legacy IdP tables in place.

These shapes do not imply two copies of the IdP schema. The existing route
groups are exposure boundaries, not database boundaries. The reference app's
`PgStorageConfig` is passed to `PostgresStorageAdapter::new`, and that adapter
is injected into the Core services ([bootstrap.rs](../crates/embedded-idp-app/src/bootstrap.rs),
[adapter.rs](../crates/embedded-idp-storage-postgres/src/adapter.rs)). The
adapter now uses a lazy bounded r2d2_postgres pool shared by its clones.
`connect()` returns a checked-out `PgPooledConnection`; dropping it returns the
connection to the pool. Both connection establishment and checkout currently use
`connect_timeout_secs`. Separate service processes own separate pools connected
to the same authoritative IdP database. Legacy initialization scripts use a
dedicated connection because they own session locks and transaction statements;
online transactions and new Access operations use the pool.

The host reads its own runtime configuration (including database URI, schema,
TLS, pool, issuer, signing keys and client policy) and injects typed values;
`EMBEDDED_IDP_APP_*` names belong to the reference app, not the module API.
The same database configuration is needed by offline initialization and each
running process. The offline host first calls `initialize_access_schema`,
then `CoreAccessBootstrapService::initialize` using that adapter. The host supplies
an explicitly selected, active `Account` with a validated identity and a securely
hashed credential; Core supplies the server timestamp and generated role/binding/audit
IDs. Use `SystemClock` and `UuidV7IdGenerator` with the PostgreSQL implementation.
Never mount bootstrap as an HTTP registration endpoint or reuse a development API
key as the administrator identity. No administrator secrets are added to persistent
startup configuration.

Hosts accepting an explicit plaintext password in their offline tool can instead
call `initialize_administrator(&AuthConfig, BootstrapAdministrator)`. Core validates
email, display name, request ID and the existing registration password policy,
hashes through the same Argon2id implementation, generates the account ID and delegates
to the atomic bootstrap above. Local-registration enablement does not control this
privileged offline action. The input uses SecretString; do not expose either
bootstrap method through a public or management registration endpoint.

Bootstrap atomically inserts the account, domain `0` membership, protected platform
role, type-wide grant, secret-free offline audit and completion marker. Repeated
calls return `AlreadyInitialized` only if an effective platform administrator still
exists; they never reset credentials or restore grants. A damaged/incomplete state
fails instead of being silently repaired. Offline audit has no fabricated session;
the schema permits a null session only for `offline_bootstrap` / `access.bootstrap`.

After bootstrap, construct `PostgresAccessStore::new(adapter.clone(), mode)` and
inject it into `CoreAccessService` / `CoreAccessAdminService`. The latter requires a
trusted `AccessAdminContext` and rechecks its current session and permissions inside
the write transaction. The supplied store also implements `TenantRegistrationStore`.
The reference host now injects this store into the tenant-aware login and HTTP services.

The admin service accepts tenant creation and updates plus tenant-scoped business
permission creation, reading, description updates, enabled-state changes and
archival. The persisted key is `(tenant_id, resource_type, action)`. The same key
can have independent definitions and role grants in different tenants. Enabled
platform administrators must select a real target tenant; tenant administrators
can manage only their own tenant. Disabled targets domain `0`. Built-in management
permissions cannot be changed through business permission CRUD. All writes reuse
Core authorization, transactions and audit; the host remains responsible for
checking permission at each business operation.

The tenant, role, permission, tenant-bound token, and tenant-owned device
flows described in the companion [tenant and access design](./tenant-role-permission-design-v1.md)
are provided by the tenant-aware integration surface described later in this document. The first Core Access
models, matching rules, read services and transactional management services exist,
with PostgreSQL Access reads, atomic registration, transactional management,
offline administrator bootstrap and explicit conflict-checked initialization available.
Tenant lifecycle and explicit catalog synchronization are implemented through
`CoreAccessAdminService`; HTTP and identity flow integration are connected in the reference host (see the [execution plan](./tenant-access-execution-plan.md)). The reference host now uses production cryptographic adapters, but production operational controls remain host-owned.

## Minimal Composition Pattern

1. Build `PgStorageConfig` in the host from env or secret store.
2. Construct `PostgresStorageAdapter`.
3. Apply migrations during host bootstrap.
4. Construct:
   - `CoreAdminService`
   - `CoreAuthService`
   - `CoreDeviceService`
   - `CoreDeviceSecurityService` for challenge, pending-device provisioning, registration, and key rotation
   - `CoreDeviceRequestVerificationService` for host protected-resource proof verification
   - `CoreProofBoundRefreshService` when refresh tokens require device proof
   - `CoreOidcService`
   - `CoreOidcResourceService`
   - `StaticOidcMetadataService` or a host-provided metadata service
5. Mount either:
   - `embedded_idp_axum::router(...)` for the full surface
   - or the split routers:
     - `embedded_idp_axum::public_router(...)`
     - `embedded_idp_axum::subject_router(...)`
     - `embedded_idp_axum::token_router(...)`
     - `embedded_idp_axum::client_authenticated_router(...)`
     - `embedded_idp_axum::admin_router(...)`
6. Attach host middleware per route group rather than assuming one shared policy fits the whole module.

## Required Host-Provided Pieces

### Session Token Issuer

The host must provide a `TokenIssuer` implementation for:

- access token issuance
- refresh token issuance

### ID Token Issuer

The host must provide an `IdTokenIssuer` implementation for OIDC authorization code exchange when `openid` scope is requested.

### Access Token Validator

The host must provide an `AccessTokenValidator` implementation for:

- `GET/POST /oidc/userinfo`
- `POST /oidc/introspect` when the token is an access token

Reason:

- the module issues refresh tokens itself, so refresh-token persistence and revocation are module-owned
- the access token format remains host-defined and should not be hardcoded into `embedded-idp-core`

### Client Secret Verifier

The host must provide a `ClientSecretVerifier` implementation for:

- `POST /oidc/token` when the caller is a confidential client
- `POST /oidc/revoke`
- `POST /oidc/introspect`

Reason:

- confidential client authentication is an OIDC business rule and is enforced by `embedded-idp-core`
- the module can use its own verifier and hashing codec, or a host-provided verifier if the host already owns secret format
- the host still decides whether client creation happens directly in bootstrap code or through trusted admin endpoint exposure
- `embedded-idp-axum` exports module-local admin routes under `/admin/...`
- the standalone `embedded-idp-app` currently nests those admin routes under `/api/admin/...`

### Protected Host Resources

For a host-owned resource route, construct `CoreDeviceRequestVerificationService`
with the storage adapter, Ed25519 public-key parser and signature verifier, server
clock, and allowed proof clock skew. Build `VerifyDeviceRequestCommand` from:

- the trusted account ID established by access-token middleware;
- the route's configured proof purpose;
- the untrusted five-header `DeviceProofPresentation`;
- a trusted `DeviceRequestBinding` containing the configured profile and audience,
  actual method and external path, and exact request-body digest.

`verify_device_request` checks the device, exact active key, account binding,
purpose-bound challenge, time window, and request-bound signature in one
transaction. A successful call consumes the challenge and returns
`VerifiedDeviceRequest`; the host must not perform a separate precheck or consume
the challenge itself.

When `DeviceHttpSecurity::ProofBound` is selected, `POST /devices/provision`
calls `CoreDeviceSecurityService::provision_pending_device`. It creates only the
pending device. Registration challenges are obtained separately from
`POST /device-proof/challenges`; no legacy nonce is created or discarded.

### JWKS Publication

The host should publish the public signing keys used by the ID token issuer through `OidcMetadataService`.
For simple cases, `StaticOidcMetadataService` can expose a fixed `JwksDocument`.

## Trusted Subject Requirement for `/oidc/authorize`

`GET /oidc/authorize` does not authenticate the end user by itself.

The host must place a trusted authenticated account context in the request before it reaches the embedded handler.

Current axum integration uses the typed request extension:

- `embedded_idp_axum::AuthenticatedSubject`

Example host middleware shape:

```rust
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use embedded_idp_axum::AuthenticatedSubject;

async fn inject_authenticated_subject(mut request: Request, next: Next) -> Response {
    request
        .extensions_mut()
        .insert(AuthenticatedSubject::new("0", "acct-host-user-1"));
    next.run(request).await
}
```

The host should set this extension from its own trusted login or session middleware.
It should not be derived from a client-controlled header directly.

For subject-bound device handlers, `embedded-idp-axum` now derives the effective account scope from this trusted subject context.
The module no longer trusts request-supplied `account_id` for self-service device register, bind, unbind, list, or detail flows.

## Route Narrowing Rule

The host should not treat the whole embedded router as one security bucket.
It should classify mounted routes into distinct trust levels:

- public anonymous endpoints
  - `POST /auth/register`
  - `POST /auth/login`
  - `POST /devices/provision`
  - `POST /devices/complete`
  - `POST /oidc/token`
  - `GET /oidc/jwks.json`
  - `GET /.well-known/openid-configuration`
- subject-bound endpoints that require a trusted authenticated account context
  - `GET /oidc/authorize`
  - user-scoped device bind, list, detail, and unbind operations when the host exposes them to end users
- token-bound endpoints
  - `POST /auth/refresh`
  - `POST /auth/logout`
  - `GET/POST /oidc/userinfo`
- client-authenticated endpoints
  - `POST /oidc/revoke`
  - `POST /oidc/introspect`
- admin or operator endpoints
  - module-local `embedded-idp-axum` paths:
    - `/admin/accounts/...`
    - `/admin/clients/...`
    - `/admin/sessions/...`
    - `/admin/devices/...`
  - standalone `embedded-idp-app` external paths:
    - `/api/admin/accounts/...`
    - `/api/admin/clients/...`
    - `/api/admin/sessions/...`
    - `/api/admin/devices/...`

Operator list endpoints now support module-owned pagination and basic filtering.
Current page responses expose `limit`, `offset`, `returned`, `total`, `has_more`, and optional `next_cursor`.
Module-local `/admin/accounts`, `/admin/sessions`, and `/admin/devices` also support additive cursor pagination via `cursor=unix_secs:id`.
For the standalone app, the corresponding external paths are `/api/admin/accounts`, `/api/admin/sessions`, and `/api/admin/devices`.
When a host or operator UI uses cursor mode, it should keep `offset=0`; the module rejects `cursor` together with a non-zero `offset`.

Current `embedded-idp-axum` keeps fixed module-local paths but does not impose a host-wide authorization policy by itself.
The host remains responsible for mounting route subsets behind the correct middleware or network boundary.

If a host wants an additional top-level prefix such as `/api/v1` or `/idp`, it should add that prefix when mounting the router.

Example narrowing pattern in an `axum` host:

```rust
use axum::{middleware, Router};
use embedded_idp_axum::{
    admin_router, client_authenticated_router, public_router, subject_router, token_router,
};

let app = Router::new()
    .merge(public_router(state.clone()))
    .merge(
        subject_router(state.clone())
            .route_layer(middleware::from_fn(inject_authenticated_subject)),
    )
    .merge(
        token_router(state.clone())
            .route_layer(middleware::from_fn(enforce_token_boundary)),
    )
    .merge(
        client_authenticated_router(state.clone())
            .route_layer(middleware::from_fn(enforce_client_auth_boundary)),
    )
    .merge(
        admin_router(state).route_layer(middleware::from_fn(enforce_admin)),
    );
```

For `POST /auth/refresh` and `POST /auth/logout`, the module validates the submitted
refresh token itself. The host decides whether those routes stay publicly reachable, same-origin
only, gateway-protected, or mounted on a dedicated auth surface.

## Recommended Exposure Profiles

Hosts should normally expose a narrowed subset rather than mounting the full module router by default.

### `oidc_only_host`

Recommended when the host mainly needs OIDC and local account login, but does not want end-user
device self-service or operator device management.

Mount:

- `public_router()` for register, login, `/oidc/token`, discovery, and JWKS
- `subject_router()` only for `GET /oidc/authorize`, behind trusted subject middleware
- `token_router()` for refresh, logout, and userinfo
- `client_authenticated_router()` for revoke and introspection

Do not expose:

- user device self-service routes
- `admin_router()`

### `end_user_app_host`

Recommended when the host app has signed-in end users and wants device self-service.

Mount:

- `public_router()`
- `subject_router()` behind trusted subject middleware
- `token_router()`

Optionally mount:

- `client_authenticated_router()` if the same host also serves confidential client revoke or introspection callers

Do not expose by default:

- `admin_router()`

Operational note:

- self-service device routes should remain subject-bound only
- the host should not let callers choose arbitrary `account_id`; the module now derives account scope from `AuthenticatedSubject`

### `admin_ops_host`

Recommended when operator or support tooling needs management operations, ideally on an internal-only
surface separated from end-user traffic.

Mount:

- `admin_router()` behind strong operator authentication and network restriction

Optionally mount:

- read-only subject-bound or client-authenticated routes if the operator console needs them

Do not expose on a public edge by default:

- `admin_router()` on the same anonymous internet surface as register or login

### `full_reference_host`

Recommended only for:

- local development
- module acceptance testing
- a tightly controlled internal integration environment

Mount:

- `router()`

This is the least narrowed shape and should not be the default production recommendation.

## Exposure Checklist

Use this checklist when choosing how much of the module to expose from a host.

| Profile | Mount | Required host control | Default exclusions | Typical use |
| --- | --- | --- | --- | --- |
| `oidc_only_host` | `public_router` + narrowed `subject_router` + `token_router` + `client_authenticated_router` | trusted subject middleware for `/oidc/authorize`; client auth boundary for revoke/introspect | self-service device routes; `admin_router` | dedicated OIDC provider surface |
| `end_user_app_host` | `public_router` + `subject_router` + `token_router` | trusted signed-in user context for subject-bound routes | `admin_router`; optional client-auth routes unless needed | product app with built-in account and device flows |
| `admin_ops_host` | `admin_router` | operator auth plus internal network restriction | anonymous/public auth routes unless explicitly needed | support console or internal ops API |
| `full_reference_host` | `router()` | all of the above controls if used outside local dev | none | local dev, acceptance checks, controlled internal integration |

Checklist before exposing a route group:

- `public_router`
  Confirm the endpoint is intended for anonymous or protocol-level entry.
- `subject_router`
  Ensure the host injects `AuthenticatedSubject` from a trusted login/session middleware.
- `token_router`
  Decide whether refresh/logout/userinfo live on a public edge, same-origin app surface, or a gateway-protected auth surface.
- `client_authenticated_router`
  Ensure confidential client authentication is enforced by host deployment boundary and module config.
- `admin_router`
  Keep it off public anonymous edges; prefer a separate internal hostname or network segment.

## Current Practical Support Level

The module is currently ready for:

- local account registration and password login
- refresh token rotation
- session logout
- device registration and heartbeat
- OIDC authorization code flow for public desktop clients
- confidential client secret validation for token, revoke, and introspection flows
- PKCE `plain` and `S256`
- refresh token revocation
- `userinfo`
- token introspection
- static JWKS publication
- operator admin APIs for account, session, OIDC client, and device management
- Postgres TLS `require` mode with optional custom CA certificate path

The module does not yet provide richer Postgres TLS options such as client
certificate authentication or `prefer` fallback-to-TLS behavior.

## Postgres TLS

`embedded-idp-storage-postgres` still receives typed database config from the host.

Current typed TLS fields on `PgConnectionConfig` are:

- `tls_mode`
  - `disable`
  - `prefer`
  - `require`
- `tls_ca_cert_path`
  - optional PEM CA bundle path used when `tls_mode=require`

Current behavior:

- `disable`
  - always uses plaintext Postgres transport
- `prefer`
  - currently behaves the same as `disable`
- `require`
  - uses a real TLS connector
  - validates against platform trust roots by default
  - additionally trusts `tls_ca_cert_path` when provided

Operational recommendation:

- production hosts should use `require`
- if the Postgres server uses a private CA, provide `tls_ca_cert_path`
- do not assume `prefer` means encrypted transport in the current implementation

## Tenant-aware module integration notes

The following sections record the tenant-aware module interfaces implemented during P3.
Their phase-specific status statements are historical; the reference-host status above is current.

### Mandatory tenant token contracts (P3 foundation)

`TokenIssuer::issue_session_tokens` and `AccessTokenIssuer::issue_access_token` require `tenant_id` as their first argument. `IdTokenClaims`, `ValidatedAccessToken`, production `ValidatedIdToken`, and HTTP `AuthenticatedSubject` also carry a required `tenant_id`. RS256 access and ID JWTs sign this exact claim; missing, empty, malformed, or tampered tenant claims are rejected, with no default-to-`0` decoding. Tenant IDs use the same 1–128 byte ASCII letters/digits/`_`/`.`/`-` syntax as Access queries. A valid signed tenant is an identity assertion, not proof that a membership or session remains active. The host must enforce those current states and compare the trusted tenant with resource ownership.

This is a breaking token/host contract change. Existing single-domain authentication, OIDC and refresh services explicitly issue domain `0`; the current resource service and subject HTTP handlers reject other tenants. The development token format also requires an explicit `0` and remains forgeable, for reference use only. These services are not yet the Enabled authentication flow: the new registration/login/session services below have separate tenant-aware storage; tenant refresh/OIDC/device binding now have separate modules below; the reference HTTP/Web composition now uses the tenant-aware services. Do not expose Enabled routes merely because the JWT adapter can sign a real tenant.

### Tenant registration and email verification (P3 service integration)

`access::CoreTenantRegistrationService::new(mode, auth_config, store, clock, ids, codes)` validates the existing `AuthConfig` and reuses the existing Argon2 password policy. Its store is the same independently injected `PostgresAccessStore` used by the Access module. `RegisterTenantAccountCommand` requires an explicit `tenant_id`, email, `SecretString` password and optional display name. The transaction rechecks current registration admission and creates the pending account, initial membership and tenant-bound verification record together. Duplicate email never overwrites credentials or joins another tenant.

The registration result is for trusted host delivery: send `verification_code` through the email adapter after commit, and expose only an appropriate public projection. It contains neither password hashes nor tokens, and its secret is redacted in Debug. Registration and verification do not accept a client/device ID because neither creates a session or device. Login will validate the client and chosen tenant independently.

`verify_email(VerifyTenantEmailCommand)` consumes a code only in the account’s original registration tenant. The transaction holds shared state and tenant locks, then locks the account before reading server time. Core checks active tenant/member, pending account, original tenant, exact code, issue time, expiration and prior consumption. Code consumption and account activation commit together; failures roll back. Closing registration does not invalidate an already-issued code by itself; tenant/member suspension does. Success returns only tenant/account IDs, with no automatic session, refresh token, authorization code or device. Hosts must separately run login.

Registration, verification and resend now have an independently mounted tenant HTTP router, described below. The reference host now mounts these routes in both modes after readiness validation.


### Tenant password login, selection and session authentication (P3)

Construct `access::CoreTenantAuthenticationService::new(mode, auth_config, entry, store, tokens, generator, digester, clock, ids)` with the independently injected `PostgresAccessStore`. `TenantLoginEntry` is trusted host configuration: registered `client_id`, stable `login_entry`, `LoginTenantPolicy`, and `require_device_proof`. Requests cannot override these values. The store checks that its initialized mode matches the service before running any transaction. Use the production `Rs256JwtService` for the combined `TokenIssuer + AccessTokenValidator` port, `SecureRefreshTokenGenerator` and `Sha256RefreshTokenDigester` for opaque credentials, plus the host's existing clock and ID generator. Signing keys, issuer, audience and client registration remain host responsibilities.

Fixed login checks the configured tenant's current membership and creates its session directly; Disabled requires tenant `0`. Enabled business login rejects `0`. ChooseAfterAuthentication verifies the password and returns only a 32-byte random selection ticket with a 300-second lifetime. Persistence contains its digest, account, client, entry, purpose and authentication time. It contains no unscoped session. Listing rechecks the ticket and returns only the user's non-removed business memberships, including their current statuses, with bounded cursor pagination. Completing selection requires an active tenant and membership.

Selection consumption, session insertion and initial refresh digest insertion share one PostgreSQL transaction. Token issuance or storage failure rolls back all three. Transactions hold shared state and sorted tenant locks, then an account lock and selection lock; waiting requests recheck expiration and current state after acquiring locks. Concurrent completion requests can create only one session. Signature validation is followed by current account, client, membership, tenant and exact tenant/session validation; a signed JWT alone is insufficient.

Mount `embedded_idp_axum::tenant_auth_router(Arc::new(service))` under the host's chosen outer prefix. Its module-local routes are:

| Method and path | Request and result |
| --- | --- |
| `GET /auth/access/capabilities` | Public mode, entry policy, optional fixed tenant, default/max page limits |
| `POST /auth/login` | JSON email/password; authenticated tenant session/tokens or `tenant_selection_required`, `selection_ticket`, `expires_in` |
| `GET /auth/tenant-selection/tenants` | `Authorization: TenantSelection <ticket>`; optional `limit` and opaque `cursor`; returns tenants with membership status and next cursor |
| `POST /auth/tenant-selection/complete` | Same selection authentication header; JSON `tenant_id`; returns session and tokens |
| `GET /auth/session` | `Authorization: Bearer <access_token>`; returns verified tenant/account/session IDs |
| `POST /auth/me/tenant-selection` | Bearer access token; returns a new selection ticket bound to the active source session |

Choice and switch routes are mounted only for Enabled + ChooseAfterAuthentication. Fixed entries cannot switch by calling a hidden route. Selection tickets never enter URLs or business Bearer authentication. Login rejects tenant hints; its tenant comes from host policy or the subsequent selection. Completion accepts an optional `X-Embedded-Idp-Tenant-Id` matching its explicit target. Session/switch accept an optional matching authenticated tenant header. Invalid or conflicting values are rejected. All router responses, including errors, carry `Cache-Control: no-store` and `Pragma: no-cache`; JSON bodies are limited to 16 KiB. Sync service calls run outside Tokio async workers.

Switching rechecks the source session when issuing and using the ticket, then creates a new target session without changing or revoking the old one. Required-device-proof entries reject device-less session issuance and authentication with `DeviceProofRequired`; use the Rust proof-login methods below to create device sessions. Use the device-aware HTTP authentication adapter below for those proofs. Initial refresh credentials and the tenant refresh methods below use the same transactional store.

This router is an explicit module integration surface, not an automatic replacement in `embedded-idp-app`. Its `/auth/login` overlaps the existing router: compose one implementation per path. Do not connect its tenant credentials to the old single-domain refresh, OIDC or device services. Platform management login, management APIs/UI and the remaining tenant security flows must be integrated before opening the multi-tenant reference host. The live PostgreSQL suite exercises this router in-process with real RS256 and database transactions; it does not claim that a production host has been deployed.


### Tenant-bound device proof bytes (P3 prerequisite for refresh)

The registration and key-rotation builders now take `tenant_id` first and emit V2
separators plus the mandatory tenant line. Construct
`DeviceRequestBinding::new(tenant_id, profile, audience, method, external_path, body_sha256)`
with a tenant verified against the authenticated identity/session and device ownership.
For HTTP, call `ProtectedRouteConfig::binding_for_request(trusted_tenant_id, method, original_uri, body_sha256)`.
The route configuration remains deployment-wide; the tenant is supplied for each
request, never selected by proof headers. `VerifyDeviceRequestCommand` carries it in
`binding`; successful `VerifiedDeviceRequest` includes `tenant_id`.

Use `DeviceProofProfile::new("EMBEDDED-IDP-DEVICE-REQUEST-V2")` or a custom profile
ending in `-V2`. Update client canonicalization and signatures together; old formats
and profile names are rejected. Exact bytes and cross-language runnable fixtures are
in [the delivery document](rust-embedded-idp-production-security-delivery-v2.md#tenant-proof-protocol-cutover-p3).

The current single-domain registration/rotation adapter signs for explicit domain `0`.
The existing request-verification and proof-bound-refresh services reject other
tenants before nonce consumption or family revocation. This is an intermediate
protocol change; the tenant services below use new-schema transactions, while
device lifecycle and proof-login/refresh HTTP routes are described below.
Do not enable real-tenant device routes by
supplying a tenant to a byte builder alone.


### Tenant device challenges and protected-request transactions (P3)

`access::CoreTenantDeviceProofService` now connects V2 proof verification to
`tenant_v2` PostgreSQL authority. Construct it with the existing independent
`PostgresAccessStore`, `TenantDeviceProofConfig`, `Ed25519PublicJwkParser`,
`RingEd25519Verifier`, `SecureDeviceChallengeGenerator`, clock and ID generator.
The typed configuration fixes the client, allowed purposes, challenge lifetime and
clock skew. No additional database connection or runtime crypto dependency is introduced.

`issue_challenge(tenant_id, device_id, purpose)` accepts an explicit business domain
(`0` only in Disabled). It verifies current tenant/client and device eligibility.
Registration-purpose challenges require pending devices; other allowed purposes
require active devices. Unknown or ineligible devices receive a random opaque
challenge and expiry in the same response shape, with no corresponding stored nonce.
This is response-shape protection, not a constant-time or rate-limiting guarantee.
Hosts retain admission control and rate limiting for their public routes.

`verify_request(VerifyTenantDeviceRequest)` accepts an already authenticated
`AccessActor`; never deserialize the actor from caller JSON. The host also constructs
the expected purpose and `DeviceRequestBinding` from its protected route, original
URI and raw body hash. The service rechecks current account, active tenant/member,
exact session, client and any session device constraint inside the same transaction
that verifies the signature and consumes the nonce. The result is the existing
`VerifiedDeviceRequest`, with the verified tenant. It proves device possession;
resource permission checks are still required before reading reports or performing
business actions.

`TenantDeviceProofTransaction` extends the existing authentication transaction, so
both share the mode/bootstrap checks and pool. Lock order is state → tenant → account
→ device → key → binding → challenge. Every device/key/binding/challenge lookup and
nonce update includes tenant; the device and key must also agree on their IDs, key
version and current-key pointer. JWK validation checks the thumbprint against the
stored key ID before Ed25519 verification. Server time is read after blocking locks.
Signature failure, inactive authority, expiry or storage failure leaves the nonce
unconsumed. Conditional consumption and commit permit only one concurrent success.

The `TenantProof*` records are minimal verification projections of the existing
new-schema rows, not replacements for the full device management models. The
PostgreSQL adapter implements challenge transactions and the lifecycle writes
below. First binding is integrated with proof login; self-service unbinding uses the
management methods and HTTP router below. Core itself never mounts routes or enables
the reference host.

### Tenant device provisioning, activation and key rotation (P3)

The same `CoreTenantDeviceProofService` provides lifecycle methods when its
transaction implements `TenantDeviceLifecycleTransaction`; `PostgresAccessStore`
already implements this contract. No second pool or separate service is required.

- `provision_device(tenant_id, name, &admission)` requires a host implementation of
  `TenantDeviceAdmission`. It must authorize the caller to provision for this tenant
  and configured client; never build this policy from caller JSON. There is no
  default allow policy. Admission runs before the transaction, and the module
  rechecks active tenant/client under the domain lock before inserting a pending
  device. The host owns authentication, rate limits and any external admission
  policy consistency; no cross-system atomicity is implied.
- `complete_registration(CompleteTenantDeviceRegistration)` requires a pending
  device and a live registration challenge for that exact tenant/device. Validate
  the submitted JWK and sign V2 registration bytes with its private key. Successful
  verification atomically consumes the challenge, inserts active key version 1 and
  activates the device. It creates no account binding or login session.
- `rotate_key(RotateTenantDeviceKey)` requires a host-authenticated `AccessActor`,
  the actor's active same-tenant device binding and a live rotation challenge.
  Both current and proposed private keys sign the same V2 rotation bytes, including
  tenant/device, old/new key IDs, next version and challenge. The transaction
  rechecks account/member/session/device/key/binding authority, retires the old key,
  inserts the new one and advances the device pointer. This self-service operation
  can rotate another device already bound to the same account; it does not require
  the login session itself to be pinned to that device. Protected-request proof
  verification still enforces any session device constraint.

Enable registration and key-rotation purposes explicitly in the service's allowed
purposes when exposing those operations. Raw challenges and signatures use
`SecretString`; persistence keeps challenge digests only. Failed signatures or
storage writes leave authority and challenge consumption unchanged. Concurrent
completion permits one winner, and the schema's global key uniqueness prevents
reusing a key in another tenant or device. Device tenant ownership never changes.

First account binding is integrated with proof-bound login below. Generic protected
request tests still use direct SQL fixtures, while the rotation test now establishes
its binding through proof login. Lifecycle HTTP routes are described below; the
reference-host Enabled cutover remains pending.

### Device-bound password login and tenant selection (P3)

Use `CoreTenantAuthenticationService::login_with_proof(command, proof, &devices)`
for a Fixed entry. For ChooseAfterAuthentication, call ordinary `login` to obtain
a selection ticket, then `select_tenant_with_proof(ticket, tenant_id, proof, &devices)`.
`devices` is the existing `CoreTenantDeviceProofService`, configured with the same
mode, client, clock and shared IdP store. Enable `tenant_login` and/or
`tenant_selection` purposes. These methods use the authentication transaction for
all proof reads and writes; they never start a second database transaction.

`TenantAuthenticationProof` contains the presentation and trusted request binding.
The host reconstructs the binding from its route, target tenant and raw-body hash;
never accept routing/body metadata from caller JSON. Use profile
`EMBEDDED-IDP-DEVICE-AUTH-V2` and `build_tenant_authentication_proof_bytes` rather
than the generic request builder. The authentication builder appends a final
`credential-sha256:<base64url digest>\n` line after the usual V2 request lines.
Core derives this digest from the actual credentials and trusted login entry;
callers cannot supply the digest to the login service.

- Password context: `tenant_password_proof_context(client, login_entry, &command)`.
- Selection context: `tenant_selection_proof_context(client, login_entry, &ticket)`.

The exact context bytes and cross-language vectors are documented in the tenant
design §13.5. This also binds selection tickets carried in the Authorization
header: a proof for one ticket cannot be reused with another live ticket, even for
the same account. Keep contexts and signature inputs out of application logs.

Password/ticket authentication and current tenant membership precede proof checks.
The transaction validates the active tenant device, current key, expected-purpose
challenge and signature, then inserts a first binding if none is current. Active
bindings are reused; suspended bindings are rejected. A historical unbound record
does not restore itself: a new binding requires a fresh credential and device
proof. Nonce consumption, new binding, selection-ticket consumption when applicable,
session insertion and initial refresh insertion commit together. Signing or storage
failure rolls everything back. The resulting session is pinned to that device.

Session authentication also checks current device, key and account-device binding
state, including for optional-proof entries. Switch tickets recheck that source
authority and require a fresh target-tenant device proof for proof-required entries;
no device, key, binding or session is copied between tenants.
`TenantAuthTransaction::session_device` reads one joined snapshot after domain and
account locks, avoiding source/target device lock inversion during switches.
Device/binding revocation must follow those locks and revoke associated sessions;
arbitrary direct SQL writes are outside this concurrency contract.

The basic `tenant_auth_router` retains its device-less request shape. For proof
entries, use the composed service and `tenant_device_auth_router` described below.
Missing proof still rejects required entries. Device management and full
reference-host cutover remain subsequent work; Enabled startup remains blocked.

### Tenant refresh rotation and committed reuse detection (P3)

`CoreTenantAuthenticationService` now provides two Rust refresh methods using the
existing authentication store, generator, digester and clock. The token adapter
additionally implements `AccessTokenIssuer` (the production RS256 adapter already
does), and the store transaction implements `TenantRefreshTransaction`.

- `rotate_refresh(refresh_token)` accepts only a device-less session at an entry
  that does not require device proof. Device-bound sessions cannot downgrade to it.
- `rotate_refresh_with_proof(command, &devices)` uses the existing
  `RotateProofBoundRefreshCommand` shape, with trusted host request binding. Enable
  purpose `refresh` in the device service. Sign the authentication V2 profile with
  `tenant_refresh_proof_context(client, login_entry, &refresh_token)` and
  `build_tenant_authentication_proof_bytes`. Core recomputes the context, preventing
  a signature for one token from being transplanted to another session's token.
  The exact device pinned to the session and an existing active binding are required;
  refresh never creates or restores bindings.

Tenant and session come from the stored digest, not a requested target. Fixed entry
policy and configured client still apply. A non-locking token/session lookup is only
a routing hint, rechecked after locks in this order: state → tenant → account →
session → refresh → device/key/binding/challenge. Current account and membership
must remain active. Proof is verified before exposing device/binding/replay details
or applying reuse revocation. Credential times are checked again after proof locks.

The current refresh version is retired with `rotated`, the session version advances,
and a new digest is inserted in one transaction with nonce consumption. Only a
committed `Rotated` result returns tokens. Refresh expiry is capped by the original
session expiry, and an issuer result extending access beyond that boundary is
rejected with rollback; a session is never extended by refresh.

An unexpired older token marked `rotated`, presented with a fresh valid proof when
required, commits revocation of that exact tenant/session and all its refresh rows.
Core returns `Ok(TenantRefreshOutcome::ReuseDetected { tenant_id, session_id })`;
the HTTP adapter must map that committed outcome to a reuse error afterwards.
Returning a transaction error for confirmed reuse would incorrectly roll it back.
Invalid signatures, expired credentials, other revocation reasons, issuer failures
and database failures roll back all changes and leave any fresh nonce unused.

Replaying the same nonce is a proof error and does not trigger family revocation.
Two concurrent requests using the same refresh token with distinct valid nonces
produce one rotation followed by committed reuse revocation. Clients must serialize
refresh attempts per session. This strict policy has no grace window.

The tenant refresh methods are also exposed by `tenant_device_auth_router` below.
OIDC authorization/token HTTP is described below; reference-host cutover remains pending.
Tenant resource and logout/revocation routes are described below.


### Tenant OIDC authorization and code exchange (P3)

Compose `CoreTenantOidcService::new(auth, issuer, oidc_config, allowed_scopes,
client_secret_verifier)` using the same injected IdP store, trusted client/login
entry, clock and token adapters as the tenant authentication service. The token
adapter implements `TokenIssuer`, `AccessTokenValidator`, `ScopedAccessTokenIssuer`
and `IdTokenIssuer`; the production RS256 adapter implements all four. Tenant
login/selection and refresh now require the scoped issuer too, so delegated scopes
survive refresh and explicit tenant switching. The OIDC scope allowlist is per entry;
the signing adapter also enforces its deployment-wide maximum scope.

- `authorize(trusted_actor, request)` accepts an actor derived by trusted host
  authentication, never deserialized from request JSON. It rechecks the live source
  session, same configured client, tenant membership and device authority. Only
  registered redirects and supported PKCE input are accepted. A short-lived code
  references that session and stores only a digest; no raw code is persisted.
- `exchange(command)` derives the tenant from the code, verifies the original
  client/redirect/PKCE and current source identity, and consumes the code once.
  It rejects device-bound source sessions even at optional-proof entries.
- `exchange_with_proof(command, proof, &devices)` additionally requires a fresh
  proof from the source session's exact device and active binding. Configure device
  purpose `authorization_code`, use the authentication V2 profile, and derive its
  credential field with `tenant_code_proof_context(login_entry, &command)`. The
  context includes grant type, code, redirect, verifier and client secret. The host
  reconstructs trusted method/path/audience and the exact raw-body digest as usual.

Code consumption, proof consumption, new session/refresh insertion and access/ID
signing share one transaction. Errors roll everything back; parallel exchanges
have one winner. Account locks serialize with identity/membership/session changes;
client configuration is read under a shared row lock. Host client-management writes
must respect the documented state/tenant/account lock order when combined with
identity mutations, and must not introduce a client-first/account-second path.

The result contains the tenant login session, exact normalized granted scope and an
ID token only for `openid`. ID tokens retain the authorization nonce, configured
client audience and original authentication time. OAuth scope remains separate from
RBAC checks. `None` session scope is a host-default password login; `Some("")` is an
explicitly empty delegated scope. Neither refresh nor tenant switching can expand
an explicit scope back to the host default.

These are Rust module APIs. The fresh tenant DDL includes code digests/source session
references and session scope/authentication time; previous incomplete layouts fail
validation rather than being migrated. No application schema is changed by tests.
Device management, management UI and reference-host
cutover remain pending; Enabled startup is still blocked. Resource routes follow.


### Tenant userinfo, introspection and session revocation (P3)

`CoreTenantOidcService` implements `TenantOidcResourceService`. Reuse its injected
IdP store and token/client adapters. `TenantOidcResourceTransaction` adds one
account-profile projection to the existing OIDC/refresh transaction; it does not
introduce a connection or schema. Mount `tenant_oidc_resource_router(Arc::new(service))`
explicitly and replace overlapping old routes. It can be merged with
`tenant_auth_router` because those new modules have no overlapping paths.

| Route | Input | Behavior |
| --- | --- | --- |
| GET `/oidc/userinfo` | One Bearer access token | Rechecks live tenant/account/membership/session/device; requires `openid`; returns `sub`, `tenant_id`, `client_id`, plus `email` only for `email` scope and `name` only for `profile` scope |
| POST `/oidc/introspect` | Form `token`, optional `token_type_hint`, client authentication | Only the entry's authenticated confidential client; inactive or wrong-tenant tokens return exactly `{"active":false}` |
| POST `/oidc/revoke` | Same form and client credentials | A current access or refresh token revokes its exact session and every refresh record; invalid/already inactive tokens return empty HTTP 200 |
| POST `/auth/logout` | Form `refresh_token`, client credentials | Same family revocation, only from a current refresh token; repeated logout is HTTP 200 |

Client authentication uses either HTTP Basic with OAuth form-encoded username and
password components, or form `client_id`/`client_secret`. Combining the two sources
or multiple Authorization headers is rejected. A public client may revoke/log out
its own current credential without a client secret, but cannot use introspection.
The first implementation does not authorize a separate resource-server client to
inspect another client's tokens. Such hosts can call their trusted session
validation module directly. `token_type_hint` is only a lookup preference; a wrong
or unknown hint cannot hide a valid token of the other supported type.

Token-management POSTs reject a tenant header and unknown form fields; tenant is
always derived from the credential. Userinfo may assert the tenant header, which
must match the validated result. No endpoint accepts caller-supplied time, account,
session or target tenant. Responses, including failures, carry `no-store` and
`no-cache`; request bodies and credential lengths are bounded. Store/cryptographic
adapter failures remain errors, not an inactive response or a successful revoke.

Resource queries inspect current device authority without consuming a nonce. Logout
and revocation remove credentials and do not issue new ones, so they do not require
a new device proof. An expired, retired or version-mismatched refresh credential
cannot revoke a live family here. Proof-confirmed reuse revocation remains the
separate refresh policy. All family updates use the shared tenant/account lock order
and commit together with reason `logout` or `client_revocation`; errors roll back.
Session revocation also prevents outstanding codes or selection tickets referencing
that source session from being redeemed. Already separate sessions are unaffected.

HTTP logout here is the new form-based tenant endpoint, not the old reference-host
JSON endpoint. The reference host is not automatically switched to this router.
Enabled startup remains blocked until the remaining proof/OIDC and management
integration is complete.


### Device-aware tenant authentication HTTP (P3)

Compose `CoreTenantDeviceAuthenticationService::new(auth, devices)` from the existing
Core tenant authentication and device-proof services. Both must use the same injected
IdP store, tenancy mode and client. The object-safe composition delegates to the
existing transactions; it does not own another state machine or database connection.

Mount `tenant_device_auth_router(service, config)` **instead of** `tenant_auth_router`.
It retains capabilities, current session, tenant listing and switch-ticket routes,
replaces login/selection handlers, and adds refresh and authentication challenges.
Merge `tenant_oidc_resource_router` separately for logout and resource operations.

```rust
let service = Arc::new(CoreTenantDeviceAuthenticationService::new(auth, devices));
let config = TenantDeviceAuthHttpConfig::new(
    "business-api",
    "/idp/auth/login",
    "/idp/auth/tenant-selection/complete",
    "/idp/auth/refresh",
).expect("valid host route configuration");
let router = Router::new().nest("/idp", tenant_device_auth_router(service, config));
```

The module keeps local paths; configuration names the literal externally visible
paths, including the host's prefix. `OriginalUri`, method and SHA-256 of the exact
received bytes must match. Query strings are rejected on signed authentication
routes, including unsigned attempts; route/audience/profile cannot come from a
request. Use the fixed authentication V2 profile and existing credential-context
helpers. Five existing device headers carry device ID, key ID, challenge, signature
and signed-at time; partial or duplicated proof headers never downgrade to bearer.

| POST route | JSON body | Authentication/proof |
| --- | --- | --- |
| `/devices/proof/challenges` | `tenant_id`, `device_id`, `purpose` | Purposes are `tenant_login`, `tenant_selection`, `refresh`, `authorization_code`, `device_registration`, `device_key_rotation`, `heartbeat`; tenant must fit the trusted entry policy. Unknown/ineligible devices receive an opaque challenge without a stored nonce |
| `/auth/login` | `email`, `password` | Fixed entry derives tenant from host policy; include proof headers for device login. Choose entry uses password only and returns a selection ticket; a tenant header or premature proof is rejected |
| `/auth/tenant-selection/complete` | `tenant_id` | `Authorization: TenantSelection <ticket>` and target-tenant proof headers when required; credential context signs the exact ticket. This route exists only for Enabled + Choose entries |
| `/auth/refresh` | `refresh_token` | For a bound device, include all proof headers plus exactly one `X-Embedded-Idp-Tenant-Id` assertion. Core derives the actual tenant from the refresh/session and rejects mismatch before nonce consumption. Device-less optional entries omit both proof and tenant headers |

Use `tenant_password_proof_context`, `tenant_selection_proof_context` or
`tenant_refresh_proof_context`, then `build_tenant_authentication_proof_bytes` to
sign. The client must hash exactly the JSON bytes it sends, including whitespace.
The tenant assertion never becomes an authenticated context on its own and is not
a request to switch tenants. Only the existing selection flow can create a session
in a different tenant after membership and target-device validation.

Login/selection/refresh responses share the existing tenant session and token
shape. A `ReuseDetected` result is mapped to HTTP 401 with
`refresh_token_reuse_detected` only after Core has committed family revocation.
Ordinary replay/validation failures do not commit state. No-cache headers and the
16 KiB body limit cover the whole router, including error responses. JSON rejects
unknown or duplicate fields; no caller-selected client, time or authority is accepted.

The self-service lifecycle and device HTTP bridge is described below. Administrative
device actions, management UI and reference-host assembly remain pending integrations.
Enabled startup remains blocked.


### Tenant OIDC authorization HTTP (P3)

Compose `CoreTenantOidcAuthorizationService::new(oidc, devices)` from the existing
`CoreTenantOidcService` and `CoreTenantDeviceProofService`. Use the same IdP database,
tenancy mode, configured client, login entry and security adapters as authentication.
Mount `tenant_oidc_authorization_router` alongside the tenant authentication and
resource routers, replacing the original single-domain authorize/token routes.

```rust,ignore
let oidc_http = tenant_oidc_authorization_router(
    Arc::new(CoreTenantOidcAuthorizationService::new(oidc, devices)),
    TenantOidcHttpConfig::new("https://api.example.test", "/api/oidc/token")?,
);
let app = Router::new().nest("/api", auth_http.merge(oidc_http).merge(resources_http));
```

The configured audience and token path are trusted host values. Include the literal
external mount prefix. Token requests reject query strings, including unsigned
requests; no proxy header supplies a different external path.

| Route | Request | Result |
| --- | --- | --- |
| GET `/oidc/authorize` | Exactly one `Authorization: Bearer <access>`; query `response_type=code`, `client_id`, `redirect_uri`, optional `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method` (`plain` or `S256`) | Validates bearer and current session, then rechecks Core authorization policy; 307 to the registered callback with encoded `code` and optional `state` |
| POST `/oidc/token` | `application/x-www-form-urlencoded`: `grant_type=authorization_code`, `code`, `redirect_uri`, optional `code_verifier`, and client credentials | Flat OAuth token JSON after the existing transaction commits |

Authorize does not accept an account ID, session ID or tenant ID from query fields.
An optional `X-Embedded-Idp-Tenant-Id` must match the authenticated actor before
code creation. This adapter uses explicit bearer authentication, not cookies or the
reference host's development subject header. The host UI handles login and consent;
this route does not add either flow. Missing scope requests the empty scope and
therefore does not implicitly request an ID Token. Invalid requests return a local
error without redirecting to unverified input.

Token client authentication uses either OAuth Basic (form-encoded components before
Base64) or form `client_id`/`client_secret`; combining sources or repeating fields
is rejected. Public clients supply form `client_id` and satisfy their PKCE policy.
Only authorization-code grants are supported here; refresh remains `/auth/refresh`.

For device-bound sources, supply all five existing proof headers plus exactly one
`X-Embedded-Idp-Tenant-Id` assertion. Hash the exact transmitted form bytes, use
`tenant_code_proof_context(login_entry, &command)` over decoded command fields,
then `build_tenant_authentication_proof_bytes`. Client credentials carried in Basic
are still included in the signed credential context. Core resolves the actual tenant
from the code/source session, verifies the assertion, and consumes nonce/code together
with token issuance. Device-less optional entries omit proof and tenant headers;
device-bound sessions cannot downgrade to this path.

Obtain the nonce from `/devices/proof/challenges` with purpose `authorization_code`.
The injected device service must explicitly allow that purpose. All other challenge
admission and anti-enumeration behavior stays the same.

Token success returns `access_token`, `refresh_token`, `refresh_token_version`,
`token_type: "Bearer"`, `expires_in`, `scope`, `tenant_id`, `subject_account_id`,
`session_id`, and `id_token` only when `openid` was granted. `expires_in` is the
access lifetime relative to the new session's issuance time. Both endpoints return
no-store/no-cache. Form bodies and authorize query strings are limited to 16 KiB.
Errors use `{"error":"..."}`: invalid client is 401 with a Basic challenge, invalid
bearer is 401 with a Bearer challenge, invalid grant/request is 400, and internal
store/signing errors remain 500. Media-type and size errors retain 415/413 (414 for
oversized authorize queries). No database details or supplied credentials appear in
error bodies.

Reference-host assembly, administrative device management and management UI
remain separate pending work. Enabled reference-host startup is still blocked.


### Tenant registration and email verification HTTP

`CoreTenantRegistrationService` implements the object-safe `TenantRegistrationService`
for registration, verification and resend. Inject the existing provider-neutral
`VerificationEmailService`; the HTTP adapter does not load environment variables or
choose an email provider. Merge these non-overlapping routes with tenant authentication
and OIDC, replacing the original single-domain registration routes:

```rust,ignore
let registration_http = tenant_registration_router(
    Arc::new(registration_service),
    login_policy.clone(),
    verification_email_service,
)?;
let app = Router::new().nest("/api", registration_http.merge(auth_http).merge(oidc_http));
```

The router validates the trusted Fixed/Choose policy against the service's mode at
construction. All bodies explicitly include `tenant_id`: Fixed accepts only its
configured tenant; Choose accepts a real business tenant; Disabled accepts only `0`.
An optional `X-Embedded-Idp-Tenant-Id` must be unique and match the body. None of these
endpoints accepts client/device IDs, caller timestamps or a claimed authenticated
subject. Duplicate/unknown JSON fields are rejected; bodies are limited to 16 KiB
and every response disables caching.

| POST route | JSON body | Success |
| --- | --- | --- |
| `/auth/register` | `tenant_id`, `email`, `password`, optional `display_name` | 202: tenant/account IDs, `account_status: pending_verification`, email channel, verification expiry and `delivery_status: sent` or `failed` |
| `/auth/verify-email` | `tenant_id`, `email`, `verification_code` | 200: tenant/account IDs and `account_status: active`; no session or tokens |
| `/auth/resend-verification` | `tenant_id`, `email` | 202: exactly `{"status":"verification_requested"}`; no account metadata, code, expiry or delivery status |

Registration commits the pending account, initial membership and verification record
before attempting delivery. Email failure does not delete or roll back the account;
the caller can request resend. Existing emails never acquire another membership
through public registration. Duplicate-account registration returns 409; closed or
unknown registration tenants return 403. Input/entry-tenant errors return 400 (Axum
JSON shape errors retain 422); body-size errors are 413. Invalid/expired verification
codes return 401. Storage failures return a generic 500 without backend details.

`resend_verification(ResendTenantVerificationCommand)` locks the tenant and account,
loads that tenant's current membership, and requires the original registration tenant,
a pending account and active tenant/member state. It retires prior unconsumed records
and inserts a replacement in the same transaction. Read time is observed after lock
acquisition; insertion failure restores prior records. Closing registration does not
prevent an existing pending user from receiving a fresh code and verifying. Requests
for unknown, active, disabled/closed, wrong-registration-tenant or inactive-member
accounts send no email and return the same accepted body. Backend failures are not
silently treated as accepted requests.

Resend's delivery result is deliberately absent from the public response; normal
provider failure preserves the pending account and current code for recovery. Reuse
the host's admission/rate limits for public registration, resend and code attempts.
There is no durable mail queue or automatic retry: email and database commit are
separate operations. Concurrent resends serialize database replacement, but email
arrival order is not guaranteed; only the current unconsumed record can verify.
The uniform resend body is not a claim of constant-time responses.

The injected email adapter receives the address, code and expiry using its existing
contract. Clients retain the explicit registration tenant for verification; verifying
never switches tenant, creates a device or signs in the user. After activation, use
the separate login flow and its fixed/selection policy.

These module routes are tested together with real PostgreSQL and RS256 login. The
reference host and Web pages have not yet switched to them; Enabled startup remains
blocked until the remaining device, management and host work is complete.


### Tenant device lifecycle and self-service HTTP

Compose `tenant_device_router(service.clone(), admission, config)` with
`tenant_device_auth_router(service, auth_config)` under the same host prefix.
The existing `CoreTenantDeviceAuthenticationService` implements `TenantDeviceService`;
use the same mode, client, entry policy, database and cryptographic adapters.
The authentication router owns the single `/devices/proof/challenges` endpoint.
`TenantDeviceAdmission` is explicitly injected by the host; there is no allow-all default.
`TenantDeviceHttpConfig::new(audience, external_heartbeat_path)` fixes the generic
request V2 profile and POST method for heartbeat, including the actual host prefix.

| Route | Input and authority |
| --- | --- |
| POST `/devices/provision` | JSON tenant_id/device_name; trusted entry policy plus host admission creates a pending device |
| POST `/devices/complete` | JSON tenant_id/device_id/public_jwk/challenge/signature; registration V2 proof atomically activates the device, without binding an account |
| POST `/devices/rotate-key` | Bearer plus JSON device_id/proposed_public_jwk/challenge/current_key_signature/proposed_key_signature; both keys sign the rotation V2 bytes |
| GET `/devices` | Bearer plus optional limit/cursor; only this actor's non-unbound devices in this tenant/client; default 50, maximum 200 |
| GET `/devices/:device_id` | Bearer; same ownership scope, no JWK or other-user bindings returned |
| POST `/devices/unbind` | Bearer plus JSON device_id; atomically unbind and revoke all this account's associated sessions/refresh credentials in this tenant |
| POST `/devices/heartbeat` | Bearer, five proof headers, JSON device_id matching proof device; generic request V2 proof with purpose heartbeat |

Registration and rotation use existing canonical-byte builders. Heartbeat hashes
exact JSON bytes and validates the literal mounted path; query strings are rejected.
A device-bound session can heartbeat only its source device. Nonce consumption and
last_seen update share a transaction; `observed_at_unix_secs` returns verification
time, while stored `last_seen_at_unix_secs` never decreases if the clock moves back.
The shared actor check revalidates current tenant/member/session/source-device and
session time, including direct Core calls. Cursor values carry no authority and
must match the actor tenant/subject and configured client.

Unbinding another owned device is allowed. Unbinding the current device also ends
that current session. Other users of the device and the device's active key remain
unchanged; new proof login can establish a new binding but cannot reactivate old
sessions. Existing authorization-code and tenant-selection flows recheck their
source session, so a revoked source cannot issue new credentials. No standalone
`/devices/bind` route is exposed. Cross-user disable/revoke belongs to the separate
administrative authorization boundary below and is not implemented by this router.

All routes disable caching and limit bodies to 16 KiB. Do not mount both legacy and
tenant device routes at the same path. This module delivery does not switch the
reference host in that historical work package. The current reference composition is described at the top of this document.

### Tenant device administration

`CoreAccessAdminService` now implements `TenantDeviceAdminService`, reusing the
existing administrative transaction and audit infrastructure. Mount
`tenant_device_admin_router(mode, Arc::new(admin_service))` independently under the
host's outer prefix; do not merge it into a public route group by default.

The host's management-authentication middleware must validate the management
credential's audience, purpose and current identity, then inject
`Extension<AccessAdminContext>` including actor tenant/subject/session, trusted
`authentication_source` and request ID. A business token, development subject
header or API key is not automatically a management identity. No such identity is
constructed from request JSON/headers by this router. Without the extension the
router returns 401. Cookie-authenticated hosts must also supply CSRF protection.
The reference host now adopts this management login/composition boundary.

| Route | Contract |
| --- | --- |
| GET `/admin/devices` | Optional limit/cursor, account_id, client_id, status, registered_after_unix_secs, registered_before_unix_secs; default 50/max 200, no total count |
| GET `/admin/devices/:device_id` | Device metadata/status, no JWK, credential or user-binding collection |
| POST `/admin/devices/:device_id/disable` | JSON `{"expected_status":"active"}`; source may also be pending/disabled; revoked cannot be disabled |
| POST `/admin/devices/:device_id/revoke` | JSON expected_status matching current state; revoke is terminal |

An Enabled platform actor (domain 0) must supply exactly one
`X-Embedded-Idp-Tenant-Id` target, which must be a real business tenant; Core checks
`idp.platform/access.manage` without changing the actor's domain. A tenant actor's
target defaults to its own tenant and cannot name another; Core requires
`idp.tenant/devices.manage`. Disabled defaults to domain 0 and rejects real tenants.
Duplicated target headers or caller-supplied actor/time/status overrides are rejected.
Lists use ascending device ID keyset pagination and fetch at most limit + 1 rows.
Cursors bind the target tenant and every filter; repeat the same filters on each
page. Changed filters or tenants are rejected, and permission is rechecked on
every page. Registration time bounds are inclusive, nonnegative whole Unix seconds;
reversed ranges, unknown fields/statuses and malformed cursors are rejected.
The account filter matches only active account-device bindings in the target
tenant; suspended and unbound records do not match. Shared devices and historical
bindings do not duplicate rows. Without an account filter, unbound devices and
all four device statuses remain visible. An unknown account or client yields an
empty list. Binding metadata and keys are not returned.

PostgreSQL uses a same-tenant EXISTS predicate for account filtering and existing
tenant/device, tenant/client/device and tenant/account/device indexes. There is no
total-count or application-side collection scan. Sparse status/time queries may
still scan a tenant's ID range; workload-specific indexes remain subject to the
planned performance acceptance, which has not yet been run.

Every service call rechecks current actor account, tenant, membership, session time
and source-device/key/binding state plus permission inside the transaction. This
also protects direct Rust calls and covers the existing role/member mutations.
A non-current expected_status returns 409; unauthorized returns 403; an authorized
lookup of a missing tenant/device returns 404. Body size is limited to 16 KiB and
all responses disable caching. The HTTP response includes device metadata and an
audit ID, never an arbitrary audit payload or key material.

Disable revokes every associated active/pending session and refresh credential,
removes source authorization codes, revokes source selection tickets and removes
nonces in this device's tenant. It retains keys and bindings without making them
usable while disabled. Revoke additionally retires active keys and unbinds all users.
There is no re-enable endpoint. Repeated commands can use the current expected_status;
a stale pre-disable expectation cannot override a later revoke.

The entire update, cleanup and secret-free before/after audit commit together;
audit failure rolls everything back. Management holds the existing exclusive tenant
lock, which excludes authentication transactions' shared tenant locks before
credential cleanup. Other tenants/devices remain unchanged. Bounded administrative
reads currently reuse this lock protocol too; measure management-read contention
before splitting a shared snapshot path. This is not a throughput claim.

### Tenant session administration

`CoreAccessAdminService` also implements `TenantSessionAdminService`. Mount
`tenant_session_admin_router(mode, Arc::new(admin_service))` in the protected
management group. It shares the trusted `AccessAdminContext`, target-tenant header,
live actor checks and transaction boundary described for device administration.
Tenant actors need `idp.tenant/sessions.manage`; platform actors use
`idp.platform/access.manage` and must explicitly name a real target tenant in
Enabled mode. A request cannot supply its own actor or revocation timestamp.

| Route | Contract |
| --- | --- |
| GET `/admin/sessions` | Optional limit/cursor and account_id, client_id, device_id, status, created_after_unix_secs, created_before_unix_secs filters |
| GET `/admin/sessions/:session_id` | Session metadata within the authorized tenant; no refresh credential or internal token version |
| POST `/admin/sessions/:session_id/revoke` | JSON `{}`; returns session metadata and audit_id |
| POST `/admin/accounts/:account_id/sessions/revoke` | JSON `{}`; revokes that user's sessions in the target tenant, returns tenant_id/account_id/revoked_session_count/audit_id |

Pagination defaults to 50, caps at 200 and reads limit+1 by session ID without a
total-count query. Repeat the same filters when passing next_cursor; the cursor
binds all filters and the target tenant. Permission is checked again on every page.
Time bounds are inclusive Unix seconds, must form a valid range and refer to
creation time. Status is the stored pending/active/revoked/expired value; listing
neither refreshes status nor authorizes a session, and expires_at_unix_secs remains
available to the UI. Unknown filters, malformed cursors and scope changes fail.

Single revocation marks the selected session revoked. Bulk revocation marks all
active/pending sessions for that tenant/member revoked, using a database aggregate
for the changed count rather than loading an unbounded session-ID collection.
Both operations revoke associated refresh credentials, delete source authorization
codes and revoke tenant-selection tickets derived from those sessions. Independent
password-login selection tickets without a source session are outside this scope.
Account status, device keys and bindings remain unchanged: a fresh login can create
a new session. Other tenants, including the same user's sessions, remain valid.

Cleanup and audit commit together; any failure rolls back the whole operation.
Repeated revocations are allowed; a repeated bulk operation reports zero newly
revoked active/pending sessions. Audit records contain bounded metadata/counts, no
credentials or unbounded session collections. Concurrent bulk operations serialize
through the existing tenant lock. Revoking an administrator's current session also
prevents that session from authorizing subsequent management calls.

All responses disable caching; bodies are limited to 16 KiB. This independent
router is now mounted by the reference host after schema and administrator readiness checks.

### Deployment client administration

Compose `CoreClientAdminService::new(access_admin_service, client_secret_hasher)`
and mount `client_admin_router(Arc::new(service))` in the protected management group.
The hasher is the existing host-injected `ClientSecretHasher`; the module introduces
no credential codec, dependency or environment variable. The Core service uses the
same administrative store, clock, ID generator, actor checks and audit transaction.

OIDC clients remain deployment-level configuration. Both modes require a current
management actor in domain 0 with `idp.platform/clients.manage`; tenant administrators
cannot list or edit shared clients. No business tenant is selected. Omit the tenant
header or supply exactly one value `0`; business tenant values are rejected. The
host must still authenticate management purpose/audience before injecting the context.

| Route | Contract |
| --- | --- |
| GET `/admin/clients` | Optional client_type, pkce_required, limit and cursor; returns items/has_more/next_cursor |
| GET `/admin/clients/:client_id` | Client metadata and client_secret_configured; no secret or hash |
| POST `/admin/clients/upsert` | client_id, client_name, redirect_uris, client_type, pkce_required, optional client_secret; returns client metadata and audit_id |

`client_type` is public_desktop or confidential_web. The existing PKCE and redirect
rules apply. Client IDs follow the bounded Access identifier contract; names allow
256 bytes, at most 32 redirects of 2048 bytes each, and secrets at most 4096 bytes.
The HTTP body is additionally capped at 16 KiB. Unknown fields (including hashes,
actor, tenant and login policy) are rejected. Empty or whitespace-only supplied
secrets are invalid; otherwise hashing uses exact bytes, without trimming.

A new confidential client requires a secret. For an existing confidential client,
omitted/null secret retains the current hash; a supplied secret rotates it. Public
clients reject supplied secrets, require PKCE and store no hash; converting to public
clears the previous hash. Login-entry tenant policies remain trusted host configuration.
Updating client configuration does not bulk-revoke existing user sessions. OIDC
operations continue to validate the current client configuration and credentials.

Updates hold the deployment-state write lock before reading current client state,
so metadata edits cannot restore a hash superseded by a concurrent rotation. The
client write and a bounded before/after audit commit together, with rollback on
any error. The audit contains only metadata and secret_changed, never raw/hash
material; hasher error details are also redacted. Authority is checked again after
hashing to reject a session that expires while the hasher runs. Hashing currently
holds this administrative lock; measure contention before splitting preparation
from the authoritative transaction.

Lists use client-ID keyset pagination (50 default, 200 maximum, limit+1, no total
count). Cursors bind both filters; repeat them on subsequent pages. The fresh-schema
client primary key and ordering use C collation so index order agrees with Core's
identifier ordering even for mixed-case IDs. This changes fresh initialization only,
with no migration of an existing application schema. Reads hold the existing domain
0 management lock, not the deployment-state exclusive lock. All responses disable
caching. The current reference host mounts this router after readiness checks.

### Account queries and tenant membership administration

`CoreAccessAdminService` implements `AccountAdminService`; mount
`account_admin_router(mode, Arc::new(admin_service))` in the trusted management group.
It reuses the actor, tenant target, live permission checks and audit transaction
already used for devices and sessions. No new runtime dependency, table or configuration
is needed. The reference host now mounts this router behind independent management authentication.

| Route | Scope and permission |
| --- | --- |
| GET `/admin/accounts` | Exactly one target tenant; tenant actor needs members.manage, platform actor needs users.read |
| GET `/admin/accounts/:account_id` | Same scope; an account without a membership row in that tenant returns 404 |
| GET `/admin/platform/accounts` | Deployment-wide user search; domain 0 actor with idp.platform/users.read |
| GET `/admin/platform/accounts/:account_id` | Platform-only identity projection, no tenant membership collection |
| POST `/admin/members/:account_id/status` | Enabled only; JSON status and expected_version; tenant members.manage or platform access.manage |
| POST `/admin/members/:account_id/bind` | Enabled only; JSON `{}`; platform users.bind and explicit target tenant |

The tenant routes use the existing target header: an Enabled platform actor must
name a real tenant, tenant actors cannot change domains, and Disabled reads target
0. Platform query routes accept no target header or a unique value 0. There is no
bare-user concept: platform search finds existing identities that were created
with a tenant membership; it does not issue tenantless identities or sessions.
Disabled mounts account queries but omits member binding/status routes entirely.

Lists accept status, email, created_after_unix_secs, created_before_unix_secs,
limit and cursor; tenant lists additionally accept membership_status. Account
status is pending_verification/active/disabled/closed; membership status is
active/suspended/removed. All existing membership states are included unless
filtered. A tenant projection contains only the selected membership (including its
version/join time); a platform projection has membership=null. Neither loads or
returns a password hash, registration tenant, other memberships or roles.

Email search is a literal substring with ASCII case folding; `%` and `_` are not
wildcards. Time bounds are inclusive creation-time Unix seconds. Pagination is by
account ID, defaults to 50, caps at 200 and reads limit+1 without a total count.
Cursors bind the query scope, target and all filters; repeat the same filters on
subsequent pages. There is no unbounded membership expansion. Substring search can
scan eligible rows and still needs the planned volume/latency benchmark before
claiming production search performance.

Member status changes use active/suspended/removed and the current membership
version. They cannot alter shared account status or credentials. Suspension and
removal reuse the existing atomic tenant credential cleanup; removal also removes
role bindings and unbinds devices. Other tenants' sessions remain valid. The last
non-removed membership and the last effective security administrator remain protected,
including concurrent requests. Audit or cleanup failures roll back the entire change.

Removed members rejoin only through the platform bind operation. Rejoining does not
restore old grants, device bindings or credentials. Repeating a bind for an already
active member returns that membership unchanged (including version/join time) and
records the attempt in audit. Binding a suspended member cannot silently reactivate
it; use the versioned status operation. User-wide password resets, whole-account status
changes and administrator-created identities use the separate platform security routes
described below. All mounted responses disable caching; bodies are
limited to 16 KiB and reject actor/time/credential overrides.

### Platform account security

Compose `CoreAccountSecurityService::new(access_admin_service, auth_config)` and
merge `account_security_admin_router(Arc::new(service))` with account query routes
inside the host's protected management group. The service reuses the existing
password policy/Argon2 implementation, administrative transaction, clock and IDs.
All operations require a current domain 0 management actor with
`idp.platform/users.security`; tenant administrators cannot call them. No extra
runtime dependency, credential store or environment variable is introduced.

Here a user's unified login credential means one person's password is used across
that person's tenant memberships; different users never share a password by design.
These platform operations affect the identity across tenants. A tenant membership
suspension remains a separate, tenant-scoped action.

| Route | JSON body |
| --- | --- |
| POST `/admin/platform/accounts` | Required tenant_id, email, password; optional display_name |
| POST `/admin/platform/accounts/:account_id/status` | status (active/disabled) and expected_status |
| POST `/admin/platform/accounts/:account_id/password` | new_password |

The header identifies platform scope: omit it or supply exactly one value 0.
Creation chooses its initial tenant explicitly in the body. Enabled requires a real,
active business tenant plus users.bind; Disabled requires tenant 0. Administrative
creation intentionally does not use the public registration toggle or send email:
the authorized operator is responsible for verifying the identity. It creates an
active account and exactly one active membership together, grants no role and issues
no session/token. Duplicate email returns a conflict and never attaches the existing
identity to another tenant. Use the audited member-binding operation for that case.

Activation can explicitly activate a pending-verification identity or reactivate a
disabled one; at least one non-removed membership must remain. Closed identities
cannot be reopened or have their password reset by these routes. expected_status
prevents an outdated status request from overwriting a newer state. An unchanged
status is idempotent; an actual identity-status transition or every password reset
atomically revokes all of this user's sessions/refresh families, deletes authorization
and verification codes, and revokes all selection tickets, including tickets without
a source session. Reactivation cannot restore any retired credential. Device keys,
bindings and role grants remain intact; future login must independently pass the
current account, membership, tenant and device checks.

Disabling an active identity validates every active domain where the person holds
an active protected-admin binding. Each domain must retain an effective security
administrator; a failure rolls back both the status update and all cleanup. Tenant
IDs are loaded in bounded pages of 100 and reuse the established administrator
predicate. This avoids an unbounded membership collection but still has per-domain
query cost; measure it in the planned performance acceptance.

Security writes take the deployment-state exclusive lock, then sorted actor/target
account locks; all participating authentication/member writes serialize against this
protocol. Credential cleanup, account/membership creation and secret-free audit are
one transaction. Password hashing currently occurs under that administrative lock,
with another live-actor time check after hashing. Neither input Debug nor output/audit
contains a password or hash. Resetting the operator's own password ends that operator's
current sessions too. Fresh-schema account-leading session, authorization-code and
verification-code indexes support cross-tenant cleanup; existing application schemas
are not migrated or switched by this delivery.

Successful writes return account metadata and audit_id, never credentials. Unknown
fields (including hash, actor or caller timestamps) are rejected; bodies are capped
at 16 KiB and mounted responses disable caching. Reference-host management login,
React pages and Enabled startup remain pending integration.

## Tenant management HTTP module

`tenant_management_admin_router(mode, Arc<dyn TenantAdminService>, Arc<dyn TenantCreationService>)` exposes only
Enabled tenant management. Disabled returns an empty router (404 on these paths);
Core independently rejects tenant-management queries and mutations in that mode.
Compose it behind the host's verified management-purpose/audience middleware,
which injects `AccessAdminContext`. Reads and writes require a current domain-0
platform identity and `idp.platform/tenants.manage`. A tenant administrator cannot
use these operations. The target-header rule is the same as other platform
operations: absent or one `X-Embedded-Idp-Tenant-Id: 0`; a business target or duplicate
header is rejected. The body/path names the tenant being managed, never the actor.

| Route | Contract |
| --- | --- |
| GET `/admin/tenants` | Optional tenant_id (exact), name (literal substring), status, limit, cursor |
| GET `/admin/tenants/:tenant_id` | tenant_id, name, status, allow_registration, version; 404 if absent |
| POST `/admin/tenants` | Required tenant_id, name, allow_registration, administrator (existing/new); 201 with tenant metadata and audit_id |
| PATCH `/admin/tenants/:tenant_id` | Required name, status, allow_registration, expected_version; 200 with tenant metadata and audit_id |

Only real tenants are returned, including suspended and archived records. Domain 0
is excluded and cannot be supplied as a filter, detail target or mutation target.
Status values are active/suspended/archived. Name matching ignores ASCII case and
treats percent/underscore literally. Empty, control-character and oversized filters
are rejected. All provided filters are combined. Results use bytewise ascending ID
keyset pagination (default 50/max 200), fetch limit + 1 and omit a total count.
Repeat the same filters with next_cursor; changes invalidate it. Every page checks
current actor/session/device authority and permission inside the transaction.
Literal substring search may scan eligible tenants; search indexes and lock
contention remain subject to performance acceptance.

Creation additionally requires users.bind and access.manage. Supply exactly one
administrator source: `{"kind":"existing","subject_id":"..."}` for an existing
active user, or `{"kind":"new","email":"...","password":"...","display_name":null}`
for a new account. The new path also requires users.security and uses the injected
AuthConfig password policy and existing Argon2 hashing; duplicate emails fail
without overwriting credentials or adopting the existing account. Inject
CoreAccountSecurityService (which implements TenantCreationService) as the third
router argument. New-account creation also records account.create in the same
transaction; either audit failing rolls back the account and tenant together.
Passwords and hashes are excluded from responses and audits. The tenant, membership,
protected administrator role/binding and audit commit together. Existing-user mode
retains that person's ID and credentials. Neither mode accepts caller-supplied roles
or permissions.
Updates require all listed fields; omitted fields are not interpreted as a partial
merge. Stale expected_version yields 409. Suspension/archive uses the existing
transaction to revoke tenant credentials and audit; audit failure rolls everything
back. Reactivation requires a current effective tenant administrator and does not
revive revoked credentials. There is no physical tenant-delete endpoint.

Bodies reject unknown fields and are capped at 16 KiB; responses disable caching.
These are independently mountable modules. The reference host's management login,
React UI, administrator startup composition and Enabled cutover are still pending.

## Role management HTTP module

`role_admin_router(mode, Arc<dyn RoleAdminService>)` uses the existing trusted
management context and tenant target rules. Disabled serves local roles in domain 0.
Enabled requires a real tenant: platform callers must select it explicitly with the
target header; tenant callers default to their authenticated tenant and cannot cross
it. Ordinary role routes do not manage Enabled platform-domain roles.

Reads require `idp.tenant/access.read`; business-role writes require
`idp.tenant/roles.manage`. Platform actors use `idp.platform/access.manage` for both.
Current account, tenant, membership, session, source-device authority and grants are
rechecked transactionally. Mutation authorization and audit remain in Core.

| Route | Contract |
| --- | --- |
| GET `/admin/access/roles` | limit/cursor; scoped role metadata, including disabled and protected roles |
| POST `/admin/access/roles` | key, name; creates an active business role with no permissions; 201 |
| GET `/admin/access/roles/:role_id` | Role metadata and complete configured permission keys, at one version |
| PATCH `/admin/access/roles/:role_id` | name, status (active/disabled), expected_version; all required |
| DELETE `/admin/access/roles/:role_id` | JSON expected_version; success returns role:null and audit_id |
| GET `/admin/access/roles/:role_id/permissions` | tenant_id, role_id, version, items of resource_type/action |
| PUT `/admin/access/roles/:role_id/permissions` | permissions array of resource_type/action and expected_version; complete replacement |

Role metadata includes tenant_id, role_id, key, name, status, kind and version.
List pagination uses ascending canonical role IDs, default 50/max 200, a tenant-bound
cursor and limit + 1 reads without COUNT. Lists do not expand permission sets or
query permissions per row. Detail and permission reads return a complete bounded
configuration snapshot (maximum 200 keys), not effective permissions or a paged
permission catalog. This keeps the version and editable set together; disabled
permission definitions can remain in a role's configuration. Authorization checks
continue to read current role, definition, membership and binding state.

Writes return role metadata/configuration and audit_id. Duplicate/unknown permission
keys, reserved role keys and attempts to place management permissions in a business
role are rejected. Protected administrator roles may be read but cannot be created,
modified, deleted or have their permissions replaced through these routes. Stale
versions yield 409. Empty permission replacement is valid; obsolete resource bindings
are removed atomically and do not reappear if a permission is later re-added. Role
removal also removes its bindings. Audit failure rolls back all these changes.

Bodies reject unknown fields, including role kind, caller authority and resource_id
on a permission definition. The body limit is 64 KiB to accommodate the existing
200-key contract, and responses disable caching. PostgreSQL uses the existing role
and role-permission composite keys; malformed or noncanonical role UUIDs are absent
resources. No new dependencies, tables or configuration are required.

Subject role-scope bindings and permission catalog management use the separate
adapters described below. Audited diagnostics and protected administrator
appointments and audit queries are also available below. This router does not
complete management login, React integration or the
reference-host cutover.

## Subject role binding HTTP module

`role_binding_admin_router(mode, Arc<dyn RoleAdminService>)` provides independently
mountable assignment routes. It shares the existing role service and audited Core
GrantRole/RevokeRole transactions. The host must verify management-purpose/audience
credentials and inject `AccessAdminContext`; the target tenant rules are identical
to role management. Disabled retains local assignments in domain 0, while Enabled
uses a real tenant. A platform actor must name the target; a tenant actor cannot
select another tenant.

| Route | Contract |
| --- | --- |
| GET `/admin/access/subjects/:subject_id/role-bindings` | limit/cursor; configured assignments for one tenant member |
| POST `/admin/access/subjects/:subject_id/role-bindings` | role_id, resource_type and explicit scope; 201 with binding and audit_id |
| DELETE `/admin/access/role-bindings/:binding_id` | No body required; 200 with binding:null and audit_id |

Grant bodies must specify either `"scope":{"kind":"type"}` or
`"scope":{"kind":"instance","resource_id":"report-1"}`. Missing scope, an
instance without its ID, or an ID attached to a type scope is rejected. Instance
IDs follow the existing resource-ID grammar: no empty string, slash or wildcard.
The subject comes from the path; JSON cannot override subject, tenant or actor.
Bindings apply the selected role's actions for that resource_type to the explicit
scope. Type and instance assignments can coexist; duplicate identical assignments
return 409 through the existing unique constraints.

Reads require access.read and writes require grants.manage within idp.tenant;
platform callers use idp.platform/access.manage. Actor authority is checked again
inside each transaction. Grants require an active target account/member, an active
business role in the same tenant, and current enabled business permissions for the
requested resource_type. Ordinary assignment routes cannot grant or revoke
protected administrator roles. Revocation uses the immutable binding ID and removes
only that assignment; a repeated deletion returns 404. Another remaining assignment
may still grant access to the same resource.

Lists return binding_id, tenant_id, subject_id, role_id, resource_type and explicit
scope. They require an existing target membership and remain available for suspended
members or disabled roles so administrators can inspect configured assignments.
Protected assignments are visible but cannot be changed here. The response is not
an effective-access decision: hosts must still call the authorization service and
verify business-resource ownership. IdP does not assert that a report ID exists.

Pagination uses ascending binding IDs, default 50/max 200, limit + 1 reads and no
COUNT. Cursors bind both tenant and subject. PostgreSQL uses the existing
(tenant_id, account_id, id) index; it does not expand type scopes into resource lists
or load other subjects' assignments. Grant/revoke and audit commit together; audit
failure leaves effective authorization unchanged. Request bodies are capped at
16 KiB and responses disable caching.

This completes the assignment module, not the application cutover. Management login,
React integration and the reference-host cutover remain separate work.

## Permission directory HTTP module

`permission_admin_router(mode, Arc<dyn PermissionAdminService>)` exposes the
persisted directory. The host verifies management purpose/audience and injects
`AccessAdminContext`; Core rechecks live authority in the transaction.

| Route | Contract |
| --- | --- |
| GET/POST `/admin/access/permissions` | List or create a business definition in the selected tenant |
| GET/PATCH/DELETE `/admin/access/permissions/:resource_type/:action` | Read, update description with `expected_version`, or archive with `expected_version` |
| POST `/admin/access/permissions/:resource_type/:action/enabled` | Toggle with `enabled` and `expected_enabled` |
| GET `/admin/platform/permissions` | Read platform `0` management definitions |

Enabled platform callers must send the trusted target-tenant header on access
routes. Tenant callers are limited to their own tenant; Disabled uses `0`. Reads
require `idp.tenant/access.read` or platform `idp.platform/access.manage`.
Writes require `idp.tenant/permissions.manage` or platform `access.manage`.
Responses include tenant_id, key, description, category, enabled, archived and
version. List filters and cursors are bound to the target tenant. Archival
immediately denies access, is audited and cannot be reversed or recreated with
the same key. A disabled definition may be re-enabled, which can restore existing
role grants; the UI makes that effect explicit. Definitions never enforce a
host endpoint by themselves: the host must invoke the Core access check for the
actual resource and tenant.

## Audited management permission diagnosis

`access_diagnostic_router(mode, Arc<dyn AccessDiagnosticService>)` mounts
`POST /admin/access/check` independently. It requires the same host-verified
management-purpose/audience context as other management modules. It never accepts
actor authority, tenant selection or a precomputed decision from JSON.

```json
{"subject_id":"<member-id>","resource_type":"report","action":"read","resource_id":"report-1"}
```

The target domain follows the existing management header/session rules: Enabled
tenant administrators can diagnose only their own tenant; a platform administrator
must explicitly select a real tenant. Disabled uses domain 0. The caller needs
idp.tenant/access.read or, for a platform caller, idp.platform/access.manage. A
platform caller's own permissions do not supply the target user's business grants.

Omitting resource_id or using null checks type-wide permission. An instance grant
alone cannot satisfy that query. Empty strings and wildcard IDs are invalid. The
target must have a membership in the selected domain; an absent membership returns
404 after caller authorization. Suspended/removed members can be diagnosed and
return deny, as do inactive accounts/roles/tenants, disabled or unknown permissions
and unmatched grants. The trusted host catalog, mode/category rules and PostgreSQL
grant predicate are shared with normal authorization checks.

The service locks state, involved domains and caller/target accounts in the existing
order, then checks current management authority using server time read after lock
acquisition. That same time stamps the audit. The query and audit commit in one
transaction. Both allow and deny return 200 only after successful audit insertion;
storage/audit failure returns an error without a decision. The response contains
audit_id, tenant_id, subject_id, resource_type, action, resource_id and decision
(allow/deny). The audit records access.check, caller, source category, request_id,
target and result, without credentials. Rejected management calls produce no
successful diagnostic audit; the host remains responsible for failure/security logs.

This is a point-in-time management diagnostic, not a credential or reusable grant.
It does not load all of a user's roles or expand type-wide grants into resources.
It does use management locks and writes an audit, so hosts should use the ordinary
authorization service for business traffic and enforce resource ownership/existence
there. Bodies reject unknown fields, are capped at 16 KiB, and responses disable
caching. No database migration or configuration changes are required.

## Protected administrator appointment HTTP module

`security_admin_router(mode, Arc<dyn SecurityAdminService>)` independently mounts
dedicated appointment/revocation routes. It reuses Core's SetSecurityAdmin command
and PostgreSQL transaction; it does not introduce another role mutation service.
The host must inject verified management-purpose/audience credentials through
`AccessAdminContext`.

| Route | Target |
| --- | --- |
| POST/DELETE `/admin/access/security-admins/:subject_id` | Enabled: explicitly selected real tenant; Disabled: domain 0 |
| POST/DELETE `/admin/platform/security-admins/:subject_id` | Explicit platform domain 0 in both modes |
| GET on either path | Read current target-domain administrator snapshot using the same platform access.manage authority |

GET reads `tenant_id`, `tenant_status`, `account` (with only this domain's nullable
membership), protected-role metadata and nullable `binding`. CoreAccessAdminService
implements SecurityAdminService; the snapshot is read transactionally under the
existing domain/account lock protocol and verifies live platform access.manage.
No account, membership or grant is created by reading. A platform snapshot for a
business-only user has membership:null; it does not imply platform eligibility.
This snapshot informs confirmation UI, and writes still recheck all current rules.

POST appoints and DELETE revokes. Both methods require an empty body; even `{}`
is rejected. The subject comes from the path. The target domain uses the existing
management header rules, with platform routes rejecting business-tenant headers.
Enabled platform callers must explicitly select a real tenant on the access route;
that route rejects target 0, which uses the platform route. Disabled access routes
default to 0. Request data cannot select a role, role kind, resource or grant scope.

Both routes require a currently active platform actor in domain 0 with
idp.platform/access.manage. Tenant security administrators cannot appoint or revoke
protected administrators, including within their own tenant. Core chooses
tenant_security_admin/idp.tenant for real tenants and system_admin/idp.platform for
domain 0, always with type-wide scope. Business role CRUD and grant APIs continue
to reject protected roles.

Appointment requires an existing active account and active membership in the exact
target domain, an active protected role with its complete expected permission set,
and enabled management permissions. It does not create an account or membership.
In particular, platform appointment in Enabled mode does not promote a business
membership into domain 0; establishing an eligible platform identity remains a
separate privileged provisioning concern. Initial offline bootstrap and management
login composition are not implemented by this router.

Success returns 201 for appointment or 200 for revocation, with audit_id and binding
(null after revocation), using the same binding projection as role assignments.
Repeating an existing appointment or revoking an absent assignment returns 409.
Revocation removes only the protected assignment; it does not remove membership,
business roles or login sessions. Management requests recheck live grants, so a
still-active session immediately loses the removed authority.

Core preserves the last effective system administrator and, for active real tenants,
the last effective tenant administrator. These checks and audit insertion occur in
the same transaction under the existing domain/account locks, including concurrent
revocations. Platform cleanup in inactive tenants follows existing Core rules; it
does not permit new appointments there. Audit failure rolls back the assignment.
Bodies are capped at 16 KiB before rejection and responses disable caching. No new
tables, dependencies or configuration are needed. The React management entry now
provides snapshot-based appointment/revocation confirmations; reference-host cutover
and privileged provisioning of additional Enabled platform identities remain separate work.

## Audit query HTTP module

`audit_admin_router(mode, Arc<dyn AuditAdminService>)` independently mounts audit
reads behind host-verified management-purpose/audience authentication. Every page
and detail request rechecks current identity, session and audit authority inside
the existing management transaction.

| Route | Contract |
| --- | --- |
| GET `/admin/access/audit-events` | Metadata for exactly the selected management domain |
| GET `/admin/access/audit-events/:id` | Stored change detail in that same domain |
| GET `/admin/platform/audit-events` | Metadata for target domain 0 only |
| GET `/admin/platform/audit-events/:id` | Stored change detail for target domain 0 only |

Enabled tenant administrators can read only their own domain and require
idp.tenant/audit.read. Platform callers require idp.platform/audit.read; access.manage
does not substitute for it. Platform callers explicitly select a real target tenant
on access routes. Platform routes reject business-tenant headers and never aggregate
other tenants. Disabled access routes use domain 0, the same domain as the explicit
platform routes. An ID from another domain returns 404 within an authorized target
query, without exposing that record. Tenant administrators cannot read platform
records or select another tenant. Existing management read rules allow authorized
platform callers to inspect an inactive tenant's history.

List filters are exact actor_id and operation, plus inclusive
occurred_after_unix_secs/occurred_before_unix_secs. Times must be nonnegative whole
seconds within the storage range and the lower bound cannot exceed the upper one.
Pagination defaults to 50 and caps at 200. It orders ascending by (occurred_at, id),
so records with the same second are paginated by UUID without omission. Cursors bind
target domain and every filter; changing a filter requires starting a new query.
They are positions, not credentials or snapshots across concurrent inserts. An
authorized caller must repeat the current filters with next_cursor.

Responses contain items, has_more and next_cursor. Each metadata item contains
audit_id, occurred_at_unix_secs, actor_id, actor_domain, actor_session_id,
authentication_source, target_domain, operation and request_id. Offline bootstrap
records have a null actor_session_id. Lists do not fetch change_json. Detail returns
the same metadata plus change, decoded from the existing secret-free projection
written at the time of the action. Current role/account changes do not rewrite the
historical snapshot. Passwords, tokens, secrets and device proofs are excluded by
the audit write projections; the read adapter does not serialize current domain or
credential models. Invalid stored JSON projections fail rather than returning an
untyped string as a successful detail.

PostgreSQL reuses the (target_domain, occurred_at_epoch, id) index and limit + 1;
there is no COUNT or per-row detail lookup. Actor/operation filters are additional
predicates within the selected domain/time range. Reads still use the existing
management locks; throughput and contention require separate measurement. Reading
an audit does not recursively append an audit event. Responses disable caching and
list queries reject unknown fields. No schema, index, dependency or configuration
changes are required. Management login, React pages and host cutover remain pending.

## Offline administrator command

After explicitly preparing a fresh Access schema, the reference host can create
its first platform administrator without starting the HTTP server:

```bash
./scripts/dev_env.sh enabled db-init
./scripts/dev_env.sh enabled bootstrap-admin --email admin@example.test --password-stdin < /path/to/private/admin-password
```

Use disabled in both commands for the non-tenant profile. Replace the example email
with the selected administrator identity. The input file must already contain the
chosen password and should be private (0600); a trusted secret provider may supply
the same stdin stream. Do not put the password in an argument, environment variable
or shell literal. No administrator credentials are added to `.env` or its templates.

The wrapper loads the existing common + mode configuration and validates the
canonical development schema. It builds Web assets with stdin disconnected before
passing the password stream to `embedded-idp-app bootstrap-admin`. The direct binary
accepts `--email`, mandatory `--password-stdin` and optional `--display-name`; use
`bootstrap-admin --help` for usage. It requires explicit tenancy mode, database URI
and schema environment values, reusing the host's existing database/TLS/pool and
AuthConfig parsing. Terminal stdin is refused to avoid echoed input. Input is a
single UTF-8 line bounded at 16 KiB; one trailing LF/CRLF is removed, password spaces
are preserved, and additional control characters/lines are rejected.

The command does not create schema tables, seed clients, issue sessions/tokens,
send email or listen on a port. It requires the prepared schema and matching
persisted mode. Email and password validation precede the bootstrap transaction;
the selected identity becomes active through this trusted offline operation.
Account, domain 0 membership, protected platform role, assignment, audit and marker
commit together. Success reports initialized or already initialized. A repeat with
valid input verifies the existing effective administrator and leaves its identity,
password and audit unchanged, even if different input was supplied. It is not a
password reset or damaged-state repair tool. Failures expose no password/hash or
database connection URI.

This command is separate from online host configuration and supports both modes.
Online startup now requires the prepared schema, completed bootstrap, an effective
administrator and a valid signing key. Explicit live tests cover this CLI and the
actual reference process, using synthetic credentials and per-test random schemas.


### Independent management authentication

`CoreManagementAuthenticationService` implements `ManagementAuthenticationService`
separately from the business `TenantAuthenticationService`. It accepts the same
injected IdP store, clock, ID generator, refresh generator/digester and typed
`AuthConfig` / `TenantLoginEntry`. Use a dedicated management client/entry and
`Rs256JwtService::new_management` with a dedicated audience. Custom token adapters
must verify purpose and audience before returning `ValidatedAccessToken.purpose`;
request headers/body cannot supply that field. A management OAuth scope is not an
RBAC grant.

A trusted Fixed `0` entry authenticates platform members in either tenancy mode.
Only the management constructor permits this under Enabled. Fixed real tenants
and ChooseAfterAuthentication retain ordinary business-tenant restrictions;
selection never includes `0`. Disabled still accepts only Fixed `0`. No client ID,
mode, purpose or login strategy is selected by the password request.

The service provides login, tenant listing/selection, begin_switch, rotate_refresh,
logout, and `authenticate(token, request_id)`. The last method constructs
`AccessAdminContext` with the verified actor/session and the fixed authentication
source `management_access`. The request ID must be a valid host-generated ID.
Hosts must not inject the context before authentication. A successful login is
not proof of administrator authority: existing admin services recheck permissions
and current actor state in each management transaction.

Both session persistence and token validation bind the purpose. RS256 management
access tokens use `token_use=management_access`; business services accept `access`
only, even when signing keys are shared. `auth_sessions.purpose` is constrained to
business/management (default business), and PostgreSQL admin checks require a
management actor session. Refresh/selection credentials from the wrong purpose
cannot rotate, consume or revoke another entry's session. Management logout
revokes only its current session and refresh family; a switch ticket whose source
session was logged out also fails validation.

This reuses existing tables, row locks and indexed lookups; it does not copy the
business authentication state machine or load roles on every login. The fresh
`tenant_v2` layout now requires `auth_session_purpose`; readiness rejects incomplete
layouts instead of migrating them. No environment variables or application data
were added by this module change.

The initial management service supports bearer sessions only and rejects
`require_device_proof=true` at construction. Do not substitute the existing
business device login to manufacture a management context. Independent management
HTTP composition is available below. Device-proof management, React login and
reference-host composition remain to be integrated. Cookie hosts must retain CSRF protection;
this module does not create cookies or mount any route by itself.


### Management HTTP login and authenticated route composition

`embedded_idp_axum::management_router(authentication, admin_routes)` wraps the
already assembled management APIs with bearer authentication, then adds the
independent `/admin/auth/*` endpoints. It accepts an injected
`Arc<dyn ManagementAuthenticationService>` and an Axum `Router`; it does not load
environment variables or open a database connection itself. Business routers are
merged separately. Build all protected routes before calling this function: routes
merged afterward are not automatically protected. An empty protected router is
allowed for a login-only surface. The host owns the outer URL prefix.

```rust,ignore
let protected = role_admin_router(mode, admin.clone())
    .merge(tenant_management_admin_router(mode, admin.clone(), account_security.clone()));
// Merge the other required admin modules into `protected` in the same way.
let management = management_router(management_auth, protected);
let app = Router::new().nest("/idp", management);
```

| Method / module-local path | Credential and behavior |
| --- | --- |
| GET /admin/auth/capabilities | Public; tenancy flag, fixed/choose policy, optional fixed tenant and paging limits |
| POST /admin/auth/login | JSON email/password only; session + tokens or short-lived tenant-selection ticket |
| GET /admin/auth/session | Management Bearer; current actor tenant/account/session IDs |
| POST /admin/auth/refresh | JSON refresh_token only; rotates the management session family |
| POST /admin/auth/logout | Management Bearer; revokes current session/family, returns 204 |
| GET /admin/auth/tenant-selection/tenants | TenantSelection ticket; bounded limit/cursor pagination |
| POST /admin/auth/tenant-selection/complete | TenantSelection ticket + JSON tenant_id; creates the selected management session |
| POST /admin/auth/me/tenant-selection | Management Bearer; creates a selection ticket bound to this source session |

The last three routes exist only when the service is Enabled with
ChooseAfterAuthentication. Disabled and Fixed policies return 404. Authentication
routes reject `X-Embedded-Idp-Tenant-Id`; the entry, verified credential or selection
body determines the authentication domain. This header remains available for the
protected management APIs as their explicit target, preserving platform cross-domain
checks without changing the actor's domain.

Protected requests require exactly one Bearer Authorization value. Scheme matching
is case-insensitive; duplicates, combined values and whitespace inside credentials
are rejected. The shared bearer parser applies this rule to its business callers
as well. Cookies, API keys, development subject headers and prefilled context do
not replace authentication. The middleware overwrites any prior AccessAdminContext
with the freshly verified one. Existing management services still enforce live
permissions and current actor/session/member state in their operation transaction.

A new server-generated request ID is passed to Core and returned as `X-Request-Id`
on responses from authenticated protected routes, including permission denials.
Caller-supplied request IDs are not used as audit IDs; successful management writes
persist the generated request ID in their existing audit record. The response
header correlates with that record; no new audit endpoint or table is needed.

Authentication JSON is capped at 16 KiB and rejects unknown/duplicate fields.
All composed responses, including validation and authentication failures, are
no-store/no-cache. Errors reuse the existing sanitized mapping. Refresh reuse
returns 401 with `refresh_token_reuse_detected` only after Core has committed
revocation. Blocking Core/Postgres calls run off the async executor. This adds no
cookies or permissive CORS; hosts retain transport, rate-limit and browser security
policies. Device-bound management is still not supported by this bearer service.

This independently mountable module is exercised with real RS256 and PostgreSQL.
The reference host now uses it in both modes, behind startup/readiness validation.

## Optional browser Cookie adapter (2026-09-26)

`BrowserSessionService` is implemented by the business Core authentication service and the independent management Core service. `browser_session_router(service, BrowserSessionHttpConfig::new(origin, cookie_name, external_cookie_path, purpose)?)` merges additional routes without replacing explicit-token or proof routes. Compose it beside `management_router`, not inside its protected admin routes. The configuration validates the origin, external path and service purpose. The adapter owns Cookie and CSRF handling; Core remains independent of HTTP and storage schema changes are not required.

Full requests, expiry/rotation/logout semantics, multi-tenant rules and React coordination are specified in [browser session design](browser-session-design.md). Statements above that the original adapters do not create cookies still apply to those adapters. Only the new opt-in browser routes read/write refresh cookies.

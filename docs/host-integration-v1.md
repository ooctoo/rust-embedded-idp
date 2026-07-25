# Host Integration v1

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

## Minimal Composition Pattern

1. Build `PgStorageConfig` in the host from env or secret store.
2. Construct `PostgresStorageAdapter`.
3. Apply migrations during host bootstrap.
4. Construct:
   - `CoreAdminService`
   - `CoreAuthService`
   - `CoreDeviceService`
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
        .insert(AuthenticatedSubject::new("acct-host-user-1"));
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

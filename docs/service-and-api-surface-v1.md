# Service and API Surface v1

## Purpose

This document defines the host-facing capability surface for `rust-embedded-idp`.

It separates:

- `core` service contracts consumed by the host or HTTP adapters
- fixed `axum` HTTP endpoints exposed by the module
- deferred interfaces that are planned but not part of the current implemented surface

## Layer Mapping

- `embedded-idp-core`: owns service traits, commands, results, validation, and business logic
- `embedded-idp-axum`: owns fixed paths, request and response DTOs, and handler wiring

`embedded-idp-storage-postgres` remains an infrastructure adapter and is not part of the public API surface.

## Current Implemented Surface

### Core Service Contracts

#### `AuthService`

- `register_account(RegisterAccountCommand) -> RegisterAccountResult`
- `login(LoginCommand) -> LoginResult`
- `rotate_refresh_token(RotateRefreshTokenCommand) -> RotateRefreshTokenResult`
- `logout(LogoutSessionCommand) -> LogoutSessionResult`

Command shape:

- `RegisterAccountCommand`
  - `email`
  - `password`
  - `display_name`
  - `client_id`
  - `device_id`
- `LoginCommand`
  - `email`
  - `password`
  - `client_id`
  - `device_id`

Password rule:

- callers send plaintext `password`
- `embedded-idp-core` hashes and verifies passwords internally before storage comparison
- persistent storage still uses the `password_hash` field on the `Account` model and database row
- registration applies `AuthConfig.password_min_length` and `AuthConfig.password_max_length`
- current recommended defaults are `8` and `128`

- `RotateRefreshTokenCommand`
  - `refresh_token`
  - `rotated_at`
- `LogoutSessionCommand`
  - `refresh_token`
  - `logged_out_at`

#### `DeviceService`

- `provision_device(ProvisionDeviceCommand) -> ProvisionDeviceResult`
- `complete_device_registration(CompleteDeviceRegistrationCommand) -> CompleteDeviceRegistrationResult`
- `bind_device_to_account(BindDeviceToAccountCommand) -> BindDeviceToAccountResult`
- `get_device(GetDeviceCommand) -> GetDeviceResult`
- `list_devices(ListDevicesCommand) -> ListDevicesResult`
- `unbind_device_from_account(UnbindDeviceFromAccountCommand) -> UnbindDeviceFromAccountResult`
- `disable_device(DisableDeviceCommand) -> DisableDeviceResult`
- `revoke_device(RevokeDeviceCommand) -> RevokeDeviceResult`
- `heartbeat(DeviceHeartbeatCommand) -> DeviceHeartbeatResult`

Command shape:

- `ProvisionDeviceCommand`
  - `client_id`
  - `device_name`
  - `requested_at`
- `CompleteDeviceRegistrationCommand`
  - `device_id`
  - `proof`
  - `completed_at`
- `BindDeviceToAccountCommand`
  - `account_id`
  - `device_id`
  - `bound_at`
- `GetDeviceCommand`
  - `device_id`
- `ListDevicesCommand`
  - `account_id`
  - `client_id`
  - `status`
  - `registered_after`
  - `registered_before`
  - `cursor`
  - `page.limit`
  - `page.offset`
- `UnbindDeviceFromAccountCommand`
  - `account_id`
  - `device_id`
  - `unbound_at`
- `DisableDeviceCommand`
  - `device_id`
- `RevokeDeviceCommand`
  - `device_id`
- `DeviceHeartbeatCommand`
  - `device_id`
  - `observed_at`

#### `AdminService`

- `list_accounts(ListAccountsCommand) -> ListAccountsResult`
- `get_account(GetAccountCommand) -> GetAccountResult`
- `activate_account(ActivateAccountCommand) -> ActivateAccountResult`
- `disable_account(DisableAccountCommand) -> DisableAccountResult`
- `set_account_password(SetAccountPasswordCommand) -> SetAccountPasswordResult`
- `revoke_account_sessions(RevokeAccountSessionsCommand) -> RevokeAccountSessionsResult`
- `list_sessions(ListSessionsCommand) -> ListSessionsResult`
- `get_session(GetSessionCommand) -> GetSessionResult`
- `revoke_session(RevokeSessionCommand) -> RevokeSessionResult`
- `list_clients(ListClientsCommand) -> ListClientsResult`
- `get_client(GetClientCommand) -> GetClientResult`
- `upsert_client(UpsertClientCommand) -> UpsertClientResult`

Command shape:

- `ListAccountsCommand`
  - `status`
  - `email`
  - `created_after`
  - `created_before`
  - `cursor`
  - `page.limit`
  - `page.offset`
- `GetAccountCommand`
  - `account_id`
- `ActivateAccountCommand`
  - `account_id`
- `DisableAccountCommand`
  - `account_id`
- `SetAccountPasswordCommand`
  - `account_id`
  - `new_password`
- `RevokeAccountSessionsCommand`
  - `account_id`
  - `revoked_at`
- `ListSessionsCommand`
  - `account_id`
  - `status`
  - `client_id`
  - `device_id`
  - `created_after`
  - `created_before`
  - `cursor`
  - `page.limit`
  - `page.offset`
- `GetSessionCommand`
  - `session_id`
- `RevokeSessionCommand`
  - `session_id`
  - `revoked_at`
- `ListClientsCommand`
  - `client_type`
  - `pkce_required`
  - `page.limit`
  - `page.offset`
- `GetClientCommand`
  - `client_id`
- `UpsertClientCommand`
  - `client_id`
  - `client_name`
  - `redirect_uris`
  - `client_type`
  - `pkce_required`
  - `client_secret`

Confidential client secret rule:

- callers submit plaintext `client_secret` when provisioning or authenticating a confidential client
- the module owns confidential client authentication logic in core
- when composed with `PhcClientSecretCodec`, the module hashes secrets to Argon2id PHC strings for storage and verifies against the same format later

List pagination rule:

- admin list results now carry `page.limit`, `page.offset`, `page.returned`, `page.total`, `page.has_more`, and optional `page.next_cursor`
- `has_more = true` means the module observed at least one additional row past the requested page window
- `page.next_cursor` is only emitted for cursor-enabled lists and only when `has_more = true`
- current cursor-enabled lists are `accounts`, `sessions`, and `devices`
- cursor format is `unix_secs:id`
- `cursor` cannot be combined with a non-zero `offset`

#### `OidcAuthorizationService`

- `start_authorization(StartAuthorizationCommand) -> StartAuthorizationResult`
- `exchange_authorization_code(ExchangeAuthorizationCodeCommand) -> ExchangeAuthorizationCodeResult`

Command shape:

- `StartAuthorizationCommand`
  - `subject_account_id`
  - `response_type`
  - `client_id`
  - `redirect_uri`
  - `scope`
  - `state`
  - `code_challenge`
  - `code_challenge_method`
  - `nonce`
- `ExchangeAuthorizationCodeCommand`
  - `grant_type`
  - `code`
  - `redirect_uri`
  - `client_id`
  - `client_secret`
  - `code_verifier`

#### `OidcMetadataService`

- `jwks_document() -> JwksDocument`

#### `TokenManagementService`

- `revoke_token(RevokeTokenCommand) -> RevokeTokenResult`

Command shape:

- `RevokeTokenCommand`
  - `token`
  - `token_type_hint`
  - `client_id`
  - `client_secret`
  - `revoked_at`

#### `UserInfoService`

- `get_user_info(GetUserInfoCommand) -> GetUserInfoResult`

Command shape:

- `GetUserInfoCommand`
  - `access_token`
  - `observed_at`

#### `TokenIntrospectionService`

- `introspect_token(IntrospectTokenCommand) -> IntrospectTokenResult`

Command shape:

- `IntrospectTokenCommand`
  - `token`
  - `token_type_hint`
  - `client_id`
  - `client_secret`
  - `observed_at`

### Current HTTP Endpoints

Access control rule:

- `embedded-idp-axum` does not impose host-wide authorization policy by itself
- the module validates protocol and domain rules, but the host must decide which middleware or network boundary protects each route group
- route grouping exposed by `embedded-idp-axum` is:
  - `public_router()`
  - `subject_router()`
  - `token_router()`
  - `client_authenticated_router()`
  - `admin_router()`
  - `router()` as the full union

Access class meanings:

- `public`: no host subject middleware required by default; route behavior is still constrained by protocol inputs handled by the module
- `subject_bound`: host must inject a trusted authenticated subject or otherwise ensure the caller is acting only on its own account scope
- `token_bound`: route is driven by possession of a protocol token, such as a bearer access token or refresh token
- `client_authenticated`: route is driven by OAuth client authentication, such as confidential client secret verification
- `admin_only`: host should only expose behind operator or privileged management controls

#### Auth

- `POST /auth/register`
  - maps to `AuthService::register_account`
  - `access_class = public`
  - request may include optional `device_id`; when present the module validates the device and auto-links the new session
- `POST /auth/login`
  - maps to `AuthService::login`
  - `access_class = public`
  - request may include optional `device_id`; when present the module validates the device and auto-links the session
- `POST /auth/refresh`
  - maps to `AuthService::rotate_refresh_token`
  - `access_class = token_bound`
  - rotation is driven by submitted `refresh_token`, not client-supplied `session_id`
- `POST /auth/logout`
  - maps to `AuthService::logout`
  - `access_class = token_bound`
  - logout is driven by submitted `refresh_token`, not client-supplied `session_id`

#### Device

- `POST /devices/provision`
  - maps to `DeviceService::provision_device`
  - `access_class = public`
- `POST /devices/complete`
  - maps to `DeviceService::complete_device_registration`
  - `access_class = public`
- `POST /devices/bind`
  - maps to `DeviceService::bind_device_to_account`
  - `access_class = subject_bound`
  - subject account comes from trusted host context, not request body `account_id`
- `GET /devices`
  - maps to `DeviceService::list_devices`
  - `access_class = subject_bound`
  - account scope is derived from trusted subject context
- `GET /devices/:device_id`
  - maps to `DeviceService::get_device`
  - `access_class = subject_bound`
  - response is filtered to active bindings owned by the trusted subject account
- `POST /devices/unbind`
  - maps to `DeviceService::unbind_device_from_account`
  - `access_class = subject_bound`
  - subject account comes from trusted host context, not request body `account_id`
- `POST /devices/heartbeat`
  - maps to `DeviceService::heartbeat`
  - `access_class = public`

#### Admin

The paths below are module-local `embedded-idp-axum` admin routes.
When these routes are exposed through the standalone `embedded-idp-app`, the external path prefix becomes `/api`, so `/admin/accounts` is served as `/api/admin/accounts`.

- `GET /admin/accounts`
  - maps to `AdminService::list_accounts`
  - `access_class = admin_only`
  - supports query params:
    - `status`
    - `email`
    - `created_after_unix_secs`
    - `created_before_unix_secs`
    - `cursor`
    - `limit`
    - `offset`
- `GET /admin/accounts/:account_id`
  - maps to `AdminService::get_account`
  - `access_class = admin_only`
- `POST /admin/accounts/activate`
  - maps to `AdminService::activate_account`
  - `access_class = admin_only`
- `POST /admin/accounts/disable`
  - maps to `AdminService::disable_account`
  - `access_class = admin_only`
- `POST /admin/accounts/set-password`
  - maps to `AdminService::set_account_password`
  - `access_class = admin_only`
- `POST /admin/accounts/revoke-sessions`
  - maps to `AdminService::revoke_account_sessions`
  - `access_class = admin_only`
- `GET /admin/sessions`
  - maps to `AdminService::list_sessions`
  - `access_class = admin_only`
  - supports query params:
    - `account_id`
    - `status`
    - `client_id`
    - `device_id`
    - `created_after_unix_secs`
    - `created_before_unix_secs`
    - `cursor`
    - `limit`
    - `offset`
- `GET /admin/sessions/:session_id`
  - maps to `AdminService::get_session`
  - `access_class = admin_only`
- `POST /admin/sessions/revoke`
  - maps to `AdminService::revoke_session`
  - `access_class = admin_only`
- `GET /admin/clients`
  - maps to `AdminService::list_clients`
  - `access_class = admin_only`
  - supports query params:
    - `client_type`
    - `pkce_required`
    - `limit`
    - `offset`
- `GET /admin/clients/:client_id`
  - maps to `AdminService::get_client`
  - `access_class = admin_only`
- `POST /admin/clients/upsert`
  - maps to `AdminService::upsert_client`
  - `access_class = admin_only`
- `GET /admin/devices`
  - maps to `DeviceService::list_devices` with unrestricted account scope
  - `access_class = admin_only`
  - supports query params:
    - `account_id`
    - `client_id`
    - `status`
    - `registered_after_unix_secs`
    - `registered_before_unix_secs`
    - `cursor`
    - `limit`
    - `offset`
- `GET /admin/devices/:device_id`
  - maps to `DeviceService::get_device`
  - `access_class = admin_only`
- `POST /admin/devices/unbind`
  - maps to `DeviceService::unbind_device_from_account`
  - `access_class = admin_only`
- `POST /admin/devices/disable`
  - maps to `DeviceService::disable_device`
  - `access_class = admin_only`
- `POST /admin/devices/revoke`
  - maps to `DeviceService::revoke_device`
  - `access_class = admin_only`

#### OIDC Discovery

- `GET /.well-known/openid-configuration`
  - returns issuer and public, subject-bound, token-bound, and client-authenticated endpoint references
  - does not advertise admin-only device disable or revoke routes
  - `access_class = public`

#### OIDC

- `GET /oidc/authorize`
  - maps to `OidcAuthorizationService::start_authorization`
  - `access_class = subject_bound`
- `POST /oidc/token`
  - maps to `OidcAuthorizationService::exchange_authorization_code`
  - `access_class = public`
- `GET /oidc/jwks.json`
  - maps to `OidcMetadataService::jwks_document`
  - `access_class = public`
- `POST /oidc/revoke`
  - maps to `TokenManagementService::revoke_token`
  - `access_class = client_authenticated`
- `GET /oidc/userinfo`
  - maps to `UserInfoService::get_user_info`
  - `access_class = token_bound`
- `POST /oidc/userinfo`
  - same as `GET /oidc/userinfo`, using bearer token in `Authorization`
  - `access_class = token_bound`
- `POST /oidc/introspect`
  - maps to `TokenIntrospectionService::introspect_token`
  - `access_class = client_authenticated`

Current status:

- authorization code persistence is implemented
- refresh token persistence is implemented for rotation and revocation
- PKCE validation for `plain` and `S256` is implemented
- `/oidc/token` now performs real authorization code exchange
- `/oidc/jwks.json` can be backed by `StaticOidcMetadataService`
- `/oidc/revoke` now revokes persisted refresh tokens and the associated session
- `/oidc/userinfo` now depends on a host-provided access token validator through core composition
- `/oidc/introspect` supports refresh-token lookup and host-validated access-token introspection
- confidential client secret validation is implemented in core through an injected `ClientSecretVerifier`
- `PhcClientSecretCodec` is the default module-owned Argon2id PHC implementation for both hashing and verification
- `/auth/logout` now revokes the session and refresh token lineage by session id
- `/oidc/authorize` currently expects the host to inject `AuthenticatedSubject` request context through host integration
- device registration is modeled as `device + binding`, not direct permanent device ownership by one account
- the canonical device flow is `provision -> complete`, with later explicit bind or auth-time auto-bind via optional `device_id`
- device management now includes query, unbind, disable, and revoke operations
- session-to-device linkage is optional and only appears when auth flows are given `device_id`
- broader admin APIs now cover account, session, client, and device operator workflows through `AdminService` and `/admin/...`

## Path Versioning Convention

The module uses module-local roots:

- `/auth/...`
- `/devices/...`
- `/admin/...`

Reason:

- the module should be embeddable under different host routing schemes
- the host may choose whether to expose the module at root or nest it under a product-specific prefix
- keeping auth, device, and admin paths prefixless inside the module avoids baking one host-wide versioning policy into the shared adapter

Standalone host note:

- `embedded-idp-app` currently serves admin APIs under `/api/admin/...`
- `embedded-idp-app` currently serves the admin UI at `/` by default
- `embedded-idp-app` currently serves admin static assets under `<admin-ui-base-path>/static/*`

If a host wants `/api/v1`, `/idp`, or another top-level prefix, it should define that at mount time rather than through module-owned path constants.

## Planned Surface

The module should evolve in phases.

### Phase 1

Phase 1 is the currently implemented bootstrap surface:

- account registration
- password login
- refresh token rotation
- account-bound device registration
- unbound device provisioning and completion
- explicit device binding
- device heartbeat
- device query and management
- basic discovery endpoint

This phase is sufficient for host-local account bootstrap, device enrollment, shared-device binding flows, and basic device lifecycle management.

### Phase 2

Phase 2 should harden the minimum standard OIDC provider surface that is now mounted as a skeleton.

#### Current OIDC Hardening Gap

The remaining OIDC gap is mainly around broader production hardening and host rollout policy, not client-auth validation itself.

Rationale:

- `AuthService` should remain focused on local account and session flows
- OIDC browser and client-facing flows have different contracts and error semantics
- resource endpoints should validate host-defined access tokens without hardcoding token format inside the module
- confidential client authentication should be enforced in core
- client creation and secret bootstrap can stay in trusted host-side flows or be exposed through trusted admin APIs
- metadata and key publication should stay read-oriented and separately testable

### Phase 3

Operational management APIs can follow after OIDC basics are stable.

Potential additions:

- session revoke or logout endpoints
- device disable or rotate endpoints
- account disable flows
- richer client management endpoints intended for trusted host-side administration only

## Explicit Non-Surface for Now

The following are intentionally out of scope for the current module surface:

- SAML endpoints
- social login endpoints
- organization or tenant admin APIs
- standalone IAM console APIs
- generic storage-provider selection APIs inside core business logic

## Stability Rules

- `embedded-idp-core` service traits are the canonical business capability contracts
- `embedded-idp-axum` handlers should remain thin adapters over those service traits
- module-local HTTP path constants should remain owned by `embedded-idp-axum`
- new HTTP endpoints should not be added without a corresponding service contract in `core`
- storage adapters must satisfy store traits and must not become alternate business entrypoints

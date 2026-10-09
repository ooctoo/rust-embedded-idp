# Changelog

## 3.0.0 — 2026-10-09

### Device scan login milestone

- Added both device-display and phone-display scan login. An authenticated business user explicitly confirms the exact registered target device; same-client and directional cross-client authorization require an explicit source-client allowlist. Hosts inject business admission and target presentation without adding factory/workstation/business ownership to IDP models.
- A successful authorization creates one Pending personnel-device session. Host release and device ACK activate it; exchange/recovery retries return the same protected initial result. Device proofs bind the actual mounted path, request bytes, tenant, entry and action through `EMBEDDED-IDP-DEVICE-SCAN-V2`. The existing device request profile remains unchanged.
- Added `close_origin` to conclusively end an uncertain original create/claim operation, including one not yet visible. Durable scoped closure records reject late submissions permanently. `scan_not_found` is nonterminal; lookup requires explicit `origin_action` to report a conclusive closure. Already activated sessions use normal logout.
- Fixed Pending-session compensation to persist the valid `client_revocation` refresh reason, so session, refresh and delivery-secret revocation commit atomically.
- Added strictly gated private-network HTTP development login across Rust, Web SDKs and the reference host. Feature + debug assertions + trusted explicit policy permit canonical RFC1918 IPv4 HTTP. Browser-only lifetime defaults to 900 seconds (60–3600 configurable), with restore/refresh disabled and expected identity checks. Device-session lifetimes and delivery-recovery windows are unaffected.
- Server-derived Web mode configuration and cryptographic UUID fallback support real insecure contexts. Default HTTPS/loopback Cookie coordination remains available. Browser camera restrictions still require HTTPS or native scanning.

### Device lifecycle and host contracts (breaking)

- Registration now requires a host-approved canonical device UUID, stable registration request UUID, pinned public key and trusted admission scope. Version-guarded device/binding mutations, exact unbind, scoped operation receipts, key metadata and identity audit support response-loss recovery. Enabling a device does not restore old sessions, credentials or challenges.
- Management clients display device/key versions, reason metadata and precise bindings. Uncertain writes retain their original operation ID and reload current details; registration records and raw receipts are not exposed by that page.
- Added strict `authenticate_device` returning validated tenant/person/session/device identity, and the separate device-only `verify_device_transport_request` capability for `client_sync_transport`. Ordinary browser authentication stays device-optional; device-only verification grants no personnel or business authority.
- Custom scan services/stores implement the new contracts, including `close_origin` and durable closure queries/writes. Rust `LookupDeviceScan` constructors include `origin_action`. Hosts must check Active session state in addition to token cryptography; Pending tokens are unusable.
- Rust workspace, internal path dependencies, the reference example and local Web packages are versioned 3.0.0. This major version includes the previously unreleased lifecycle DTO/schema changes since 2.0.0; it is not an automatic compatibility upgrade.

### Upgrade and acceptance

- Current Access storage is `tenant_v6` in both tenancy modes. From released 2.0.0 (`tenant_v3`), stop all writers and follow **v3 → v4 → v5 → v6**; v4/v5 installations start at their respective step, v6 needs no migration, and new schemas initialize v6. Each migration defaults to dry-run and applies in a separate transaction. Startup never migrates. See the consolidated [upgrade procedure](docs/device-scan-login-upgrade.md).
- Preserve encrypted-result keys until all protected presentations and recoverable results have expired and been cleaned; retain durable origin-closure denial records. Historical migration scripts target their own step and cannot be replayed against v6. There is no downgrade by changing the version marker or deleting tables.
- Pin matching Rust and Web artifacts by version, source commit and SHA-256. Source defaults keep scan login disabled; enable it only after admission, presentation, proof purposes, cleanup and secure result-key configuration are installed.
- Core/HTTP/storage, isolated PostgreSQL, default/feature/Release gates and real private-HTTP browser flows have been validated. Physical phones/scanners, host target platforms, real HTTPS proxy deployment and production capacity remain deployment acceptance work. Evidence is recorded in [scan validation](docs/device-scan-login-validation.md) and [development HTTP validation](docs/development-private-http-validation.md).

## 2.0.0 — 2026-09-27

### Business-scoped authorization (breaking)

- Business permissions, roles, bindings, queries and cursors now carry explicit `business_id` within each tenant. The reserved `idp` namespace contains only built-in management authorization. No implicit default business or cross-business fallback is accepted.
- Added one `business_admin` role per tenant/business, with a caller-defined display name. An explicit business-scoped user binding grants all registered, enabled, unarchived permissions in that business, including future permissions. This does not grant IdP management access.
- Protected role keys become `idp_system_admin` and `idp_tenant_security_admin`; kinds remain unchanged. Default names become IDP管理员 and IDP租户管理员.
- Access storage moves to `tenant_v3`. Existing v2 deployments require an offline, explicit mapping migration; startup never migrates data or elevates existing users. See the [migration design](docs/business-domain-authorization-design-v1.md#10-tenant_v2--tenant_v3-显式迁移) and `scripts/migrate_business_scope.sql`.
- Management role, permission and binding lists accept an optional `X-Embedded-IdP-Business-Id` filter; omission lists all permitted records in the target tenant. Detail, creation, mutation and diagnostic requests require an exact business header. `/auth/me/roles` requires the `business_id` query parameter. Business role assignments use `scope.kind=business` without resource fields; ordinary assignments retain type/instance scope.
- Rust workspace and embedded React package move to 2.0.0. Affected management cursors move to v3 and self/role-permission cursors to v2. Restart pagination when changing the business filter; unaffected lists retain their version.

### Earlier changes included in this release

- Added optional same-origin browser login, restore, refresh and logout with HttpOnly refresh cookies, separate business/management purposes and expected-session checks. Explicit-token and device-proof routes remain available; the browser-session changes alone require no schema migration.
- React clients support opt-in Cookie restoration and serialized cross-tab session changes. This release permits one current business tenant per browser entry, while Core continues to support independent tenant sessions. The reference management page and no-tenant host use Cookie mode.

- Management lists support `sort_order=asc|desc`, defaulting to newest-first time/ID pagination, including permission catalogs embedded in host applications. Tenant members use join time; devices use registration time; audit uses event time.
- Unaffected management cursors remain v2 and bind the chosen direction; changing direction requires a fresh first page. Existing v2 cursors without a direction remain descending; v1 management cursors must restart. Rust `AccessPageRequest` and `AccessCursor` now carry optional `sort_order`. Rust role, binding and tenant records now include `created_at`; permission and client projections carry optional creation metadata. The ordering changes alone do not change JSON item shapes.
- Before the v3 migration, older `tenant_v2` schemas require the explicit, repeatable `scripts/migrate_list_time_desc.sql` upgrade for permission creation metadata and time pagination indexes. Unknown historical permission times remain null. Initialization and startup do not run this upgrade automatically.

- Added a no-tenant Axum host example with its own configuration and startup script; it embeds IdP business routes and React login while authorizing reads against host-owned report data.
- Access initialization now permits unrelated host objects in the selected PostgreSQL schema, while rejecting conflicting IdP objects atomically. The host still supplies runtime database and security configuration.

## 1.0.0 — 2026-09-25

This is a breaking contract release of the embeddable IdP workspace. The Rust workspace moves from `0.2.0` to `1.0.0`; the local Web packages move from `0.1.0` to `1.0.0`. The version does not turn `embedded-idp-app` into a production host.

### Breaking changes

- Identity, sessions, OAuth/OIDC, devices and authorization now require an explicit tenancy mode. In `disabled`, business access uses domain `0`; in `enabled`, `0` is reserved for platform administration and business access uses real tenant IDs. Users must have a first tenant when created; one user ID and credential can join multiple tenants.
- New installations use the `tenant_v2` Access schema. The old database layout is not migrated or read alongside it. Startup checks schema version, mode, administrator bootstrap and readiness instead of applying Access DDL or creating an administrator.
- Business and management tokens have distinct purposes and audiences. Tenant identity is bound to the authenticated session and token; old tokens and caller-supplied subject headers cannot stand in for it. Management API keys and the old development authentication path are removed from the reference host.
- Device proofs include tenant-bound v2 canonical bytes and use the current request-bound proof contracts. Old proof formats and unbound device/session data are not accepted.
- The old React admin entry, API-key client and Tailwind UI have been removed. The reference host serves the account-based management app; the local `@embedded-idp/react` package provides a separate identity entry and `/admin` permission-directory entry.
- Local environment templates now live together at the repository root: `.env.example`, `.env.disabled.example` and `.env.enabled.example`. The local scripts require an explicit mode and mode-specific schema. Existing untracked `.env` files are not overwritten.

### Added

- Tenant-scoped business permission definitions with create, list/read, description update, enable/disable and irreversible archive. The same `resource_type::action` can be defined independently in different tenants. Roles contain actions; subject-role bindings carry type-wide or concrete resource-ID scope.
- Core authorization and membership/role queries, PostgreSQL transactions and indexes, optional Axum management/business routes, audit and diagnostic APIs, and a React management console for tenants, members, roles, permissions, devices, sessions and clients.
- Fixed-tenant and choose-tenant login policies; explicit offline administrator bootstrap; local disabled/enabled reference profiles; same-origin embeddable React identity and permission-directory components.

### Upgrade path

There is no in-place migration or compatibility bridge. Prepare a new empty `tenant_v2` schema for each local mode, initialize an administrator separately in each, and provision a signing key before starting the reference host. Update embedding hosts to pass trusted tenant/user/session context, use the new Core/Axum contracts, and perform resource checks at the business operation. Re-register clients, users, tenants, devices, roles and permissions as needed; do not copy old credentials or authorization rows into the new schema without a separately designed migration.

The reference app remains for development and integration. Production deployment still requires host-owned rate limits, key rotation, device admission, operations and performance acceptance; see [security requirements](docs/rust-embedded-idp-production-security-delivery-v2.md) and [current gaps](docs/tenant-access-execution-plan.md).

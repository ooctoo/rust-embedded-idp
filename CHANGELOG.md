# Changelog

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

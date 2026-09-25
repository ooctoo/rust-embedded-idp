# Changelog

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

# Overview

`rust-embedded-idp` is designed as an embeddable identity module for Rust backends.

The module goal is not to become a full standalone cloud IAM product.
It is intended to be linked into a host backend and provide:

- auth APIs
- device APIs
- admin APIs
- OIDC provider endpoints
- database-backed persistence
- confidential client authentication hooks with host-owned secret verification

An optional runnable host crate, `embedded-idp-app`, can also be used when this module needs to run as a standalone local service.

## Design Priorities

1. Embeddable first
2. Desktop public client and confidential web client support
3. Deterministic API paths
4. Postgres-first storage
5. Future standalone repo extraction

## Host Integration Rule

- storage adapters receive database configuration from the host application
- environment variables may be used by the host to build config, but the module should consume typed config rather than read globals directly
- provider selection should happen in the host composition root; this module should not branch on a provider enum across business logic

## Identifier Rule

- host-facing identifiers such as `account_id`, `device_id`, and `session_id` stay opaque strings at the Rust and HTTP boundary
- the recommended identifier value is a UUIDv7 string
- hosts and adapters should not expose sequential database row ids as module business identifiers

## Storage Design Doc

- Postgres schema planning is tracked in [postgres-schema-design-v1.md](./postgres-schema-design-v1.md)
- service and HTTP surface planning is tracked in [service-and-api-surface-v1.md](./service-and-api-surface-v1.md)
- host composition guidance is tracked in [host-integration-v1.md](./host-integration-v1.md)
- device domain and registration flow design is tracked in [device-model-v1.md](./device-model-v1.md)

## Initial Domains

- accounts
- sessions
- OAuth/OIDC clients
- device registry
- account-device bindings
- device proof

## Non-goals for v0.1

- multi-tenant org model
- SAML
- social login
- admin UI
- multiple storage backends

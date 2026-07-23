# Module Architecture v1

## Workspace Shape

```text
rust-embedded-idp/
  docs/
  crates/
    embedded-idp-core/
    embedded-idp-email/
    embedded-idp-axum/
    embedded-idp-storage-postgres/
    embedded-idp-app/
```

## Layer Model

This module is split into `2` architecture layers:

1. `core service layer`
2. `axum http layer`

`embedded-idp-storage-postgres` is an infrastructure adapter crate consumed by the core layer.
It is not a third architecture layer.
`embedded-idp-app` is an optional runnable host crate for standalone usage.
It is also not a third business layer.

## Crate Responsibilities

### `embedded-idp-core`

Owns:

- domain models
- auth and device service contracts and implementations
- store traits
- token issuance and refresh rotation logic
- device proof validation logic
- host-facing configuration types
- reusable support utilities such as UUIDv7 business-id generation

Does not own:

- HTTP framework code
- database-specific queries

### `embedded-idp-axum`

Owns:

- route mounting
- fixed API paths
- HTTP request and response adapters
- HTTP handlers that call core services

Does not own:

- persistence
- auth, token, or device proof business rules

### `embedded-idp-storage-postgres`

Owns:

- Postgres store implementation
- typed Postgres storage configuration and adapter construction
- structured Postgres-specific nested config such as connection and pool sections
- schema design and migration alignment for module storage tables
- migration plan references
- SQL-oriented storage models

Does not own:

- route definitions
- host web framework integration
- core service business rules
- process-global configuration loading as a primary runtime contract

### `embedded-idp-app`

Owns:

- standalone `axum` server bootstrap
- environment loading for standalone usage
- typed config construction for the runnable host
- storage migration bootstrap and default client seeding
- host middleware composition for split route groups

Does not own:

- core auth, device, token, or proof business rules
- database adapter internals
- alternative HTTP contracts beyond `embedded-idp-axum`

## Future Multi-Database Rule

- do not flatten `postgres` and `mysql` fields into one broad config struct inside this module
- when a second backend is added, provider selection should happen once in the host composition root
- provider-specific leaf configs should stay isolated in their adapter crates

## Fixed Route Roots

The module will reserve these module-local route roots:

- `/auth`
- `/devices`
- `/admin`
- `/oidc`
- `/.well-known/openid-configuration`

Hosts may mount the module under an additional top-level prefix if needed.

## Documentation Placement

Project architecture and integration documentation lives under `docs/`.

## Related Docs

- [Postgres Schema Design v1](./postgres-schema-design-v1.md)
- [Service and API Surface v1](./service-and-api-surface-v1.md)
- [Host Integration v1](./host-integration-v1.md)
- [Device Model v1](./device-model-v1.md)
- [Standalone App v1](./standalone-app-v1.md)

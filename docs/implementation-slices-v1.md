# Implementation Slices v1

> 历史文档：早期实施切片记录。当前进度和剩余工作以 docs/tenant-access-execution-plan.md 开头的交付边界为准。

## Slice 1

- define core configuration
- define initial module HTTP path constants
- define account, device, session, and client domain types

## Slice 2

- add repository traits to `embedded-idp-core`
- add auth register and login services
- add refresh token rotation
- add device register and heartbeat services
- add token and device proof logic

## Slice 3

- add `axum` routes and fixed HTTP handlers
- add request/response DTOs
- add error-to-http mapping

## Slice 4

- publish Postgres schema design doc
- add Postgres schema and migration plan
- add postgres store implementations
- wire core services to postgres adapters
- add local bootstrap and live verification entrypoints

## Slice 5

- add OIDC authorization and token endpoints
- add PKCE validation
- add JWKS and discovery endpoints
- split OIDC-facing service contracts from local auth service contracts

## Slice 6

- refactor device domain into `device + account_device_binding`
- add provision / complete / bind device flows
- activate `device_nonces` write path
- keep shared-device semantics as the default model

## Slice 7

- add user manager and device manager APIs
- add revoke and disable flows

## Slice 8

- harden tests, docs, and examples for future repo extraction

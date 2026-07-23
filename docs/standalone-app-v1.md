# Standalone App v1

## Purpose

`embedded-idp-app` is a thin runnable host for `rust-embedded-idp`.

It is intended for:

- local development
- module acceptance checks
- standalone deployment experiments before a larger host integrates the module

It is not a separate business layer.
It composes:

- `embedded-idp-core`
- `embedded-idp-axum`
- `embedded-idp-storage-postgres`

## Current Behavior

At startup the app will:

1. load env into typed config
2. validate embedded idp and Postgres config
3. apply Postgres migrations
4. seed one public desktop client
5. optionally seed one confidential web client
6. mount split route groups into one `axum` server

Seeded confidential clients use module-owned Argon2id PHC hashing before the secret is persisted.

## Route Mounting

The app mounts:

- `public_router()`
- `token_router()` for refresh, logout, and userinfo
- `client_authenticated_router()`
- `subject_router()` behind a dev subject-header middleware
- `admin_router()` only when `EMBEDDED_IDP_APP_ADMIN_API_KEY` is configured, nested under `/api`
- a static admin UI shell at `EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH`, with static assets under `<base-path>/static/*`

Current dev host middleware conventions:

- subject header: `x-embedded-idp-account-id`
- admin header: `x-embedded-idp-admin-key`

These are development-oriented host controls, not a production auth model.
For subject-bound device routes, the effective account scope is derived from the subject header middleware, not from request payload `account_id` fields.

## Run

From the repository root:

```bash
cp .env.example .env
./scripts/run_embedded_idp_app.sh
```

The helper script explicitly sources the repository-root `.env` before starting
`embedded-idp-app`. The app itself still reads process environment only; it does not
auto-load `.env`.

Useful endpoints after startup:

- `GET /healthz`
- `GET /`
- `GET /static/admin-app.js`
- `GET /.well-known/openid-configuration`
- `POST /auth/register`
- `POST /auth/verify-email`
- `POST /auth/resend-verification`
- `POST /auth/login`
- `GET /api/admin/accounts` with `x-embedded-idp-admin-key`
- `GET /oidc/authorize` with `x-embedded-idp-account-id`

For local verification-email testing:

- `EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE=log` prints the verification code to the standalone app log
- `EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE=smtp` lets the host send through a standard SMTP mailbox provider

## Important Environment Variables

### Server

- `EMBEDDED_IDP_APP_BIND_ADDR`
- `EMBEDDED_IDP_APP_ISSUER`
- `EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH`

### Postgres

- `EMBEDDED_IDP_APP_PG_URI`
- `EMBEDDED_IDP_APP_PG_SCHEMA`
- `EMBEDDED_IDP_APP_PG_TLS_MODE`
- `EMBEDDED_IDP_APP_PG_TLS_CA_CERT_PATH`
- `EMBEDDED_IDP_APP_PG_APP_NAME`
- `EMBEDDED_IDP_APP_PG_MAX_CONNECTIONS`
- `EMBEDDED_IDP_APP_PG_CONNECT_TIMEOUT_SECS`

### Password Policy

- `EMBEDDED_IDP_APP_PASSWORD_MIN_LENGTH`
- `EMBEDDED_IDP_APP_PASSWORD_MAX_LENGTH`
- `EMBEDDED_IDP_APP_VERIFICATION_CODE_TTL_SECS`

### Verification Email Delivery

- `EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE`
- `EMBEDDED_IDP_APP_EMAIL_SENDMAIL_COMMAND`
- `EMBEDDED_IDP_APP_EMAIL_FROM`
- `EMBEDDED_IDP_APP_EMAIL_FROM_NAME`
- `EMBEDDED_IDP_APP_EMAIL_VERIFICATION_SUBJECT`
- `EMBEDDED_IDP_APP_EMAIL_SMTP_HOST`
- `EMBEDDED_IDP_APP_EMAIL_SMTP_PORT`
- `EMBEDDED_IDP_APP_EMAIL_SMTP_TLS_MODE`
- `EMBEDDED_IDP_APP_EMAIL_SMTP_USERNAME`
- `EMBEDDED_IDP_APP_EMAIL_SMTP_PASSWORD`

### Public Client Seed

- `EMBEDDED_IDP_APP_PUBLIC_CLIENT_ID`
- `EMBEDDED_IDP_APP_PUBLIC_CLIENT_NAME`
- `EMBEDDED_IDP_APP_PUBLIC_REDIRECT_URI`

### Optional Confidential Client Seed

- `EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_ID`
- `EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_NAME`
- `EMBEDDED_IDP_APP_CONFIDENTIAL_REDIRECT_URI`
- `EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_SECRET`

### Host Middleware Controls

- `EMBEDDED_IDP_APP_DEV_SUBJECT_HEADER`
- `EMBEDDED_IDP_APP_ADMIN_API_KEY`

## Current Standalone Paths

For the standalone `embedded-idp-app` host:

- admin UI shell defaults to `/`
- admin UI static assets are served under `<admin-ui-base-path>/static/*`
- operator APIs are served under `/api/admin/*`

Examples:

- `GET /`
- `GET /static/admin-app.css`
- `GET /api/admin/accounts`
- `POST /api/admin/accounts/set-password`

## Current Simplifications

- access tokens and id tokens use development-only local issuers
- JWKS is currently empty in the standalone host
- subject-bound host auth is based on a dev header middleware
- self-service device handlers still rely on host policy to constrain account scope
- confidential client secrets are seeded as Argon2id PHC hashes through the same module codec used for verification
- `EMBEDDED_IDP_APP_PG_TLS_MODE=prefer` still behaves as plaintext transport; use `require` when TLS is needed

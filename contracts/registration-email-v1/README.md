# IDP registration email v1 contract

This directory freezes the local I1 JSON shapes for the profile
`idp-registration-email-v1`. It is a contract artifact, not a published
OpenAPI document and not an HTTP implementation. The SUT has not switched to
this profile; HTTP and SDK integration are I2 work.

The trusted transport sends the fixed header
`X-IDP-Registration-Profile: idp-registration-email-v1`. The profile has no
body field that selects a profile. The module-local routes were checked against
`crates/embedded-idp-axum/src/tenant_registration.rs` and remain:

| Method | Path |
| --- | --- |
| `POST` | `/auth/register` |
| `POST` | `/auth/resend-verification` |
| `POST` | `/auth/verify-email` |

The outer host may add its own prefix. This directory records the routes only;
it does not change route assembly.

Transport body-size failures and other host-level over-limit responses are
outside this profile. They must be handled by the embedding Host and are not
represented by an `Error` fixture or schema member here.

`schema.json` is JSON Schema draft 2020-12. Each request and response is an
independent `$defs` entry; the schema intentionally has no root `oneOf`
validator. All request definitions reject unknown properties. The schema owns
shape and length constraints only. Email canonicalization, tenant admission,
password policy, operation idempotency, context expiry, verification budgets,
and the state machine remain Core/host semantics and are not claimed to be
JSON Schema validation.

`RegisterAccepted` is the only public registration acceptance object:

```json
{
  "accepted_at_unix_secs": 1713894200,
  "context_lifetime_secs": 900,
  "resend_after_secs": 60,
  "status": "verification_requested",
  "verification_context": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}
```

`accepted_at_unix_secs` is the public acceptance time from the admission
boundary. It is not an account timestamp or a verification-code timestamp.
Replaying the original `client_operation_id` returns the same accepted object,
so a client can recover after losing the first response without renewing its
context or changing the UI expiry calculation. Unknown, pending, active, and
disabled state fixtures intentionally use this same object; the public shape
does not disclose account, delivery, or state facts. No account id, session,
token, email, delivery status, cookie, redirect, or arbitrary message/details
is present in a public response.

Resend returns only `{"status":"verification_requested","resend_after_secs":60}`.
Verification success returns only `{"status":"verified"}`. An error is always
`{"error":{"code":"..."}}` with one code from the schema enum. The profile
uses `Cache-Control: no-store` for every response and emits neither
`Set-Cookie` nor `Location`.

An empty or non-numeric verification code still satisfies the request shape so
that Core can apply its verification-attempt budget. Shape validation does not
turn either value into a successful verification; the fixtures represent the
budgeted semantic outcome separately.

Fixture `valid` means only that the request JSON has the selected `$defs`
shape. It does not assert that Core will accept the email, tenant, operation,
context, or verification code. Shape-valid fixtures carry `runtime` metadata
for the trusted server clock and effective scope, plus `semantic` metadata
that names the expected state-machine result or error code. The metadata is
test input, not a public response field. Shape-invalid fixtures intentionally
carry no clock or scope metadata, so malformed UUID/date and DTO cases cannot
be mistaken for an expiry or semantic-state check. The two original-key
registration fixtures share the UUIDv7 timestamp and deadline; their
`deadline_extended` value is `false`.

For the two `request_expired` cases, `runtime.server_now_unix_secs` is one
second beyond both the UUIDv7 operation max age and the recorded context
expiry. The `RegisterAccepted.accepted_at_unix_secs` value is the trusted
admission clock represented by the corresponding normal fixture and is not an
account or verification-code fact.

Frozen status mapping:

| Condition | HTTP status |
| --- | ---: |
| Missing or wrong profile header | 400 |
| Invalid JSON | 400 |
| Tenant admission failure | 400 |
| DTO field/shape violation (`invalid_request`) | 422 |
| Core semantic registration rejection (`invalid_registration`) | 400 |
| Source-only rate limit | 429, with source-scoped `Retry-After` |
| Global forbidden | 403 |
| Global or verification service unavailable | 503 |
| Operation conflict | 409 |
| Register/resend accepted | 202 |
| Verify success | 200 |

The fixture file contains request-shape, response-shape, state, and transport
metadata cases. It is not a replacement for an Ajv run. To validate the schema
with Ajv 2020 from a JavaScript environment that already has Ajv installed:

```js
import Ajv2020 from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";

const ajv = new Ajv2020({ strict: true });
const schema = JSON.parse(readFileSync("schema.json", "utf8"));
const validate = Object.fromEntries(
  Object.keys(schema.$defs).map((name) => [
    name,
    ajv.compile({
      $schema: schema.$schema,
      $defs: schema.$defs,
      $ref: `#/$defs/${name}`,
    }),
  ]),
);
```

For a normal Ajv invocation, compile `schema.json` with the `$ref` for the
selected `$defs` entry and validate the corresponding fixture value. The
repository does not add an Ajv dependency for this local freeze. Run the
stdlib-only integrity check from this directory:

```sh
python3 check.py
```

The checker verifies raw schema/fixture hashes, canonical fixture hashes,
manifest identity, fixture ids, minimum coverage, the four shared accepted
state objects, fixed transport metadata, trusted-clock/scope metadata,
UUIDv7/expiry consistency, the original-key replay pair, and forbidden
disclosure fields. It does not implement a second JSON Schema validator.

Canonical serialization for manifest and fixture hashes is UTF-8 JSON with
`sort_keys=True`, compact separators `(',', ':')`, and `ensure_ascii=False`.
`schema_sha256` and `fixtures_sha256` hash the exact checked-in file bytes.
Each manifest fixture hash covers one complete fixture object in that canonical
form. `manifest.canonical_sha256` covers the manifest with only its own
`canonical_sha256` member removed, using the same canonical form.

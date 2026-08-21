# rust-embedded-idp Production Security Delivery and Verification v2

Updated: 2026-08-07

## 1. Authority

This is the delivery companion to
[rust-embedded-idp Production Security Extension Design v2](rust-embedded-idp-production-security-extension-design-v2.md).
It defines the upstream HTTP, error, migration, health, test, delivery, and SUT
adoption requirements. It does not change the ownership or domain decisions in
the primary design.

## 2. HTTP adapter changes

New or wire-breaking public routes are:

```text
POST /devices/provision
POST /device-proof/challenges
POST /auth/refresh
POST /auth/logout
POST /devices/complete
POST /devices/rotate-key
POST /devices/bind
POST /devices/unbind
POST /devices/heartbeat
POST /oidc/revoke
```

The host still chooses its top-level prefix. `embedded-idp-axum` must:

- use one injected server-clock value for every public and admin mutation and
  for introspection;
- remove public `*_at_unix_secs` authority fields;
- apply the 16 KiB auth/device body limit before buffering;
- buffer exact refresh bytes, compute the digest, then deserialize with unknown
  fields rejected;
- construct method, full mounted path, audience, and proof profile from trusted
  configuration and actual request state;
- parse the five device-proof headers without logging them;
- require proof on refresh and expose a reusable extractor/service call for
  host resource routes;
- keep route groups independently mountable;
- never mount admin routes implicitly.

### 2.1 Public JSON contracts

Existing `POST /devices/provision` remains the operation that creates a pending
device, but it uses server time and no longer creates or returns a registration
challenge. It accepts only `client_id` and `device_name` and returns the pending
device projection. The client obtains every challenge through the purpose-bound
challenge endpoint.

`POST /device-proof/challenges` accepts:

```json
{"device_id":"<device-id>","purpose":"<allowed-purpose>"}
```

It returns the same success status and shape for eligible, unknown, and
ineligible device IDs:

```json
{"challenge":"<43-char-base64url>","expires_at_unix_secs":1700000300}
```

Only an eligible device has an authorizing digest stored. Purpose validation is
not hidden: an unsupported or malformed purpose is a request-contract error,
independent of device existence.

`POST /devices/complete` accepts:

```json
{
  "device_id":"<device-id>",
  "public_jwk":{"kty":"OKP","crv":"Ed25519","x":"<base64url>","kid":"<thumbprint>"},
  "challenge":"<43-char-base64url>",
  "signature":"<86-char-base64url>"
}
```

The server requires challenge purpose `device_registration`, derives and
compares the JWK thumbprint, and does not accept a client operation time or key
version.

`POST /devices/rotate-key` accepts:

```json
{
  "device_id":"<device-id>",
  "new_public_jwk":{"kty":"OKP","crv":"Ed25519","x":"<base64url>","kid":"<thumbprint>"},
  "challenge":"<43-char-base64url>",
  "current_key_signature":"<86-char-base64url>",
  "new_key_signature":"<86-char-base64url>"
}
```

The server requires challenge purpose `device_key_rotation`, derives the old
key and next version from locked state, and accepts neither from JSON.

`POST /auth/refresh` accepts only:

```json
{"refresh_token":"<43-char-base64url>"}
```

It no longer accepts a rotation timestamp. JSON whitespace is allowed, but the
client signs the exact transmitted bytes. All four DTOs reject duplicate or
unknown members; JWK parsing additionally rejects private or non-canonical
members before domain validation.

Logout keeps only `refresh_token`. Device bind, unbind, and heartbeat keep their
existing identifier fields but remove their operation timestamps. OIDC
revocation keeps `token`, optional hint, and client authentication fields but
removes `revoked_at_unix_secs`. Admin mutation DTOs likewise remove caller-
supplied operation times. Introspection remains non-mutating but evaluates token
state against the one injected server-clock value.

### 2.2 Device-proof header contract

Refresh and reusable protected-resource verification use exactly these five
headers:

| Header | Value |
| --- | --- |
| `X-Device-Id` | presented device ID |
| `X-Device-Key-Id` | exactly 43 canonical unpadded base64url characters containing the RFC 7638 SHA-256 thumbprint |
| `X-Device-Challenge` | exactly 43 canonical unpadded base64url characters |
| `X-Device-Signature` | exactly 86 canonical unpadded base64url characters encoding a 64-byte Ed25519 signature |
| `X-Device-Signed-At` | unsigned decimal Unix seconds with no sign, leading zero except `0`, or surrounding whitespace |

Header names follow normal HTTP case-insensitive matching. Every value must be
present exactly once, ASCII, within its domain length bound, and must not be
trimmed or combined. Missing headers produce `device_proof_required`; duplicate,
empty, non-ASCII, overlong, padded, non-canonical, or otherwise malformed values
produce the safe `device_proof_invalid` class. Proxies must forward these values
unchanged and neither the module nor host may log them.

All five values are untrusted presentation data. For refresh, the expected
device ID is loaded from the locked session and compared with `X-Device-Id`
only after the presented device proof validates.
For a protected host resource, the account comes from the validated access
token and the upstream transaction verifies that the presented device has an
active binding to that account.

Device registration completion carries its public JWK, challenge, and one
proof-of-possession signature in a JSON body. Device-key rotation carries its
proposed public JWK, challenge, current-key signature, and proposed-key
signature in a JSON body. Those two domain-specific proof formats do not reuse
the five request-proof headers.

### 2.3 Request bytes and path contract

Auth and device routes have a 16 KiB body limit applied before buffering; a
host may lower but not raise it for these upstream handlers. JSON DTOs reject
unknown fields. For refresh, the adapter buffers the exact bytes once, checks
the limit, computes SHA-256, and then deserializes the same buffer. A bodyless
protected request hashes the zero-length byte string.

Each protected route is registered at composition time with one literal
externally visible path after the host prefix, one method, one purpose, one
audience, and one proof profile. The path begins with `/`, is ASCII, and contains
no query, fragment, percent escape, dot segment, repeated slash, or trailing
slash unless it is `/`. The adapter compares the original request URI path with
that configured path byte for byte and rejects all query strings. It does not
decode or normalize the path and does not derive canonical bytes from a
router-local stripped path.

### 2.4 Refresh client concurrency contract

Clients must serialize refresh attempts per session. Version 2 intentionally
has no grace window or idempotent response replay. After a successful rotation,
a second valid use of the old token and a fresh valid proof commits whole-family
revocation and returns `refresh_token_reuse_detected`. Possession of an old token
without a valid active-device proof cannot trigger that revocation.

## 3. Error and disclosure model

Core errors remain typed and more specific than public responses. Required
stable public codes are:

```text
device_proof_required
device_proof_invalid
device_proof_expired
device_proof_replayed
device_key_mismatch
device_inactive
device_binding_inactive
refresh_device_mismatch
refresh_token_invalid
refresh_token_reuse_detected
```

Malformed signatures, unknown devices, and unknown keys collapse to a safe
external class where a specific code would reveal existence. The challenge
endpoint never reports device existence. Messages contain no token, proof,
JWK, digest, database identifier, or backend error. Host logs and metrics use
only stable codes and route templates.

Required mapping rules are:

| Condition | Public code |
| --- | --- |
| one or more request-proof headers absent | `device_proof_required` |
| malformed presentation, unknown device/key, bad signature, or relationship that would reveal existence | `device_proof_invalid` |
| structurally valid proof outside allowed clock skew | `device_proof_expired` |
| otherwise valid proof using an already consumed challenge | `device_proof_replayed` |
| authenticated device context presents a key other than the expected active version | `device_key_mismatch` |
| authenticated device is disabled or revoked | `device_inactive` |
| authenticated account-device relationship is absent, suspended, or unbound | `device_binding_inactive` |
| valid refresh proof is for a different device than the locked session | `refresh_device_mismatch` |
| unknown, expired, malformed, or otherwise unusable refresh token | `refresh_token_invalid` |
| valid proof confirms reuse and family revocation commits | `refresh_token_reuse_detected` |

The more specific device and binding codes are emitted only after an access
token or cryptographically valid device proof establishes a context in which
the distinction does not disclose an unrelated identity. Storage and internal
errors never reuse a security rejection code and map to the host's generic
availability response. Every security rejection is rollback-only except
committed `refresh_token_reuse_detected`.

## 4. Migration and compatibility

This is a breaking pre-1.0 upstream release and uses minor revision `0.2`
before SUT repins it. Insecure behavior is not preserved through dual parsing.
The cutover deliberately requires a bounded identity-write outage; this design
does not claim zero-downtime compatibility with development token formats.

### 4.1 Schema states and binary compatibility

| Schema state | Contents | `0.1` binary | `0.2` online binary |
| --- | --- | --- | --- |
| `0001` | current development schema | allowed | refuses startup |
| `0002_expand` | additive v2 tables, nullable transition columns, version ledger | read/write allowed | refuses startup |
| `0003_enforce` | cutover marker, secure invariants and digest-only writes required | must not run; legacy writes fail constraints | required and allowed |
| `0004_contract` | raw and obsolete columns removed in a later release | incompatible | allowed only after that release declares support |

Every online binary declares both `minimum_supported_schema` and
`maximum_supported_schema` and requires the observed version to fall inside the
closed interval. It never treats an arbitrary newer schema as compatible.

### 4.2 `0002_expand`

The upstream migration command acquires a schema-specific PostgreSQL advisory
lock and verifies an exact `0001` fingerprint before recording it in a new
schema-version ledger. It then:

- creates `device_proof_keys` with key ID, device/version uniqueness, status,
  public JWK, and timestamps;
- adds nullable purpose and challenge-digest columns to device challenges;
- adds nullable refresh digest and revocation reason columns;
- creates supporting indexes and the one-active-key partial unique constraint;
- retains legacy raw columns so the running `0.1` binary remains functional.

This phase does not hash and preserve predictable development refresh tokens;
doing so would turn an insecure bearer value into an apparently production
credential.

### 4.3 Security cutover

The operator performs these ordered steps:

1. takes and verifies a backup and runs the migration dry-run checks;
2. applies `0002_expand` while `0.1` may still serve;
3. drains and stops every old identity writer;
4. reacquires the advisory lock and verifies schema `0002_expand` exactly;
5. marks every legacy session revoked as part of the `security_cutover` event;
6. consumes every outstanding legacy authorization code and deletes legacy
   refresh-token rows and raw device challenges;
7. revokes legacy devices because the old records contain no server-verifiable
   public key; existing binding rows remain as non-authorizing history because
   a revoked device can never satisfy verification;
8. records one durable v2 cutover marker and timestamp;
9. applies `0003_enforce`, then deploys `0.2` online binaries;
10. requires users to authenticate again and devices to reprovision keys.

The cutover is idempotent under the advisory lock. Re-running it after the
marker exists verifies the resulting state and performs no second semantic
transition.

### 4.4 `0003_enforce` and later contraction

`0003_enforce` makes purpose and digest fields mandatory for new writes, adds
length/status/check constraints, validates the one-active-key invariant, and
switches every lookup to a digest. These constraints intentionally cause an
accidentally restarted `0.1` writer to fail closed. The online binary starts
only when the cutover marker exists and all invariant probes succeed.

`0004_contract` is a later release after operational evidence shows no old
binary is deployed. It removes raw refresh/challenge columns, the device-level
legacy proof-key ID, and obsolete request-time columns. Column removal is not
part of the initial v2 rollback plan.

The migration tool belongs upstream, but the production host decides when to
run it. Online Server startup checks version and invariants only; it does not
apply DDL while serving traffic. Rollback is supported only before step 5 of
the security cutover. After session/device revocation or raw-value deletion,
rollback cannot recreate valid credentials and must instead complete forward
recovery.

## 5. Health and administration boundary

The upstream module exposes safe component facts:

- minimum, maximum, and observed schema version;
- v2 security cutover marker present;
- active signing key present;
- active key present in projected JWKS;
- overlap key metadata internally consistent;
- bounded Postgres probe success.

The host aggregates these with entitlement, provider, audit, release, and rate-
limit readiness. The IDP does not expose a public aggregate readiness route.

Existing account, session, client, and device admin services remain reusable.
Production SUT exposes them only through Online Admin Server with its independent
operator session. Admin projections may show device key ID, version, status,
and timestamps, but not full proofs, refresh digests, token values, or private
key material.

## 6. Required tests

### 6.1 Core and cryptography

- valid access and ID token issue/validate round trips;
- forged signature, unknown `kid`, wrong algorithm, issuer, audience,
  token-use, scope, expiry, `nbf`, nonce, session, client, and account rejection;
- active/overlap JWKS cardinality, canonical ETag, normal rotation, and
  emergency retired-key rejection;
- malformed/private/wrong-curve JWK, wrong thumbprint, invalid signature, and
  key-version rejection;
- exact challenge/signature decoded lengths, canonical base64url lengths, and
  rejection of padding and alternate encodings;
- canonical byte vectors for registration, rotation, refresh, invoke, and
  stream request bindings;
- changed method, path, body byte, audience, purpose, challenge, device, key, or
  signed time rejection;
- random refresh-token length/encoding and digest determinism;
- no `Debug`, error, or admin response exposes secret material.

### 6.2 Transaction and Postgres

- registration atomically activates device, key, and consumed challenge;
- failed registration commits none of them;
- concurrent nonce verification produces one success;
- expired, consumed, cross-device, and cross-purpose challenges reject;
- key rotation retires exactly one old key and activates one next version;
- refresh success rotates version, token digest, and challenge together;
- missing proof, forged proof, wrong device, inactive binding, and revoked
  device commit no refresh change;
- concurrent refresh/replay deterministically detects reuse and revokes the
  family under the fixed strict policy;
- confirmed reuse commits family revocation before the public error is mapped;
- an old raw refresh token with missing or invalid proof commits no revocation;
- application/database clock disagreement cannot change nonce expiry because
  the conditional update uses the injected `observed_at` value;
- logout and introspection use digest lookup;
- database and application output contain no raw refresh token;
- migration from the last released schema revokes development sessions and
  legacy devices, removes raw credentials, rejects legacy writers, and leaves
  no accepted insecure format.

### 6.3 HTTP and host integration

- public requests cannot inject operation time, account, session, method, path,
  audience, or body digest;
- every proof header is required exactly once and malformed, duplicate,
  padded, non-canonical, non-ASCII, and overlong values reject safely;
- the 16 KiB limit is enforced before buffering and unknown JSON fields reject;
- different JSON whitespace verifies only against its own exact transmitted
  bytes;
- the original URI must equal the configured mounted path byte for byte;
- router-local paths, percent escapes, repeated/trailing slashes, and alternate
  mount prefixes cannot verify under the literal-path v2 contract;
- query strings on protected mutation routes reject;
- challenge responses do not reveal device status;
- route subsets can be mounted without admin routes;
- SUT proof fixtures produce the same canonical bytes upstream and downstream;
- after SUT repins, refresh and model invocation use the upstream verifier and
  no `Dev*` type appears in the production composition graph;
- SUT refresh clients demonstrate one in-flight refresh attempt per session.

## 7. Upstream delivery slices

| Slice | Main goal | Required result |
| --- | --- | --- |
| IDP-0 | Freeze upstream contracts | domain records, commands, proof headers, literal paths, errors, committed outcomes, canonical vectors, migration plan |
| IDP-1 | Secure token persistence | secure random refresh tokens, digest-only store API, strict family-reuse behavior |
| IDP-2 | Device key lifecycle | public JWK validation, proof-key table, registration and rotation transactions |
| IDP-3 | Request proof | purpose challenge, canonical binding, Ed25519 verification, atomic consumption |
| IDP-4 | Proof-bound refresh | one refresh/device/binding/nonce/token-family transaction and HTTP contract |
| IDP-5 | JWT and JWKS | production RS256 adapter, key ring, access/ID validation, JWKS and rotation tests |
| IDP-6 | Release and migration | single-clock cutover, schema compatibility matrix, Postgres migration, health facts, docs, full test evidence |

Each slice has one primary goal. IDP-1 through IDP-4 may break internal traits
before the new upstream version is released; SUT repins only a reviewed commit
where all required slices pass together.

## 8. SUT adoption and definition of done

After the upstream revision is merged, SUT:

1. pins one immutable upstream commit in every embedded-IDP dependency;
2. updates its PR-0 Schema fixtures only if an explicitly reviewed HTTP contract
   changed;
3. composes production JWT/JWKS with host-loaded key material;
4. calls the upstream request verifier for LLM invoke and stream routes using
   SUT-owned literal external-path and purpose mapping;
5. uses the upstream proof-bound refresh route without an outer transaction and
   serializes refresh attempts per session;
6. forwards the five device-proof headers unchanged through every trusted proxy;
7. removes production `DevTokenIssuer`, `DevAccessTokenValidator`,
   `DevIdTokenIssuer`, and `DevDeviceProofVerifier` wiring;
8. keeps the reference implementations only in the development binary;
9. records migration, rotation, replay, and end-to-end evidence.

The upstream work is complete only when the module owns every identity-state
mutation atomically, SUT owns no duplicate identity state machine, production
tokens and proofs are cryptographically verifiable, raw refresh tokens are
absent from persistence, and all rejection and concurrency tests pass.

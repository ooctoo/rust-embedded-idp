# rust-embedded-idp Production Security Extension Design v2

Updated: 2026-08-07

## 1. Authority and status

This document defines the upstream changes that must be made in
`rust-embedded-idp` before SUT Online Server can complete its production token,
device-proof, and refresh-token work.

Classification:

- plane: Cloud identity and device-security boundary;
- upstream owner: `rust-embedded-idp`;
- consuming host: SUT Online Server and Online Admin Server;
- implementation mode: contract and transaction first, then Rust, SQL, and HTTP;
- status: implementation proposal for the next upstream revision.

The central ownership rule is:

```text
rust-embedded-idp owns identity state and atomic identity security decisions.
The host owns deployment material, route exposure, and product-specific policy.
```

SUT must not copy the upstream source, implement a parallel refresh or device
state machine, or simulate an identity transaction in host middleware.

## 2. Scope and non-goals

### 2.1 Required upstream capabilities

The upstream change includes:

1. production-safe access and ID token implementations behind existing core
   ports;
2. signing-key-ring validation and JWKS derivation;
3. device public-key registration, versioning, rotation, and revocation;
4. purpose-bound challenges and atomic nonce consumption;
5. canonical request-bound Ed25519 device proof;
6. reusable verification of an authenticated account-device request;
7. high-entropy refresh-token generation, digest-only persistence, rotation,
   and reuse detection;
8. one atomic proof-bound refresh transaction;
9. server-derived time for every public HTTP command;
10. Postgres migrations, stable errors, health facts, and complete security
    tests.

### 2.2 Host-owned capabilities

The following remain outside `rust-embedded-idp`:

- loading private keys from deployment-mounted files or secret management;
- deciding normal and emergency key-rotation rollout;
- TLS termination, trusted proxies, request IDs, rate-limit policy, logs,
  metrics, backup, restore, and aggregate readiness;
- selecting which IDP route groups are mounted in each production profile;
- authenticating the independent Online Admin session;
- SUT entitlement, release policy, LLM provider catalog, provider secrets,
  invocation audit, or model routing;
- SUT-specific scope policy and the mapping between `llm_invoke`,
  `llm_invoke_stream`, and concrete Online Server routes.

The upstream module may validate opaque proof-purpose identifiers for exact
equality. It must not understand LLM, Workspace, Agent, Workflow, candidate,
Dataset, Outcome, or Report semantics.

## 3. Current baseline and required corrections

The pinned revision already owns `DeviceRecord`, `DeviceNonceRecord`,
`AccountDeviceBinding`, `AuthSession`, `RefreshTokenRecord`, their store traits,
and one aggregate transaction runner. That is the correct authority boundary.

The current implementation is not production-safe because:

- a device stores only an optional proof key ID, not the public key or version;
- a nonce is not bound to a purpose;
- `DeviceProofVerifier` receives no public key or HTTP request binding;
- public HTTP DTOs accept caller-supplied operation times;
- refresh tokens are predictable through development issuers and stored by raw
  value;
- refresh rotation does not verify the device, binding, nonce, or proof;
- access and ID tokens are supplied by development implementations and JWKS is
  empty;
- SUT currently performs an additional device lookup and binding transaction
  in middleware, creating split authority.

The correction is an upstream domain and transaction change, not a SUT wrapper.

## 4. Target crate ownership

The existing crates remain, with one concrete production-security crate added:

```text
crates/
  embedded-idp-core/
    domain.rs
    device_proof.rs
    token.rs
    store.rs
    service/
      device.rs
      device_request.rs
      auth.rs
      oidc.rs
  embedded-idp-security/
    jwt.rs
    signing_key_ring.rs
    jwks.rs
    ed25519.rs
    refresh_token.rs
  embedded-idp-axum/
    proof_http.rs
    ... existing handlers and DTOs
  embedded-idp-storage-postgres/
    ... schema, transaction, migration, and SQL
  embedded-idp-app/
    ... development/reference composition only
```

`embedded-idp-core` owns state, commands, invariant checks, transaction order,
and cryptography ports. It must remain independent of Axum, Postgres, filesystem
paths, and deployment secrets.

`embedded-idp-security` is a real adapter required by the production profile,
not a registry or plugin framework. It implements fixed RS256 and Ed25519
behavior, secure refresh-token generation, digesting, and public JWKS
projection. It receives already-loaded key material; it never reads environment
variables or chooses deployment paths.

`embedded-idp-axum` derives HTTP facts from the actual request and server clock;
it never accepts method, path, body digest, actor, or time as caller authority.

`embedded-idp-storage-postgres` implements the exact locking and conditional
updates required by the core transactions. The reference app may continue to
wire explicit `Dev*` adapters, but its types and routes must remain visibly
development-only.

## 5. Domain model

### 5.1 Device proof keys

Do not add more optional cryptographic fields directly to `DeviceRecord`.
Introduce one record per key version so rotation and history have coherent
state:

```rust
pub struct DeviceProofKeyRecord {
    pub key_id: String,              // RFC 7638 JWK thumbprint
    pub device_id: DeviceId,
    pub algorithm: DeviceProofAlgorithm, // Ed25519 only in this version
    pub public_jwk: String,           // validated canonical public JWK JSON
    pub version: u64,
    pub status: DeviceProofKeyStatus, // Active | Retired
    pub registered_at: SystemTime,
    pub retired_at: Option<SystemTime>,
}
```

Required invariants:

- the JWK contains only `kty=OKP`, `crv=Ed25519`, public `x`, and the derived
  `kid`; private `d` is rejected;
- `x` is exactly 43 canonical unpadded base64url characters decoding to the
  32-byte Ed25519 public key;
- `key_id` equals the RFC 7638 thumbprint recomputed by the server;
- `key_id` is the canonical 43-character unpadded base64url encoding of that
  SHA-256 thumbprint;
- `(device_id, version)` and `key_id` are unique;
- one device has at most one active key;
- version starts at one and increases by exactly one;
- a retired key can never verify a new request;
- revoking a device removes authority from every associated key.

### 5.2 Device proof challenges

Replace the current raw challenge record with a purpose-bound record:

```rust
pub struct DeviceProofChallengeRecord {
    pub id: DeviceNonceId,
    pub device_id: DeviceId,
    pub purpose: DeviceProofPurpose,
    pub challenge_digest: [u8; 32],
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
}
```

`DeviceProofPurpose` is one to 64 ASCII characters matching
`[a-z][a-z0-9_]{0,63}`. Core constants define `device_registration`,
`device_key_rotation`, and `refresh`. A host may register additional allowed
identifiers such as `llm_invoke` at service construction; the set is immutable
after construction and the core only compares values exactly.

The response returns a random 32-byte challenge once, encoded as exactly 43
unpadded base64url ASCII characters. The decoder rejects padding,
non-canonical encodings, and decoded values whose length is not 32 bytes.
Postgres stores only its SHA-256 digest. Challenge generation uses a
cryptographically secure random source, not the general ID generator. Issuance
does not disclose whether a supplied device ID exists or is active.

### 5.3 Refresh tokens

Refactor refresh persistence to:

```rust
pub struct RefreshTokenRecord {
    pub id: RefreshTokenId,
    pub session_id: SessionId,       // also the first token-family boundary
    pub token_digest: [u8; 32],
    pub token_version: u64,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub revoked_at: Option<SystemTime>,
    pub revocation_reason: Option<RefreshTokenRevocationReason>,
}
```

`RefreshTokenRevocationReason` is a closed enum containing at least `Rotated`,
`ReuseDetected`, `Logout`, `Administrative`, and `SecurityCutover`. A revoked
record always has both `revoked_at` and a reason; an active record has neither.
The session is the token-family identifier, so a family revocation sets the
session status to revoked and applies the same reason and timestamp to every
still-active record in that session.

The raw token is 32 random bytes encoded as 43 unpadded base64url characters.
Presented values must have that exact canonical encoding before digest lookup;
padding, alternate encodings, and other lengths reject as invalid. The raw
token is returned once and never stored, logged, included in an error, or exposed
through an admin projection. In memory it uses a redacting secret wrapper whose
`Debug` output is `<redacted>` and which has no implicit `Display` or
serialization implementation; only the HTTP success adapter explicitly exposes
it after commit. Revoked records remain long enough to detect reuse.

### 5.4 Ephemeral verified device fact

Successful request verification returns an in-memory fact:

```rust
pub struct VerifiedDeviceRequest {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub key_id: String,
    pub key_version: u64,
    pub purpose: DeviceProofPurpose,
    pub challenge_id: DeviceNonceId,
    pub verified_at: SystemTime,
}
```

This is not persisted as a new product object. It authorizes only the current
host request after the nonce-consumption transaction commits.

## 6. Cryptography ports and implementations

### 6.1 Core ports

Split the current broad token issuer so raw refresh-token lifecycle is not
hidden inside access-token signing:

```rust
pub trait AccessTokenIssuer { ... }
pub trait AccessTokenValidator { ... }
pub trait IdTokenIssuer { ... }
pub trait RefreshTokenGenerator { ... }
pub trait RefreshTokenDigester { ... }
pub trait DeviceSignatureVerifier { ... }
pub trait SecureRandom { ... }
pub trait Clock { ... }
```

Services receive these focused ports directly. There is no runtime registry,
algorithm negotiation, or host-selected implementation per request.

Every public service operation reads `Clock` once and passes that immutable
`observed_at` through all domain checks and store calls. HTTP DTOs never contain
an authority time, the Axum adapter does not synthesize a second value, and SQL
does not replace it with database `now()`.

### 6.2 Production JWT and JWKS

`embedded-idp-security` supplies one RS256 implementation with:

- RSA keys of at least 3072 bits;
- exactly one active private signing key;
- zero or more overlap public keys;
- unique, non-reused `kid` values matching public material;
- fixed `alg=RS256`; `none` and algorithm substitution are rejected;
- access claims `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sid`,
  `client_id`, `scope`, and `token_use=access`;
- ID claims `iss`, `sub`, client `aud`, `exp`, `iat`, `auth_time`, exact
  `nonce`, and `token_use=id`;
- issuer, audience, time, token-use, and host-configured scope validation;
- public JWKS with only `kid`, `kty`, `alg`, `use`, `n`, and `e`;
- a deterministic ETag over canonical public JWK content.

Cryptographic validation is followed by existing core validation of the current
session, client, account status, expiry, and revocation. A valid signature alone
never authenticates an inactive identity.

Issued access and ID token strings use the same redacting secret-value boundary
as raw refresh tokens: no implicit `Display` or serialization and no plaintext
`Debug`. Only the explicit HTTP success projection exposes them.

The host supplies key bytes and rotation metadata at composition time. File
loading, rolling deployment, emergency removal, and session revocation policy
remain host responsibilities.

### 6.3 Device signatures

The production verifier accepts only Ed25519 public keys. An Ed25519 signature
is exactly 64 bytes before encoding and exactly 86 ASCII characters in its
canonical unpadded base64url representation. The decoder rejects padding,
non-canonical encodings, and decoded values whose length is not 64 bytes. The
verifier checks a server-constructed canonical byte string; it never parses
signed semantics from model- or caller-produced JSON.

Registration and rotation use an upstream-owned domain separator. Resource
requests use a configured proof profile so SUT can retain its frozen
`SUT-DEVICE-PROOF-V1` separator without making SUT semantics part of the core.
The profile is fixed at service construction and rejects control characters.

Registration proof-of-possession bytes are:

```text
EMBEDDED-IDP-DEVICE-REGISTRATION-V1\n
device-id:<device-id>\n
key-id:<derived-new-key-id>\n
challenge:<base64url-nonce>\n
```

Key rotation uses one byte string signed by both the current and proposed keys:

```text
EMBEDDED-IDP-DEVICE-KEY-ROTATION-V1\n
device-id:<device-id>\n
old-key-id:<active-key-id>\n
new-key-id:<derived-new-key-id>\n
new-key-version:<next-version>\n
challenge:<base64url-nonce>\n
```

Both formats require UTF-8, the shown field order, lowercase field names, no
extra fields, and the final newline.

## 7. Canonical request proof

### 7.1 Presentation and trusted inputs

The HTTP adapter parses one untrusted presentation:

```rust
pub struct DeviceProofPresentation {
    pub device_id: DeviceId,
    pub key_id: String,
    pub challenge: String,
    pub signature: String,
    pub signed_at: SystemTime,
}
```

None of these fields is identity authority before verification. For a protected
resource route, the trusted account ID comes from the validated access token.
For refresh, the expected device ID comes from the locked session; the presented
device ID must equal it. The challenge, active key, device, and binding then
establish the verified device fact.

The trusted adapter also constructs:

```rust
pub struct DeviceRequestBinding {
    pub profile: DeviceProofProfile,
    pub audience: String,
    pub method: CanonicalHttpMethod,
    pub external_path: String,
    pub body_sha256: [u8; 32],
}
```

The verification command carries the trusted account ID when one exists, the
expected purpose, the untrusted presentation, and the adapter-derived binding.
It never accepts an account ID, expected device ID, purpose, method, path,
audience, profile, or body digest from request JSON.

### 7.2 External-path contract

Version 2 protects only literal, statically configured paths. At composition
time the host registers the exact externally visible mounted path for each
protected route after applying its top-level prefix. A configured path:

- begins with `/` and uses ASCII only;
- contains no query, fragment, percent escape, dot segment, repeated slash, or
  trailing slash unless the path is exactly `/`;
- maps to exactly one method, proof purpose, audience, and proof profile.

The Axum adapter reads the original request URI, rejects every query string, and
requires its path to equal the configured external path byte for byte. It does
not decode, normalize, case-fold, or reconstruct the path from router-local
state. Canonical bytes use the configured value after this equality check. A
future dynamic or percent-encoded route requires a new versioned contract; it
is not generalized in this revision.

### 7.3 Canonical bytes

For the SUT profile, canonical UTF-8 bytes remain:

```text
SUT-DEVICE-PROOF-V1\n
audience:<configured-api-audience>\n
method:<uppercase-method>\n
path:<external-path>\n
body-sha256:<base64url-sha256>\n
challenge:<base64url-nonce>\n
device-id:<device-id>\n
key-id:<key-id>\n
signed-at:<unix-seconds>\n
```

Rules:

- the body digest covers exact received bytes before JSON decoding;
- a bodyless protected request hashes the zero-length byte string;
- the method comes from the actual request and the path follows section 7.2;
- protected mutation routes reject query parameters until a separate canonical
  query contract exists;
- the audience and profile come from trusted service configuration;
- identifiers cannot contain whitespace or control characters;
- the final newline is mandatory;
- signed time is checked against the injected server clock and configured skew;
- canonicalization has fixed cross-language byte vectors.

The upstream implementation owns byte construction and signature verification.
SUT owns the literal route-to-purpose configuration and proves parity with its
JSON contract fixtures. Fixed vectors cover the configured mount prefix,
zero-length and JSON bodies, all five presentation fields, and every canonical
line including the final newline.

## 8. Service contracts and transactions

### 8.1 Challenge issuance

`IssueDeviceProofChallengeCommand` contains device ID and purpose but no time.
The service:

1. validates that the purpose is configured;
2. reads server time;
3. generates 32 random bytes;
4. resolves purpose-specific device eligibility without exposing the result;
5. for an eligible pending or active device, stores the digest, device ID,
   purpose, and expiry;
6. for an unknown or ineligible device, stores no authorizing record;
7. returns the raw challenge and expiry with the same public status and shape.

Unknown, inactive, and active device IDs use the same public status and response
shape. A challenge returned for an unknown or ineligible device can never
verify. The host rate-limits admission before calling the service, and tests
assert that storage errors do not turn device existence into a distinct public
response.

### 8.2 Device registration

Completion receives device ID, public JWK, challenge, and signature. In one
transaction it:

1. locks the pending device and registration challenge;
2. verifies purpose, device match, expiry, and unconsumed state;
3. validates the public JWK and derives its key ID;
4. verifies proof of possession over the upstream registration bytes;
5. inserts key version one as active;
6. consumes the challenge;
7. activates the device.

No active device may exist without one active proof key.

### 8.3 Device-key rotation

Rotation requires a fresh `device_key_rotation` challenge, an active account
binding, an authorization signature from the current key, and proof of
possession from the proposed new key. One transaction:

1. locks the device, active key, binding, and challenge;
2. validates both signatures over bytes containing device ID, old key ID, new
   key ID, next version, and challenge;
3. retires the old key;
4. inserts and activates the next key version;
5. consumes the challenge.

If the current private key is lost, rotation is forbidden. Recovery provisions
a new device identity and revokes or unbinds the old device.

### 8.4 Generic authenticated-device request

`VerifyDeviceRequestCommand` receives the trusted account ID from the access
token, expected purpose, untrusted proof presentation, and trusted request
binding. One transaction:

1. digests and locks the challenge;
2. checks exact device, purpose, expiry, and unconsumed state;
3. locks the active device and exact active key version;
4. loads the active binding for the trusted account and presented device;
5. checks time skew and request-bound Ed25519 signature;
6. consumes the challenge conditionally;
7. returns `VerifiedDeviceRequest`.

Concurrent verification of one challenge produces exactly one success. No host
middleware performs a second identity transaction.

### 8.5 Proof-bound refresh

`RotateRefreshTokenCommand` contains the raw refresh token and untrusted device
proof presentation. It contains no client-supplied operation time, account ID,
session ID, method, path, audience, profile, purpose, or body digest. The Axum
adapter supplies the trusted request binding.

The transaction returns a committed business outcome rather than representing
confirmed reuse as a storage error:

```rust
pub enum RotateRefreshOutcome {
    Rotated(RotateRefreshTokenResult),
    ReuseDetected { session_id: SessionId },
}
```

The service reads the injected clock exactly once before opening the
transaction and uses that `observed_at` value for every expiry, skew,
revocation, issuance, and conditional-update decision. One transaction:

1. digests and locks the presented refresh-token record;
2. loads and locks its session and account;
3. rejects an unknown token, an expired token, a non-active account, a session
   already inactive for a reason other than this request, or a session without
   a device using safe external errors;
4. validates the presented active device, exact active key, binding to the
   locked account, `refresh` challenge purpose, signed time, request binding,
   and Ed25519 signature before disclosing a device relationship or applying
   any reuse penalty;
5. after cryptographic verification, requires the presented device ID to equal
   the locked session device ID;
6. if the presented record is the active current version, conditionally consumes
   the challenge, advances the session version, revokes the old digest with
   reason `rotated`, generates a new raw refresh token, persists only its digest,
   and issues the new access token;
7. if the presented record is an older version revoked with reason `rotated`,
   conditionally consumes the challenge, revokes the session and every token in
   the family with reason `reuse_detected`, and returns
   `ReuseDetected { session_id }`;
8. commits either business outcome; only `Rotated` returns raw tokens.

The HTTP layer maps a committed `ReuseDetected` outcome to the stable
`refresh_token_reuse_detected` response after commit. Cryptographic,
validation, storage, and token-issuance failures return an error and roll back
nonce consumption, token changes, and session changes. Consequently, knowledge
of an old raw refresh token without a valid proof cannot revoke the family.
Provider, entitlement, and model work is never part of this transaction.

Version 2 deliberately uses strict reuse handling. A client must serialize
refresh attempts per session with a single-flight mechanism. A second valid,
concurrent use of the old token is confirmed reuse and revokes the family. A
grace window, successor-token replay, encrypted response cache, and host-
configurable reuse policy are non-goals for this revision.

Logout and refresh introspection digest presented tokens before lookup. Logout
uses server time. Admin projections never return digests or raw token values.

## 9. Store and Postgres requirements

The store interface must express locking intent rather than relying on an outer
middleware transaction. Required operations include:

```text
lock_device(device_id)
lock_active_device_key(device_id)
lock_device_key(key_id)
lock_active_binding(account_id, device_id)
lock_challenge(challenge_digest)
consume_challenge_if_active(challenge_digest, consumed_at)
lock_refresh_token(token_digest)
revoke_refresh_family(session_id, reason, revoked_at)
```

Postgres uses `SELECT ... FOR UPDATE` for locked records and a conditional
update equivalent to:

```sql
UPDATE device_proof_challenges
SET consumed_at_epoch = :observed_at_epoch
WHERE challenge_digest = :challenge_digest
  AND consumed_at_epoch IS NULL
  AND expires_at_epoch > :observed_at_epoch
```

The value of `observed_at_epoch` comes from the service's injected clock, not
the database clock. A zero-row update is replay or expiry, never success. The
database clock may be observed for health diagnostics but is not a second
identity-security time authority.

New storage includes:

- `device_proof_keys` with unique key ID, `(device_id, version)`, and one-active-
  key constraint;
- purpose and challenge digest on device challenges;
- refresh token `BYTEA` digest with a unique index and no raw value;
- revocation reason and indexes for active token-family lookup;
- an upstream schema-version record readable without applying DDL.

Database constraints backstop core invariants; they do not replace core
validation or stable error mapping.

### 9.1 Proof-key storage

`device_proof_keys` contains:

```text
key_id text primary key
device_id uuid not null references devices(id) on delete restrict
algorithm text not null check (algorithm = 'ed25519')
public_jwk text not null
version bigint not null check (version > 0)
status text not null check (status in ('active', 'retired'))
registered_at_epoch bigint not null
retired_at_epoch bigint null
unique (device_id, version)
unique (device_id) where status = 'active'
```

Checks require `retired_at_epoch` to be null exactly for `active` rows. The
canonical public JWK is stored as text so a database JSON serializer cannot
silently change the byte representation used by projections and test vectors.
The server reparses and validates it when loading verification authority.

### 9.2 Challenge storage

The existing `device_nonces` table is retained during expansion and gains
`purpose text` and `challenge_digest bytea`. Enforced rows require a valid
purpose, exactly 32 digest bytes, a unique digest, `expires_at_epoch` later than
`issued_at_epoch`, and `consumed_at_epoch` null or no earlier than issuance.
The raw `challenge` column remains only for `0002_expand`, contains no v2 value,
and is removed by `0004_contract`.

### 9.3 Refresh and schema metadata

`refresh_tokens.token_digest` is `bytea`, exactly 32 bytes, globally unique, and
the only lookup key after enforcement. A check requires `revoked_at_epoch` and
`revocation_reason` to be both null or both non-null. The existing
`(session_id, token_version)` uniqueness remains the monotonic family backstop.
The raw `token_value` column remains null for v2 rows until contraction.

The schema ledger stores one monotonically applied version per configured IDP
schema. A separate single-row security-cutover record stores the v2 cutover ID
and timestamp. Neither record contains deployment secrets or credential
material, and both are readable by the bounded startup health check.

The security cutover also marks every outstanding legacy authorization code as
consumed before the v2 marker commits. This prevents a code issued by a drained
development writer from bypassing the required post-cutover reauthentication.

## 10. Delivery and verification companion

HTTP changes, error disclosure, migration compatibility, health facts, the
complete test matrix, upstream delivery slices, and SUT adoption gates are
defined in
[rust-embedded-idp Production Security Delivery and Verification v2](rust-embedded-idp-production-security-delivery-v2.md).

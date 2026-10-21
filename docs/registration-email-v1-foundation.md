# Registration email v1: D0 contract and I1 foundation

Latest runtime candidate: [I2 implementation and limits](registration-email-v1-runtime.md). The I1 record below is historical.

Date: 2026-10-21. Scope: local D0 engineering freeze and I1 storage/identity
foundation. This is not a released HTTP capability, an OpenAPI publication, or
production security acceptance. SUT's owning revision-2 design is
`docs/engineering/online-registration-abuse-{design,policy,plan}-2026-10-21.md`
in the SUT repository. Production capacity and statistical timing gates remain
open until I2–I5 evidence exists.

## Frozen ownership and contract

IDP owns canonical email, authority/product buckets, candidate credentials,
context/code state, activation eligibility, identity/membership writes,
idempotent receipts, anonymous security events and delivery effects. SUT owns
trusted peer/transport and source/global ingress admission, configuration,
business entitlements, platform audits and consumer UX. SUT must not implement
email counters, rewrite an old conflict into a fake accepted registration, or
add Admin APIs to disclose codes, clear budgets or force sending.

`contracts/registration-email-v1/` owns the draft-2020-12 schemas, 36 fixtures,
canonical hashes and manifest. The required header is
`X-IDP-Registration-Profile: idp-registration-email-v1`. The module paths are
POST `/auth/register`, `/auth/resend-verification`, `/auth/verify-email`.
SUT's current external prefix is `/api/v2`; the profile does not yet run there.
Bodies cannot choose authority, product, profile or account facts.

A register accepts an opaque context and its original `accepted_at_unix_secs`;
its 900-second lifetime and 60-second public resend guidance are not refreshed
by original-key replay. The accepted timestamp is common admission state, not
account/code/delivery state. Resend is a uniform accepted response. Verification
requires context plus code and creates no session, token or entitlement. New
business verification failures use 400 `verification_unavailable`; there is no
fake Bearer challenge. Full status/error shapes are frozen in the contract README.

The default policy revision is 2 in `embedded-idp-core/.../registration_email/policy.rs`.
Smaller bounded policies are permitted for controlled component fixtures; no Host
may advertise the frozen public constants against a different effective policy.
Default numbers are an implementation freeze for isolated validation, not a
production traffic/cost approval. Full-load/timing gates, NAT impacts and Secret
custody remain required release inputs.

Canonical identity trims outer ASCII spaces, preserves local-part case and
lowercases the DNS domain. The supported ASCII dot-atom profile is deliberately
bounded; abuse identity lowercases the local part too, without provider-specific
alias rewriting. The schema rejects noncanonical account writes after cutover.
No automatic account merge is allowed.

## Entry and bypass inventory

| Surface | Current owner/exposure | Required cutover handling |
| --- | --- | --- |
| Three registration POST paths above | IDP tenant-registration router; SUT end-user `/api/v2` | I2 replaces their old DTO/adapter together; profile gate precedes DTO; no old alias or header bypass |
| `/auth/login`, `/auth/refresh`, `/auth/session`, `/auth/logout` | Device-proof router or tenant auth according to Host exposure | IDP adjacent anonymous-failure/KDF and revision recheck in I2; SUT source class remains separate |
| `/bootstrap/auth/login`, `/bootstrap/auth/session`, `/bootstrap/auth/logout` | SUT end-user composition, path allowlist | Same anonymous-login assessment; bootstrap cannot become a registration fallback |
| `/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, `/oidc/introspect`, `/oidc/revoke` | IDP protected protocol routes, Host exposure specific | Maintain proof/client/token scope; no anonymous mailbox/eligibility lookup |
| `/devices/provision`, `/devices/registration-result`, `/devices/complete`, proof challenges and operation results | IDP device protocols, SUT proof/admission middleware | Device result is operation/proof bound; never add mailbox-driven account lookup |
| `/auth/config`, discovery and JWKS GET | SUT route composition | Advertise new registration capability only when actual new adapter/store/policy/worker is loaded |
| `/admin/auth/*`, account/member/security/session/device/audit management | IDP management plus SUT business session/mapping | Preserve double session and permission checks; no OTP/opaque/candidate projections |
| Generic legacy `embedded-idp-axum` root router and direct core/store calls | Other IDP embeddings/reference app | Not production substitutes; old verification-code writer is rejected after explicit extension install; isolate old binaries/ports |
| Password recovery | SUT metadata currently false | No new recovery capability is implied; any later route needs its own anti-enumeration contract |
| Standalone IDP OpenAPI/service identity | Separate product | Deferred until service stability and explicit cutover; no remote service, credential or transport introduced here |

This inventory is a source review of the two checkouts, not an assertion about
all external Hosts or deployed network reachability. I2/I3 release checks must
prove exact mounted routes, aliases, headers and old port isolation at runtime.

## I1 persistence and lock graph

`PostgresRegistrationEmailStore` is an IDP internal storage port. Preparation
accepts a plaintext password only through the core Argon2 path, then seals its
candidate hash/name and canonical email with separate authenticated purposes.
Five independent nonzero keys separate subject, opaque, request, code and
payload purposes; Debug output is redacted. Raw passwords and codes are not
persisted. This is not a secret-inspection HTTP API.

P is a short transaction: shared access-state/tenant → global capacity → new
operation reservation. It never holds global capacity across A/B/C account
work. A/C use operation → authority/product buckets → context → code → account
(only after a matching proof) → membership → receipts/events. A reads no account
or membership and creates no identity. B locks a bounded processing slot/context
and uses nonlocking account snapshots; B creates code/work, never identities.
C creates or activates account/member atomically with consumption, candidate
selection, receipt and event. Anonymous proof failures do not wait on account locks.

Scope/kind/operation is the durable unique key; its digest binds the payload.
Expired same-key reservations can be reclaimed without another new-operation
charge; incremented fences reject old holders. A failed private transaction
retains a bounded P reservation for explicit reconciliation. No receipt is
silently converted into a second attempt. UUIDv7 freshness precedes receipts.

`accepted_seq` prevents late B work from replacing newer accepted generations.
Unready, suppressed, expired, consumed and exhausted contexts do not add mailbox
wrong counts. Rejected traffic cannot slide the block anchor or extend a context.
Counters do not disable accounts or login.

Account credential/status/email changes invalidate older candidates. Member
version and its own invalidation watermark handle suspend/resume; short email
and member deletion tombstones cover deletion/recreation. Membership triggers
never update accounts, avoiding member → account reverse locks. Conservative
same-second rejection is intentional; a fresh later context can proceed.

Delivery claims have fixed deadlines. Unknown physical delivery continues to
occupy an SMTP slot until trusted stop evidence; lease expiry is not evidence
that a network call ended. Receipts derive stored claim fields and generation,
not caller-mutated lease fields. Upkeep uses independent bounded transactions;
context/code/work order is preserved and subject GC shares the advisory subject
gate. No automatic SMTP retry, refund, daemon or startup cleanup is introduced.

## Explicit migration and compatibility

The extension version is `registration_email_v1`, alongside unchanged
`tenant_v6`; no base schema version or automatic startup migration is changed.
The new feature requires PostgreSQL 17+ because `transaction_timeout` bounds the
whole transaction, unlike per-statement timeout. See the official [transaction
settings](https://www.postgresql.org/docs/17/runtime-config-client.html).
This requirement does not upgrade any existing database. The current live
acceptance target is PostgreSQL 18.6; 17 is not claimed as integration-tested.

Plan is read-only and hashes cluster identity, database/schema OIDs and identity
facts with native SHA-256. Explicit apply locks/re-inventories the target before
one transaction of DDL and normalization. Invalid addresses, normalization
collisions, drift, partial install or repeat apply fail closed. Account/member
IDs, hashes and references are retained. Legacy codes are consumed, then the old
code writer is guarded. New bindings are explicit and constrained to the installed
authority/mode; ordinary construction/inspection performs no DDL or pruning.
Migration operators require the documented privileged `pg_control_system`
read in addition to explicit DDL ownership; runtime inspection does not.

Do not run this migration while old writers are live, or point the current SUT
binary at the extended schema. It cannot be safely rolled back by deleting only
new tables or starting the old binary. Keep registration closed and forward-fix
unless a coordinated cutover/rollback has been independently proved. The
foundation reports `public_profile_ready=false` until the later runtime exists.

## Evidence and remaining acceptance

The SUT execution report records exact tests, source hashes and isolated resource
cleanup. Unit/real PostgreSQL tests are not HTTP, real SMTP, browser, two-process,
production timing or deployment acceptance. I2 HTTP/discovery/worker and adjacent
login hardening, S1 shared source gates, I3 pinned integration, I4 full R01–R64
acceptance and I5 release/maintenance rehearsal remain prerequisites. Never
promote a local fixture into production readiness.

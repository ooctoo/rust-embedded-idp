# Registration email v1: I2 runtime candidate

Date: 2026-10-21. This is owning IDP work; no production host or consumer has
been promoted. D0/I1 was signed as `60274ea`; I2 remains a reviewable local
change. See `registration-email-v1-foundation.md` for the identity rules and
`../contracts/registration-email-v1/manifest.json` for the current wire hashes.

The core owns `RegistrationEmailService`, commands, fenced claims and the
shared `PasswordWorkBudget`. The email crate owns the typed physical delivery
port. PostgreSQL owns durable admission and worker facts. Axum owns the thin
three-route `registration_email_router` and bounded runtime supervisor. An
embedding product does not implement its own OTP budgets or fetch codes for
its own sender.

A trusted Host must install the runtime extension explicitly with the
read-only target-bound plan/apply ports. Installation is atomic and paused by
default; normal startup/readiness does not run migrations. Full retention GC
remains the explicit maintenance port. The running worker only expires bounded
work and claims. Plan/apply currently need privileged maintenance access; least
privilege acceptance remains I5. Never enable the new routes over an I1-only
store or roll back to a binary with the retired verification writer.

Host composition must inject one shared password budget into the registration,
tenant, device/bootstrap, management and applicable legacy password services.
Registration can occupy at most two of four KDF slots. The supervisor checks
that its budget is the service's budget; it cannot inspect arbitrary adjacent
Host services. Wrap the complete merged router with
`with_anonymous_login_budget(router, runtime.login_http_budget())`. Module
limits are not a replacement for the Host's shared ingress capacity, source
limiting, body-read deadlines, trusted peer/proxy validation and TLS. The
registration config's Origin allowlist does not attest network TLS. Only
explicit local loopback development uses plaintext; production remains TLS.

Call `runtime.start()` to load workers; new admissions require an actually
running, healthy worker and ready, accepting store. A fresh installation also
requires trusted `resume_after_operator_check()`. There is no public resume,
mail-status or email-exists endpoint. Store pause is persistent and checked in
admission and dispatch transactions. Legitimate prepared verification and
fresh original-key reconciliation remain available when paused.

Processing uses shared leased claims (four total), checks token, sequence and
absolute expiry before committing, and never hashes passwords or sends mail
under identity locks. After a database error, any retry uses the same still
valid claim; expiration does not silently grant another token. Delivery uses
two shared slots. The encrypted payload is atomically consumed once, with a
current-generation/expiry CAS, before invoking the effect adapter. That point
is the logical dispatch grant; a later generation may race an already granted
send, but an old code is never revived. No claim is retried after an unknown
message-take commit.

The trusted delivery adapter must honor its absolute deadline and return only
when its physical call has stopped, with no hidden background sends. It returns
Sent (upstream accepted), Rejected (known nonacceptance), or Unknown. Network
work never holds identity transactions. A timeout marks Unknown and pauses
admission atomically in PostgreSQL, keeps physical local capacity until the
blocking task actually exits, and retains shared quarantine until stop evidence
is recorded. Lease expiry alone never frees uncertain shared capacity or
redispatches the effect. Shutdown stops local admission, drains existing work,
and reports unresolved physical tasks when grace expires; such a shutdown
persists pause. Arbitrary synchronous adapters cannot be forcibly killed by
Tokio cancellation, so provider/network-deadline acceptance is still mandatory.

Tenant password authentication reads a nonlocking credential snapshot, runs
one real/dummy Argon2 operation outside identity locks, then locks by the original email and rechecks its binding and
ID/hash/status in the authoritative issuing transaction. Wrong, unknown,
pending and disabled failure projections are uniform; shared KDF/HTTP slots
survive cancellation until physical work exits. A response floor is not proof
of statistical nonenumerability. Historic PHC cost differences and every
Host alias/legacy/OIDC route remain release-matrix obligations. Legacy generic
routers are not a substitute for the tenant-aware candidate host.

Two I2 errata reconcile the revision-2 design with the earlier implementation:

- Business `verification_unavailable` is HTTP 400, infrastructure
  `temporarily_unavailable` is 503. Three D0 fixture statuses and their checker
  were wrong and now have corrected manifest hashes. The schema/profile is
  unchanged; use only the new manifest.
- Normal tenant `allow_registration=false` blocks new registration while an
  already accepted context can still resend/verify within its existing limits.
  Emergency runtime pause also prevents new resend/dispatch. Neither extends
  context or operation lifetime.

Validation is isolated: core/security/email/store and Axum component tests;
fresh PostgreSQL 18.6 runtime/migration/claim tests; actual loopback HTTP and
SMTP-sink registration, verification and separate password login. These do
not prove browser/Native delivery, official SMTP/TLS, PG17, distributed load,
all 64 revision-2 matrix cases, or target deployment readiness. SUT pinning,
consumer cutover and old-route isolation remain I3; comprehensive fault/timing
acceptance is I4; protected operator recovery, keys, permissions and rollout
are I5. Full counts and artifact fingerprints are recorded in SUT's
`docs/engineering/evidence/online-registration-i2-2026-10-21.json`.

## I4 HTTP canonical-context correction (2026-10-23)

SUT isolated investigation found that the HTTP validator omitted the canonical
Base64URL tail `w`, although the IDP crypto and store accept it. Registration
could commit successfully and then fail the HTTP acceptance check with 503;
resend/verify requests containing the same valid token were rejected as input.
The adapter now accepts all sixteen canonical tails and still rejects nonzero
unused bits, padding and wrong lengths. A deterministic regression checks all
256 final-byte values for generated 32-byte contexts and all 64 possible tail
characters. The test failed before this correction. No profile, policy,
schema, fixture or manifest definition changed. This establishes one concrete
register failure, not the root cause of the historical unclassified resend 503.

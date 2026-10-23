# Storage adapter and worker lifecycle (2026-10-23)

Supersedes the remaining synchronous-adapter and worker boundaries in
[the registration transport checkpoint](registration-email-physical-deadline-2026-10-23.md).
The earlier checkpoint remains historical evidence.

## Ownership and cutover

IDP owns the storage transport, identity SQL/transactions, registration policy,
worker admission, physical-work accounting and shutdown report. SUT owns Host
composition, configuration validation, source limiting, process signals and the
one total process deadline. No identity schema, HTTP contract, policy revision,
mutation retry, automatic resume or alternate authoritative adapter is added.

All `PostgresStorageAdapter` clones now share one owned Tokio PostgreSQL
transport and one semaphore, including legacy access/session/device/admin and
registration paths. There are no idle r2d2/native-TLS connections. The adapter
retains its configured maximum; independent adapters and Host pools still add
to process capacity. This is not production sizing acceptance.

`PgPooledConnection` is the existing public name for a fresh owned lease. It no
longer dereferences to `postgres::Client`. Consumers use `PgTransaction`,
`PgError` and the closed `PgExecutor` SQL subset. Native Row, ToSql and isolation
level types are preserved. No synchronous fallback or compatibility executor is
kept. The synchronous `postgres` dependency remains only in isolated fixtures.

## Physical budgets and lifecycle

A normal adapter lease has one absolute 10-second deadline including capacity
wait, TCP/TLS/authentication, caller idle time, BEGIN, all queries and COMMIT.
Legacy schema health uses five seconds. Explicit initialization/migration/apply
uses an internal 60-second setup lease, preserving the existing session advisory
lock and SQL script transaction boundaries. Setup is explicit and never a normal
startup mutation. A composed service may acquire several leases; these are not
end-to-end HTTP deadlines.

Registration retains its existing five-second read and ten-second identity
budgets and PG17+ `transaction_timeout`. Generic access does not newly require
that parameter; statement/lock/idle server limits and the physical client timer
remain. This preserves old generic PostgreSQL parameter compatibility; live
acceptance here uses PostgreSQL 18.3 only.

One one-worker Tokio runtime per transport drives all its native connection
futures and deadlines. It closes an idle expired driver independently of the
caller. The lease retains capacity until actual driver shutdown/join and Drop.
Synchronous calls and runtime destruction work outside Tokio and inside both
current-thread and multi-thread Hosts. Transactions, rollback-on-drop and COMMIT
remain native. A COMMIT timeout does not prove rollback; explicit readback or
original-operation replay observes the authoritative result. Transport never
retries a mutation.

DNS resolution cannot be physically cancelled through libc. A TLS DNS name must
therefore have one trusted numeric `hostaddr`; certificate validation still uses
the DNS name and configured CA. Literal numeric hosts need no resolver. Missing
or malformed dial addresses reject access. Production still requires verified
TLS; plaintext remains an explicit literal-loopback development option only.

## Worker shutdown

`begin_shutdown(grace)` closes admission immediately and fixes an idempotent
absolute deadline; later calls may shorten but cannot extend it. Every storage
blocking closure retains a physical counter until actual closure destruction.
Processing, SMTP and HTTP request permits likewise remain held by physical work.
Storage panics map to unavailable instead of silently losing accounting.

Shutdown stops new maintenance/claims and waits existing work within that same
deadline. On expiry it aborts and joins the outer async task, without pretending
that this abort killed a blocking closure and without appending a pause write.
The report adds unresolved storage/request counts and a failed latch. `drained`
requires the outer task joined and every physical counter/permit reached zero;
it may coexist with `failed` after a real prior fault, so Hosts must check both.
A short budget truthfully returns unresolved; driver deadlines still close the
physical connection. Drop signals stop/abort and never claims successful drain.
There is no automatic unpause, lease reset, redistribution or mutation retry.

The SUT consumer starts this deadline when HTTP draining starts and spends one
G + F + 5s budget across HTTP/audit/server/worker, reserving at most one second
for Host runtime shutdown. Pending or failed work causes a nonzero process exit.
That process-exit bound is distinct from a library report proving physical drain.

## Acceptance and limits

Component acceptance covers blocked facts, maintenance, claims and pause,
request completion/cancellation, physical permits, admission fencing and SMTP
unknown/stop confirmation. Real wire cases cover old adapter BEGIN/query/COMMIT,
idle expiry with retained capacity, runtime-flavor destruction, panic unwind and
async cancellation; worker wire cases cover short query and long BEGIN shutdown.
The relay stays alive until observed EOF; teardown cannot manufacture a pass.
SUT additionally tests SIGTERM under a worker query blackhole and rejects a clean
exit while the physical storage call remains unresolved.

Final owning checks: 466 library tests pass. The latest results for all 18
storage live targets total 198 passing cases (combined targeted runs, not a
claim that the earlier interrupted full invocation passed). Reference app
all-target checking passes after building its own locked Web assets offline.
The unchanged old fdecd391 source plus the new lifecycle test rejects the old
implementation with a nested-runtime panic and no observed EOF.

Earlier attempts remain failures: two obsolete backend-PID-reuse assertions;
a candidate-only regression that narrowed successful preparation to Prepared
and incorrectly paused on Suppressed/Superseded; and a new fixture that tried
to use its native cleanup client inside Tokio. The final source preserves all
successful preparation terminal states, latches real job failure during stop,
and destroys that fixture outside its Host runtime. None attributes the old 503.

Frozen counts, timings, source fingerprints, failures and cleanup evidence live
in the SUT execution record `online-idp-adapter-worker-deadline-2026-10-23.md`.
No existing database, deployment, remote push or production acceptance is part
of this work. The historical intermittent resend 503 remains unattributed until
a diagnostic snapshot from the same failure establishes its cause. Controlled
faults and successful reruns do not retrospectively attribute that event.

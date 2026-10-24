# Registration control closeout — 2026-10-24

This closes the known operator-resume race from the
[adapter/worker checkpoint](storage-adapter-worker-lifecycle-2026-10-23.md).
It adds no identity feature, route, SQL, policy, schema, retry or public API.

A trusted operator resume now acquires one of the existing four probe permits
under the same admission fence as shutdown. A private async mutex serializes
pause/resume effects, and its owned guard moves into the actual blocking
closure together with the physical permit. Cancellation cannot release either
before the database operation ends. Waiters are bounded by those same permits.

Every local failure increments a revision under admission. Resume checks that
revision and running/stopping both before dispatch and after its committed
result. It cannot clear a newer failure, restore a stopped worker or dispatch
a queued control call after stop. A newer pause waits for an already dispatched
resume effect, then persists its pause; this preserves physical write order.
The synchronous admission mutex is never held across an await; the owned
effect mutex remains held by the physical closure.

A pre-stop resume may commit before the caller learns shutdown won the race.
The result remains unavailable/unknown to that caller; there is no compensating
write, automatic retry, falsely clean drain or claim that abort cancelled SQL.
Hosts still inspect both failed and drained, and explicitly reconcile facts.

Four regression tests were first run against unchanged d588d48 production:
one success passed and three race/accounting assertions failed. After the fix,
all four pass. A fifth test fills all four control slots, rejects a fifth,
stops admission and proves only the already dispatched effect executes.
The initial complete Axum library passes 145 tests. A final dispatch-fence
follow-up passes 146: stop/revision checking, physical counter registration
and spawn now happen inside one admission critical section. A queued pause
after stop performs no database write. The admission lock is released before
awaiting the JoinHandle; budgets and SQL remain unchanged.

Two opt-in wire tests exercise real inspect_schema_health (5s) and
initialize_access_schema BEGIN (60s). They observe driver EOF and call-thread
join while the relay remains open, then recover through a fresh connection.
Their physical observation allowance is one second; the production budgets
remain unchanged. Results, source fingerprints and isolated cleanup are recorded
in SUT's first-release closeout execution evidence, not inferred from compilation.

The full P/B/D/reaper/GC failure and cross-process fencing matrix, statistical
anti-enumeration and natural long windows remain required and unfinished.
The historical resend 503 is still unattributed. No existing database, deployed
service, remote push, standalone IDP cutover or production acceptance is included.

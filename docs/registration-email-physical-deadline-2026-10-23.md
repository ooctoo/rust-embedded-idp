# Registration PostgreSQL physical deadlines (2026-10-23)

This change is based on `6b6f9d9565bff1c151a8edf2f9d3ed54a1e89355`. It belongs to the IDP registration-email storage adapter, not to SUT identity policy. Policy revision 2, the `idp-registration-email-v1` profile, schemas, fixtures and manifest hashes are unchanged. No existing database, deployed service or remote ref was changed.

## Implemented boundary

The registration store keeps its synchronous Core service contract. A private bridge drives native `tokio-postgres::Client` and `Transaction` futures on an owned current-thread runtime. Original SQL, parameter order, transaction boundaries, savepoints, lock order and error projections remain. COMMIT and rollback use native transaction semantics; no mutation is automatically retried.

Each connection has one absolute deadline covering capacity wait, connect/authentication, BEGIN, all queries, COMMIT and rollback. Existing replay/read-only paths use 5 seconds; identity/runtime transactions use the frozen 10-second policy. Startup PostgreSQL options enforce server limits before BEGIN acknowledgement. Existing connection options are preserved, with owned timeouts appended. The construction/runtime foundation inspection is also read-only and physically bounded at 10 seconds. Existing version/catalog checks remain; the redundant constructor version query is removed.

Timeout aborts and awaits the actual connection driver before returning a neutral storage error. Connection Drop also joins it before releasing capacity. An expired connection cannot execute more queries. There is no broken pooled registration connection or detached mutation. Socket closure does not prove remote rollback: A/C may already have committed. Explicit original-operation replay reads the authoritative facts; there is no refund, fresh-key substitution or automatic mutation retry.

Clones of one `PostgresStorageAdapter` share registration capacity across scopes, capped at `pool.max_connections` live connections with no idle registration connections. Other adapter paths retain their original synchronous pool. The two physical pools require a combined budget of up to twice the configured maximum, plus other Host pools, before release. This change does not raise configuration values or establish production capacity acceptance. Processing/SMTP policy limits are unchanged.

## TLS and composition

Registration uses locked `tokio-postgres-rustls` 0.14.0, an explicit Ring provider, safe Rustls versions, WebPKI roots and any explicit PEM CA. Chain/hostname verification remains enabled, without native-TLS fallback. Custom system roots must use the existing CA configuration. Only the trusted Host's development/loopback policy allows plaintext.

Database calls never invoke uncancellable libc DNS. Literal PostgreSQL hosts or matching trusted `hostaddr` entries are required; the DNS hostname still authenticates TLS. Disabling hostname checks is not a workaround. Loading trusted local configuration/certificates is composition work outside the database-call deadline. Target DNS/CA/connection capacity validation remains a release prerequisite.

## Executable acceptance

Ignored tests require an explicitly confirmed fresh loopback `sut_idp3_test` and random disposable schemas. BEGIN/query blackholes exercise the actual 5-second `is_replay` path. Register/verify COMMIT tests skip the reservation COMMIT and withhold the final A/C acknowledgement. Selected-connection EOF and caller join precede disabling the fault; constructor/idle EOF cannot substitute. Relay teardown is only timeout rescue for a failed test.

A/C tests independently read authority facts, then replay the original key without adding contexts, intents, accounts, memberships, consumed codes or receipts. Verify must replay its original `Verified` result. Strict TLS tests accept the temporary CA/hostname, reject IP mismatch and untrusted CA, and stop SSL negotiation blackholes before direct TLS recovery. They do not proxy encrypted SQL frames or prove production PKI.

The exact new BEGIN regression also ran against an unchanged `6b6f9d9` archive with only test files added: it failed beyond the 6-second observation window, without physical EOF until relay rescue. The fixed candidate initially passed all four store cases, approximately 5,001ms for reads and 10,008–10,031ms for commits. SUT's execution record retains frozen final counts, safe markers and failure fingerprints.

## Frozen local validation

All 28 non-document source fingerprints matched after the final run. Five owning libraries passed 455 tests with no failures or ignored cases. The storage crate all-target check passed. Six real isolated targets passed 55 tests: foundation 31, migration 7, runtime store 9, HTTP 2, store blackholes/recovery 4 and TLS 2. Seven before/after inventories found no extra schemas, roles or connections. These checks used only the freshly created PostgreSQL 18.3 loopback/tmpfs instance with a temporary CA. The separate old-revision regression failed as expected and is retained as negative evidence.

The implementation preserves all 95 SQL literals across the 15 runtime store files. Scoped formatting, diff and document-link checks passed. This is local integration evidence, not published dependency, remote CI, target deployment or full I4/I5 acceptance. The isolated instance is retained only until the consuming SUT run completes, then must be verified and destroyed with its temporary TLS keys.

## Remaining gates

Generic legacy account/session/device/admin operations and explicit offline migration/apply still use the synchronous pool; this is not an adapter-wide deadline claim. Composed service/HTTP operations may use multiple separately bounded connections and CPU work; 5/10 seconds is not an end-to-end HTTP promise.

All registration worker/maintenance connection sites use the bridge, but negative tests for every claim/B/D/GC point, process suspension, partition and lease-fencing permutation remain open. SMTP unknown/stop-evidence and trusted operator recovery rules are unchanged. Natural long windows, anti-enumeration statistics and capacity remain separate I4/I5 gates.

Historical unclassified resend 503 remains unattributed. Known source-lock, store-pause, runtime-latch or audit-failure experiments cannot establish past causality without phase facts. Preserve complete new samples and failures without secrets, mutation retries, quota resets or lease manipulation. Dependency publication and remote CI still require authorization.

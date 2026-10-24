//! Isolated PostgreSQL lock-release acceptance for the legacy synchronous adapter.
//!
//! These probes are intentionally ignored by default. They use the fresh
//! loopback fixture and record only bounded, fixed-category backend evidence.
//! No backend is terminated and no cleanup retry is used as evidence.

#![allow(dead_code, unused_imports)]

mod registration_email_support;

use postgres::{Client, NoTls};
use registration_email_support::Fixture;
use serde_json::json;
use std::time::{Duration, Instant};

const LOCK_TIMEOUT: &str = "250ms";
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const LOCK_TABLE: &str = "legacy_adapter_lock_probe";
const COMMIT_PARENT_TABLE: &str = "legacy_adapter_commit_parent";
const COMMIT_CHILD_TABLE: &str = "legacy_adapter_commit_child";

#[derive(Clone, Copy, Debug)]
struct BackendObservation {
    backend_present: bool,
    idle_in_transaction: bool,
    lock_held: bool,
}

fn install_probe_tables(fixture: &Fixture) {
    let mut client = fixture.adapter.connect().expect("probe setup connection");
    client
        .batch_execute(&format!(
            "create table {schema}.{lock_table}(id integer primary key); \
             create table {schema}.{parent_table}(id integer primary key); \
             create table {schema}.{child_table}(id integer primary key, parent_id integer not null references {schema}.{parent_table}(id) deferrable initially deferred)",
            schema = fixture.schema,
            lock_table = LOCK_TABLE,
            parent_table = COMMIT_PARENT_TABLE,
            child_table = COMMIT_CHILD_TABLE,
        ))
        .expect("probe tables");
}

fn relation_oid(observer: &mut Client, fixture: &Fixture, table: &str) -> i64 {
    observer
        .query_one(
            "select c.oid::bigint
             from pg_class c
             join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = $1 and c.relname = $2",
            &[&fixture.schema, &table],
        )
        .expect("probe relation oid")
        .get(0)
}

fn backend_pid(client: &mut embedded_idp_storage_postgres::PgPooledConnection) -> i32 {
    client
        .query_one("select pg_backend_pid()", &[])
        .expect("adapter backend pid")
        .get(0)
}

fn observer(uri: &str) -> Client {
    let mut client = Client::connect(uri, NoTls).expect("observation connection");
    client
        .batch_execute(&format!(
            "set statement_timeout='1s'; set lock_timeout='{LOCK_TIMEOUT}'"
        ))
        .expect("observation timeouts");
    client
}

fn observe(observer: &mut Client, pid: i32, relation: i64) -> BackendObservation {
    let row = observer
        .query_one(
            "select
                 exists(select 1 from pg_stat_activity where pid=$1),
                 coalesce((select state='idle in transaction' or state='idle in transaction (aborted)' from pg_stat_activity where pid=$1),false),
                 exists(select 1 from pg_locks where pid=$1 and relation::bigint=$2 and granted)",
            &[&pid, &relation],
        )
        .expect("backend observation");
    BackendObservation {
        backend_present: row.get(0),
        idle_in_transaction: row.get(1),
        lock_held: row.get(2),
    }
}

fn wait_for<F>(
    observer: &mut Client,
    pid: i32,
    relation: i64,
    mut predicate: F,
) -> (BackendObservation, u128)
where
    F: FnMut(BackendObservation) -> bool,
{
    let started = Instant::now();
    let deadline = started + OBSERVATION_TIMEOUT;
    let mut last = observe(observer, pid, relation);
    while !predicate(last) && Instant::now() < deadline {
        std::thread::sleep(POLL_INTERVAL);
        last = observe(observer, pid, relation);
    }
    (last, started.elapsed().as_millis())
}

fn peer_lock_probe(uri: &str, fixture: &Fixture, table: &str) -> bool {
    let mut client = match Client::connect(uri, NoTls) {
        Ok(client) => client,
        Err(_) => return false,
    };
    let sql = format!(
        "set statement_timeout='1s'; set lock_timeout='{LOCK_TIMEOUT}'; begin; lock table {}.{} in access share mode; rollback",
        fixture.schema, table
    );
    client.batch_execute(&sql).is_ok()
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn implicit_transaction_drop_releases_lock_while_client_is_retained() {
    let fixture = Fixture::new();
    install_probe_tables(&fixture);
    let mut held = fixture.adapter.connect().expect("held adapter client");
    let pid = backend_pid(&mut held);
    let mut inspection = observer(&fixture.uri);
    let relation = relation_oid(&mut inspection, &fixture, LOCK_TABLE);

    let mut transaction = held.transaction().expect("implicit-drop transaction");
    transaction
        .batch_execute(&format!(
            "lock table {}.{} in access exclusive mode",
            fixture.schema, LOCK_TABLE
        ))
        .expect("exclusive lock");
    let before_drop = observe(&mut inspection, pid, relation);
    assert!(
        before_drop.backend_present,
        "client backend was not observed"
    );
    assert!(before_drop.lock_held, "exclusive lock was not observed");
    drop(transaction);

    let (after_drop, elapsed_ms) = wait_for(&mut inspection, pid, relation, |state| {
        state.backend_present && !state.idle_in_transaction && !state.lock_held
    });
    let peer_probe = peer_lock_probe(&fixture.uri, &fixture, LOCK_TABLE);
    println!(
        "SUT_IDP_LEGACY_LOCK_RELEASE {}",
        json!({
            "mode": "implicit_transaction_drop",
            "backend_pid": pid,
            "backend_present_before_drop": before_drop.backend_present,
            "lock_held_before_drop": before_drop.lock_held,
            "backend_present_after_drop": after_drop.backend_present,
            "idle_in_transaction_after_drop": after_drop.idle_in_transaction,
            "lock_held_after_drop": after_drop.lock_held,
            "peer_lock_probe": peer_probe,
            "elapsed_ms": elapsed_ms,
        })
    );

    assert!(
        after_drop.backend_present,
        "client must remain alive after tx drop"
    );
    assert!(!after_drop.idle_in_transaction);
    assert!(!after_drop.lock_held);
    assert!(peer_probe, "peer lock probe remained blocked after tx drop");
    drop(held);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn deferred_commit_error_releases_lock_while_client_is_retained() {
    let fixture = Fixture::new();
    install_probe_tables(&fixture);
    let mut held = fixture.adapter.connect().expect("held adapter client");
    let pid = backend_pid(&mut held);
    let mut inspection = observer(&fixture.uri);
    let relation = relation_oid(&mut inspection, &fixture, COMMIT_CHILD_TABLE);

    let mut transaction = held.transaction().expect("deferred-commit transaction");
    transaction
        .execute(
            &format!(
                "insert into {}.{}(id,parent_id) values (1,999)",
                fixture.schema, COMMIT_CHILD_TABLE
            ),
            &[],
        )
        .expect("deferred foreign-key write");
    let commit_started = Instant::now();
    let commit_error = transaction
        .commit()
        .expect_err("deferred constraint commit must fail");
    assert_eq!(
        commit_error.code().map(|code| code.code()),
        Some("23503"),
        "deferred constraint must report foreign_key_violation"
    );
    let after_commit = observe(&mut inspection, pid, relation);
    assert!(
        after_commit.backend_present,
        "client disappeared after commit error"
    );
    assert!(!after_commit.idle_in_transaction);
    assert!(!after_commit.lock_held);

    held.batch_execute("rollback")
        .expect("explicit rollback after deferred commit error");
    let (after_rollback, elapsed_ms) = wait_for(&mut inspection, pid, relation, |state| {
        state.backend_present && !state.idle_in_transaction && !state.lock_held
    });
    let peer_probe = peer_lock_probe(&fixture.uri, &fixture, COMMIT_CHILD_TABLE);
    println!(
        "SUT_IDP_LEGACY_LOCK_RELEASE {}",
        json!({
            "mode": "deferred_commit_error",
            "backend_pid": pid,
            "commit_sqlstate_23503": commit_error.code().map(|code| code.code()) == Some("23503"),
            "backend_present_after_commit": after_commit.backend_present,
            "idle_in_transaction_after_commit": after_commit.idle_in_transaction,
            "lock_held_after_commit": after_commit.lock_held,
            "backend_present_after_rollback": after_rollback.backend_present,
            "idle_in_transaction_after_rollback": after_rollback.idle_in_transaction,
            "lock_held_after_rollback": after_rollback.lock_held,
            "peer_lock_probe": peer_probe,
            "elapsed_ms": commit_started.elapsed().as_millis().max(elapsed_ms),
        })
    );

    assert!(
        after_rollback.backend_present,
        "client did not survive explicit rollback"
    );
    assert!(!after_rollback.idle_in_transaction);
    assert!(!after_rollback.lock_held);
    assert!(
        peer_probe,
        "peer lock probe remained blocked after rollback"
    );
    drop(held);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn dropping_client_with_held_transaction_releases_backend_and_lock() {
    let fixture = Fixture::new();
    install_probe_tables(&fixture);
    let mut held = fixture.adapter.connect().expect("held adapter client");
    let pid = backend_pid(&mut held);
    let mut inspection = observer(&fixture.uri);
    let relation = relation_oid(&mut inspection, &fixture, LOCK_TABLE);

    held.batch_execute(&format!(
        "begin; lock table {}.{} in access exclusive mode",
        fixture.schema, LOCK_TABLE
    ))
    .expect("held transaction lock");
    let before_drop = observe(&mut inspection, pid, relation);
    assert!(before_drop.backend_present);
    assert!(before_drop.lock_held);
    drop(held);

    let (after_drop, elapsed_ms) = wait_for(&mut inspection, pid, relation, |state| {
        !state.backend_present && !state.lock_held
    });
    let peer_probe = peer_lock_probe(&fixture.uri, &fixture, LOCK_TABLE);
    println!(
        "SUT_IDP_LEGACY_LOCK_RELEASE {}",
        json!({
            "mode": "client_drop_transaction",
            "backend_pid": pid,
            "backend_present_before_drop": before_drop.backend_present,
            "lock_held_before_drop": before_drop.lock_held,
            "backend_present_after_drop": after_drop.backend_present,
            "idle_in_transaction_after_drop": after_drop.idle_in_transaction,
            "lock_held_after_drop": after_drop.lock_held,
            "peer_lock_probe": peer_probe,
            "elapsed_ms": elapsed_ms,
        })
    );

    assert!(
        !after_drop.backend_present,
        "client backend survived client drop"
    );
    assert!(!after_drop.idle_in_transaction);
    assert!(!after_drop.lock_held);
    assert!(
        peer_probe,
        "peer lock probe remained blocked after client drop"
    );
}

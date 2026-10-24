#![allow(dead_code, unused_imports)]
mod registration_email_support;
mod registration_transport_support;
use embedded_idp_storage_postgres::PostgresStorageAdapter;
use postgres::{Client, NoTls};
use registration_email_support::Fixture;
use registration_transport_support::{database, relay_adapter, Cut, Relay};
use serde_json::json;
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const LOCK_TABLE: &str = "legacy_adapter_active_backend_probe";
const PRE_SLEEP_WAIT: Duration = Duration::from_secs(7);
const ACTIVE_WAIT: Duration = Duration::from_secs(3);
const CALL_WAIT: Duration = Duration::from_secs(6);
const OBSERVATION_WAIT: Duration = Duration::from_secs(8);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
#[derive(Clone, Copy, Debug)]
struct BackendObservation {
    backend_present: bool,
    active_pg_sleep: bool,
    lock_held: bool,
}
#[derive(Clone, Copy, Debug)]
struct StartupLimits {
    statement_timeout_10s: bool,
    lock_timeout_1s: bool,
    idle_in_transaction_timeout_10s: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerLockOutcome {
    Acquired,
    LockTimeout55p03,
    StatementTimeout57014,
    OtherSqlState,
    OtherError,
}
#[derive(Clone, Copy, Debug)]
struct ActiveCallEvidence {
    call_returned_error: Option<bool>,
    active_sql_observed: bool,
    physical_eof: bool,
    thread_joined: bool,
    total_lease_elapsed_ms: u128,
}

fn install_probe_table(fixture: &Fixture) {
    let mut client = fixture.adapter.connect().expect("probe setup connection");
    client
        .batch_execute(&format!(
            "create table {}.{}(id integer primary key)",
            fixture.schema, LOCK_TABLE
        ))
        .expect("probe table");
}

fn bounded_uri(uri: &str) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };
    format!("{uri}{separator}connect_timeout=1")
}

fn observer(uri: &str) -> Client {
    let mut client = Client::connect(&bounded_uri(uri), NoTls).expect("observation connection");
    client
        .batch_execute("set statement_timeout='1s'; set lock_timeout='1s'")
        .expect("observation timeouts");
    client
}

fn backend_pid(client: &mut embedded_idp_storage_postgres::PgPooledConnection) -> i32 {
    client
        .query_one("select pg_backend_pid()", &[])
        .expect("adapter backend pid")
        .get(0)
}

fn startup_limits(client: &mut embedded_idp_storage_postgres::PgPooledConnection) -> StartupLimits {
    let row = client
        .query_one(
            "select
                 current_setting('statement_timeout')::interval = interval '10 seconds',
                 current_setting('lock_timeout')::interval = interval '1 second',
                 current_setting('idle_in_transaction_session_timeout')::interval = interval '10 seconds'",
            &[],
        )
        .expect("adapter startup limits");
    StartupLimits {
        statement_timeout_10s: row.get(0),
        lock_timeout_1s: row.get(1),
        idle_in_transaction_timeout_10s: row.get(2),
    }
}

fn relation_oid(observer: &mut Client, schema: &str) -> i64 {
    observer
        .query_one(
            "select c.oid::bigint
             from pg_class c
             join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = $1 and c.relname = $2",
            &[&schema, &LOCK_TABLE],
        )
        .expect("probe relation oid")
        .get(0)
}

fn observe(observer: &mut Client, pid: i32, relation: i64) -> BackendObservation {
    let row = observer
        .query_one(
            "select
                 exists(select 1 from pg_stat_activity where pid=$1),
                 coalesce((select state='active' and wait_event='PgSleep' from pg_stat_activity where pid=$1), false),
                 exists(select 1 from pg_locks where pid=$1 and relation::bigint=$2 and granted)",
            &[&pid, &relation],
        )
        .expect("backend observation");
    BackendObservation {
        backend_present: row.get(0),
        active_pg_sleep: row.get(1),
        lock_held: row.get(2),
    }
}

fn wait_for<F>(
    observer: &mut Client,
    pid: i32,
    relation: i64,
    timeout: Duration,
    mut done: F,
) -> (BackendObservation, u128)
where
    F: FnMut(BackendObservation) -> bool,
{
    let started = Instant::now();
    let deadline = started + timeout;
    let mut last = observe(observer, pid, relation);
    while !done(last) && Instant::now() < deadline {
        thread::sleep(POLL_INTERVAL);
        last = observe(observer, pid, relation);
    }
    (last, started.elapsed().as_millis())
}

fn peer_lock_probe(uri: &str, fixture: &Fixture) -> PeerLockOutcome {
    let mut client = match Client::connect(&bounded_uri(uri), NoTls) {
        Ok(client) => client,
        Err(_) => return PeerLockOutcome::OtherError,
    };
    if client
        .batch_execute("set statement_timeout='2s'; set lock_timeout='1s'; begin")
        .is_err()
    {
        return PeerLockOutcome::OtherError;
    }
    let result = client.batch_execute(&format!(
        "lock table {}.{} in access share mode",
        fixture.schema, LOCK_TABLE
    ));
    let outcome = match result {
        Ok(()) => PeerLockOutcome::Acquired,
        Err(error) if error.code().is_some_and(|code| code.code() == "55P03") => {
            PeerLockOutcome::LockTimeout55p03
        }
        Err(error) if error.code().is_some_and(|code| code.code() == "57014") => {
            PeerLockOutcome::StatementTimeout57014
        }
        Err(error) if error.code().is_some() => PeerLockOutcome::OtherSqlState,
        Err(_) => PeerLockOutcome::OtherError,
    };
    let _ = client.batch_execute("rollback");
    outcome
}

fn run_active_call(
    adapter: PostgresStorageAdapter,
    schema: String,
    uri: &str,
    relay: &mut Relay,
) -> (i32, StartupLimits, ActiveCallEvidence) {
    let peer_eof_before = relay.peer_eof();
    let (ready_sender, ready_receiver) = mpsc::channel();
    let (start_sender, start_receiver) = mpsc::channel();
    let (result_sender, result_receiver) = mpsc::channel();
    let lock_sql = format!(
        "lock table {}.{} in access exclusive mode",
        schema, LOCK_TABLE
    );
    let worker = thread::spawn(move || {
        let lease_started = Instant::now();
        let mut client = adapter.connect().expect("active probe connection");
        let pid = backend_pid(&mut client);
        let limits = startup_limits(&mut client);
        let mut transaction = client.transaction().expect("active probe transaction");
        transaction
            .batch_execute(&lock_sql)
            .expect("exclusive probe lock");
        ready_sender
            .send((pid, limits, lease_started))
            .expect("active probe ready");
        start_receiver.recv().expect("active probe start");
        let result = transaction.query_one("select pg_sleep(6)", &[]).is_err();
        let _ = result_sender.send(result);
    });

    let (pid, limits, lease_started) = ready_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("active probe setup");
    thread::sleep(PRE_SLEEP_WAIT);
    let mut inspection = observer(uri);
    let relation = relation_oid(&mut inspection, &schema);
    start_sender.send(()).expect("active probe release");
    let (active_state, _) = wait_for(&mut inspection, pid, relation, ACTIVE_WAIT, |state| {
        state.backend_present && state.active_pg_sleep && state.lock_held
    });
    let call_returned_error = result_receiver.recv_timeout(CALL_WAIT).ok();
    let physical_eof =
        call_returned_error.is_some() && relay.wait_for_peer_eof(peer_eof_before + 1);
    let thread_joined = worker.join().is_ok();
    (
        pid,
        limits,
        ActiveCallEvidence {
            call_returned_error,
            active_sql_observed: active_state.active_pg_sleep && active_state.lock_held,
            physical_eof,
            thread_joined,
            total_lease_elapsed_ms: lease_started.elapsed().as_millis(),
        },
    )
}

fn recovered(fixture: &Fixture) -> bool {
    let Ok(mut client) = fixture.adapter.connect() else {
        return false;
    };
    client.query_one("select 1", &[]).is_ok()
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn ordinary_adapter_lease_observes_active_backend_after_driver_deadline() {
    let fixture = Fixture::new();
    install_probe_table(&fixture);
    let mut relay = Relay::new(database(), Cut::Startup);
    let adapter = relay_adapter(&fixture, &relay);
    let (pid, limits, evidence) =
        run_active_call(adapter, fixture.schema.clone(), &fixture.uri, &mut relay);
    let mut inspection = observer(&fixture.uri);
    let relation = relation_oid(&mut inspection, &fixture.schema);
    let post_call = observe(&mut inspection, pid, relation);
    let peer = peer_lock_probe(&fixture.uri, &fixture);
    let (after_wait, release_elapsed_ms) =
        wait_for(&mut inspection, pid, relation, OBSERVATION_WAIT, |state| {
            !state.backend_present && !state.lock_held
        });
    let recovered = recovered(&fixture);

    println!(
        "SUT_IDP_ACTIVE_BACKEND {}",
        json!({
            "backend_pid": pid,
            "statement_timeout_10s": limits.statement_timeout_10s,
            "lock_timeout_1s": limits.lock_timeout_1s,
            "idle_in_transaction_timeout_10s": limits.idle_in_transaction_timeout_10s,
            "active_sql_observed": evidence.active_sql_observed,
            "call_returned_error": evidence.call_returned_error == Some(true),
            "physical_eof": evidence.physical_eof,
            "thread_joined": evidence.thread_joined,
            "total_lease_elapsed_ms": evidence.total_lease_elapsed_ms,
            "post_call_backend_present": post_call.backend_present,
            "post_call_lock_held": post_call.lock_held,
            "peer_lock_outcome": format!("{peer:?}"),
            "after_wait_backend_present": after_wait.backend_present,
            "after_wait_lock_held": after_wait.lock_held,
            "release_elapsed_ms": release_elapsed_ms,
            "recovered": recovered,
        })
    );

    assert!(limits.statement_timeout_10s);
    assert!(limits.lock_timeout_1s);
    assert!(limits.idle_in_transaction_timeout_10s);
    assert!(evidence.active_sql_observed);
    assert_eq!(evidence.call_returned_error, Some(true));
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert!((9_000..=10_500).contains(&evidence.total_lease_elapsed_ms));
    match (post_call.lock_held, peer) {
        (true, PeerLockOutcome::LockTimeout55p03) | (false, PeerLockOutcome::Acquired) => {}
        _ => panic!("peer lock result did not match observed lock state"),
    }
    assert!(!after_wait.backend_present);
    assert!(!after_wait.lock_held);
    assert!(recovered);
    relay.close();
}

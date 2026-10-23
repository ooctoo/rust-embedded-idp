//! Physical deadline and lifecycle acceptance for the legacy storage adapter.
//!
//! These probes are intentionally ignored by default.  They require the fresh
//! loopback PostgreSQL instance selected by `registration_email_support` and
//! keep the relay alive until the driver's socket EOF has been observed.  A
//! relay cleanup is therefore never used as evidence that the owned transport
//! stopped.

#![allow(dead_code, unused_imports)]

mod registration_email_support;
mod registration_transport_support;

use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresStorageAdapter,
};
use registration_email_support::Fixture;
use registration_transport_support::{
    database, finish_call, relay_adapter, Cut, Relay, IDENTITY_DEADLINE,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use tokio::runtime::Builder;
use tokio::sync::oneshot;

const ADAPTER_DEADLINE: Duration = Duration::from_secs(11);

fn one_slot_relay_adapter(fixture: &Fixture, relay: &Relay) -> PostgresStorageAdapter {
    let mut config = fixture.adapter.config().clone();
    config.connection.connection_uri = config
        .connection
        .connection_uri
        .replace("127.0.0.1:51412", &format!("127.0.0.1:{}", relay.port));
    config.pool = DbPoolConfig {
        application_name: "legacy-adapter-physical-live".to_string(),
        max_connections: 1,
        connect_timeout_secs: 1,
    };
    PostgresStorageAdapter::new(PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri: config.connection.connection_uri,
            schema_name: config.connection.schema_name,
            tls_mode: PgTlsMode::Disable,
            tls_ca_cert_path: None,
        },
        pool: config.pool,
    })
    .expect("relay adapter")
}

fn print_marker(
    mode: &str,
    elapsed_ms: u128,
    physical_eof: bool,
    thread_joined: bool,
    recovered: bool,
) {
    println!(
        "SUT_IDP_LEGACY_ADAPTER {{\"mode\":\"{}\",\"elapsed_ms\":{},\"physical_eof\":{},\"thread_joined\":{},\"recovered\":{}}}",
        mode,
        elapsed_ms,
        physical_eof,
        thread_joined,
        recovered
    );
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn adapter_begin_blackhole_returns_with_physical_eof_and_recovers() {
    let fixture = Fixture::new();
    let mut relay = Relay::new(database(), Cut::Begin);
    let adapter = relay_adapter(&fixture, &relay);
    // Complete startup while the relay is forwarding.  Only the subsequent
    // BEGIN is blackholed, so this exercises the old adapter.connect path and
    // the native transaction start separately.
    let mut client = adapter.connect().expect("relay connection");
    let hit_eof_before = relay.hit_peer_eof();
    relay.arm();
    let evidence = finish_call(&mut relay, hit_eof_before, ADAPTER_DEADLINE, move || {
        client.transaction().is_err()
    });
    let recovered = if evidence.relay_open {
        let mut fresh = adapter.connect().expect("fresh connection after EOF");
        fresh.query_one("select 1", &[]).expect("recovery query");
        true
    } else {
        false
    };
    relay.close();
    print_marker(
        "begin",
        evidence.elapsed_ms,
        evidence.physical_eof,
        evidence.thread_joined,
        recovered,
    );
    assert!(evidence.hit);
    assert_eq!(evidence.result, Some(true));
    assert!(evidence.elapsed_ms < ADAPTER_DEADLINE.as_millis());
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert!(recovered);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn adapter_query_blackhole_returns_with_physical_eof_and_recovers() {
    let fixture = Fixture::new();
    let mut relay = Relay::new(database(), Cut::Query);
    let adapter = relay_adapter(&fixture, &relay);
    let mut client = adapter.connect().expect("relay connection");
    let hit_eof_before = relay.hit_peer_eof();
    relay.arm();
    let evidence = finish_call(&mut relay, hit_eof_before, ADAPTER_DEADLINE, move || {
        client.query_one("select 1", &[]).is_err()
    });
    let recovered = if evidence.relay_open {
        let mut fresh = adapter.connect().expect("fresh connection after EOF");
        let value: i32 = fresh
            .query_one("select 1", &[])
            .expect("recovery query")
            .get(0);
        value == 1
    } else {
        false
    };
    relay.close();
    print_marker(
        "query",
        evidence.elapsed_ms,
        evidence.physical_eof,
        evidence.thread_joined,
        recovered,
    );
    assert!(evidence.hit);
    assert_eq!(evidence.result, Some(true));
    assert!(evidence.elapsed_ms < ADAPTER_DEADLINE.as_millis());
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert!(recovered);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn adapter_commit_blackhole_preserves_commit_without_retry_and_recovers() {
    let fixture = Fixture::new();
    let table = format!("{}.legacy_adapter_commit_probe", fixture.schema);
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .batch_execute(&format!("create table {table}(id integer primary key)"))
        .expect("fixture-owned commit table");

    let mut relay = Relay::new(database(), Cut::Commit);
    let adapter = relay_adapter(&fixture, &relay);
    let mut client = adapter.connect().expect("relay connection");
    let hit_eof_before = relay.hit_peer_eof();
    relay.arm();
    let table_for_call = table.clone();
    let evidence = finish_call(&mut relay, hit_eof_before, ADAPTER_DEADLINE, move || {
        let mut transaction = client.transaction().expect("BEGIN before blackhole");
        transaction
            .execute(&format!("insert into {table_for_call}(id) values (1)"), &[])
            .expect("mutation before COMMIT blackhole");
        transaction.commit().is_err()
    });

    // The commit response is lost, but the server received and committed the
    // write.  Readback is explicit and uses the fixture's direct adapter.
    let mut readback = fixture.adapter.connect().expect("commit readback");
    let committed: i64 = readback
        .query_one(&format!("select count(*) from {table}"), &[])
        .expect("commit count")
        .get(0);
    let recovered = if evidence.relay_open {
        let mut fresh = adapter.connect().expect("fresh connection after EOF");
        let value: i64 = fresh
            .query_one(&format!("select count(*) from {table}"), &[])
            .expect("recovery readback")
            .get(0);
        value == 1
    } else {
        false
    };
    relay.close();
    print_marker(
        "commit",
        evidence.elapsed_ms,
        evidence.physical_eof,
        evidence.thread_joined,
        recovered,
    );
    assert!(evidence.hit);
    assert_eq!(evidence.result, Some(true));
    assert!(evidence.elapsed_ms < ADAPTER_DEADLINE.as_millis());
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert_eq!(committed, 1, "commit was not retried or rolled back");
    assert!(recovered);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn adapter_idle_client_closes_driver_but_holds_capacity_until_drop() {
    let fixture = Fixture::new();
    let mut relay = Relay::new(database(), Cut::Query);
    let adapter = one_slot_relay_adapter(&fixture, &relay);
    let held = adapter.connect().expect("held relay connection");

    // Wait for the driver's own deadline first.  Starting the waiter only
    // after that point gives it a fresh ten-second budget, so a successful
    // connection after `held` is dropped proves that the semaphore permit was
    // retained by the client lease rather than merely timing out.
    let started = Instant::now();
    while relay.peer_eof() == 0 && started.elapsed() < ADAPTER_DEADLINE {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(relay.peer_eof() > 0, "idle driver did not close the socket");

    let (sender, receiver) = mpsc::channel();
    let second_adapter = adapter.clone();
    let second = thread::spawn(move || {
        let result = second_adapter.connect().map(|_| ());
        let _ = sender.send(result);
    });

    // No request is in flight, so the driver itself enforced the absolute
    // lease deadline and closed the socket while `held` remains in scope.
    assert!(
        receiver.recv_timeout(Duration::from_millis(250)).is_err(),
        "capacity was released before the client lease was dropped"
    );

    drop(held);
    let recovered = receiver
        .recv_timeout(Duration::from_secs(5))
        .is_ok_and(|result| result.is_ok());
    second.join().expect("capacity waiter thread");
    relay.close();
    print_marker(
        "idle-capacity",
        started.elapsed().as_millis(),
        true,
        true,
        recovered,
    );
    assert!(recovered);
}

struct DropEvidence {
    elapsed_ms: u128,
    physical_eof: bool,
    task_joined: bool,
    recovered: bool,
}

fn exercise_last_drop(fixture: &Fixture, multi_thread: bool) -> DropEvidence {
    let mut relay = Relay::new(database(), Cut::Query);
    let adapter = relay_adapter(fixture, &relay);
    let peer_eof_before = relay.peer_eof();
    let started = Instant::now();
    let runtime = if multi_thread {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi-thread runtime")
    } else {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        runtime.block_on(async move {
            let client = adapter.connect().expect("runtime-flavor connection");
            drop(client);
            let panic_result = catch_unwind(AssertUnwindSafe(|| {
                // Keep this client alive until the panic unwinds the closure;
                // no explicit drop may manufacture the lifecycle evidence.
                let _unwinding_client = adapter.connect().expect("unwind connection");
                panic!("intentional transport unwind");
            }));
            assert!(panic_result.is_err());

            // Cancellation must also drop an in-flight client.  The task sends
            // its creation acknowledgement before waiting forever, then the
            // outer runtime aborts and joins it.
            let (created_sender, created_receiver) = oneshot::channel();
            let task_adapter = adapter.clone();
            let task = tokio::spawn(async move {
                let _cancelled_client = task_adapter.connect().expect("cancel connection");
                created_sender
                    .send(())
                    .expect("cancellation creation acknowledgement");
                std::future::pending::<()>().await;
            });
            created_receiver.await.expect("cancellation task started");
            task.abort();
            let task_joined = task.await.is_err_and(|error| error.is_cancelled());

            // This is the last adapter/runtime owner and runs inside the
            // Tokio flavor under test.  DriverRuntime::Drop must stay safe.
            drop(adapter);
            task_joined
        })
    }));
    drop(runtime);
    let physical_eof = relay.wait_for_peer_eof(peer_eof_before + 3);
    let task_joined = result.as_ref().ok().copied().unwrap_or(false);
    let recovered = result.is_ok() && task_joined;
    let elapsed_ms = started.elapsed().as_millis();
    relay.close();
    DropEvidence {
        elapsed_ms,
        physical_eof,
        task_joined,
        recovered,
    }
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn adapter_last_drop_is_safe_inside_current_thread_runtime_and_unwind() {
    let fixture = Fixture::new();
    let evidence = exercise_last_drop(&fixture, false);
    print_marker(
        "drop-current",
        evidence.elapsed_ms,
        evidence.physical_eof,
        evidence.task_joined,
        evidence.recovered,
    );
    assert!(evidence.physical_eof);
    assert!(evidence.task_joined);
    assert!(evidence.recovered);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn adapter_last_drop_is_safe_inside_multi_thread_runtime_and_unwind() {
    let fixture = Fixture::new();
    let evidence = exercise_last_drop(&fixture, true);
    print_marker(
        "drop-multi",
        evidence.elapsed_ms,
        evidence.physical_eof,
        evidence.task_joined,
        evidence.recovered,
    );
    assert!(evidence.physical_eof);
    assert!(evidence.task_joined);
    assert!(evidence.recovered);
}

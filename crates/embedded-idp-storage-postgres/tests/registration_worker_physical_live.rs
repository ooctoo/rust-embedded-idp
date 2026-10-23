//! Physical shutdown acceptance for the IDP registration worker.
//!
//! These cases stay ignored by default. They require the isolated PostgreSQL
//! fixture and deliberately keep a wire relay alive until the client closes
//! the blackholed connection.

#![allow(dead_code, unused_imports)]

mod registration_email_support;
mod registration_transport_support;

use embedded_idp_axum::{RegistrationEmailRuntime, RegistrationEmailWorkers};
use embedded_idp_core::access::{RegistrationEmailOperationKind, RegistrationEmailService};
use embedded_idp_core::PasswordWorkBudget;
use embedded_idp_email::{
    RegistrationEmailDeliveryRequest, RegistrationEmailDeliveryService,
    RegistrationEmailSendOutcome,
};
use registration_email_support::Fixture;
use registration_transport_support::{
    database, install_runtime_and_resume, relay_store, Cut, Relay,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

struct NoSendMailer;

impl RegistrationEmailDeliveryService for NoSendMailer {
    fn send_registration_email(
        &self,
        _: RegistrationEmailDeliveryRequest,
        _: Instant,
    ) -> RegistrationEmailSendOutcome {
        RegistrationEmailSendOutcome::Rejected
    }
}

async fn start_runtime(
    fixture: &Fixture,
    relay: &Relay,
) -> (Arc<RegistrationEmailRuntime>, RegistrationEmailWorkers) {
    let budget = PasswordWorkBudget::default();
    let service: Arc<dyn RegistrationEmailService> =
        Arc::new(relay_store(fixture, relay).with_password_work_budget(budget.clone()));
    let runtime = RegistrationEmailRuntime::new(service, Arc::new(NoSendMailer), budget)
        .expect("registration runtime composition");
    let workers = runtime.start().await.expect("registration worker startup");
    (runtime, workers)
}

fn paused(fixture: &Fixture) -> bool {
    fixture
        .adapter
        .connect()
        .expect("pause-state connection")
        .query_one(
            &format!(
                "select paused from {}.registration_email_runtime_state where authority=$1",
                fixture.schema
            ),
            &[&fixture.scope.authority],
        )
        .expect("pause-state query")
        .get(0)
}

fn wait_for_hit_eof(relay: &Relay, count: usize, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while relay.hit_peer_eof() < count {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    true
}

fn query_recovery(fixture: &Fixture) -> bool {
    let store = fixture.store();
    RegistrationEmailService::runtime_facts(&store).is_ok()
}

async fn run_short_query_shutdown(fixture: &Fixture) {
    install_runtime_and_resume(&fixture);
    assert!(!paused(&fixture));

    let mut relay = Relay::new(database(), Cut::Query);
    let (runtime, workers) = start_runtime(&fixture, &relay).await;
    relay.arm();
    assert!(relay.wait_for_hits(1), "worker query did not reach relay");

    let hit_eof_before = relay.hit_peer_eof();
    let shutdown_started = Instant::now();
    workers.begin_shutdown(Duration::from_millis(50));
    assert!(runtime
        .try_request(RegistrationEmailOperationKind::Register, false)
        .is_err());
    assert!(runtime.try_probe().is_err());
    let report = workers.shutdown(Duration::from_millis(50)).await;
    let shutdown_elapsed = shutdown_started.elapsed();
    assert!(shutdown_elapsed <= Duration::from_millis(250));
    assert!(!report.drained);
    assert!(report.failed);
    assert!(report.unresolved_storage > 0);
    assert_eq!(report.unresolved_processing, 0);
    assert_eq!(report.unresolved_delivery, 0);
    assert_eq!(report.unresolved_requests, 0);
    assert!(!runtime.worker_running());

    // The returned report is intentionally early. Keep the relay available
    // until the physical client EOF and then prove a fresh query can recover.
    let observed_physical_eof =
        wait_for_hit_eof(&relay, hit_eof_before + 1, Duration::from_secs(12));
    assert!(observed_physical_eof);
    relay.disarm();
    let recovered = query_recovery(&fixture);
    let pause_unchanged = !paused(&fixture);
    println!(
        "SUT_IDP_WORKER_PHYSICAL {{\"case\":\"short_query\",\"drained\":{},\"failed\":{},\"unresolved_storage\":{},\"physical_eof\":{},\"recovered\":{},\"pause_unchanged\":{},\"shutdown_ms\":{}}}",
        report.drained,
        report.failed,
        report.unresolved_storage,
        observed_physical_eof,
        recovered,
        pause_unchanged,
        shutdown_elapsed.as_millis(),
    );
    assert!(recovered);
    assert!(pause_unchanged);
    drop(runtime);
    relay.close();
}

async fn run_long_begin_shutdown(fixture: &Fixture) {
    install_runtime_and_resume(&fixture);
    assert!(!paused(&fixture));

    let mut relay = Relay::new(database(), Cut::Begin);
    let (runtime, workers) = start_runtime(&fixture, &relay).await;
    relay.arm();
    assert!(relay.wait_for_hits(1), "worker BEGIN did not reach relay");

    let hit_eof_before = relay.hit_peer_eof();
    let shutdown_started = Instant::now();
    let report = workers.shutdown(Duration::from_secs(12)).await;
    let shutdown_elapsed = shutdown_started.elapsed();
    // A small scheduler margin keeps the test bound distinct from the shared
    // twelve-second shutdown deadline while still rejecting an unbounded wait.
    assert!(shutdown_elapsed <= Duration::from_secs(13));
    assert!(report.drained);
    assert!(!report.failed);
    assert_eq!(report.unresolved_processing, 0);
    assert_eq!(report.unresolved_delivery, 0);
    assert_eq!(report.unresolved_storage, 0);
    assert_eq!(report.unresolved_requests, 0);
    assert!(!runtime.worker_running());
    let observed_physical_eof =
        wait_for_hit_eof(&relay, hit_eof_before + 1, Duration::from_secs(1));
    assert!(observed_physical_eof);
    relay.disarm();
    let recovered = query_recovery(&fixture);
    let pause_unchanged = !paused(&fixture);
    println!(
        "SUT_IDP_WORKER_PHYSICAL {{\"case\":\"long_begin\",\"drained\":{},\"failed\":{},\"unresolved_storage\":{},\"physical_eof\":{},\"recovered\":{},\"pause_unchanged\":{},\"shutdown_ms\":{}}}",
        report.drained,
        report.failed,
        report.unresolved_storage,
        observed_physical_eof,
        recovered,
        pause_unchanged,
        shutdown_elapsed.as_millis(),
    );
    assert!(recovered);
    assert!(pause_unchanged);
    drop(runtime);
    relay.close();
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn short_worker_shutdown_reports_physical_storage_and_closes_admission() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let fixture = Fixture::new();
    runtime.block_on(run_short_query_shutdown(&fixture));
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn long_worker_shutdown_waits_for_physical_eof_before_clean_drain() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let fixture = Fixture::new();
    runtime.block_on(run_long_begin_shutdown(&fixture));
}

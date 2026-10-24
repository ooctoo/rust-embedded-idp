//! Physical budget acceptance for the legacy adapter's bounded operations.
//!
//! These probes are intentionally ignored by default. They require the fresh
//! loopback PostgreSQL instance selected by `registration_email_support` and
//! keep the relay alive until the driver's socket EOF and call-thread join
//! have both been observed. Recovery is then checked through a new connection
//! before the relay is closed.

#![allow(dead_code, unused_imports)]

mod registration_email_support;
mod registration_transport_support;

use embedded_idp_core::access::{PermissionCatalog, TenancyMode};
use registration_email_support::Fixture;
use registration_transport_support::{
    database, finish_call, relay_adapter, CallEvidence, Cut, Relay,
};
use std::time::{Duration, Instant};

const SCHEMA_HEALTH_BUDGET: Duration = Duration::from_secs(5);
const SETUP_BUDGET: Duration = Duration::from_secs(60);
const OBSERVATION_MARGIN: Duration = Duration::from_secs(1);

fn print_marker(
    mode: &str,
    budget: Duration,
    evidence: &CallEvidence,
    physical_elapsed_ms: u128,
    recovered: bool,
) {
    println!(
        "SUT_IDP_LEGACY_ADAPTER_BUDGET {{\"mode\":\"{}\",\"budget_ms\":{},\"elapsed_ms\":{},\"physical_elapsed_ms\":{},\"physical_eof\":{},\"thread_joined\":{},\"relay_open\":{},\"recovered\":{}}}",
        mode,
        budget.as_millis(),
        evidence.elapsed_ms,
        physical_elapsed_ms,
        evidence.physical_eof,
        evidence.thread_joined,
        evidence.relay_open,
        recovered,
    );
}

fn assert_budget_evidence(
    mode: &str,
    budget: Duration,
    evidence: &CallEvidence,
    physical_elapsed_ms: u128,
) {
    assert!(evidence.hit, "{mode} blackhole frame was not observed");
    assert_eq!(
        evidence.result,
        Some(true),
        "{mode} operation did not return its expected error"
    );
    assert!(
        evidence.relay_open,
        "{mode} relay was closed before EOF and thread join evidence"
    );
    assert!(
        evidence.physical_eof,
        "{mode} did not observe client EOF while relay remained open"
    );
    assert!(
        evidence.thread_joined,
        "{mode} call thread did not join while relay remained open"
    );
    let minimum = budget
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_default();
    let maximum = budget + OBSERVATION_MARGIN;
    let physical_elapsed = Duration::from_millis(physical_elapsed_ms as u64);
    assert!(
        physical_elapsed >= minimum,
        "{mode} completed physical observation before its configured budget: {}ms < {}ms",
        physical_elapsed_ms,
        minimum.as_millis()
    );
    assert!(
        physical_elapsed <= maximum,
        "{mode} exceeded its configured physical budget window: {}ms > {}ms",
        physical_elapsed_ms,
        maximum.as_millis()
    );
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn legacy_schema_health_blackhole_honors_five_second_budget_and_recovers() {
    let fixture = Fixture::new();
    let mut relay = Relay::new(database(), Cut::Query);
    let adapter = relay_adapter(&fixture, &relay);
    let hit_eof_before = relay.hit_peer_eof();
    relay.arm();
    let call_adapter = adapter.clone();
    let physical_started = Instant::now();
    let evidence = finish_call(
        &mut relay,
        hit_eof_before,
        SCHEMA_HEALTH_BUDGET + OBSERVATION_MARGIN,
        move || call_adapter.inspect_schema_health().is_err(),
    );
    let physical_elapsed_ms = physical_started.elapsed().as_millis();
    assert_budget_evidence(
        "schema-health",
        SCHEMA_HEALTH_BUDGET,
        &evidence,
        physical_elapsed_ms,
    );

    // `finish_call` has already joined the operation thread and disarmed the
    // cut while leaving the relay open. A fresh lease must be usable before
    // relay cleanup can contribute any EOF.
    let recovered = {
        let mut fresh = adapter
            .connect()
            .expect("schema-health recovery connection");
        let value: i32 = fresh
            .query_one("select 1", &[])
            .expect("schema-health recovery query")
            .get(0);
        value == 1
    };
    print_marker(
        "schema-health",
        SCHEMA_HEALTH_BUDGET,
        &evidence,
        physical_elapsed_ms,
        recovered,
    );
    relay.close();
    assert!(recovered);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn legacy_setup_begin_blackhole_honors_sixty_second_budget_and_recovers() {
    let fixture = Fixture::new();
    let mut relay = Relay::new(database(), Cut::Begin);
    let adapter = relay_adapter(&fixture, &relay);
    let hit_eof_before = relay.hit_peer_eof();
    relay.arm();
    let call_adapter = adapter.clone();
    let physical_started = Instant::now();
    let evidence = finish_call(
        &mut relay,
        hit_eof_before,
        SETUP_BUDGET + OBSERVATION_MARGIN,
        move || {
            let catalog = PermissionCatalog::new(vec![]).expect("empty permission catalog");
            call_adapter
                .initialize_access_schema(TenancyMode::Enabled, &catalog)
                .is_err()
        },
    );
    let physical_elapsed_ms = physical_started.elapsed().as_millis();
    assert_budget_evidence("setup-begin", SETUP_BUDGET, &evidence, physical_elapsed_ms);

    // The setup lease's BEGIN failed and was joined before this fresh query;
    // relay.close below is therefore not the source of the recovery evidence.
    let recovered = {
        let mut fresh = adapter.connect().expect("setup recovery connection");
        let value: i32 = fresh
            .query_one("select 1", &[])
            .expect("setup recovery query")
            .get(0);
        value == 1
    };
    print_marker(
        "setup-begin",
        SETUP_BUDGET,
        &evidence,
        physical_elapsed_ms,
        recovered,
    );
    relay.close();
    assert!(recovered);
}

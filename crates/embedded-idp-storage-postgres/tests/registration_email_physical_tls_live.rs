//! Strict TLS acceptance for the IDP registration store.
//!
//! These ignored tests require the fresh isolated PostgreSQL fixture and its
//! temporary ingress CA.  Preparation remains on the fixture's loopback
//! plaintext adapter; only the registration-store probes use TLS.

#![allow(dead_code, unused_imports)]

mod registration_email_support;
mod registration_transport_support;

use embedded_idp_core::access::{RegistrationEmailOperationKind, RegistrationEmailService};
use registration_email_support::Fixture;
use registration_transport_support::{
    confirmed_ca_path, counts, database, finish_call, install_runtime_and_resume, operation_count,
    tls_store_parts, Cut, IDENTITY_DEADLINE,
};
use std::time::Instant;
use uuid::Uuid;

#[test]
#[ignore = "requires fresh isolated PostgreSQL with a temporary TLS CA"]
fn tls_accepts_matching_hostname_and_ca_for_store_and_readonly_probe() {
    let ca_path = confirmed_ca_path();
    let fixture = Fixture::new();
    install_runtime_and_resume(&fixture);
    let before = counts(&fixture);
    let before_operations = operation_count(&fixture);
    let started = Instant::now();
    let store = tls_store_parts(
        fixture.uri.clone(),
        fixture.schema.clone(),
        fixture.scope.clone(),
        fixture.crypto.clone(),
        database().port(),
        "localhost",
        Some(&ca_path),
    )
    .expect("matching TLS hostname and CA should construct the store");
    let accepted = RegistrationEmailService::is_replay(
        &store,
        RegistrationEmailOperationKind::Register,
        Uuid::now_v7(),
    ) == Ok(false);
    let elapsed_ms = started.elapsed().as_millis();
    let after = counts(&fixture);
    let after_operations = operation_count(&fixture);
    let hostname_rejected = tls_store_parts(
        fixture.uri.clone(),
        fixture.schema.clone(),
        fixture.scope.clone(),
        fixture.crypto.clone(),
        database().port(),
        "127.0.0.1",
        Some(&ca_path),
    )
    .is_err();
    let untrusted_rejected = tls_store_parts(
        fixture.uri.clone(),
        fixture.schema.clone(),
        fixture.scope.clone(),
        fixture.crypto.clone(),
        database().port(),
        "localhost",
        None,
    )
    .is_err();
    assert!(hostname_rejected);
    assert!(untrusted_rejected);
    assert_eq!(before, counts(&fixture));
    assert_eq!(before_operations, operation_count(&fixture));

    println!(
        "SUT_IDP_TLS {{\"mode\":0,\"elapsed_ms\":{},\"physical_eof\":0,\"accepted\":{},\"hostname_rejected\":true,\"untrusted_rejected\":true,\"recovered\":false}}",
        elapsed_ms, accepted
    );
    assert!(accepted);
    assert!(elapsed_ms <= IDENTITY_DEADLINE.as_millis());
    assert_eq!(before, after);
    assert_eq!(before_operations, after_operations);
}

#[test]
#[ignore = "requires fresh isolated PostgreSQL with a temporary TLS CA"]
fn tls_startup_blackhole_rejects_bad_identity_and_recovers_directly() {
    let ca_path = confirmed_ca_path();
    let fixture = Fixture::new();
    install_runtime_and_resume(&fixture);
    let before = counts(&fixture);
    let before_operations = operation_count(&fixture);
    let target = database();

    let mut relay = registration_transport_support::Relay::new(target, Cut::Startup);
    let hit_eof_before = relay.hit_peer_eof();
    relay.arm_after(0);
    let base_uri = fixture.uri.clone();
    let schema_name = fixture.schema.clone();
    let scope = fixture.scope.clone();
    let crypto = fixture.crypto.clone();
    let relay_port = relay.port;
    let relay_ca_path = ca_path.clone();
    let evidence = finish_call(&mut relay, hit_eof_before, IDENTITY_DEADLINE, move || {
        tls_store_parts(
            base_uri,
            schema_name,
            scope,
            crypto,
            relay_port,
            "localhost",
            Some(&relay_ca_path),
        )
        .is_err()
    });
    // The relay is kept alive until physical EOF and the worker join have
    // both been observed.  Recovery then uses the direct TLS endpoint.
    relay.close();
    let recovered = tls_store_parts(
        fixture.uri.clone(),
        fixture.schema.clone(),
        fixture.scope.clone(),
        fixture.crypto.clone(),
        target.port(),
        "localhost",
        Some(&ca_path),
    )
    .ok()
    .is_some_and(|store| {
        RegistrationEmailService::is_replay(
            &store,
            RegistrationEmailOperationKind::Register,
            Uuid::now_v7(),
        ) == Ok(false)
    });
    let after = counts(&fixture);
    let after_operations = operation_count(&fixture);
    println!(
        "SUT_IDP_TLS {{\"mode\":1,\"elapsed_ms\":{},\"physical_eof\":{},\"accepted\":false,\"hostname_rejected\":{},\"untrusted_rejected\":{},\"recovered\":{}}}",
        evidence.elapsed_ms,
        usize::from(evidence.physical_eof),
        false,
        false,
        recovered
    );
    assert!(evidence.hit);
    assert_eq!(evidence.result, Some(true));
    assert!(evidence.elapsed_ms >= 9500 && evidence.elapsed_ms < IDENTITY_DEADLINE.as_millis());
    assert!(evidence.physical_eof);
    assert!(evidence.thread_joined);
    assert!(evidence.relay_open);
    assert!(recovered);
    assert_eq!(before, after);
    assert_eq!(before_operations, after_operations);
}

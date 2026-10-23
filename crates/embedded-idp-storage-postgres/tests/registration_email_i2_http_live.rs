//! I2 registration profile over an actual loopback HTTP server and local SMTP sink.
//!
//! These tests require an explicitly selected fresh isolated PostgreSQL
//! fixture. They never discover or reuse a database.

mod registration_email_i2_http_support;
#[allow(dead_code, unused_imports)]
mod registration_email_support;

use registration_email_i2_http_support::{
    post_json, post_without_profile, seed_registration_states, start_harness,
    worker_diagnostic_snapshot, HttpResponse,
};
use registration_email_support::{Fixture, EXISTING_EMAIL};
use serde_json::Value;
use std::time::{Duration, Instant};
use uuid::Uuid;

const NEW_EMAIL: &str = "new-i2@example.test";
const NEW_PASSWORD: &str = "NewPassword123";
const EXISTING_PASSWORD: &str = "ExistingPass123";

#[tokio::test]
#[ignore = "requires the explicitly authorized isolated loopback PostgreSQL fixture"]
async fn new_profile_requires_worker_and_trusted_resume() {
    let no_worker = start_harness(build_fixture(false).await, false, false).await;
    let response = post_json(
        no_worker.server.addr,
        "/auth/register",
        &register_body(Uuid::now_v7(), "no-worker@example.test"),
        true,
    )
    .await;
    assert_error(&response, 503, "temporarily_unavailable");
    let shutdown = no_worker.shutdown().await;
    assert!(shutdown.drained);

    let paused = start_harness(build_fixture(false).await, true, false).await;
    let response = post_json(
        paused.server.addr,
        "/auth/register",
        &register_body(Uuid::now_v7(), "paused@example.test"),
        true,
    )
    .await;
    assert_error(&response, 503, "temporarily_unavailable");
    let shutdown = paused.shutdown().await;
    assert!(shutdown.drained);
}

#[tokio::test]
#[ignore = "requires the explicitly authorized isolated loopback PostgreSQL fixture"]
async fn loopback_register_delivery_verify_replay_and_independent_login() {
    let fixture = tokio::task::spawn_blocking(|| {
        let fixture = Fixture::with_existing_account();
        seed_registration_states(&fixture);
        fixture
    })
    .await
    .expect("fixture setup task");
    let harness = start_harness(fixture, true, true).await;
    let address = harness.server.addr;

    let missing_profile = post_without_profile(
        address,
        "/auth/register",
        &register_body(Uuid::now_v7(), "missing-profile@example.test"),
    )
    .await;
    assert_error(&missing_profile, 400, "registration_profile_required");

    let operation = Uuid::now_v7();
    let first = post_json(
        address,
        "/auth/register",
        &register_body(operation, NEW_EMAIL),
        true,
    )
    .await;
    assert_eq!(first.status, 202);
    assert_no_store(&first);
    let first_json = json(&first);
    assert_eq!(first_json["status"], "verification_requested");
    let context = first_json["verification_context"]
        .as_str()
        .expect("verification context")
        .to_owned();

    assert!(
        harness.smtp.wait_for_count(1, Duration::from_secs(5)).await,
        "worker should deliver through local SMTP"
    );
    let mail = harness.smtp.messages()[0].clone();
    assert_eq!(mail.recipient, NEW_EMAIL);
    assert_eq!(mail.code.len(), 6);

    let replay = post_json(
        address,
        "/auth/register",
        &register_body(operation, NEW_EMAIL),
        true,
    )
    .await;
    assert_eq!(replay.status, 202);
    assert_no_store(&replay);
    assert_eq!(json(&replay)["verification_context"], context);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        harness.smtp.messages().len(),
        1,
        "replay sent duplicate mail"
    );

    let wrong_code = if mail.code == "000000" {
        "111111"
    } else {
        "000000"
    };
    let wrong = post_json(
        address,
        "/auth/verify-email",
        &verify_body(Uuid::now_v7(), &context, wrong_code),
        true,
    )
    .await;
    assert_error(&wrong, 400, "verification_unavailable");

    let verified = post_json(
        address,
        "/auth/verify-email",
        &verify_body(Uuid::now_v7(), &context, &mail.code),
        true,
    )
    .await;
    assert_eq!(verified.status, 200);
    assert_no_store(&verified);
    assert_eq!(json(&verified)["status"], "verified");

    let login = post_json(
        address,
        "/auth/login",
        &format!(r#"{{"email":"{NEW_EMAIL}","password":"{NEW_PASSWORD}"}}"#),
        false,
    )
    .await;
    assert_eq!(login.status, 200);
    assert_no_store(&login);
    assert_eq!(json(&login)["status"], "authenticated");

    let mut failure_bodies = Vec::new();
    for (email, password) in [
        ("unknown-i2@example.test", NEW_PASSWORD),
        (EXISTING_EMAIL, "WrongPassword123"),
        ("active@example.test", "WrongPassword123"),
        ("disabled@example.test", EXISTING_PASSWORD),
    ] {
        let started = Instant::now();
        let response = post_json(
            address,
            "/auth/login",
            &format!(r#"{{"email":"{email}","password":"{password}"}}"#),
            false,
        )
        .await;
        assert!(
            started.elapsed() >= Duration::from_millis(750),
            "login floor was not enforced for {email}"
        );
        assert_eq!(response.status, 401, "login response for {email}");
        assert_no_store(&response);
        assert_eq!(json(&response)["code"], "invalid_credentials");
        failure_bodies.push(response.body);
    }
    assert!(failure_bodies.windows(2).all(|pair| pair[0] == pair[1]));

    let account_lock = harness.hold_account_lock("active@example.test");
    let started = Instant::now();
    let locked_wrong_password = post_json(
        address,
        "/auth/login",
        r#"{"email":"active@example.test","password":"WrongPassword123"}"#,
        false,
    )
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "wrong password waited on the account lock"
    );
    assert_eq!(locked_wrong_password.status, 401);
    assert_no_store(&locked_wrong_password);
    assert_eq!(locked_wrong_password.body, failure_bodies[2]);
    drop(account_lock);

    for email in [
        "unknown-i2@example.test",
        EXISTING_EMAIL,
        "active@example.test",
        "disabled@example.test",
    ] {
        let response = post_json(
            address,
            "/auth/register",
            &register_body(Uuid::now_v7(), email),
            true,
        )
        .await;
        if response.status != 202 {
            let snapshot = worker_diagnostic_snapshot(&harness, response.status).await;
            println!(
                "SUT_IDP_I2_DIAGNOSTIC {{\"status\":{},\"worker_running\":{},\"store_ready\":{},\"accepting\":{},\"overdue_processing\":{},\"unresolved_delivery\":{},\"snapshot_available\":{},\"intent_reserved\":{},\"delivery_reserved\":{},\"delivery_claimed\":{},\"delivery_unknown\":{},\"paused\":{},\"event_register\":{},\"event_resend\":{},\"event_verify\":{}}}",
                snapshot.status,
                snapshot.worker_running,
                snapshot.store_ready,
                snapshot.accepting,
                snapshot.overdue_processing,
                snapshot.unresolved_delivery,
                snapshot.snapshot_available,
                snapshot.intent_reserved,
                snapshot.delivery_reserved,
                snapshot.delivery_claimed,
                snapshot.delivery_unknown,
                snapshot.paused,
                snapshot.event_register,
                snapshot.event_resend,
                snapshot.event_verify,
            );
        }
        assert_eq!(response.status, 202, "registration response for {email}");
        assert_no_store(&response);
        assert_eq!(json(&response)["status"], "verification_requested");
    }

    let shutdown = harness.shutdown().await;
    assert!(shutdown.drained);
    assert_eq!(shutdown.unresolved_processing, 0);
    assert_eq!(shutdown.unresolved_delivery, 0);
}

async fn build_fixture(existing: bool) -> Fixture {
    tokio::task::spawn_blocking(move || {
        if existing {
            Fixture::with_existing_account()
        } else {
            Fixture::new()
        }
    })
    .await
    .expect("fixture setup task")
}

fn register_body(operation: Uuid, email: &str) -> String {
    format!(
        r#"{{"tenant_id":"t1","email":"{email}","password":"{NEW_PASSWORD}","client_operation_id":"{operation}"}}"#
    )
}

fn verify_body(operation: Uuid, context: &str, code: &str) -> String {
    format!(
        r#"{{"tenant_id":"t1","verification_context":"{context}","verification_code":"{code}","client_operation_id":"{operation}"}}"#
    )
}

fn json(response: &HttpResponse) -> Value {
    serde_json::from_str(&response.body).expect("JSON response")
}

fn assert_error(response: &HttpResponse, status: u16, code: &str) {
    assert_eq!(response.status, status);
    assert_no_store(response);
    assert_eq!(json(response)["error"]["code"], code);
}

fn assert_no_store(response: &HttpResponse) {
    assert_eq!(
        response.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    for name in [
        "set-cookie",
        "location",
        "www-authenticate",
        "access-control-allow-origin",
        "access-control-allow-credentials",
    ] {
        assert!(!response.headers.contains_key(name), "unexpected {name}");
    }
}

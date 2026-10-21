use super::registration_email_support::*;
use embedded_idp_core::access::RegistrationEmailCrypto;
use embedded_idp_storage_postgres::RegistrationEmailPreparation;
use std::sync::{Arc, Barrier};
use std::thread;
use uuid::Uuid;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn registration_adds_no_account_or_membership_before_verification() {
    let fixture = Fixture::new();
    let accounts = fixture.count("accounts");
    let memberships = fixture.count("access_memberships");
    let operation = Uuid::now_v7();
    let prepared = fixture.prepared(
        operation,
        "new-a@example.test",
        "NewPassword123",
        Some("New A"),
    );
    let accepted = fixture.store().register(&prepared).expect("registration");
    assert_eq!(fixture.count("accounts"), accounts);
    assert_eq!(fixture.count("access_memberships"), memberships);
    let context = fixture.context_id(&accepted.verification_context);
    assert_eq!(fixture.count("registration_email_contexts"), 1);
    assert_eq!(fixture.count("registration_email_intents"), 1);
    assert_eq!(fixture.count("registration_email_codes"), 0);
    assert_eq!(
        fixture.store().prepare(context, 1).unwrap(),
        RegistrationEmailPreparation::Prepared
    );
    assert_eq!(fixture.count("registration_email_events"), 2);
    assert_eq!(fixture.count("accounts"), accounts);
    assert_eq!(fixture.count("access_memberships"), memberships);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn same_operation_concurrent_prepared_bodies_create_one_context_and_send() {
    let fixture = Arc::new(Fixture::new());
    let operation = Uuid::now_v7();
    let first = fixture.prepared(operation, "same-op@example.test", "SamePassword123", None);
    let second = fixture.prepared(operation, "same-op@example.test", "SamePassword123", None);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for prepared in [first, second] {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            fixture.store().register(&prepared)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(fixture.count("registration_email_contexts"), 1);
    assert_eq!(fixture.count("registration_email_subjects"), 1);
    assert_eq!(fixture.count("registration_email_buckets"), 1);
    assert_eq!(send_history_lengths(&fixture), (1, 1));
    assert_eq!(fixture.count("registration_email_intents"), 1);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn same_operation_changed_body_is_a_conflict_without_second_context() {
    let fixture = Fixture::new();
    let operation = Uuid::now_v7();
    let first = fixture.prepared(
        operation,
        "first-body@example.test",
        "BodyPassword123",
        None,
    );
    let second = fixture.prepared(
        operation,
        "second-body@example.test",
        "BodyPassword123",
        None,
    );
    fixture
        .store()
        .register(&first)
        .expect("first registration");
    assert!(matches!(
        fixture.store().register(&second),
        Err(embedded_idp_core::access::RegistrationEmailError::RequestConflict)
    ));
    assert_eq!(fixture.count("registration_email_contexts"), 1);
    assert_eq!(fixture.count("registration_email_subjects"), 1);
    assert_eq!(fixture.count("registration_email_operations"), 1);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn cooling_suppresses_repeated_register_and_resend_without_extending_send_budget() {
    let fixture = Fixture::new();
    let first = fixture.prepared(
        Uuid::now_v7(),
        "cooling@example.test",
        "CoolingPassword123",
        None,
    );
    let accepted = fixture
        .store()
        .register(&first)
        .expect("first registration");
    let token = accepted.verification_context.clone();
    let initial_sends = fixture.count("registration_email_deliveries");
    let suppressed = fixture.prepared(
        Uuid::now_v7(),
        "cooling@example.test",
        "CoolingPassword123",
        None,
    );
    fixture
        .store()
        .register(&suppressed)
        .expect("suppressed registration");
    assert_eq!(
        fixture.count("registration_email_deliveries"),
        initial_sends
    );
    assert_eq!(fixture.count("registration_email_contexts"), 2);
    let second_context = fixture.context_id_str(
        &fixture
            .crypto
            .context_token(&fixture.scope, suppressed.seed())
            .expose_secret(),
    );
    assert!(!fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select deliverable from {}.registration_email_contexts where id=$1",
                fixture.schema
            ),
            &[&second_context],
        )
        .unwrap()
        .get::<_, bool>(0));
    for _ in 0..3 {
        fixture
            .store()
            .resend(Uuid::now_v7(), token.expose_secret())
            .expect("suppressed resend");
    }
    assert_eq!(
        fixture.count("registration_email_deliveries"),
        initial_sends
    );
    assert_eq!(fixture.count("registration_email_intents"), 1);
}

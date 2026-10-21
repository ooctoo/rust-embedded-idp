use super::registration_email_support::*;
use embedded_idp_core::access::{
    TenantAuthenticationService, TenantLoginOutcome, TenantPasswordLogin,
};
use embedded_idp_core::SecretString;
use embedded_idp_storage_postgres::{RegistrationEmailPreparation, RegistrationEmailVerification};
use std::sync::{Arc, Barrier};
use std::thread;
use uuid::Uuid;

fn ready(fixture: &Fixture, email: &str) -> (SecretString, Uuid, DeliveryPayload) {
    let accepted = fixture
        .store()
        .register(&fixture.prepared(Uuid::now_v7(), email, "ReadyPassword123", None))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    let payload = delivery(fixture, context, 1);
    (token, context, payload)
}

fn different_code(payload: &DeliveryPayload) -> &'static str {
    if payload.code.expose_secret() == "999999" {
        "888888"
    } else {
        "999999"
    }
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn existing_pending_account_verifies_and_logs_in_with_the_new_hash() {
    let fixture = Fixture::with_existing_account();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            EXISTING_EMAIL,
            "NewPassword123",
            Some("Updated existing"),
        ))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    let code = delivery(&fixture, context, 1).code;
    assert_eq!(
        fixture
            .store()
            .verify(Uuid::now_v7(), token.expose_secret(), code.expose_secret()),
        Ok(RegistrationEmailVerification::Verified)
    );
    assert!(matches!(
        status_for_email(&fixture, EXISTING_EMAIL),
        Some((_, status)) if status == "active"
    ));
    let logged_in = auth_service(&fixture)
        .login(TenantPasswordLogin {
            email: EXISTING_EMAIL.to_string(),
            password: SecretString::new("NewPassword123"),
        })
        .expect("existing login");
    assert!(matches!(logged_in, TenantLoginOutcome::Authenticated(_)));
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn postcompletion_resend_does_not_consume_send_budget_or_enqueue_intent() {
    let fixture = Fixture::new();
    let (token, context, payload) = ready(&fixture, "postcomplete-resend@example.test");
    assert_eq!(
        fixture.store().verify(
            Uuid::now_v7(),
            token.expose_secret(),
            payload.code.expose_secret()
        ),
        Ok(RegistrationEmailVerification::Verified)
    );
    let send_history = send_history_lengths(&fixture);
    let deliveries = fixture.count("registration_email_deliveries");
    let intents = fixture.count("registration_email_intents");
    let operation = Uuid::now_v7();
    fixture
        .store()
        .resend(operation, token.expose_secret())
        .expect("completed-context resend is a closed no-op");
    assert_eq!(send_history_lengths(&fixture), send_history);
    assert_eq!(fixture.count("registration_email_deliveries"), deliveries);
    assert_eq!(fixture.count("registration_email_intents"), intents);
    assert_eq!(operation_phase(&fixture, operation, "resend"), "attached");
    assert_eq!(context_row(&fixture, context).2, Some(1));
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn unprepared_and_suppressed_contexts_do_not_charge_wrong_email_budget() {
    let fixture = Fixture::new();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "unprepared@example.test",
            "UnpreparedPassword123",
            None,
        ))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    for _ in 0..3 {
        assert_eq!(
            fixture
                .store()
                .verify(Uuid::now_v7(), token.expose_secret(), "999999"),
            Ok(RegistrationEmailVerification::Unavailable)
        );
    }
    assert_eq!(wrong_counts(&fixture, context), (0, 0, 0));

    let suppressed = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "suppressed@example.test",
            "SuppressedPassword123",
            None,
        ))
        .expect("suppressed registration");
    let suppressed_token = suppressed.verification_context;
    let suppressed_context = fixture.context_id(&suppressed_token);
    fixture.set_context_deliverable(suppressed_context, false);
    assert_eq!(
        fixture.store().prepare(suppressed_context, 1),
        Ok(RegistrationEmailPreparation::Suppressed)
    );
    for _ in 0..3 {
        assert_eq!(
            fixture
                .store()
                .verify(Uuid::now_v7(), suppressed_token.expose_secret(), "999999",),
            Ok(RegistrationEmailVerification::Unavailable)
        );
    }
    assert_eq!(wrong_counts(&fixture, suppressed_context), (0, 0, 0));
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn fifth_ready_wrong_code_exhausts_and_replay_does_not_increment_again() {
    let fixture = Fixture::new();
    let (token, context, payload) = ready(&fixture, "wrong-limit@example.test");
    let baseline_events = fixture.count("registration_email_events");
    let wrong = different_code(&payload);
    let mut operations = Vec::new();
    for _ in 0..5 {
        let operation = Uuid::now_v7();
        operations.push(operation);
        assert_eq!(
            fixture
                .store()
                .verify(operation, token.expose_secret(), wrong),
            Ok(RegistrationEmailVerification::Unavailable)
        );
    }
    assert_eq!(wrong_counts(&fixture, context), (5, 5, 5));
    assert_eq!(
        fixture
            .store()
            .verify(operations[4], token.expose_secret(), wrong),
        Ok(RegistrationEmailVerification::Unavailable)
    );
    assert_eq!(wrong_counts(&fixture, context), (5, 5, 5));
    assert_eq!(
        fixture.count("registration_email_events"),
        baseline_events + 5
    );
    assert_eq!(fixture.count("registration_email_codes"), 1);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn concurrent_wrong_codes_from_two_store_instances_do_not_lose_counts() {
    let fixture = Arc::new(Fixture::new());
    let (token, context, payload) = ready(&fixture, "concurrent-wrong@example.test");
    let baseline_events = fixture.count("registration_email_events");
    let compared_events = || -> i64 {
        fixture.adapter.connect().unwrap().query_one(&format!("select count(*) from {}.registration_email_events where context_id=$1 and reason='wrong_code'",fixture.schema),&[&context]).unwrap().get(0)
    };
    let wrong = different_code(&payload).to_string();
    let barrier = Arc::new(Barrier::new(2));
    let operations = [Uuid::now_v7(), Uuid::now_v7()];
    let mut handles = Vec::new();
    for operation in operations {
        let fixture = Arc::clone(&fixture);
        let token = token.clone();
        let wrong = wrong.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            fixture
                .store()
                .verify(operation, token.expose_secret(), &wrong)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert!(results
        .iter()
        .all(|result| { *result == Ok(RegistrationEmailVerification::Unavailable) }));
    let initial_counts = wrong_counts(&fixture, context);
    assert!((1..=2).contains(&initial_counts.0));
    assert_eq!(initial_counts.1, i64::from(initial_counts.0));
    assert_eq!(initial_counts.2, i64::from(initial_counts.0));
    assert_eq!(compared_events(), i64::from(initial_counts.0));
    assert_eq!(
        fixture.count("registration_email_events") - baseline_events,
        2
    );
    for operation in operations {
        assert_eq!(
            fixture
                .store()
                .verify(operation, token.expose_secret(), &wrong),
            Ok(RegistrationEmailVerification::Unavailable)
        );
    }
    assert_eq!(wrong_counts(&fixture, context), initial_counts);
    if initial_counts.0 == 1 {
        assert_eq!(
            fixture
                .store()
                .verify(Uuid::now_v7(), token.expose_secret(), &wrong),
            Ok(RegistrationEmailVerification::Unavailable)
        );
        assert_eq!(wrong_counts(&fixture, context), (2, 2, 2));
        assert_eq!(compared_events(), 2);
    }
}

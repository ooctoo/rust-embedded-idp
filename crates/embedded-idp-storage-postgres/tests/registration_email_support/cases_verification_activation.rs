use super::registration_email_support::*;
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

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn concurrent_correct_codes_for_two_contexts_activate_once() {
    let fixture = Arc::new(Fixture::new());
    let (first_token, first_context, first_payload) = ready(&fixture, "winner@example.test");
    fixture.shift_send_timestamps(60);
    let second = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "winner@example.test",
            "ReadyPassword123",
            None,
        ))
        .expect("second registration");
    let second_token = second.verification_context;
    let second_context = fixture.context_id(&second_token);
    assert_eq!(
        fixture.store().prepare(second_context, 1),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    let second_payload = delivery(&fixture, second_context, 1);
    let barrier = Arc::new(Barrier::new(2));
    let inputs = [
        (first_token, first_payload.code),
        (second_token, second_payload.code),
    ];
    let mut handles = Vec::new();
    for (token, code) in inputs {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            fixture
                .store()
                .verify(Uuid::now_v7(), token.expose_secret(), code.expose_secret())
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Ok(RegistrationEmailVerification::Verified))
            .count(),
        1
    );
    assert_eq!(fixture.count("accounts"), 2);
    assert_eq!(fixture.count("access_memberships"), 2);
    assert_eq!(fixture.count("registration_email_contexts"), 2);
    let _ = first_context;
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn newer_intent_prepares_before_older_intent_and_supersedes_old_sequence() {
    let fixture = Fixture::new();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "intent-order@example.test",
            "IntentOrderPassword123",
            None,
        ))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    fixture
        .store()
        .prepare(context, 1)
        .expect("first preparation");
    fixture.shift_send_timestamps(60);
    fixture
        .store()
        .resend(Uuid::now_v7(), token.expose_secret())
        .expect("resend");
    assert_eq!(context_row(&fixture, context).2, Some(1));
    assert_eq!(
        fixture.store().prepare(context, 2),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Superseded)
    );
    assert_eq!(intent_status(&fixture, context, 1), "superseded");
    assert_eq!(intent_status(&fixture, context, 2), "prepared");
    assert_eq!(fixture.count("registration_email_codes"), 2);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn failed_new_generation_transaction_preserves_the_previous_code() {
    let fixture = Fixture::new();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "generation-failure@example.test",
            "GenerationPassword123",
            None,
        ))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    fixture
        .store()
        .prepare(context, 1)
        .expect("first preparation");
    let first = delivery(&fixture, context, 1);
    fixture.shift_send_timestamps(60);
    fixture
        .store()
        .resend(Uuid::now_v7(), token.expose_secret())
        .expect("resend");
    let mut client = fixture.adapter.connect().unwrap();
    client
        .batch_execute(&format!(
            "create function {}.reject_registration_code() returns trigger language plpgsql as $$ begin raise exception 'test code failure'; end $$; create trigger reject_registration_code before insert on {}.registration_email_codes for each row execute function {}.reject_registration_code()",
            fixture.schema, fixture.schema, fixture.schema
        ))
        .unwrap();
    assert!(fixture.store().prepare(context, 2).is_err());
    client
        .batch_execute(&format!(
            "drop trigger reject_registration_code on {}.registration_email_codes; drop function {}.reject_registration_code()",
            fixture.schema, fixture.schema
        ))
        .unwrap();
    assert_eq!(fixture.count("registration_email_codes"), 1);
    assert!(delivery(&fixture, context, 1).code.expose_secret() == first.code.expose_secret());
    assert_eq!(context_row(&fixture, context).2, Some(1));
    assert_eq!(
        fixture.store().prepare(context, 2),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    assert_eq!(fixture.count("registration_email_codes"), 2);
}

use super::registration_email_support::*;
use embedded_idp_core::SecretString;
use embedded_idp_storage_postgres::{
    RegistrationEmailDeliveryResult, RegistrationEmailPreparation, RegistrationEmailVerification,
};
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
fn failed_delivery_does_not_make_the_old_code_active_again() {
    let fixture = Fixture::new();
    let (token, context, old_payload) = ready(&fixture, "failed-delivery@example.test");
    fixture.shift_send_timestamps(60);
    fixture
        .store()
        .resend(Uuid::now_v7(), token.expose_secret())
        .expect("resend");
    assert_eq!(context_row(&fixture, context).1, 2);
    assert_eq!(
        fixture.store().prepare(context, 2),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    let new_payload = delivery(&fixture, context, 2);
    let claim = claim(&fixture, new_payload.effect_id);
    fixture
        .store()
        .finish_delivery(&claim, RegistrationEmailDeliveryResult::Failed)
        .expect("failed delivery receipt");
    assert_eq!(
        fixture.store().verify(
            Uuid::now_v7(),
            token.expose_secret(),
            old_payload.code.expose_secret()
        ),
        Ok(RegistrationEmailVerification::Unavailable)
    );
    assert_eq!(
        fixture.store().verify(
            Uuid::now_v7(),
            token.expose_secret(),
            new_payload.code.expose_secret()
        ),
        Ok(RegistrationEmailVerification::Verified)
    );
    assert!(matches!(
        status_for_email(&fixture, "failed-delivery@example.test"),
        Some((_, status)) if status == "active"
    ));
    assert_eq!(wrong_counts(&fixture, context), (1, 1, 1));
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn event_failure_rolls_back_wrong_count_and_bucket_counters() {
    let fixture = Fixture::new();
    let (token, context, payload) = ready(&fixture, "event-failure@example.test");
    let events = fixture.count("registration_email_events");
    fixture.install_event_failure();
    assert!(fixture
        .store()
        .verify(
            Uuid::now_v7(),
            token.expose_secret(),
            different_code(&payload),
        )
        .is_err());
    fixture.drop_event_failure();
    assert_eq!(wrong_counts(&fixture, context), (0, 0, 0));
    assert_eq!(fixture.count("registration_email_events"), events);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn successful_verification_event_failure_rolls_back_identity_and_code() {
    let fixture = Fixture::new();
    let (token, context, payload) = ready(&fixture, "success-event-failure@example.test");
    let accounts = fixture.count("accounts");
    let memberships = fixture.count("access_memberships");
    let events = fixture.count("registration_email_events");
    fixture.install_event_failure();
    assert!(fixture
        .store()
        .verify(
            Uuid::now_v7(),
            token.expose_secret(),
            payload.code.expose_secret(),
        )
        .is_err());
    fixture.drop_event_failure();
    assert_eq!(fixture.count("accounts"), accounts);
    assert_eq!(fixture.count("access_memberships"), memberships);
    assert!(status_for_email(&fixture, "success-event-failure@example.test").is_none());
    let context_row = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select password_cipher,prepared,completed_operation from {}.registration_email_contexts where id=$1",
                fixture.schema
            ),
            &[&context],
        )
        .unwrap();
    assert!(!context_row.get::<_, Vec<u8>>(0).is_empty());
    assert!(context_row.get::<_, bool>(1));
    assert!(context_row.get::<_, Option<Uuid>>(2).is_none());
    let consumed: Option<i64> = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select consumed_at from {}.registration_email_codes where context_id=$1 and seq=1",
                fixture.schema
            ),
            &[&context],
        )
        .unwrap()
        .get(0);
    assert!(consumed.is_none());
    assert_eq!(fixture.count("registration_email_events"), events);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn exact_context_and_code_expiry_boundary_is_unavailable_without_wrong_charge() {
    let fixture = Fixture::new();
    let (token, context, payload) = ready(&fixture, "exact-expiry@example.test");
    let now = fixture.now();
    assert!(payload.expires_at > now);
    fixture.set_expiry(context, now, now);
    assert_eq!(
        fixture.store().verify(
            Uuid::now_v7(),
            token.expose_secret(),
            payload.code.expose_secret()
        ),
        Ok(RegistrationEmailVerification::Unavailable)
    );
    assert_eq!(wrong_counts(&fixture, context), (0, 0, 0));
}

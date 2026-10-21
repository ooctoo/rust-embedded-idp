use super::*;
use embedded_idp_core::access::RegistrationEmailError;
use embedded_idp_storage_postgres::RegistrationEmailDeliveryResult;
use uuid::Uuid;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn forged_delivery_claim_is_rejected_without_audit_or_state_change() {
    let fixture = Fixture::new();
    let operation = Uuid::now_v7();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            operation,
            "forged-claim@example.test",
            "BoundaryPassword123",
            None,
        ))
        .expect("registration");
    let context = fixture.context_id(&accepted.verification_context);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    let payload = delivery(&fixture, context, 1);
    let claim = claim(&fixture, payload.effect_id);
    let event_count = fixture.count("registration_email_events");
    let stored_lease = delivery_lease(&fixture, claim.effect_id);

    let mut forged_lease = claim.clone();
    forged_lease.lease_until += 1;
    assert!(matches!(
        fixture
            .store()
            .finish_delivery(&forged_lease, RegistrationEmailDeliveryResult::Sent),
        Err(RegistrationEmailError::Unavailable)
    ));
    assert_eq!(fixture.count("registration_email_events"), event_count);
    assert_eq!(delivery_state(&fixture, claim.effect_id).0, "claimed");
    assert_eq!(delivery_lease(&fixture, claim.effect_id), stored_lease);

    let mut forged_context = claim.clone();
    forged_context.context_id = Uuid::now_v7();
    assert!(matches!(
        fixture
            .store()
            .finish_delivery(&forged_context, RegistrationEmailDeliveryResult::Sent),
        Err(RegistrationEmailError::Unavailable)
    ));
    assert_eq!(fixture.count("registration_email_events"), event_count);
    assert_eq!(delivery_state(&fixture, claim.effect_id).0, "claimed");
    assert_eq!(delivery_lease(&fixture, claim.effect_id), stored_lease);

    let mut forged_sequence = claim.clone();
    forged_sequence.sequence += 1;
    assert!(matches!(
        fixture
            .store()
            .finish_delivery(&forged_sequence, RegistrationEmailDeliveryResult::Sent),
        Err(RegistrationEmailError::Unavailable)
    ));
    assert_eq!(fixture.count("registration_email_events"), event_count);
    assert_eq!(delivery_state(&fixture, claim.effect_id).0, "claimed");
    assert_eq!(delivery_lease(&fixture, claim.effect_id), stored_lease);

    fixture
        .store()
        .finish_delivery(&claim, RegistrationEmailDeliveryResult::Sent)
        .expect("correct delivery claim");
    assert_eq!(fixture.count("registration_email_events"), event_count + 1);
    assert_eq!(
        event_kind_and_reason(&fixture, operation),
        ("register".into(), "sent".into())
    );
    assert_eq!(
        delivery_state(&fixture, claim.effect_id),
        ("sent".into(), true, 0)
    );
}

use super::*;
use embedded_idp_core::access::RegistrationEmailError;
use embedded_idp_storage_postgres::RegistrationEmailDeliveryResult;
use uuid::Uuid;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn inactive_tenant_allows_maintenance_receipts_but_denies_new_claims() {
    let fixture = Fixture::new();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "inactive-tenant@example.test",
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
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .execute(
            &format!(
                "update {}.access_tenants set status='suspended' where id=$1",
                fixture.schema
            ),
            &[&TENANT],
        )
        .expect("suspend tenant");

    assert!(matches!(
        fixture.store().claim_delivery(claim.effect_id),
        Err(RegistrationEmailError::Unavailable)
    ));
    fixture
        .store()
        .finish_delivery(&claim, RegistrationEmailDeliveryResult::Unknown)
        .expect("finish unknown delivery while inactive");
    fixture
        .store()
        .maintain(1)
        .expect("maintenance while inactive");
    fixture
        .store()
        .confirm_delivery_stopped(&claim)
        .expect("confirm stopped delivery while inactive");
    let state = delivery_state(&fixture, claim.effect_id);
    assert_eq!(state.0, "unknown");
    assert!(state.1);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn bounded_retention_gc_preserves_active_window_and_candidate_batches() {
    let fixture = Fixture::new();
    let first_operation = Uuid::now_v7();
    let second_operation = Uuid::now_v7();
    let active_operation = Uuid::now_v7();
    let first = expired_prepared_context(&fixture, "gc-first@example.test", first_operation);
    let second = expired_prepared_context(&fixture, "gc-second@example.test", second_operation);
    let active = expired_prepared_context(&fixture, "gc-active@example.test", active_operation);
    let now = fixture.now();
    fixture.set_expiry(first, now - 2, now - 2);
    fixture.set_expiry(second, now - 1, now - 1);

    assert_eq!(fixture.store().maintain(1).expect("first bounded sweep"), 0);
    assert_eq!(password_cipher_len(&fixture, first), 0);
    assert!(password_cipher_len(&fixture, second) > 0);
    assert!(password_cipher_len(&fixture, active) > 0);
    assert!(context_exists(&fixture, first));
    assert!(context_exists(&fixture, second));
    assert!(context_exists(&fixture, active));
    assert_eq!(fixture.count("registration_email_codes"), 3);
    assert_eq!(fixture.count("registration_email_deliveries"), 3);

    fixture.store().maintain(1).expect("second candidate batch");
    assert_eq!(password_cipher_len(&fixture, first), 0);
    assert_eq!(password_cipher_len(&fixture, second), 0);
    assert!(password_cipher_len(&fixture, active) > 0);
    assert_eq!(fixture.count("registration_email_codes"), 3);
    assert_eq!(fixture.count("registration_email_deliveries"), 3);

    fixture.set_expiry(active, now + 600, now + 600);
    set_operation_retention(&fixture, first_operation, fixture.now() - 1);
    set_operation_retention(&fixture, second_operation, fixture.now() + 600);
    assert_eq!(
        fixture.store().maintain(1).expect("first retention batch"),
        1
    );
    assert!(!context_exists(&fixture, first));
    assert!(context_exists(&fixture, second));
    assert!(context_exists(&fixture, active));

    set_operation_retention(&fixture, second_operation, fixture.now() - 1);
    assert_eq!(
        fixture.store().maintain(1).expect("second retention batch"),
        1
    );
    assert!(!context_exists(&fixture, second));
    assert!(context_exists(&fixture, active));
}

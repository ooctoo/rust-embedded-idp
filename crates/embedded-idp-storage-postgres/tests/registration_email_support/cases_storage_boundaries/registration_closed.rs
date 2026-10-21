use super::*;
use embedded_idp_core::access::RegistrationEmailError;
use embedded_idp_storage_postgres::RegistrationEmailVerification;
use uuid::Uuid;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn closed_registration_blocks_new_register_but_prior_resend_and_verify_continue() {
    let fixture = Fixture::new();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "closed-verify@example.test",
            "BoundaryPassword123",
            None,
        ))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Prepared)
    );
    let code = delivery(&fixture, context, 1).code;
    let new_registration = fixture.prepared(
        Uuid::now_v7(),
        "closed-new@example.test",
        "BoundaryPassword123",
        None,
    );
    fixture
        .adapter
        .connect()
        .expect("fixture connection")
        .execute(
            &format!(
                "update {}.access_tenants set allow_registration=false where id=$1",
                fixture.schema
            ),
            &[&TENANT],
        )
        .expect("close registration");

    assert!(matches!(
        fixture.store().register(&new_registration),
        Err(RegistrationEmailError::RegistrationClosed)
    ));
    fixture
        .store()
        .resend(Uuid::now_v7(), token.expose_secret())
        .expect("normal closure retains prior context resend under existing cooldown");
    assert_eq!(fixture.count("registration_email_contexts"), 1);
    assert_eq!(
        fixture
            .store()
            .verify(Uuid::now_v7(), token.expose_secret(), code.expose_secret()),
        Ok(RegistrationEmailVerification::Verified)
    );
    assert_eq!(
        status_for_email(&fixture, "closed-verify@example.test")
            .unwrap()
            .1,
        "active"
    );
}

use super::*;
use embedded_idp_core::access::{RegistrationEmailError, RegistrationEmailScope, TenancyMode};
use uuid::Uuid;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn product_subject_bucket_cap_is_scoped_to_product_binding() {
    let fixture = Fixture::new();
    let store_a = capped_store(&fixture, fixture.scope.clone());
    store_a
        .register(&fixture.prepared(
            Uuid::now_v7(),
            "product-cap@example.test",
            "BoundaryPassword123",
            None,
        ))
        .expect("first product bucket");
    assert_eq!(bucket_count(&fixture, PRODUCT), 1);

    let second = fixture.prepared(
        Uuid::now_v7(),
        "product-cap-second@example.test",
        "BoundaryPassword123",
        None,
    );
    assert!(matches!(
        store_a.register(&second),
        Err(RegistrationEmailError::Unavailable)
    ));
    assert_eq!(bucket_count(&fixture, PRODUCT), 1);

    fixture.shift_send_timestamps(60);
    let product_b = "other";
    let scope_b = RegistrationEmailScope::new(AUTHORITY, product_b, TENANT, TenancyMode::Enabled)
        .expect("product scope");
    fixture
        .adapter
        .bind_registration_email_product(&scope_b)
        .expect("product binding");
    let store_b = capped_store(&fixture, scope_b.clone());
    store_b
        .register(&prepare_for_scope(
            &fixture,
            &scope_b,
            Uuid::now_v7(),
            "product-cap@example.test",
        ))
        .expect("different product bucket");
    assert_eq!(bucket_count(&fixture, product_b), 1);
}

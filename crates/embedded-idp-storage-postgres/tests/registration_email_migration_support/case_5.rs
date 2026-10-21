use super::*;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn normalization_collision_and_plan_drift_are_rejected() {
    let collision = Fixture::new(true);
    let plan = collision.plan();
    assert_eq!(plan.normalization_collision_count, 1);
    assert!(collision
        .adapter
        .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled)
        .is_err());
    let drift = Fixture::new(false);
    let plan = drift.plan();
    let mut client = drift.adapter.connect().unwrap();
    client
        .execute(
            &format!(
                "update {}.accounts set password_hash='changed' where id=$1",
                drift.schema
            ),
            &[&drift.account_id],
        )
        .unwrap();
    assert!(matches!(
        drift
            .adapter
            .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled),
        Err(embedded_idp_core::StoreError::Conflict(
            "registration_email.plan_drift"
        ))
    ));
}

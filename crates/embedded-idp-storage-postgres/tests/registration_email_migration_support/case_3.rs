use super::*;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn wrong_schema_plan_is_rejected_before_install() {
    let source = Fixture::new(false);
    let target = Fixture::new(false);
    let plan = source.plan();
    assert!(matches!(
        target
            .adapter
            .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled),
        Err(embedded_idp_core::StoreError::Conflict(
            "registration_email.plan_scope"
        ))
    ));
    let mut client = target.adapter.connect().unwrap();
    assert_eq!(
        client
            .query_one(
                "select to_regclass($1)::text",
                &[&format!("{}.registration_email_state", target.schema)]
            )
            .unwrap()
            .get::<_, Option<String>>(0),
        None
    );
}

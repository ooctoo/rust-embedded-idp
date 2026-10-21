use super::*;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn plan_is_read_only_and_no_startup_auto_migration() {
    let fixture = Fixture::new(false);
    let plan = fixture.plan();
    assert_eq!(plan.account_count, 1);
    assert_eq!(plan.normalized_count, 1);
    assert_eq!(plan.legacy_code_count, 1);
    let mut client = fixture.adapter.connect().unwrap();
    assert_eq!(
        client
            .query_one(
                "select to_regclass($1)::text",
                &[&format!("{}.registration_email_state", fixture.schema)]
            )
            .unwrap()
            .get::<_, Option<String>>(0),
        None
    );
}

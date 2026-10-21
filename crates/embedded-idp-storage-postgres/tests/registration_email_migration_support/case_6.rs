use super::*;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn migration_rolls_back_columns_legacy_consumption_and_state() {
    let fixture = Fixture::new(false);
    let mut client = fixture.adapter.connect().unwrap();
    client.batch_execute(&format!("create function {}.reject_email_normalization() returns trigger language plpgsql as $$ begin raise exception 'test rollback'; end $$; create trigger reject_email_normalization before update of email on {}.accounts for each row execute function {}.reject_email_normalization()", fixture.schema, fixture.schema, fixture.schema)).unwrap();
    let plan = fixture.plan();
    assert!(fixture
        .adapter
        .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled)
        .is_err());
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
    assert_eq!(client.query_one(&format!("select count(*) from {}.email_verification_codes where consumed_at_epoch is null", fixture.schema), &[]).unwrap().get::<_, i64>(0), 1);
}

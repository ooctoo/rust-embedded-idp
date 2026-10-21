use super::*;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn invalid_index_is_not_reported_as_a_complete_foundation() {
    let fixture = Fixture::new(false);
    let plan = fixture.plan();
    fixture
        .adapter
        .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled)
        .unwrap();
    fixture
        .adapter
        .bind_registration_email_product(&fixture.scope())
        .unwrap();
    let mut client = fixture.adapter.connect().unwrap();
    let digest = vec![0_u8; 32];
    for operation_id in [Uuid::now_v7(), Uuid::now_v7()] {
        client
            .execute(
                &format!(
                    "insert into {}.registration_email_operations(authority,product,kind,operation_id,request_digest,phase,reserved_rows,lease_until,fence,retain_until) values('sut','online','register',$1,$2,'reserved',1,1700000000,1,1700000000)",
                    fixture.schema
                ),
                &[&operation_id, &digest],
            )
            .unwrap();
    }
    client
        .batch_execute(&format!(
            "drop index {}.registration_email_operations_phase_idx",
            fixture.schema
        ))
        .unwrap();
    assert!(client
        .batch_execute(&format!(
            "create unique index concurrently registration_email_operations_phase_idx on {}.registration_email_operations(authority,product,phase,retain_until)",
            fixture.schema
        ))
        .is_err());
    assert!(client
        .query_one(
            "select not indisvalid from pg_index i join pg_class c on c.oid=i.indexrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname='registration_email_operations_phase_idx'",
            &[&fixture.schema]
        )
        .unwrap()
        .get::<_, bool>(0));
    let facts = fixture
        .adapter
        .inspect_registration_email_foundation(&fixture.scope())
        .unwrap();
    assert!(!facts.indexes_complete);
}

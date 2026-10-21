use super::*;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn explicit_apply_installs_binds_consumes_and_rejects_legacy_writer() {
    let fixture = Fixture::new(false);
    let plan = fixture.plan();
    fixture
        .adapter
        .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled)
        .unwrap();
    assert!(matches!(
        fixture
            .adapter
            .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled),
        Err(embedded_idp_core::StoreError::Conflict(
            "registration_email.already_installed"
        ))
    ));
    fixture
        .adapter
        .bind_registration_email_product(&fixture.scope())
        .unwrap();
    let facts = fixture
        .adapter
        .inspect_registration_email_foundation(&fixture.scope())
        .unwrap();
    assert!(facts.state_present && facts.binding_matches);
    assert!(
        facts.tables_complete
            && facts.columns_complete
            && facts.indexes_complete
            && facts.triggers_complete
            && facts.constraints_complete
    );
    assert!(facts.legacy_codes_consumed && !facts.public_profile_ready);
    let mut client = fixture.adapter.connect().unwrap();
    assert_eq!(
        client
            .query_one(
                &format!("select email from {}.accounts where id=$1", fixture.schema),
                &[&fixture.account_id]
            )
            .unwrap()
            .get::<_, String>(0),
        "User@example.com"
    );
    let invalid_insert = Uuid::now_v7();
    let mut invalid_insert_tx = client.transaction().unwrap();
    assert!(invalid_insert_tx
        .execute(
            &format!(
                "insert into {}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,'t1',' New@EXAMPLE.COM ','hash','pending_verification',1700000000)",
                fixture.schema
            ),
            &[&invalid_insert]
        )
        .is_err());
    invalid_insert_tx.rollback().unwrap();
    assert!(client
        .execute(
            &format!(
                "update {}.accounts set email=' User@example.com ' where id=$1",
                fixture.schema
            ),
            &[&fixture.account_id]
        )
        .is_err());
    assert!(client.execute(&format!("insert into {}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values('t1',$1,$2,'User@example.com','123456',1,2)", fixture.schema), &[&Uuid::now_v7(), &fixture.account_id]).is_err());
    assert!(client
        .execute(
            &format!(
                "update {}.email_verification_codes set code='654321' where id=$1",
                fixture.schema
            ),
            &[&fixture.code_id]
        )
        .is_err());
    client
        .batch_execute(&format!(
            "alter table {}.accounts disable trigger registration_email_account_security_bu",
            fixture.schema
        ))
        .unwrap();
    let disabled = fixture
        .adapter
        .inspect_registration_email_foundation(&fixture.scope())
        .unwrap();
    assert!(!disabled.triggers_complete);
    client
        .batch_execute(&format!(
            "alter table {}.accounts enable trigger registration_email_account_security_bu",
            fixture.schema
        ))
        .unwrap();
    client
        .batch_execute(&format!(
            "alter table {}.access_memberships disable trigger registration_email_member_security_bu",
            fixture.schema
        ))
        .unwrap();
    let member_disabled = fixture
        .adapter
        .inspect_registration_email_foundation(&fixture.scope())
        .unwrap();
    assert!(!member_disabled.triggers_complete);
    client
        .batch_execute(&format!(
            "alter table {}.access_memberships enable trigger registration_email_member_security_bu",
            fixture.schema
        ))
        .unwrap();
    client
        .batch_execute(&format!(
            "drop trigger registration_email_legacy_code_guard on {}.email_verification_codes",
            fixture.schema
        ))
        .unwrap();
    let drifted = fixture
        .adapter
        .inspect_registration_email_foundation(&fixture.scope())
        .unwrap();
    assert!(!drifted.triggers_complete);
    client
        .batch_execute(&format!(
            "alter table {}.accounts drop constraint registration_email_account_email_canonical_ck",
            fixture.schema
        ))
        .unwrap();
    let missing_constraint = fixture
        .adapter
        .inspect_registration_email_foundation(&fixture.scope())
        .unwrap();
    assert!(!missing_constraint.constraints_complete);
}

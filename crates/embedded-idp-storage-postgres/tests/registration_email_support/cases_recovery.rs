use super::registration_email_support::*;
use embedded_idp_storage_postgres::{RegistrationEmailPreparation, RegistrationEmailVerification};
use uuid::Uuid;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn account_change_and_delete_recreate_invalidate_the_old_context() {
    let fixture = Fixture::with_existing_account();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(Uuid::now_v7(), EXISTING_EMAIL, "RecoveryPassword123", None))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    fixture.store().prepare(context, 1).expect("preparation");
    let code = delivery(&fixture, context, 1).code;
    let old_account: Uuid = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!("select id from {}.accounts where email=$1", fixture.schema),
            &[&EXISTING_EMAIL],
        )
        .unwrap()
        .get(0);
    fixture
        .adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.accounts set password_hash=$2 where id=$1",
                fixture.schema
            ),
            &[&old_account, &"admin-changed-hash"],
        )
        .unwrap();
    assert_eq!(
        fixture
            .store()
            .verify(Uuid::now_v7(), token.expose_secret(), code.expose_secret()),
        Ok(RegistrationEmailVerification::Unavailable)
    );
    assert_eq!(
        status_for_email(&fixture, EXISTING_EMAIL).unwrap().1,
        "pending_verification"
    );

    let mut client = fixture.adapter.connect().unwrap();
    let mut tx = client.transaction().unwrap();
    tx.execute(
        &format!(
            "delete from {}.email_verification_codes where account_id=$1",
            fixture.schema
        ),
        &[&old_account],
    )
    .unwrap();
    tx.execute(
        &format!(
            "delete from {}.access_memberships where account_id=$1",
            fixture.schema
        ),
        &[&old_account],
    )
    .unwrap();
    tx.execute(
        &format!("delete from {}.accounts where id=$1", fixture.schema),
        &[&old_account],
    )
    .unwrap();
    let new_account = Uuid::now_v7();
    tx.execute(
        &format!(
            "insert into {}.accounts(id,registration_tenant_id,email,password_hash,display_name,status,created_at_epoch) values($1,$2,$3,$4,$5,'pending_verification',$6)",
            fixture.schema
        ),
        &[&new_account, &TENANT, &EXISTING_EMAIL, &"new-pending-hash", &"Recreated", &fixture.now()],
    )
    .unwrap();
    tx.execute(
        &format!(
            "insert into {}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',$3)",
            fixture.schema
        ),
        &[&TENANT, &new_account, &fixture.now()],
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        fixture
            .store()
            .verify(Uuid::now_v7(), token.expose_secret(), code.expose_secret()),
        Ok(RegistrationEmailVerification::Unavailable)
    );
    assert_eq!(
        status_for_email(&fixture, EXISTING_EMAIL).unwrap().0,
        new_account
    );
    assert_eq!(fixture.count("registration_email_tombstones"), 1);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn member_suspend_and_reactivate_invalidates_the_old_context() {
    let fixture = Fixture::with_existing_account();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            EXISTING_EMAIL,
            "MemberVersionPassword123",
            None,
        ))
        .expect("registration");
    let context = fixture.context_id(&accepted.verification_context);
    let account: Uuid = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!("select id from {}.accounts where email=$1", fixture.schema),
            &[&EXISTING_EMAIL],
        )
        .unwrap()
        .get(0);
    let mut client = fixture.adapter.connect().unwrap();
    let mut tx = client.transaction().unwrap();
    tx.execute(
        &format!(
            "update {}.access_memberships set status='suspended',version=version+1 where tenant_id=$1 and account_id=$2",
            fixture.schema
        ),
        &[&TENANT, &account],
    )
    .unwrap();
    tx.execute(
        &format!(
            "update {}.access_memberships set status='active',version=version+1 where tenant_id=$1 and account_id=$2",
            fixture.schema
        ),
        &[&TENANT, &account],
    )
    .unwrap();
    tx.commit().unwrap();

    let row = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select status,version,registration_invalidated_at from {}.access_memberships where tenant_id=$1 and account_id=$2",
                fixture.schema
            ),
            &[&TENANT, &account],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "active");
    assert_eq!(row.get::<_, i64>(1), 3);
    assert!(row.get::<_, i64>(2) >= accepted.accepted_at_unix_secs);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Suppressed)
    );
    assert_eq!(fixture.count("registration_email_codes"), 0);
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn member_delete_and_recreate_invalidates_the_old_context() {
    let fixture = Fixture::with_existing_account();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            EXISTING_EMAIL,
            "MemberDeletePassword123",
            None,
        ))
        .expect("registration");
    let token = accepted.verification_context;
    let context = fixture.context_id(&token);
    fixture.store().prepare(context, 1).expect("preparation");
    let code = delivery(&fixture, context, 1).code;
    let account: Uuid = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!("select id from {}.accounts where email=$1", fixture.schema),
            &[&EXISTING_EMAIL],
        )
        .unwrap()
        .get(0);
    let old_version: i64 = fixture
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select version from {}.access_memberships where tenant_id=$1 and account_id=$2",
                fixture.schema
            ),
            &[&TENANT, &account],
        )
        .unwrap()
        .get(0);
    let mut client = fixture.adapter.connect().unwrap();
    let mut tx = client.transaction().unwrap();
    tx.execute(
        &format!(
            "delete from {}.email_verification_codes where account_id=$1",
            fixture.schema
        ),
        &[&account],
    )
    .unwrap();
    tx.execute(
        &format!(
            "delete from {}.access_memberships where tenant_id=$1 and account_id=$2",
            fixture.schema
        ),
        &[&TENANT, &account],
    )
    .unwrap();
    tx.execute(
        &format!(
            "insert into {}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch) values($1,$2,'active',$3,$4)",
            fixture.schema
        ),
        &[&TENANT, &account, &(old_version + 1), &fixture.now()],
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(fixture.count("registration_email_member_tombstones"), 1);
    assert_eq!(
        fixture
            .store()
            .verify(Uuid::now_v7(), token.expose_secret(), code.expose_secret()),
        Ok(RegistrationEmailVerification::Unavailable)
    );
}

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn email_rename_between_accept_and_prepare_is_suppressed_by_tombstone() {
    let fixture = Fixture::with_existing_account();
    let accepted = fixture
        .store()
        .register(&fixture.prepared(
            Uuid::now_v7(),
            EXISTING_EMAIL,
            "EmailRenamePassword123",
            None,
        ))
        .expect("registration");
    let context = fixture.context_id(&accepted.verification_context);
    fixture
        .adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.accounts set email=$2 where email=$1",
                fixture.schema
            ),
            &[&EXISTING_EMAIL, &"renamed@example.test"],
        )
        .unwrap();
    assert_eq!(fixture.count("registration_email_tombstones"), 1);
    assert_eq!(
        fixture.store().prepare(context, 1),
        Ok(RegistrationEmailPreparation::Suppressed)
    );
    assert_eq!(fixture.count("registration_email_codes"), 0);
}

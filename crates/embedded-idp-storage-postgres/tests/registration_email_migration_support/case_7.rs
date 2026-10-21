use super::*;

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn account_security_revision_and_delete_tombstone_survive_admin_changes() {
    let fixture = Fixture::new(false);
    let plan = fixture.plan();
    fixture
        .adapter
        .apply_registration_email_foundation(&plan, "sut", TenancyMode::Enabled)
        .unwrap();
    let mut client = fixture.adapter.connect().unwrap();
    let initial_account_revision = client
        .query_one(
            &format!(
                "select registration_security_revision from {}.accounts where id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(initial_account_revision, 0);
    client
        .execute(
            &format!(
                "update {}.accounts set password_hash='new-hash' where id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    let revision = client
        .query_one(
            &format!(
                "select registration_security_revision from {}.accounts where id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(revision, 1);
    client
        .execute(
            &format!(
                "update {}.accounts set email='Renamed@example.com' where id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    let renamed_email_tombstone = client
        .query_one(
            &format!(
                "select account_id,revision,retain_until-invalidated_at from {}.registration_email_tombstones where email='User@example.com'",
                fixture.schema
            ),
            &[],
        )
        .unwrap();
    assert_eq!(
        renamed_email_tombstone.get::<_, Uuid>(0),
        fixture.account_id
    );
    assert!(renamed_email_tombstone.get::<_, i64>(1) >= 2);
    assert!(renamed_email_tombstone.get::<_, i64>(2) >= 960);

    let account_revision_before_membership_changes = client
        .query_one(
            &format!(
                "select registration_security_revision from {}.accounts where id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap()
        .get::<_, i64>(0);
    client
        .execute(
            &format!(
                "update {}.access_memberships set status='suspended',version=version+1,joined_at_epoch=joined_at_epoch+1 where tenant_id='t1' and account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    let first_member_watermark = client
        .query_one(
            &format!(
                "select registration_invalidated_at from {}.access_memberships where tenant_id='t1' and account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap()
        .get::<_, i64>(0);
    client
        .execute(
            &format!(
                "update {}.access_memberships set status='active',version=version+1,joined_at_epoch=joined_at_epoch+1 where tenant_id='t1' and account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    let second_member_watermark = client
        .query_one(
            &format!(
                "select registration_invalidated_at from {}.access_memberships where tenant_id='t1' and account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap()
        .get::<_, i64>(0);
    assert!(second_member_watermark >= first_member_watermark);
    assert!(second_member_watermark > 0);
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select registration_security_revision from {}.accounts where id=$1",
                    fixture.schema
                ),
                &[&fixture.account_id],
            )
            .unwrap()
            .get::<_, i64>(0),
        account_revision_before_membership_changes
    );

    client
        .execute(
            &format!(
                "delete from {}.email_verification_codes where account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    let mut recreate = client.transaction().unwrap();
    recreate
        .execute(
            &format!(
                "delete from {}.access_memberships where tenant_id='t1' and account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    recreate
        .execute(
            &format!(
                "insert into {}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch) values('t1',$1,'active',4,1700000003)",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    recreate.commit().unwrap();
    let recreated_member_tombstone = client
        .query_one(
            &format!(
                "select invalidated_at,retain_until from {}.registration_email_member_tombstones where tenant='t1' and account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    assert!(recreated_member_tombstone.get::<_, i64>(0) >= second_member_watermark);
    assert!(
        recreated_member_tombstone.get::<_, i64>(1)
            >= recreated_member_tombstone.get::<_, i64>(0) + 960
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select registration_security_revision from {}.accounts where id=$1",
                    fixture.schema
                ),
                &[&fixture.account_id],
            )
            .unwrap()
            .get::<_, i64>(0),
        account_revision_before_membership_changes
    );
    client
        .execute(
            &format!(
                "update {}.accounts set status='closed' where id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    let mut tx = client.transaction().unwrap();
    tx.execute(
        &format!(
            "update {}.access_memberships set status='removed',removed_at_epoch=1700000001 where account_id=$1",
            fixture.schema
        ),
        &[&fixture.account_id],
    )
    .unwrap();
    tx.execute(
        &format!(
            "delete from {}.access_memberships where account_id=$1",
            fixture.schema
        ),
        &[&fixture.account_id],
    )
    .unwrap();
    tx.execute(
        &format!("delete from {}.accounts where id=$1", fixture.schema),
        &[&fixture.account_id],
    )
    .unwrap();
    tx.commit().unwrap();
    let final_member_tombstone = client
        .query_one(
            &format!(
                "select invalidated_at,retain_until from {}.registration_email_member_tombstones where tenant='t1' and account_id=$1",
                fixture.schema
            ),
            &[&fixture.account_id],
        )
        .unwrap();
    assert!(final_member_tombstone.get::<_, i64>(0) >= recreated_member_tombstone.get::<_, i64>(0));
    assert!(
        final_member_tombstone.get::<_, i64>(1) >= final_member_tombstone.get::<_, i64>(0) + 960
    );
    let tombstone = client
        .query_one(
            &format!(
                "select email,account_id,revision,retain_until-invalidated_at from {}.registration_email_tombstones where email='Renamed@example.com'",
                fixture.schema
            ),
            &[],
        )
        .unwrap();
    assert_eq!(tombstone.get::<_, String>(0), "Renamed@example.com");
    assert_eq!(tombstone.get::<_, Uuid>(1), fixture.account_id);
    assert!(tombstone.get::<_, i64>(2) >= 3);
    assert!(tombstone.get::<_, i64>(3) >= 960);
}

use super::*;

const AUTHORITY: &str = "phase-one-test";

fn version(db: &Db) -> i64 {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select security_credential_version from {}.accounts where id=$1",
                db.schema()
            ),
            &[&db.member],
        )
        .unwrap()
        .get(0)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_foundation_plan_is_read_only_and_bound_to_target() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let plan = db
            .adapter
            .plan_security_foundation(mode, AUTHORITY)
            .unwrap();
        let mut c = db.adapter.connect().unwrap();
        assert!(!c
            .query_one(
                "select to_regclass($1) is not null",
                &[&format!("{}.security_state", db.schema())]
            )
            .unwrap()
            .get::<_, bool>(0));
        assert!(db
            .adapter
            .check_security_foundation(mode, AUTHORITY)
            .is_err());
        let mut wrong = plan.clone();
        wrong.authority = "other-authority".into();
        assert!(db.adapter.apply_security_foundation(&wrong).is_err());
        let another = Db::new(mode);
        assert!(another.adapter.apply_security_foundation(&plan).is_err());
        db.adapter.apply_security_foundation(&plan).unwrap();
        db.adapter
            .check_security_foundation(mode, AUTHORITY)
            .unwrap();
        assert!(db
            .adapter
            .check_security_foundation(mode, "other-authority")
            .is_err());
        let other_mode = if mode == TenancyMode::Enabled {
            TenancyMode::Disabled
        } else {
            TenancyMode::Enabled
        };
        assert!(db
            .adapter
            .check_security_foundation(other_mode, AUTHORITY)
            .is_err());
        assert!(db.adapter.apply_security_foundation(&plan).is_err());
        assert_eq!(version(&db), 1);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_foundation_versions_and_events_commit_or_roll_back_together() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let plan = db
            .adapter
            .plan_security_foundation(mode, AUTHORITY)
            .unwrap();
        db.adapter.apply_security_foundation(&plan).unwrap();
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        let inserted = Uuid::now_v7();
        {
            let mut tx = c.transaction().unwrap();
            tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,$2,'new-default@example.test','synthetic','active',1000)"), &[&inserted,&db.target()]).unwrap();
            tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',1000)"), &[&db.target(),&inserted]).unwrap();
            assert_eq!(
                tx.query_one(
                    &format!("select security_credential_version from {s}.accounts where id=$1"),
                    &[&inserted]
                )
                .unwrap()
                .get::<_, i64>(0),
                1
            );
            tx.commit().unwrap();
        }
        let error = c.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch,security_credential_version) values($1,$2,'invalid-version@example.test','synthetic','active',1000,2)"), &[&Uuid::now_v7(),&db.target()]).unwrap_err();
        assert_eq!(error.code().map(|c| c.code()), Some("23514"));
        c.execute(
            &format!("update {s}.accounts set display_name='new profile' where id=$1"),
            &[&db.member],
        )
        .unwrap();
        assert_eq!(version(&db), 1);
        let mut changes = vec![
            ("password_hash", "new-synthetic-hash"),
            ("email", "changed@example.test"),
            ("status", "disabled"),
        ];
        if mode == TenancyMode::Enabled {
            changes.push(("registration_tenant_id", "t2"));
        }
        let updated_version = 1 + changes.len() as i64;
        for (column, value) in changes {
            let old = version(&db);
            c.execute(
                &format!("update {s}.accounts set {column}=$2 where id=$1"),
                &[&db.member, &value],
            )
            .unwrap();
            assert_eq!(version(&db), old + 1);
            c.execute(
                &format!("update {s}.accounts set {column}=$2 where id=$1"),
                &[&db.member, &value],
            )
            .unwrap();
            assert_eq!(version(&db), old + 1);
        }
        assert!(c
            .execute(
                &format!("update {s}.accounts set security_credential_version=1 where id=$1"),
                &[&db.member]
            )
            .is_err());
        assert_eq!(version(&db), updated_version);
        let event = Uuid::now_v7();
        {
            let mut tx = c.transaction().unwrap();
            tx.query_one(
                &format!("select singleton from {s}.access_state where singleton for update"),
                &[],
            )
            .unwrap();
            tx.execute(
                &format!("update {s}.accounts set password_hash='rolled-back-hash' where id=$1"),
                &[&db.member],
            )
            .unwrap();
            tx.execute(&format!("insert into {s}.security_events(id,kind,outcome,account_id,occurred_at_epoch) values($1,'password_changed','accepted',$2,1000)"), &[&event,&db.member]).unwrap();
            tx.rollback().unwrap();
        }
        assert_eq!(version(&db), updated_version);
        assert_eq!(
            c.query_one(&format!("select count(*) from {s}.security_events"), &[])
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        {
            let mut tx = c.transaction().unwrap();
            tx.query_one(
                &format!("select singleton from {s}.access_state where singleton for update"),
                &[],
            )
            .unwrap();
            tx.execute(
                &format!("update {s}.accounts set password_hash='committed-hash' where id=$1"),
                &[&db.member],
            )
            .unwrap();
            tx.execute(&format!("insert into {s}.security_events(id,kind,outcome,account_id,occurred_at_epoch) values($1,'password_changed','accepted',$2,1000)"), &[&event,&db.member]).unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(version(&db), updated_version + 1);
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_events where id=$1"),
                &[&event]
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        assert!(c.execute(&format!("insert into {s}.security_events(id,kind,outcome,occurred_at_epoch) values($1,'arbitrary_payload','accepted',1000)"), &[&Uuid::now_v7()]).is_err());
        db.adapter
            .check_security_foundation(mode, AUTHORITY)
            .unwrap();
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_foundation_rejects_partial_objects_and_detects_layout_drift() {
    let db = Db::new(TenancyMode::Disabled);
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!(
        "create table {}.security_events(unrelated text)",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .is_err());
    c.batch_execute(&format!("drop table {}.security_events", db.schema()))
        .unwrap();
    c.batch_execute(&format!(
        "alter table {}.accounts add column security_credential_version bigint",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .is_err());
    c.batch_execute(&format!(
        "alter table {}.accounts drop column security_credential_version",
        db.schema()
    ))
    .unwrap();
    c.batch_execute(&format!("create function {}.security_foundation_account_credential_version() returns integer language sql as 'select 1'",db.schema())).unwrap();
    assert!(db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .is_err());
    c.batch_execute(&format!(
        "drop function {}.security_foundation_account_credential_version()",
        db.schema()
    ))
    .unwrap();
    let plan = db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_foundation(&plan).unwrap();
    c.batch_execute(&format!(
        "alter table {}.security_events add column unreviewed text",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .is_err());
    c.batch_execute(&format!(
        "alter table {}.security_events drop column unreviewed",
        db.schema()
    ))
    .unwrap();
    // A restore to the same declared structure remains compatible.
    db.adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    let trigger: String = c.query_one("select t.tgname from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace join pg_proc p on p.oid=t.tgfoid where n.nspname=$1 and c.relname='accounts' and not t.tgisinternal and p.prosrc like '%security_credential_version%'", &[&db.schema()]).unwrap().get(0);
    c.batch_execute(&format!(
        "alter table {}.accounts disable trigger {trigger}",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .is_err());
    c.batch_execute(&format!(
        "alter table {}.accounts enable trigger {trigger}",
        db.schema()
    ))
    .unwrap();
    db.adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .unwrap();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_foundation_coexists_with_registration_revision_in_both_install_orders() {
    for registration_first in [true, false] {
        let db = Db::new(TenancyMode::Enabled);
        let install_registration = || {
            let plan = db
                .adapter
                .registration_email_migration_plan(db.mode)
                .unwrap();
            db.adapter
                .apply_registration_email_foundation(&plan, AUTHORITY, db.mode)
                .unwrap();
        };
        if registration_first {
            install_registration();
        }
        let plan = db
            .adapter
            .plan_security_foundation(db.mode, AUTHORITY)
            .unwrap();
        db.adapter.apply_security_foundation(&plan).unwrap();
        if !registration_first {
            install_registration();
        }
        db.adapter
            .check_security_foundation(db.mode, AUTHORITY)
            .unwrap();
        let mut c = db.adapter.connect().unwrap();
        let sql = format!(
            "select security_credential_version,registration_security_revision from {}.accounts where id=$1",
            db.schema()
        );
        let before = c.query_one(&sql, &[&db.member]).unwrap();
        c.execute(
            &format!(
                "update {}.accounts set password_hash='coexist-synthetic-hash' where id=$1",
                db.schema()
            ),
            &[&db.member],
        )
        .unwrap();
        let after = c.query_one(&sql, &[&db.member]).unwrap();
        for i in 0..2 {
            assert_eq!(after.get::<_, i64>(i), before.get::<_, i64>(i) + 1);
        }
        db.adapter
            .check_security_foundation(db.mode, AUTHORITY)
            .unwrap();
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_foundation_concurrent_apply_has_one_winner_and_checks_actual_constraint() {
    let db = Db::new(TenancyMode::Disabled);
    let plan = db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    let gate = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let adapter = db.adapter.clone();
            let plan = plan.clone();
            let gate = gate.clone();
            thread::spawn(move || {
                gate.wait();
                adapter.apply_security_foundation(&plan)
            })
        })
        .collect();
    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap().is_ok() as usize)
        .sum::<usize>();
    assert_eq!(successes, 1);
    db.adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!("alter table {s}.accounts drop constraint accounts_security_credential_version_ck; alter table {s}.accounts add constraint accounts_security_credential_version_ck check (true)",s=db.schema())).unwrap();
    assert!(db
        .adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .is_err());
}

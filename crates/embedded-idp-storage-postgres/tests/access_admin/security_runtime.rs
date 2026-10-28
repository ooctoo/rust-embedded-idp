use super::*;

const AUTHORITY: &str = "phase-one-test";

fn apply_foundation(db: &Db) {
    let plan = db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_foundation(&plan).unwrap();
}

fn apply_runtime(db: &Db) {
    apply_foundation(db);
    let plan = db
        .adapter
        .plan_security_runtime(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_runtime(&plan).unwrap();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_runtime_plan_is_read_only_and_requires_bound_foundation() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        assert!(db.adapter.plan_security_runtime(mode, AUTHORITY).is_err());
        apply_foundation(&db);

        let plan = db.adapter.plan_security_runtime(mode, AUTHORITY).unwrap();
        let mut c = db.adapter.connect().unwrap();
        assert!(!c
            .query_one(
                "select to_regclass($1) is not null",
                &[&format!("{}.security_runtime_state", db.schema())]
            )
            .unwrap()
            .get::<_, bool>(0));
        assert!(db.adapter.check_security_runtime(mode, AUTHORITY).is_err());
        assert!(db
            .adapter
            .plan_security_runtime(mode, "bad authority")
            .is_err());

        let mut forged = plan.clone();
        forged.authority = "another-authority".into();
        assert!(db.adapter.apply_security_runtime(&forged).is_err());
        let mut forged = plan.clone();
        forged.fingerprint = "0".repeat(64);
        assert!(db.adapter.apply_security_runtime(&forged).is_err());

        c.batch_execute(&format!(
            "alter table {}.security_events add column stale_plan_probe text",
            db.schema()
        ))
        .unwrap();
        assert!(db.adapter.apply_security_runtime(&plan).is_err());
        assert!(!c
            .query_one(
                "select to_regclass($1) is not null",
                &[&format!("{}.security_runtime_state", db.schema())]
            )
            .unwrap()
            .get::<_, bool>(0));
        c.batch_execute(&format!(
            "alter table {}.security_events drop column stale_plan_probe",
            db.schema()
        ))
        .unwrap();
        c.batch_execute(&format!(
            "alter table {}.accounts disable trigger security_foundation_account_credential_version_biu",
            db.schema()
        ))
        .unwrap();
        assert!(db.adapter.apply_security_runtime(&plan).is_err());
        c.batch_execute(&format!(
            "alter table {}.accounts enable trigger security_foundation_account_credential_version_biu",
            db.schema()
        ))
        .unwrap();
        let another = Db::new(mode);
        apply_foundation(&another);
        assert!(another.adapter.apply_security_runtime(&plan).is_err());

        db.adapter.apply_security_runtime(&plan).unwrap();
        db.adapter.check_security_runtime(mode, AUTHORITY).unwrap();
        db.adapter
            .check_security_foundation(mode, AUTHORITY)
            .unwrap();
        assert!(db
            .adapter
            .check_security_runtime(mode, "another-authority")
            .is_err());
        let other_mode = if mode == TenancyMode::Enabled {
            TenancyMode::Disabled
        } else {
            TenancyMode::Enabled
        };
        assert!(db
            .adapter
            .check_security_runtime(other_mode, AUTHORITY)
            .is_err());
        assert!(db.adapter.apply_security_runtime(&plan).is_err());
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_runtime_rejects_partial_objects_and_detects_only_its_own_drift() {
    let db = Db::new(TenancyMode::Disabled);
    apply_foundation(&db);
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!(
        "create table {}.security_receipts(unrelated text)",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .plan_security_runtime(db.mode, AUTHORITY)
        .is_err());
    c.batch_execute(&format!("drop table {}.security_receipts", db.schema()))
        .unwrap();
    c.batch_execute(&format!(
        "create index security_receipts_expiry_idx on {}.accounts(id)",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .plan_security_runtime(db.mode, AUTHORITY)
        .is_err());
    c.batch_execute(&format!(
        "drop index {}.security_receipts_expiry_idx",
        db.schema()
    ))
    .unwrap();

    let plan = db
        .adapter
        .plan_security_runtime(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_runtime(&plan).unwrap();
    c.batch_execute(&format!(
        "alter table {}.security_receipts add column unreviewed text",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .check_security_runtime(db.mode, AUTHORITY)
        .is_err());
    // The foundation layout deliberately excludes the separate runtime tables.
    db.adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    c.batch_execute(&format!(
        "alter table {}.security_receipts drop column unreviewed",
        db.schema()
    ))
    .unwrap();
    db.adapter
        .check_security_runtime(db.mode, AUTHORITY)
        .unwrap();
    c.batch_execute(&format!(
        "drop index {}.security_receipts_expiry_idx",
        db.schema()
    ))
    .unwrap();
    assert!(db
        .adapter
        .check_security_runtime(db.mode, AUTHORITY)
        .is_err());
    db.adapter
        .check_security_foundation(db.mode, AUTHORITY)
        .unwrap();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_runtime_concurrent_apply_has_one_winner_in_each_mode() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        apply_foundation(&db);
        let plan = db.adapter.plan_security_runtime(mode, AUTHORITY).unwrap();
        let gate = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let adapter = db.adapter.clone();
                let plan = plan.clone();
                let gate = gate.clone();
                thread::spawn(move || {
                    gate.wait();
                    adapter.apply_security_runtime(&plan)
                })
            })
            .collect();
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().is_ok() as usize)
            .sum::<usize>();
        assert_eq!(successes, 1);
        db.adapter.check_security_runtime(mode, AUTHORITY).unwrap();
        db.adapter
            .check_security_foundation(mode, AUTHORITY)
            .unwrap();
    }
}

fn seed_runtime_records(db: &Db) -> (Uuid, Uuid, Uuid) {
    let s = db.schema();
    let flow = Uuid::now_v7();
    let operation = Uuid::now_v7();
    let outbox = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    let mut tx = c.transaction().unwrap();
    tx.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_change',$1,$2,'current',$3,'current',$3,1000,86500)"), &[&operation, &db.member, &&[7_u8; 32][..]]).unwrap();
    tx.execute(&format!("insert into {s}.password_recovery_budgets(subject_digest,window_start_epoch,start_count,failure_count,expires_at_epoch) values($1,1000,1,0,4600)"), &[&&[8_u8; 32][..]]).unwrap();
    tx.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,1000,1900,87400,'pending',0)"), &[&flow, &&[8_u8; 32][..], &db.member, &&[9_u8; 32][..]]).unwrap();
    tx.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,1000,1900)"), &[&Uuid::now_v7(), &flow, &&[10_u8; 32][..], &&[11_u8; 28][..]]).unwrap();
    tx.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',1000,1900,1000,0)"), &[&outbox, &flow, &&[12_u8; 28][..]]).unwrap();
    tx.commit().unwrap();
    (flow, operation, outbox)
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_runtime_rows_commit_rollback_validate_and_cascade() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        apply_runtime(&db);
        let (flow, operation, outbox) = seed_runtime_records(&db);
        let s = db.schema();
        let mut c = db.adapter.connect().unwrap();
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_receipts where operation_id=$1"),
                &[&operation]
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_email_outbox where id=$1"),
                &[&outbox]
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );

        let lease = Uuid::now_v7();
        c.execute(
            &format!("update {s}.security_email_outbox set state='sending',lease_token=$2,lease_until_epoch=1030,attempts=1 where id=$1"),
            &[&outbox, &lease],
        )
        .unwrap();
        c.execute(
            &format!("update {s}.security_email_outbox set state='accepted',envelope_key_id=null,ciphertext=null,lease_token=null,lease_until_epoch=null,last_outcome='accepted' where id=$1 and state='sending' and lease_token=$2"),
            &[&outbox, &lease],
        )
        .unwrap();
        let terminal = c.query_one(
            &format!("select state,envelope_key_id,ciphertext,lease_token,lease_until_epoch,last_outcome from {s}.security_email_outbox where id=$1"),
            &[&outbox],
        ).unwrap();
        assert_eq!(terminal.get::<_, String>(0), "accepted");
        assert!(terminal.get::<_, Option<String>>(1).is_none());
        assert!(terminal.get::<_, Option<Vec<u8>>>(2).is_none());
        assert!(terminal.get::<_, Option<Uuid>>(3).is_none());
        assert!(terminal.get::<_, Option<i64>>(4).is_none());
        assert_eq!(terminal.get::<_, String>(5), "accepted");

        let rolled_back = Uuid::now_v7();
        let rolled_back_flow = Uuid::now_v7();
        let rolled_back_outbox = Uuid::now_v7();
        let mut tx = c.transaction().unwrap();
        tx.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('session_revoke',$1,$2,'current',$3,'current',$3,1000,86500)"), &[&rolled_back, &db.member, &&[13_u8; 32][..]]).unwrap();
        tx.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,1000,1900,87400,'pending',0)"), &[&rolled_back_flow, &&[25_u8; 32][..], &db.member, &&[26_u8; 32][..]]).unwrap();
        tx.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,1000,1900)"), &[&Uuid::now_v7(), &rolled_back_flow, &&[27_u8; 32][..], &&[28_u8; 28][..]]).unwrap();
        tx.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',1000,1900,1000,0)"), &[&rolled_back_outbox, &rolled_back_flow, &&[29_u8; 28][..]]).unwrap();
        tx.rollback().unwrap();
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_receipts where operation_id=$1"),
                &[&rolled_back]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.password_recovery_flows where id=$1"),
                &[&rolled_back_flow]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_email_outbox where id=$1"),
                &[&rolled_back_outbox]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );

        // The receipt table intentionally has no account FK, preserving short-lived
        // confirmation after account deletion. Exercise the flow FK cascades below.
        c.execute(
            &format!("delete from {s}.password_recovery_flows where id=$1"),
            &[&flow],
        )
        .unwrap();
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {s}.password_recovery_start_receipts where flow_id=$1"
                ),
                &[&flow]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_email_outbox where flow_id=$1"),
                &[&flow]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );

        // Use an account with no other dependents so deletion exercises the
        // declared FK cascade without bypassing tenant_v6 constraints.
        let deleted_account = Uuid::now_v7();
        let deleted_flow = Uuid::now_v7();
        let deleted_operation = Uuid::now_v7();
        let deleted_outbox = Uuid::now_v7();
        let mut tx = c.transaction().unwrap();
        tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,$2,'runtime-cascade@example.test','synthetic','active',1000)"), &[&deleted_account, &db.target()]).unwrap();
        tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',1000)"), &[&db.target(), &deleted_account]).unwrap();
        tx.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_recovery',$1,$2,'current',$3,'current',$3,1000,86500)"), &[&deleted_operation, &deleted_account, &&[14_u8; 32][..]]).unwrap();
        tx.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,1000,1900,87400,'pending',0)"), &[&deleted_flow, &&[15_u8; 32][..], &deleted_account, &&[16_u8; 32][..]]).unwrap();
        tx.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,1000,1900)"), &[&Uuid::now_v7(), &deleted_flow, &&[17_u8; 32][..], &&[18_u8; 28][..]]).unwrap();
        tx.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',1000,1900,1000,0)"), &[&deleted_outbox, &deleted_flow, &&[19_u8; 28][..]]).unwrap();
        let anonymous_flow = Uuid::now_v7();
        let anonymous_outbox = Uuid::now_v7();
        tx.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,null,null,'current',$3,'current',$3,1000,1900,87400,'pending',0)"), &[&anonymous_flow, &&[20_u8; 32][..], &&[21_u8; 32][..]]).unwrap();
        tx.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,1000,1900)"), &[&Uuid::now_v7(), &anonymous_flow, &&[22_u8; 32][..], &&[23_u8; 28][..]]).unwrap();
        tx.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,last_outcome) values($1,$2,null,null,'cancelled',1000,1900,1000,0,'not_started')"), &[&anonymous_outbox, &anonymous_flow]).unwrap();
        tx.execute(
            &format!("delete from {s}.access_memberships where tenant_id=$1 and account_id=$2"),
            &[&db.target(), &deleted_account],
        )
        .unwrap();
        tx.execute(
            &format!("delete from {s}.accounts where id=$1"),
            &[&deleted_account],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_receipts where operation_id=$1"),
                &[&deleted_operation]
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.password_recovery_flows where id=$1"),
                &[&deleted_flow]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {s}.password_recovery_start_receipts where flow_id=$1"
                ),
                &[&deleted_flow]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_email_outbox where id=$1"),
                &[&deleted_outbox]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.security_email_outbox where id=$1 and state='cancelled' and ciphertext is null"),
                &[&anonymous_outbox]
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        db.adapter.check_security_runtime(mode, AUTHORITY).unwrap();
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_runtime_rejects_invalid_ids_digests_ttls_and_lease_combinations() {
    let db = Db::new(TenancyMode::Disabled);
    apply_runtime(&db);
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();

    let nil = Uuid::nil();
    assert!(c.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_change',$1,$2,'current',$3,'current',$3,1000,86500)"), &[&nil, &db.member, &&[1_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_change',$1,$2,'current',$3,'current',$3,1000,87401)"), &[&Uuid::now_v7(), &db.member, &&[1_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_change',$1,$2,'bad/key',$3,'current',$3,1000,86500)"), &[&Uuid::now_v7(), &db.member, &&[1_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_change',$1,$2,$3,$4,'current',$4,1000,86500)"), &[&Uuid::now_v7(), &db.member, &"k".repeat(33), &&[1_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_change',$1,$2,'current',$3,'current',$3,1000,86500)"), &[&Uuid::now_v7(), &db.member, &&[1_u8; 31][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_budgets(subject_digest,window_start_epoch,start_count,failure_count,expires_at_epoch) values($1,1000,4,0,4600)"), &[&&[2_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_budgets(subject_digest,window_start_epoch,start_count,failure_count,expires_at_epoch) values($1,1000,1,11,4600)"), &[&&[24_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_budgets(subject_digest,window_start_epoch,start_count,failure_count,expires_at_epoch) values($1,1000,1,0,4599)"), &[&&[3_u8; 32][..]]).is_err());

    let flow = Uuid::now_v7();
    assert!(c.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,1000,1900,87400,'pending',0)"), &[&nil, &&[4_u8; 32][..], &db.member, &&[5_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,1000,1901,87400,'pending',0)"), &[&Uuid::now_v7(), &&[4_u8; 32][..], &db.member, &&[5_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,null,'current',$4,'current',$4,1000,1900,87400,'pending',0)"), &[&Uuid::now_v7(), &&[4_u8; 32][..], &db.member, &&[5_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,null,1,'current',$3,'current',$3,1000,1900,87400,'pending',0)"), &[&Uuid::now_v7(), &&[4_u8; 32][..], &&[5_u8; 32][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,1000,1900,87400,'pending',0)"), &[&flow, &&[4_u8; 32][..], &db.member, &&[5_u8; 32][..]]).is_ok());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'sending',1000,1900,1000,1)"), &[&Uuid::now_v7(), &flow, &&[6_u8; 28][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,1000,1900)"), &[&Uuid::now_v7(), &flow, &&[7_u8; 32][..], &&[8_u8; 27][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,'current',$3,'current',$4,1000,1901)"), &[&Uuid::now_v7(), &flow, &&[7_u8; 32][..], &&[8_u8; 28][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',1000,1900,1000,3)"), &[&Uuid::now_v7(), &flow, &&[8_u8; 28][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',1000,1900,1000,0)"), &[&nil, &flow, &&[8_u8; 28][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'accepted',1000,1900,1000,1)"), &[&Uuid::now_v7(), &flow, &&[8_u8; 28][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,lease_token) values($1,$2,'current',$3,'sending',1000,1900,1000,1,$4)"), &[&Uuid::now_v7(), &flow, &&[8_u8; 28][..], &Uuid::now_v7()]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,lease_until_epoch) values($1,$2,'current',$3,'sending',1000,1900,1000,1,1030)"), &[&Uuid::now_v7(), &flow, &&[8_u8; 28][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,lease_token,lease_until_epoch) values($1,$2,'current',$3,'sending',1000,1900,1000,1,$4,1030)"), &[&Uuid::now_v7(), &flow, &&[8_u8; 28][..], &nil]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,null,$3,'pending',1000,1900,1000,0)"), &[&Uuid::now_v7(), &flow, &&[8_u8; 28][..]]).is_err());
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',null,'pending',1000,1900,1000,0)"), &[&Uuid::now_v7(), &flow]).is_err());
    let oversized_ciphertext = vec![0_u8; 16_413];
    assert!(c.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',1000,1900,1000,0)"), &[&Uuid::now_v7(), &flow, &&oversized_ciphertext[..]]).is_err());
}

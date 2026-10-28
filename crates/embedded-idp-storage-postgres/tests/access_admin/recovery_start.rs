use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::{
        CoreRecoveryStartService, RecoveryStartCommand, RecoveryStartResult, RecoveryStartService,
    },
    AccountSecurityCrypto, SecretString, SecurityCryptoContext, SecurityDigest,
    SecurityDigestPurpose, SecurityEnvelope, SecurityEnvelopePurpose,
};
use embedded_idp_security::{AccountSecurityKeySet, RingAccountSecurityCrypto};

const AUTHORITY: &str = "phase-one-test";

fn install(db: &Db) {
    let foundation = db
        .adapter
        .plan_security_foundation(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_foundation(&foundation).unwrap();
    let runtime = db
        .adapter
        .plan_security_runtime(db.mode, AUTHORITY)
        .unwrap();
    db.adapter.apply_security_runtime(&runtime).unwrap();
}

fn crypto() -> RingAccountSecurityCrypto {
    RingAccountSecurityCrypto::new(
        AUTHORITY.into(),
        [200; 32],
        AccountSecurityKeySet::new("current".into(), [10; 32], [11; 32], [12; 32], [13; 32]),
        None,
    )
    .unwrap()
}

fn service(
    db: &Db,
) -> CoreRecoveryStartService<PostgresAccessStore, FixedClock, RingAccountSecurityCrypto, UuidIds> {
    CoreRecoveryStartService::new(db.mode, db.store(), FixedClock, crypto(), UuidIds)
}

fn secret(byte: u8) -> SecretString {
    SecretString::new(Base64UrlUnpadded::encode_string(&[byte; 32]))
}

fn start(
    service: &impl RecoveryStartService,
    email: &str,
    operation: Uuid,
    secret_byte: u8,
) -> Result<RecoveryStartResult, AccessError> {
    service.start_recovery(RecoveryStartCommand {
        email: SecretString::new(email),
        operation_id: operation,
        receipt_secret: secret(secret_byte),
    })
}

fn flow_id(result: &RecoveryStartResult) -> Uuid {
    let bytes = Base64UrlUnpadded::decode_vec(result.handle.expose_secret()).unwrap();
    assert_eq!(bytes.len(), 48);
    Uuid::from_slice(&bytes[..16]).unwrap()
}

fn assert_uniform_result(result: &RecoveryStartResult) {
    assert_eq!(result.handle.expose_secret().len(), 64);
    assert_eq!(
        result
            .expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        NOW + 900
    );
}

fn account_record(db: &Db, email: &str, status: &str, membership_status: &str) -> Uuid {
    let account = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    let mut tx = c.transaction().unwrap();
    tx.execute(
        &format!("insert into {}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,'0',$2,'synthetic-test-hash',$3,900)", db.schema()),
        &[&account, &email, &status],
    )
    .unwrap();
    tx.execute(
        &format!("insert into {}.access_memberships(tenant_id,account_id,status,joined_at_epoch,removed_at_epoch) values('0',$1,$2,900,$3)", db.schema()),
        &[&account, &membership_status, &if membership_status == "removed" { Some(950_i64) } else { None }],
    )
    .unwrap();
    tx.commit().unwrap();
    account
}

fn add_business_admin(db: &Db) {
    let tenant = db.target();
    let role = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    let mut tx = c.transaction().unwrap();
    tx.execute(
        &format!("insert into {}.access_roles(tenant_id,business_id,id,key,name,status,kind,created_at_epoch) values($1,'f_01',$2,'business_admin','Business admin','active','business_admin',900)", db.schema()),
        &[&tenant, &role],
    )
    .unwrap();
    tx.execute(
        &format!("insert into {}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,created_at_epoch,created_by) values($1,$2,'f_01',$3,$4,'business',null,900,$5)", db.schema()),
        &[&Uuid::now_v7(), &tenant, &db.member, &role, &db.actor],
    )
    .unwrap();
    tx.commit().unwrap();
}

fn row_for_flow(
    db: &Db,
    flow: Uuid,
) -> (
    Option<Uuid>,
    Option<i64>,
    String,
    Option<String>,
    Option<Vec<u8>>,
) {
    let mut c = db.adapter.connect().unwrap();
    let row = c
        .query_one(
            &format!("select f.account_id,f.snapshot_credential_version,f.state,o.envelope_key_id,o.ciphertext from {}.password_recovery_flows f join {}.security_email_outbox o on o.flow_id=f.id where f.id=$1", db.schema(), db.schema()),
            &[&flow],
        )
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

fn query_counts(db: &Db) -> (i64, i64, i64, i64, i64) {
    let mut c = db.adapter.connect().unwrap();
    let row = c
        .query_one(
            &format!("select (select count(*) from {}.password_recovery_budgets),(select count(*) from {}.password_recovery_flows),(select count(*) from {}.password_recovery_start_receipts),(select count(*) from {}.security_email_outbox),(select count(*) from {}.security_events where kind='recovery_started')", db.schema(), db.schema(), db.schema(), db.schema(), db.schema()),
            &[],
        )
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

fn insert_old_flow(db: &Db, subject: [u8; 32], state: &str, outbox_state: &str, seed: u8) -> Uuid {
    let flow = Uuid::now_v7();
    let outbox = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    let mut tx = c.transaction().unwrap();
    tx.execute(
        &format!("insert into {}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,1,'current',$4,'current',$4,900,1800,87300,$5,0)", db.schema()),
        &[&flow, &&subject[..], &db.member, &&[seed; 32][..], &state],
    )
    .unwrap();
    match outbox_state {
        "pending" => {
            tx.execute(
                &format!("insert into {}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts) values($1,$2,'current',$3,'pending',900,1800,900,0)", db.schema()),
                &[&outbox, &flow, &&[seed + 1; 28][..]],
            )
            .unwrap();
        }
        "sending" => {
            tx.execute(
                &format!("insert into {}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,lease_token,lease_until_epoch) values($1,$2,'current',$3,'sending',900,1800,900,1,$4,950)", db.schema()),
                &[&outbox, &flow, &&[seed + 1; 28][..], &Uuid::now_v7()],
            )
            .unwrap();
        }
        "accepted" => {
            tx.execute(
                &format!("insert into {}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,last_outcome) values($1,$2,null,null,'accepted',900,1800,900,1,'accepted')", db.schema()),
                &[&outbox, &flow],
            )
            .unwrap();
        }
        other => panic!("unsupported fixture state {other}"),
    }
    tx.commit().unwrap();
    flow
}

fn assert_receipt_and_mail_context(
    db: &Db,
    operation: Uuid,
    result: &RecoveryStartResult,
    expected_email: &str,
) {
    let flow = flow_id(result);
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    let receipt = c.query_one(
        &format!("select flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,expires_at_epoch from {s}.password_recovery_start_receipts where operation_id=$1"),
        &[&operation],
    ).unwrap();
    assert_eq!(receipt.get::<_, Uuid>(0), flow);
    let start_envelope = SecurityEnvelope {
        key_id: receipt.get(3),
        ciphertext: receipt.get(4),
    };
    let opened = crypto()
        .open(
            SecurityEnvelopePurpose::RecoveryStartReceipt,
            &SecurityCryptoContext {
                reference_id: operation,
                related_id: Some(flow),
            },
            &start_envelope,
        )
        .unwrap();
    assert_eq!(opened.expose_secret(), result.handle.expose_secret());
    assert_eq!(receipt.get::<_, i64>(5), (NOW + 900) as i64);

    let row = c.query_one(
        &format!("select o.id,o.envelope_key_id,o.ciphertext,f.code_key_id,f.code_digest,f.handle_key_id,f.handle_digest from {s}.security_email_outbox o join {s}.password_recovery_flows f on f.id=o.flow_id where f.id=$1"),
        &[&flow],
    ).unwrap();
    let outbox_id: Uuid = row.get(0);
    let email_envelope = SecurityEnvelope {
        key_id: row.get(1),
        ciphertext: row.get(2),
    };
    let payload = crypto()
        .open(
            SecurityEnvelopePurpose::RecoveryEmail,
            &SecurityCryptoContext {
                reference_id: outbox_id,
                related_id: Some(flow),
            },
            &email_envelope,
        )
        .unwrap();
    let fields = payload.expose_secret().split('\n').collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "recovery-email-v1");
    assert_eq!(fields[1], expected_email);
    assert_eq!(fields[2].len(), 6);
    assert!(fields[2].bytes().all(|byte| byte.is_ascii_digit()));
    assert!(!payload.expose_secret().ends_with('\n'));
    let code_digest: Vec<u8> = row.get(4);
    let code_digest = SecurityDigest {
        key_id: row.get(3),
        bytes: code_digest.try_into().unwrap(),
    };
    assert!(crypto()
        .verify_digest(
            SecurityDigestPurpose::RecoveryCode,
            &SecurityCryptoContext {
                reference_id: flow,
                related_id: None,
            },
            fields[2].as_bytes(),
            &code_digest,
        )
        .unwrap());
    let handle_bytes = Base64UrlUnpadded::decode_vec(result.handle.expose_secret()).unwrap();
    let handle_digest_bytes: Vec<u8> = row.get(6);
    let handle_digest = SecurityDigest {
        key_id: row.get(5),
        bytes: handle_digest_bytes.try_into().unwrap(),
    };
    assert!(crypto()
        .verify_digest(
            SecurityDigestPurpose::RecoveryHandle,
            &SecurityCryptoContext {
                reference_id: flow,
                related_id: None,
            },
            &handle_bytes[16..],
            &handle_digest,
        )
        .unwrap());
}

fn assert_handle_receipt(db: &Db, operation: Uuid, result: &RecoveryStartResult) {
    let flow = flow_id(result);
    let mut c = db.adapter.connect().unwrap();
    let row = c.query_one(
        &format!("select flow_id,envelope_key_id,ciphertext from {}.password_recovery_start_receipts where operation_id=$1", db.schema()),
        &[&operation],
    ).unwrap();
    assert_eq!(row.get::<_, Uuid>(0), flow);
    let envelope = SecurityEnvelope {
        key_id: row.get(1),
        ciphertext: row.get(2),
    };
    let decrypted = crypto()
        .open(
            SecurityEnvelopePurpose::RecoveryStartReceipt,
            &SecurityCryptoContext {
                reference_id: operation,
                related_id: Some(flow),
            },
            &envelope,
        )
        .unwrap();
    assert_eq!(decrypted.expose_secret(), result.handle.expose_secret());
}

#[derive(Clone, Copy)]
struct CollisionIds;
impl IdGenerator for CollisionIds {
    fn next_id(&self, purpose: &str) -> String {
        if purpose == "evt" {
            Uuid::from_u128(0xfeed).to_string()
        } else {
            Uuid::now_v7().to_string()
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_start_returns_uniform_handles_and_persists_eligibility_safely_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        add_business_admin(&db);
        account_record(&db, "disabled@example.test", "disabled", "active");
        account_record(&db, "closed@example.test", "closed", "removed");
        account_record(&db, "suspended@example.test", "active", "suspended");

        let service = service(&db);
        let operation = Uuid::now_v7();
        let first = start(&service, " member@example.test ", operation, 21).unwrap();
        assert_uniform_result(&first);
        let after_first = query_counts(&db);
        let replay = start(&service, "member@example.test", operation, 21).unwrap();
        assert_eq!(replay.handle.expose_secret(), first.handle.expose_secret());
        assert_eq!(replay.expires_at, first.expires_at);
        assert_eq!(
            query_counts(&db),
            after_first,
            "replay creates no records or budget charge"
        );
        let (account, version, state, outbox_key, outbox_ciphertext) =
            row_for_flow(&db, flow_id(&first));
        assert_eq!(account, Some(db.member));
        assert_eq!(version, Some(1));
        assert_eq!(state, "pending");
        assert!(outbox_key.is_some() && outbox_ciphertext.is_some());
        assert_receipt_and_mail_context(&db, operation, &first, "member@example.test");

        let upper_operation = Uuid::now_v7();
        let case_variant = start(&service, "Member@example.test", upper_operation, 22).unwrap();
        assert_uniform_result(&case_variant);
        let (account, version, state, outbox_key, outbox_ciphertext) =
            row_for_flow(&db, flow_id(&case_variant));
        assert_eq!(account, None, "identity lookup remains exact-case");
        assert_eq!(version, None);
        assert_eq!(state, "pending");
        assert_eq!(outbox_key, None);
        assert_eq!(outbox_ciphertext, None);
        let mut c = db.adapter.connect().unwrap();
        let subject = crypto().subject_digest("member@example.test").unwrap();
        let budget = c.query_one(
            &format!("select start_count,failure_count,window_start_epoch,expires_at_epoch from {}.password_recovery_budgets where subject_digest=$1", db.schema()),
            &[&&subject[..]],
        ).unwrap();
        assert_eq!(
            budget.get::<_, i32>(0),
            2,
            "ASCII case variants share a lower-case bucket"
        );
        assert_eq!(budget.get::<_, i32>(1), 0);
        assert_eq!(budget.get::<_, i64>(2), NOW as i64);
        assert_eq!(budget.get::<_, i64>(3), (NOW + 3600) as i64);

        let mut ineligible = vec![
            "unknown@example.test",
            "disabled@example.test",
            "closed@example.test",
            "suspended@example.test",
            "actor@example.test",
        ];
        if mode == TenancyMode::Enabled {
            ineligible.push("owner@example.test");
        }
        for (index, email) in ineligible.into_iter().enumerate() {
            let operation = Uuid::now_v7();
            let result = start(&service, email, operation, 30 + index as u8).unwrap();
            assert_uniform_result(&result);
            let (account, version, state, outbox_key, outbox_ciphertext) =
                row_for_flow(&db, flow_id(&result));
            assert_eq!(account, None, "{email}");
            assert_eq!(version, None, "{email}");
            assert_eq!(
                state, "pending",
                "eligibility is not exposed in the flow state"
            );
            assert_eq!(
                outbox_key, None,
                "noneligible starts have no email envelope"
            );
            assert_eq!(
                outbox_ciphertext, None,
                "noneligible starts persist no email/code payload"
            );
            assert_handle_receipt(&db, operation, &result);
            let outbox_state: String = c
                .query_one(
                    &format!(
                        "select state from {}.security_email_outbox where flow_id=$1",
                        db.schema()
                    ),
                    &[&flow_id(&result)],
                )
                .unwrap()
                .get(0);
            assert_eq!(outbox_state, "cancelled");
        }
        assert!(start(&service, "invalid-email", Uuid::now_v7(), 51).is_err());
        let invalid_subject = crypto().subject_digest("invalid-email").unwrap();
        assert!(
            c.query_opt(
                &format!(
                    "select start_count from {}.password_recovery_budgets where subject_digest=$1",
                    db.schema()
                ),
                &[&&invalid_subject[..]],
            )
            .unwrap()
            .is_none(),
            "invalid syntax must not create a budget row"
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_start_replay_budget_generation_close_and_receipt_deletion_work_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let service = service(&db);
        let email = "member@example.test";
        let subject = crypto().subject_digest(email).unwrap();
        let first_operation = Uuid::now_v7();
        let first = start(&service, email, first_operation, 61).unwrap();
        let first_flow = flow_id(&first);
        assert!(matches!(
            start(&service, email, first_operation, 62),
            Err(AccessError::Conflict("recovery.operation_conflict"))
        ));
        assert!(matches!(
            start(&service, "unknown@example.test", first_operation, 61),
            Err(AccessError::Conflict("recovery.operation_conflict"))
        ));

        let sending_flow = insert_old_flow(&db, subject, "pending", "sending", 111);
        let terminal_flow = insert_old_flow(&db, subject, "consumed", "accepted", 121);
        let sending_outbox_before = db.adapter.connect().unwrap().query_one(
            &format!("select state,last_outcome,envelope_key_id is not null,ciphertext is not null,lease_token is not null from {}.security_email_outbox where flow_id=(select id from {}.password_recovery_flows where id=$1)", db.schema(), db.schema()),
            &[&sending_flow],
        ).unwrap();
        assert_eq!(sending_outbox_before.get::<_, String>(0), "sending");

        let second_operation = Uuid::now_v7();
        let second = start(&service, email, second_operation, 63).unwrap();
        let second_flow = flow_id(&second);
        assert_ne!(first_flow, second_flow);
        let mut c = db.adapter.connect().unwrap();
        for old_flow in [first_flow, sending_flow] {
            assert_eq!(
                c.query_one(
                    &format!(
                        "select state from {}.password_recovery_flows where id=$1",
                        db.schema()
                    ),
                    &[&old_flow]
                )
                .unwrap()
                .get::<_, String>(0),
                "invalidated"
            );
        }
        assert_eq!(
            c.query_one(
                &format!(
                    "select state from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&terminal_flow]
            )
            .unwrap()
            .get::<_, String>(0),
            "consumed"
        );
        let old_outboxes = c.query(
            &format!("select o.flow_id,o.state,o.last_outcome,o.envelope_key_id is null,o.ciphertext is null,o.lease_token is null,o.lease_until_epoch is null from {}.security_email_outbox o where o.flow_id=any($1) order by o.flow_id", db.schema()),
            &[&vec![first_flow, sending_flow, terminal_flow]],
        ).unwrap();
        assert_eq!(old_outboxes.len(), 3);
        for row in old_outboxes {
            let flow: Uuid = row.get(0);
            if flow == first_flow {
                assert_eq!(row.get::<_, String>(1), "cancelled");
                assert_eq!(row.get::<_, String>(2), "not_started");
                assert!(row.get::<_, bool>(3) && row.get::<_, bool>(4));
            } else if flow == sending_flow {
                assert_eq!(row.get::<_, String>(1), "cancelled");
                assert_eq!(row.get::<_, String>(2), "unknown");
                assert!(
                    row.get::<_, bool>(3)
                        && row.get::<_, bool>(4)
                        && row.get::<_, bool>(5)
                        && row.get::<_, bool>(6)
                );
            } else {
                assert_eq!(row.get::<_, String>(1), "accepted");
                assert_eq!(row.get::<_, String>(2), "accepted");
                assert!(row.get::<_, bool>(3) && row.get::<_, bool>(4));
            }
        }
        let before_replay = query_counts(&db);
        let replay = start(&service, email, first_operation, 61).unwrap();
        assert_eq!(replay.handle.expose_secret(), first.handle.expose_secret());
        assert_eq!(
            query_counts(&db),
            before_replay,
            "receipt replay never restores a closed flow"
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select state from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&first_flow]
            )
            .unwrap()
            .get::<_, String>(0),
            "invalidated"
        );

        // An expired retained receipt conflicts. Removing it allows a new
        // generation for the same operation, which consumes the next budget slot.
        c.execute(
            &format!("update {}.password_recovery_start_receipts set created_at_epoch=0,expires_at_epoch=900 where operation_id=$1", db.schema()),
            &[&first_operation],
        ).unwrap();
        assert!(matches!(
            start(&service, email, first_operation, 61),
            Err(AccessError::Conflict("recovery.operation_conflict"))
        ));
        c.execute(
            &format!(
                "delete from {}.password_recovery_start_receipts where operation_id=$1",
                db.schema()
            ),
            &[&first_operation],
        )
        .unwrap();
        let before_new_generation = query_counts(&db);
        let new_generation = start(&service, email, first_operation, 61).unwrap();
        let new_flow = flow_id(&new_generation);
        assert_ne!(
            new_generation.handle.expose_secret(),
            first.handle.expose_secret()
        );
        assert_ne!(new_flow, first_flow);
        assert_ne!(new_flow, second_flow);
        assert_eq!(
            c.query_one(
                &format!(
                    "select state from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&second_flow]
            )
            .unwrap()
            .get::<_, String>(0),
            "invalidated"
        );
        let budget = c
            .query_one(
                &format!(
                    "select start_count from {}.password_recovery_budgets where subject_digest=$1",
                    db.schema()
                ),
                &[&&subject[..]],
            )
            .unwrap();
        assert_eq!(budget.get::<_, i32>(0), 3);
        assert_eq!(query_counts(&db).0, before_new_generation.0);
        assert!(matches!(
            start(&service, email, Uuid::now_v7(), 64),
            Err(AccessError::Conflict("recovery.rate_limited"))
        ));
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_start_concurrent_requests_respect_three_per_window_limit() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let barrier = Arc::new(Barrier::new(4));
        let handles = (0..4)
            .map(|index| {
                let store = db.store();
                let barrier = barrier.clone();
                let operation = Uuid::now_v7();
                thread::spawn(move || {
                    let service =
                        CoreRecoveryStartService::new(mode, store, FixedClock, crypto(), UuidIds);
                    barrier.wait();
                    service.start_recovery(RecoveryStartCommand {
                        email: SecretString::new("concurrent@example.test"),
                        operation_id: operation,
                        receipt_secret: secret(80 + index as u8),
                    })
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 3);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(AccessError::Conflict("recovery.rate_limited"))
                ))
                .count(),
            1
        );
        let subject = crypto().subject_digest("concurrent@example.test").unwrap();
        let mut c = db.adapter.connect().unwrap();
        assert_eq!(
            c.query_one(
                &format!(
                    "select start_count from {}.password_recovery_budgets where subject_digest=$1",
                    db.schema()
                ),
                &[&&subject[..]]
            )
            .unwrap()
            .get::<_, i32>(0),
            3
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.password_recovery_flows where subject_digest=$1",
                    db.schema()
                ),
                &[&&subject[..]]
            )
            .unwrap()
            .get::<_, i64>(0),
            3
        );
        assert_eq!(
            c.query_one(&format!("select count(*) from {}.security_email_outbox o join {}.password_recovery_flows f on f.id=o.flow_id where f.subject_digest=$1 and o.state='cancelled' and o.envelope_key_id is null and o.ciphertext is null", db.schema(), db.schema()), &[&&subject[..]])
                .unwrap()
                .get::<_, i64>(0),
            3
        );
        assert_eq!(
            c.query_one(&format!("select count(*) from {}.security_events e where e.kind='recovery_started' and e.operation_id in (select operation_id from {}.password_recovery_start_receipts)", db.schema(), db.schema()), &[])
                .unwrap()
                .get::<_, i64>(0),
            3
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_start_event_collision_rolls_back_budget_flow_receipt_and_outbox() {
    let db = Db::new(TenancyMode::Disabled);
    install(&db);
    let email = "event-collision@example.test";
    let operation = Uuid::now_v7();
    let before = query_counts(&db);
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!(
        "create unique index recovery_start_collision_probe on {}.security_events(kind,operation_id)",
        db.schema()
    ))
    .unwrap();
    let event_id = Uuid::from_u128(0xfeed);
    c.execute(
        &format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'recovery_started','accepted',null,$2,1000)", db.schema()),
        &[&event_id, &operation],
    )
    .unwrap();
    let with_collision = query_counts(&db);
    assert_eq!(with_collision.0, before.0);
    assert_eq!(with_collision.1, before.1);
    assert_eq!(with_collision.2, before.2);
    assert_eq!(with_collision.3, before.3);

    let collision_service =
        CoreRecoveryStartService::new(db.mode, db.store(), FixedClock, crypto(), CollisionIds);
    assert!(start(&collision_service, email, operation, 101).is_err());
    assert_eq!(
        query_counts(&db),
        with_collision,
        "event insert collision rolls the full transaction back"
    );
    let subject = crypto().subject_digest(email).unwrap();
    assert!(c
        .query_opt(
            &format!(
                "select 1 from {}.password_recovery_budgets where subject_digest=$1",
                db.schema()
            ),
            &[&&subject[..]]
        )
        .unwrap()
        .is_none());
    assert_eq!(
        c.query_one(
            &format!(
                "select count(*) from {}.password_recovery_start_receipts where operation_id=$1",
                db.schema()
            ),
            &[&operation]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
}

use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::{
        CoreRecoveryCompletionService, CoreRecoveryStartService, CoreSecurityOutboxService,
        RecoveryCompleteCommand, RecoveryCompleteError, RecoveryCompletionService,
        RecoveryStartCommand, RecoveryStartService, SecurityMailCompletion, SecurityMailOutcome,
        SecurityOutboxService, SecurityReceiptQuery,
    },
    AccountSecurityCrypto, AuthConfig, PasswordWorkBudget, SecretString, SecurityCryptoContext,
    SecurityEnvelope, SecurityEnvelopePurpose,
};
use embedded_idp_security::{AccountSecurityKeySet, RingAccountSecurityCrypto};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Barrier,
};

const AUTHORITY: &str = "phase-one-test";
const MEMBER_EMAIL: &str = "member@example.test";
const NEW_PASSWORD: &str = "New-recovery-password-789!";

#[derive(Clone, Copy)]
struct AtClock(u64);
impl Clock for AtClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0)
    }
}

#[derive(Clone)]
struct SharedClock(Arc<AtomicU64>);
impl SharedClock {
    fn new(now: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now)))
    }
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
impl Clock for SharedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}

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

fn secret(byte: u8) -> SecretString {
    SecretString::new(Base64UrlUnpadded::encode_string(&[byte; 32]))
}

fn start_at(db: &Db, email: &str, operation: Uuid, now: u64) -> String {
    CoreRecoveryStartService::new(db.mode, db.store(), AtClock(now), crypto(), UuidIds)
        .start_recovery(RecoveryStartCommand {
            email: SecretString::new(email),
            operation_id: operation,
            receipt_secret: secret(201),
        })
        .unwrap()
        .handle
        .expose_secret()
        .to_owned()
}

fn flow_id(handle: &str) -> Uuid {
    let bytes = Base64UrlUnpadded::decode_vec(handle).unwrap();
    Uuid::from_slice(&bytes[..16]).unwrap()
}

fn outbox_id(db: &Db, flow: Uuid) -> Uuid {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select id from {}.security_email_outbox where flow_id=$1",
                db.schema()
            ),
            &[&flow],
        )
        .unwrap()
        .get(0)
}

fn code_for_flow(db: &Db, flow: Uuid) -> String {
    let mut c = db.adapter.connect().unwrap();
    let row = c
        .query_one(
            &format!("select id,envelope_key_id,ciphertext from {}.security_email_outbox where flow_id=$1", db.schema()),
            &[&flow],
        )
        .unwrap();
    let outbox = row.get::<_, Uuid>(0);
    let payload = crypto()
        .open(
            SecurityEnvelopePurpose::RecoveryEmail,
            &SecurityCryptoContext {
                reference_id: outbox,
                related_id: Some(flow),
            },
            &SecurityEnvelope {
                key_id: row.get(1),
                ciphertext: row.get(2),
            },
        )
        .unwrap();
    let fields = payload.expose_secret().split('\n').collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "recovery-email-v1");
    fields[2].to_owned()
}

fn service<C>(
    db: &Db,
    clock: C,
) -> CoreSecurityOutboxService<PostgresAccessStore, C, RingAccountSecurityCrypto, UuidIds>
where
    C: Clock + Send + Sync,
{
    CoreSecurityOutboxService::new(db.mode, db.store(), clock, crypto(), UuidIds)
}

fn finish(
    service: &impl SecurityOutboxService,
    claim: &SecurityMailClaim,
    outcome: SecurityMailOutcome,
) -> Result<bool, AccessError> {
    service.finish(SecurityMailCompletion {
        outbox_id: claim.outbox_id,
        lease_token: claim.lease_token,
        outcome,
    })
}

fn assert_terminal_and_redacted(db: &Db, outbox: Uuid, expected: &str, outcome: &str) {
    let row = db.adapter.connect().unwrap().query_one(
        &format!("select state,last_outcome,envelope_key_id,ciphertext,lease_token,lease_until_epoch from {}.security_email_outbox where id=$1", db.schema()),
        &[&outbox],
    ).unwrap();
    assert_eq!(row.get::<_, String>(0), expected);
    assert_eq!(row.get::<_, String>(1), outcome);
    assert!(row.get::<_, Option<String>>(2).is_none());
    assert!(row.get::<_, Option<Vec<u8>>>(3).is_none());
    assert!(row.get::<_, Option<Uuid>>(4).is_none());
    assert!(row.get::<_, Option<i64>>(5).is_none());
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_claim_finish_and_terminal_redaction_work_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for outcome in [SecurityMailOutcome::Accepted, SecurityMailOutcome::Unknown] {
            let db = Db::new(mode);
            install(&db);
            let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
            let flow = flow_id(&handle);
            let outbox = outbox_id(&db, flow);
            let service = service(&db, FixedClock);
            let claim = service
                .claim()
                .unwrap()
                .expect("eligible pending mail is claimed");
            assert_eq!(claim.flow_id, flow);
            assert_eq!(claim.outbox_id, outbox);
            assert_eq!(claim.recipient.expose_secret(), MEMBER_EMAIL);
            assert_eq!(claim.code.expose_secret().len(), 6);
            assert!(
                service
                    .finish(SecurityMailCompletion {
                        outbox_id: claim.outbox_id,
                        lease_token: Uuid::now_v7(),
                        outcome,
                    })
                    .unwrap()
                    == false
            );
            assert!(finish(&service, &claim, outcome).unwrap());
            let (state, value) = match outcome {
                SecurityMailOutcome::Accepted => ("accepted", "accepted"),
                SecurityMailOutcome::Unknown => ("unknown", "unknown"),
                _ => unreachable!(),
            };
            assert_terminal_and_redacted(&db, outbox, state, value);
            assert!(
                !finish(&service, &claim, outcome).unwrap(),
                "duplicate finish is inert"
            );
            assert!(
                service.claim().unwrap().is_none(),
                "terminal messages are not reclaimed"
            );
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_concurrent_workers_claim_one_message_once_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let barrier = Arc::new(Barrier::new(2));
        let workers = (0..2)
            .map(|_| {
                let store = db.store();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let service =
                        CoreSecurityOutboxService::new(mode, store, FixedClock, crypto(), UuidIds);
                    barrier.wait();
                    service.claim().unwrap()
                })
            })
            .collect::<Vec<_>>();
        let claims = workers
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
        assert_eq!(claims.iter().filter(|claim| claim.is_none()).count(), 1);
        let flow = flow_id(&handle);
        let row = db.adapter.connect().unwrap().query_one(
            &format!("select state,attempts,lease_token from {}.security_email_outbox where flow_id=$1", db.schema()),
            &[&flow],
        ).unwrap();
        assert_eq!(row.get::<_, String>(0), "sending");
        assert_eq!(row.get::<_, i32>(1), 1);
        assert_eq!(
            row.get::<_, Option<Uuid>>(2),
            claims
                .iter()
                .find_map(|claim| claim.as_ref().map(|claim| claim.lease_token))
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_not_started_retries_after_one_second_and_stops_after_three_claims() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let flow = flow_id(&handle);
        let outbox = outbox_id(&db, flow);
        let clock = SharedClock::new(NOW);
        let service = service(&db, clock.clone());
        for attempt in 1..=3 {
            let claim = service.claim().unwrap().expect("retry is due");
            assert!(finish(&service, &claim, SecurityMailOutcome::NotStarted).unwrap());
            let row = db.adapter.connect().unwrap().query_one(
                &format!("select state,attempts,last_outcome,next_attempt_at_epoch from {}.security_email_outbox where id=$1", db.schema()),
                &[&outbox],
            ).unwrap();
            if attempt < 3 {
                assert_eq!(row.get::<_, String>(0), "pending");
                assert_eq!(row.get::<_, i32>(1), attempt);
                assert_eq!(row.get::<_, String>(2), "not_started");
                clock.set(NOW + attempt as u64);
                assert_eq!(row.get::<_, i64>(3), (NOW + attempt as u64) as i64);
            } else {
                assert_eq!(row.get::<_, String>(0), "cancelled");
                assert_eq!(row.get::<_, i32>(1), 3);
                assert_eq!(row.get::<_, String>(2), "not_started");
            }
        }
        assert_terminal_and_redacted(&db, outbox, "cancelled", "not_started");
        assert!(service.claim().unwrap().is_none());
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_late_success_becomes_unknown_and_cannot_be_replayed() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let flow = flow_id(&handle);
        let outbox = outbox_id(&db, flow);
        let clock = SharedClock::new(NOW);
        let service = service(&db, clock.clone());
        let claim = service.claim().unwrap().unwrap();
        let lease_end = claim
            .lease_until
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        clock.set(lease_end);
        assert!(finish(&service, &claim, SecurityMailOutcome::Accepted).unwrap());
        assert_terminal_and_redacted(&db, outbox, "unknown", "unknown");
        assert!(!finish(&service, &claim, SecurityMailOutcome::Accepted).unwrap());
        assert!(service.claim().unwrap().is_none());
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_new_generation_and_password_change_cancellation_reject_late_finish() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let old_handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let old_flow = flow_id(&old_handle);
        let old_outbox = outbox_id(&db, old_flow);
        let service = service(&db, FixedClock);
        let claim = service.claim().unwrap().unwrap();
        start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        assert_terminal_and_redacted(&db, old_outbox, "cancelled", "unknown");
        assert!(!finish(&service, &claim, SecurityMailOutcome::Accepted).unwrap());

        let password_handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let password_flow = flow_id(&password_handle);
        let password_outbox = outbox_id(&db, password_flow);
        let password_claim = service.claim().unwrap().unwrap();
        let config = AuthConfig {
            allow_local_registration: false,
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 600,
            session_ttl_secs: 1200,
            verification_code_ttl_secs: 300,
            password_min_length: 8,
            password_max_length: 128,
        };
        let admin = CoreAccountSecurityService::new(db.service(), config.clone()).unwrap();
        admin
            .set_account_password(
                db.context(db.actor_session.to_string()),
                AdminSetAccountPassword {
                    account_id: db.member.to_string(),
                    new_password: SecretString::new("Changed-member-password-456!"),
                },
            )
            .unwrap();
        let before_finish = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select state,attempts,lease_token from {}.security_email_outbox where id=$1",
                    db.schema()
                ),
                &[&password_outbox],
            )
            .unwrap();
        assert_eq!(before_finish.get::<_, String>(0), "sending");
        assert_eq!(before_finish.get::<_, i32>(1), 1);
        assert_eq!(
            before_finish.get::<_, Option<Uuid>>(2),
            Some(password_claim.lease_token)
        );
        assert!(finish(&service, &password_claim, SecurityMailOutcome::Accepted).unwrap());
        assert_terminal_and_redacted(&db, password_outbox, "cancelled", "accepted");
        assert!(!finish(&service, &password_claim, SecurityMailOutcome::Accepted).unwrap());
        let completion = CoreRecoveryCompletionService::new(
            mode,
            db.store(),
            FixedClock,
            crypto(),
            UuidIds,
            config,
            PasswordWorkBudget::default(),
        )
        .unwrap();
        assert!(matches!(
            completion.complete_recovery(RecoveryCompleteCommand {
                handle: SecretString::new(password_handle),
                code: SecretString::new("000000"),
                new_password: SecretString::new(NEW_PASSWORD),
                operation_id: Uuid::now_v7(),
                receipt_secret: secret(202),
            }),
            Err(RecoveryCompleteError::InvalidRecovery)
        ));
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_cleanup_obeys_global_limit_and_retains_budget_with_flow() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        const CLEANUP_NOW: u64 = 3_000_000;
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), CLEANUP_NOW - 50_000);
        let flow = flow_id(&handle);
        let subject = crypto().subject_digest(MEMBER_EMAIL).unwrap();
        let mut c = db.adapter.connect().unwrap();
        for _ in 0..105 {
            c.execute(
                &format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'email_delivery','accepted',null,null,0)", db.schema()),
                &[&Uuid::now_v7()],
            ).unwrap();
        }
        let result = service(&db, AtClock(CLEANUP_NOW)).cleanup().unwrap();
        assert_eq!(result.processed, 100);
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.security_events where occurred_at_epoch=0",
                    db.schema()
                ),
                &[],
            )
            .unwrap()
            .get::<_, i64>(0),
            8,
            "three earlier cleanup categories share the same 100-record limit"
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select state from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&flow],
            )
            .unwrap()
            .get::<_, String>(0),
            "expired"
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.password_recovery_budgets where subject_digest=$1",
                    db.schema()
                ),
                &[&subject.as_slice()],
            )
            .unwrap()
            .get::<_, i64>(0),
            1,
            "budget remains while its retained recovery flow exists"
        );
        let completion = CoreRecoveryCompletionService::new(
            mode,
            db.store(),
            AtClock(CLEANUP_NOW),
            crypto(),
            UuidIds,
            AuthConfig {
                allow_local_registration: false,
                access_token_ttl_secs: 60,
                refresh_token_ttl_secs: 600,
                session_ttl_secs: 1200,
                verification_code_ttl_secs: 300,
                password_min_length: 8,
                password_max_length: 128,
            },
            PasswordWorkBudget::default(),
        )
        .unwrap();
        assert!(matches!(
            completion.complete_recovery(RecoveryCompleteCommand {
                handle: SecretString::new(handle),
                code: SecretString::new("000000"),
                new_password: SecretString::new(NEW_PASSWORD),
                operation_id: Uuid::now_v7(),
                receipt_secret: secret(203),
            }),
            Err(RecoveryCompleteError::InvalidRecovery)
        ));
    }
}

#[derive(Clone, Copy)]
struct CollisionIds;
impl IdGenerator for CollisionIds {
    fn next_id(&self, purpose: &str) -> String {
        if purpose == "evt" {
            Uuid::from_u128(0xb2).to_string()
        } else {
            Uuid::now_v7().to_string()
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_event_collision_rolls_back_terminal_transition() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let flow = flow_id(&handle);
        let outbox = outbox_id(&db, flow);
        let base = service(&db, FixedClock);
        let claim = base.claim().unwrap().unwrap();
        let mut c = db.adapter.connect().unwrap();
        let event_id = Uuid::from_u128(0xb2);
        c.execute(
            &format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'email_delivery','accepted',null,null,$2)", db.schema()),
            &[&event_id, &(NOW as i64)],
        ).unwrap();
        let collision =
            CoreSecurityOutboxService::new(db.mode, db.store(), FixedClock, crypto(), CollisionIds);
        assert!(matches!(
            finish(&collision, &claim, SecurityMailOutcome::Accepted),
            Err(AccessError::Conflict("access.unique"))
        ));
        let row = c.query_one(
            &format!("select state,attempts,lease_token,envelope_key_id,ciphertext from {}.security_email_outbox where id=$1",db.schema()),
            &[&outbox],
        ).unwrap();
        assert_eq!(row.get::<_, String>(0), "sending");
        assert_eq!(row.get::<_, i32>(1), 1);
        assert_eq!(row.get::<_, Option<Uuid>>(2), Some(claim.lease_token));
        assert!(row.get::<_, Option<String>>(3).is_some());
        assert!(row.get::<_, Option<Vec<u8>>>(4).is_some());
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_cleanup_lease_expiry_marks_unknown_and_emits_event() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let flow = flow_id(&handle);
        let outbox = outbox_id(&db, flow);
        let outbox_service = service(&db, FixedClock);
        let claim = outbox_service.claim().unwrap().unwrap();
        let cleanup_now = claim
            .lease_until
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let result = service(&db, AtClock(cleanup_now)).cleanup().unwrap();
        assert_eq!(result.processed, 1);
        assert_terminal_and_redacted(&db, outbox, "unknown", "unknown");
        let mut c = db.adapter.connect().unwrap();
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {}.security_events where kind='email_delivery' and outcome='unknown'", db.schema()),
                &[],
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
    }
}

#[derive(Clone)]
struct CleanupCollisionIds(Arc<AtomicU64>);
impl IdGenerator for CleanupCollisionIds {
    fn next_id(&self, purpose: &str) -> String {
        if purpose == "evt" && self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            Uuid::from_u128(0xb2).to_string()
        } else {
            Uuid::now_v7().to_string()
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_cleanup_event_collision_rolls_back_lease_expiry() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let flow = flow_id(&handle);
        let outbox = outbox_id(&db, flow);
        let claim = service(&db, FixedClock).claim().unwrap().unwrap();
        let mut c = db.adapter.connect().unwrap();
        c.execute(
            &format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'email_delivery','accepted',null,null,$2)", db.schema()),
            &[&Uuid::from_u128(0xb2), &(NOW as i64)],
        )
        .unwrap();
        let cleanup_now = claim
            .lease_until
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let collision = CoreSecurityOutboxService::new(
            mode,
            db.store(),
            AtClock(cleanup_now),
            crypto(),
            CleanupCollisionIds(Arc::new(AtomicU64::new(0))),
        );
        assert!(matches!(
            collision.cleanup(),
            Err(AccessError::Conflict("access.unique"))
        ));
        let row = c.query_one(
            &format!("select state,attempts,lease_token,envelope_key_id,ciphertext from {}.security_email_outbox where id=$1", db.schema()),
            &[&outbox],
        ).unwrap();
        assert_eq!(row.get::<_, String>(0), "sending");
        assert_eq!(row.get::<_, i32>(1), 1);
        assert_eq!(row.get::<_, Option<Uuid>>(2), Some(claim.lease_token));
        assert!(row.get::<_, Option<String>>(3).is_some());
        assert!(row.get::<_, Option<Vec<u8>>>(4).is_some());
        assert_eq!(flow_id(&handle), flow);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn security_outbox_cleanup_cascades_retained_flow_receipts_and_budget_after_24_hours() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let handle = start_at(&db, MEMBER_EMAIL, Uuid::now_v7(), NOW);
        let flow = flow_id(&handle);
        let code = code_for_flow(&db, flow);
        let operation = Uuid::now_v7();
        let completion = CoreRecoveryCompletionService::new(
            mode,
            db.store(),
            FixedClock,
            crypto(),
            UuidIds,
            AuthConfig {
                allow_local_registration: false,
                access_token_ttl_secs: 60,
                refresh_token_ttl_secs: 600,
                session_ttl_secs: 1200,
                verification_code_ttl_secs: 300,
                password_min_length: 8,
                password_max_length: 128,
            },
            PasswordWorkBudget::default(),
        )
        .unwrap();
        completion
            .complete_recovery(RecoveryCompleteCommand {
                handle: SecretString::new(handle.clone()),
                code: SecretString::new(code),
                new_password: SecretString::new(NEW_PASSWORD),
                operation_id: operation,
                receipt_secret: secret(204),
            })
            .unwrap();
        assert!(completion
            .recovery_completion_result(SecurityReceiptQuery {
                operation_id: operation,
                receipt_secret: secret(204),
            })
            .unwrap());

        const AFTER_RETENTION: u64 = NOW + 86_400;
        let cleanup = service(&db, AtClock(AFTER_RETENTION)).cleanup().unwrap();
        assert_eq!(cleanup.processed, 3);
        let mut c = db.adapter.connect().unwrap();
        for (table, query) in [
            (
                "flow",
                format!(
                    "select count(*) from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
            ),
            (
                "outbox",
                format!(
                    "select count(*) from {}.security_email_outbox where flow_id=$1",
                    db.schema()
                ),
            ),
            (
                "start receipt",
                format!(
                    "select count(*) from {}.password_recovery_start_receipts where flow_id=$1",
                    db.schema()
                ),
            ),
        ] {
            assert_eq!(
                c.query_one(&query, &[&flow]).unwrap().get::<_, i64>(0),
                0,
                "expired retained {table} is removed"
            );
        }
        let subject = crypto().subject_digest(MEMBER_EMAIL).unwrap();
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.password_recovery_budgets where subject_digest=$1",
                    db.schema()
                ),
                &[&subject.as_slice()],
            )
            .unwrap()
            .get::<_, i64>(0),
            0,
            "budget is removed only after no retained flow remains"
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {}.security_receipts where purpose='password_recovery' and operation_id=$1", db.schema()),
                &[&operation],
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        assert!(!completion
            .recovery_completion_result(SecurityReceiptQuery {
                operation_id: operation,
                receipt_secret: secret(204),
            })
            .unwrap());
    }
}

use super::*;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::{
        CoreRecoveryCompletionService, CoreRecoveryStartService, CoreTenantAuthenticationService,
        LoginTenantPolicy, RecoveryCompleteCommand, RecoveryCompleteError,
        RecoveryCompletionService, RecoveryStartCommand, RecoveryStartService,
        SecurityReceiptQuery, TenantLoginEntry, TenantLoginOutcome, TenantPasswordLogin,
    },
    AccountSecurityCrypto, AuthConfig, PasswordWorkBudget, SecretString, SecurityCryptoContext,
    SecurityEnvelope, SecurityEnvelopePurpose,
};
use embedded_idp_security::{
    AccountSecurityKeySet, ProductionJwtConfig, RingAccountSecurityCrypto, Rs256JwtService,
    RsaSigningKeyConfig, SecureRefreshTokenGenerator, Sha256RefreshTokenDigester,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc, Barrier, Mutex,
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

fn config() -> AuthConfig {
    AuthConfig {
        allow_local_registration: false,
        access_token_ttl_secs: 60,
        refresh_token_ttl_secs: 600,
        session_ttl_secs: 1200,
        verification_code_ttl_secs: 300,
        password_min_length: 8,
        password_max_length: 128,
    }
}

fn tokens() -> Rs256JwtService {
    let key = RsaSigningKeyConfig::from_private_key_der(
        Base64::decode_vec(
            include_str!("../../../embedded-idp-security/tests/fixtures/rsa_3072_key_1.pk8.b64")
                .trim(),
        )
        .unwrap(),
    )
    .unwrap();
    Rs256JwtService::new(
        ProductionJwtConfig {
            issuer: "https://idp.example.test".into(),
            audience: "recovery-completion-test".into(),
            scope: "openid".into(),
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 600,
            clock_skew_secs: 0,
        },
        key,
        vec![],
    )
    .unwrap()
}

fn service(
    db: &Db,
) -> CoreRecoveryCompletionService<
    PostgresAccessStore,
    FixedClock,
    RingAccountSecurityCrypto,
    UuidIds,
> {
    CoreRecoveryCompletionService::new(
        db.mode,
        db.store(),
        FixedClock,
        crypto(),
        UuidIds,
        config(),
        PasswordWorkBudget::default(),
    )
    .unwrap()
}

fn secret(byte: u8) -> SecretString {
    SecretString::new(Base64UrlUnpadded::encode_string(&[byte; 32]))
}

fn started(db: &Db, email: &str, operation: Uuid, secret_byte: u8) -> (String, String) {
    let start = CoreRecoveryStartService::new(db.mode, db.store(), FixedClock, crypto(), UuidIds);
    let result = start
        .start_recovery(RecoveryStartCommand {
            email: SecretString::new(email),
            operation_id: operation,
            receipt_secret: secret(secret_byte),
        })
        .unwrap();
    let bytes = Base64UrlUnpadded::decode_vec(result.handle.expose_secret()).unwrap();
    let flow = Uuid::from_slice(&bytes[..16]).unwrap();
    let mut c = db.adapter.connect().unwrap();
    let row = c
        .query_one(
            &format!("select id,envelope_key_id,ciphertext from {}.security_email_outbox where flow_id=$1", db.schema()),
            &[&flow],
        )
        .unwrap();
    let outbox = row.get::<_, Uuid>(0);
    let opened = crypto()
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
    let fields = opened.expose_secret().split('\n').collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "recovery-email-v1");
    assert_eq!(fields[1], email);
    (
        result.handle.expose_secret().to_owned(),
        fields[2].to_owned(),
    )
}

fn started_at(
    db: &Db,
    email: &str,
    operation: Uuid,
    secret_byte: u8,
    now: u64,
) -> (String, String) {
    let start = CoreRecoveryStartService::new(db.mode, db.store(), AtClock(now), crypto(), UuidIds);
    let result = start
        .start_recovery(RecoveryStartCommand {
            email: SecretString::new(email),
            operation_id: operation,
            receipt_secret: secret(secret_byte),
        })
        .unwrap();
    let bytes = Base64UrlUnpadded::decode_vec(result.handle.expose_secret()).unwrap();
    let flow = Uuid::from_slice(&bytes[..16]).unwrap();
    let mut c = db.adapter.connect().unwrap();
    let row = c
        .query_one(
            &format!("select id,envelope_key_id,ciphertext from {}.security_email_outbox where flow_id=$1", db.schema()),
            &[&flow],
        )
        .unwrap();
    let outbox = row.get::<_, Uuid>(0);
    let opened = crypto()
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
    let fields = opened.expose_secret().split('\n').collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], "recovery-email-v1");
    assert_eq!(fields[1], email);
    (
        result.handle.expose_secret().to_owned(),
        fields[2].to_owned(),
    )
}

fn command(handle: &str, code: &str, operation: Uuid, receipt_byte: u8) -> RecoveryCompleteCommand {
    RecoveryCompleteCommand {
        handle: SecretString::new(handle),
        code: SecretString::new(code),
        new_password: SecretString::new(NEW_PASSWORD),
        operation_id: operation,
        receipt_secret: secret(receipt_byte),
    }
}

fn flow_id(handle: &str) -> Uuid {
    let decoded = Base64UrlUnpadded::decode_vec(handle).unwrap();
    Uuid::from_slice(&decoded[..16]).unwrap()
}

fn wrong_code(code: &str) -> String {
    let mut bytes = code.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    String::from_utf8(bytes).unwrap()
}

fn wrong_handle(handle: &str) -> String {
    let mut bytes = Base64UrlUnpadded::decode_vec(handle).unwrap();
    bytes[16] ^= 1;
    Base64UrlUnpadded::encode_string(&bytes)
}

fn assert_invalid(result: Result<(), RecoveryCompleteError>) {
    assert_eq!(result, Err(RecoveryCompleteError::InvalidRecovery));
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_completion_success_receipt_and_credential_retirement_work_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let (handle, code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 101);
        let op = Uuid::now_v7();
        let receipt_secret = secret(102);
        let complete = service(&db);
        let submitted = command(&handle, &code, op, 102);
        complete.complete_recovery(submitted.clone()).unwrap();

        let flow = flow_id(&handle);
        let mut c = db.adapter.connect().unwrap();
        let row = c.query_one(
            &format!("select a.password_hash,a.security_credential_version,f.state,o.state,o.ciphertext from {}.accounts a join {}.password_recovery_flows f on f.account_id=a.id join {}.security_email_outbox o on o.flow_id=f.id where a.id=$1 and f.id=$2", db.schema(),db.schema(),db.schema()),
            &[&db.member,&flow],
        ).unwrap();
        let password_hash: String = row.get(0);
        assert!(password_hash.starts_with("$argon2id$"));
        assert_eq!(row.get::<_, i64>(1), 2);
        assert_eq!(row.get::<_, String>(2), "consumed");
        assert_eq!(row.get::<_, String>(3), "cancelled");
        assert!(row.get::<_, Option<Vec<u8>>>(4).is_none());
        let auth = CoreTenantAuthenticationService::new(
            mode,
            config(),
            TenantLoginEntry {
                client_id: "live-admin-client".into(),
                login_entry: "recovery-completion-test".into(),
                policy: LoginTenantPolicy::Fixed {
                    tenant_id: db.target().into(),
                },
                require_device_proof: false,
            },
            db.store(),
            tokens(),
            SecureRefreshTokenGenerator,
            Sha256RefreshTokenDigester,
            FixedClock,
            UuidIds,
        )
        .unwrap();
        let login = auth
            .login(TenantPasswordLogin {
                email: MEMBER_EMAIL.into(),
                password: SecretString::new(NEW_PASSWORD),
            })
            .unwrap();
        assert!(matches!(login, TenantLoginOutcome::Authenticated(_)));
        assert_eq!(
            c.query_one(
                &format!(
                    "select status from {}.auth_sessions where id=$1",
                    db.schema()
                ),
                &[&db.member_session],
            )
            .unwrap()
            .get::<_, String>(0),
            "revoked",
            "password recovery retires the account's existing session"
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {}.security_events where kind='recovery_completed' and outcome='accepted' and account_id=$1 and operation_id=$2", db.schema()),
                &[&db.member,&op],
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        let receipt_query = || SecurityReceiptQuery {
            operation_id: op,
            receipt_secret: receipt_secret.clone(),
        };
        assert!(complete
            .recovery_completion_result(receipt_query())
            .unwrap());
        assert!(!complete
            .recovery_completion_result(SecurityReceiptQuery {
                operation_id: op,
                receipt_secret: secret(103),
            })
            .unwrap());
        complete.complete_recovery(submitted).unwrap();
        let mut changed = command(&handle, &code, op, 102);
        changed.new_password = SecretString::new("Different-command-password-890!");
        assert!(matches!(
            complete.complete_recovery(changed),
            Err(RecoveryCompleteError::Access(AccessError::Conflict(
                "recovery.operation_conflict"
            )))
        ));
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_completion_wrong_handle_does_not_count_but_wrong_code_commits_failure() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let (handle, code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 111);
        let service = service(&db);
        let flow = flow_id(&handle);
        assert_invalid(service.complete_recovery(command(
            &wrong_handle(&handle),
            &code,
            Uuid::now_v7(),
            112,
        )));
        let mut c = db.adapter.connect().unwrap();
        let attempts: i32 = c
            .query_one(
                &format!(
                    "select failed_attempts from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&flow],
            )
            .unwrap()
            .get(0);
        let failures: i32 = c.query_one(
            &format!("select failure_count from {}.password_recovery_budgets where subject_digest=$1", db.schema()),
            &[&crypto().subject_digest(MEMBER_EMAIL).unwrap().as_slice()],
        ).unwrap().get(0);
        assert_eq!((attempts, failures), (0, 0));
        assert_invalid(service.complete_recovery(command(
            &handle,
            &wrong_code(&code),
            Uuid::now_v7(),
            113,
        )));
        assert_eq!(
            c.query_one(
                &format!(
                    "select failed_attempts from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&flow]
            )
            .unwrap()
            .get::<_, i32>(0),
            1
        );
        assert_eq!(c.query_one(&format!("select failure_count from {}.password_recovery_budgets where subject_digest=$1", db.schema()), &[&crypto().subject_digest(MEMBER_EMAIL).unwrap().as_slice()]).unwrap().get::<_,i32>(0),1);
        assert_eq!(c.query_one(&format!("select count(*) from {}.security_events where kind='recovery_failed' and outcome='rejected'", db.schema()), &[]).unwrap().get::<_,i64>(0),1);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_completion_enforces_five_flow_and_ten_subject_failures_and_resets_expired_window() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let svc = service(&db);
        let (first_handle, first_code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 121);
        for _ in 0..5 {
            assert_invalid(svc.complete_recovery(command(
                &first_handle,
                &wrong_code(&first_code),
                Uuid::now_v7(),
                122,
            )));
        }
        let first_flow = flow_id(&first_handle);
        let mut c = db.adapter.connect().unwrap();
        assert_eq!(
            c.query_one(
                &format!(
                    "select state,failed_attempts from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&first_flow]
            )
            .unwrap()
            .get::<_, String>(0),
            "invalidated"
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select failed_attempts from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&first_flow]
            )
            .unwrap()
            .get::<_, i32>(0),
            5
        );
        assert_eq!(c.query_one(&format!("select state,envelope_key_id,ciphertext from {}.security_email_outbox where flow_id=$1", db.schema()), &[&first_flow]).unwrap().get::<_,String>(0),"cancelled");

        let (second_handle, second_code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 123);
        for _ in 0..5 {
            assert_invalid(svc.complete_recovery(command(
                &second_handle,
                &wrong_code(&second_code),
                Uuid::now_v7(),
                124,
            )));
        }
        let subject = crypto().subject_digest(MEMBER_EMAIL).unwrap();
        assert_eq!(c.query_one(&format!("select failure_count from {}.password_recovery_budgets where subject_digest=$1", db.schema()), &[&subject.as_slice()]).unwrap().get::<_,i32>(0),10);
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.security_events where kind='recovery_failed'",
                    db.schema()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
            10
        );
        assert!(matches!(
            CoreRecoveryStartService::new(db.mode, db.store(), FixedClock, crypto(), UuidIds)
                .start_recovery(RecoveryStartCommand {
                    email: SecretString::new(MEMBER_EMAIL),
                    operation_id: Uuid::now_v7(),
                    receipt_secret: secret(125)
                }),
            Err(AccessError::Conflict("recovery.rate_limited"))
        ));

        let db_window = Db::new(mode);
        install(&db_window);
        const WINDOW_TEST_NOW: u64 = 10_000;
        let (handle, code) = started_at(
            &db_window,
            MEMBER_EMAIL,
            Uuid::now_v7(),
            126,
            WINDOW_TEST_NOW,
        );
        let mut c_window = db_window.adapter.connect().unwrap();
        let subject = crypto().subject_digest(MEMBER_EMAIL).unwrap();
        c_window.execute(&format!("update {}.password_recovery_budgets set window_start_epoch=0,expires_at_epoch=3600,start_count=3,failure_count=10 where subject_digest=$1", db_window.schema()), &[&subject.as_slice()]).unwrap();
        let completion = CoreRecoveryCompletionService::new(
            mode,
            db_window.store(),
            AtClock(WINDOW_TEST_NOW),
            crypto(),
            UuidIds,
            config(),
            PasswordWorkBudget::default(),
        )
        .unwrap();
        assert_invalid(completion.complete_recovery(command(
            &handle,
            &wrong_code(&code),
            Uuid::now_v7(),
            127,
        )));
        let budget = c_window.query_one(&format!("select window_start_epoch,expires_at_epoch,start_count,failure_count from {}.password_recovery_budgets where subject_digest=$1",db_window.schema()), &[&subject.as_slice()]).unwrap();
        assert_eq!(
            (
                budget.get::<_, i64>(0),
                budget.get::<_, i64>(1),
                budget.get::<_, i32>(2),
                budget.get::<_, i32>(3)
            ),
            (
                WINDOW_TEST_NOW as i64,
                (WINDOW_TEST_NOW + 3600) as i64,
                0,
                1
            )
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_completion_completion_event_collision_rolls_back_password_and_receipt() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let (handle, code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 131);
        let flow = flow_id(&handle);
        let mut c = db.adapter.connect().unwrap();
        let before_hash: String = c
            .query_one(
                &format!(
                    "select password_hash from {}.accounts where id=$1",
                    db.schema()
                ),
                &[&db.member],
            )
            .unwrap()
            .get(0);
        let before_failures: i32 = c
            .query_one(
                &format!("select failure_count from {}.password_recovery_budgets where subject_digest=$1", db.schema()),
                &[&crypto().subject_digest(MEMBER_EMAIL).unwrap().as_slice()],
            )
            .unwrap()
            .get(0);
        let event_id = Uuid::from_u128(0xfade);
        c.execute(&format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'email_delivery','accepted',null,null,$2)",db.schema()), &[&event_id,&(NOW as i64)]).unwrap();
        let collision_service = CoreRecoveryCompletionService::new(
            db.mode,
            db.store(),
            FixedClock,
            crypto(),
            CompletionCollisionIds,
            config(),
            PasswordWorkBudget::default(),
        )
        .unwrap();
        assert!(matches!(
            collision_service.complete_recovery(command(&handle, &code, Uuid::now_v7(), 132)),
            Err(RecoveryCompleteError::Access(AccessError::Conflict(
                "access.unique"
            )))
        ));
        assert_eq!(
            c.query_one(
                &format!(
                    "select password_hash from {}.accounts where id=$1",
                    db.schema()
                ),
                &[&db.member],
            )
            .unwrap()
            .get::<_, String>(0),
            before_hash
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
            "pending"
        );
        assert_eq!(
            c.query_one(
                &format!("select failure_count from {}.password_recovery_budgets where subject_digest=$1", db.schema()),
                &[&crypto().subject_digest(MEMBER_EMAIL).unwrap().as_slice()],
            )
            .unwrap()
            .get::<_, i32>(0),
            before_failures
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.security_receipts where purpose='password_recovery'",
                    db.schema()
                ),
                &[],
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
    }
}

#[derive(Clone, Copy)]
struct CompletionCollisionIds;
impl IdGenerator for CompletionCollisionIds {
    fn next_id(&self, purpose: &str) -> String {
        if purpose == "evt" {
            Uuid::from_u128(0xfade).to_string()
        } else {
            Uuid::now_v7().to_string()
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_completion_failure_event_collision_rolls_back_guess_counters() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let (handle, code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 133);
        let flow = flow_id(&handle);
        let event_id = Uuid::from_u128(0xfade);
        let mut c = db.adapter.connect().unwrap();
        c.execute(
            &format!("insert into {}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'email_delivery','accepted',null,null,$2)", db.schema()),
            &[&event_id, &(NOW as i64)],
        )
        .unwrap();
        let collision_service = CoreRecoveryCompletionService::new(
            db.mode,
            db.store(),
            FixedClock,
            crypto(),
            CompletionCollisionIds,
            config(),
            PasswordWorkBudget::default(),
        )
        .unwrap();
        assert!(matches!(
            collision_service.complete_recovery(command(
                &handle,
                &wrong_code(&code),
                Uuid::now_v7(),
                134
            )),
            Err(RecoveryCompleteError::Access(AccessError::Conflict(
                "access.unique"
            )))
        ));
        assert_eq!(
            c.query_one(
                &format!(
                    "select failed_attempts from {}.password_recovery_flows where id=$1",
                    db.schema()
                ),
                &[&flow],
            )
            .unwrap()
            .get::<_, i32>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!("select failure_count from {}.password_recovery_budgets where subject_digest=$1", db.schema()),
                &[&crypto().subject_digest(MEMBER_EMAIL).unwrap().as_slice()],
            )
            .unwrap()
            .get::<_, i32>(0),
            0
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.security_events where kind='recovery_failed'",
                    db.schema()
                ),
                &[],
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
    }
}

#[derive(Clone)]
struct FirstPhaseBarrierStore {
    inner: PostgresAccessStore,
    barrier: Arc<Barrier>,
    calls: Arc<AtomicUsize>,
}

impl RecoveryCompletionStore for FirstPhaseBarrierStore {
    type Transaction<'a> = PostgresRecoveryCompletionTransaction<'a>;

    fn recovery_completion_transaction<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        flow_id: Option<Uuid>,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        let wait_for_both_verified_reads =
            flow_id.is_some() && self.calls.fetch_add(1, Ordering::SeqCst) < 2;
        let result = self
            .inner
            .recovery_completion_transaction(mode, authority, flow_id, run)?;
        if wait_for_both_verified_reads {
            self.barrier.wait();
        }
        Ok(result)
    }
}

struct VerifiedSnapshotGateStore {
    inner: PostgresAccessStore,
    calls: AtomicUsize,
    reached: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl RecoveryCompletionStore for VerifiedSnapshotGateStore {
    type Transaction<'a> = PostgresRecoveryCompletionTransaction<'a>;

    fn recovery_completion_transaction<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        flow_id: Option<Uuid>,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        let pause_after_verified_snapshot =
            flow_id.is_some() && self.calls.fetch_add(1, Ordering::SeqCst) == 0;
        let result = self
            .inner
            .recovery_completion_transaction(mode, authority, flow_id, run)?;
        if pause_after_verified_snapshot {
            self.reached.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(15))
                .expect("test releases verified snapshot gate");
        }
        Ok(result)
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_completion_rechecks_membership_after_verified_snapshot() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let (handle, code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 151);
        let (reached_tx, reached_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let service = CoreRecoveryCompletionService::new(
            mode,
            VerifiedSnapshotGateStore {
                inner: db.store(),
                calls: AtomicUsize::new(0),
                reached: reached_tx,
                release: Mutex::new(release_rx),
            },
            FixedClock,
            crypto(),
            UuidIds,
            config(),
            PasswordWorkBudget::default(),
        )
        .unwrap();
        let handle_for_thread = handle.clone();
        let code_for_thread = code.clone();
        let completion = std::thread::spawn(move || {
            service.complete_recovery(command(
                &handle_for_thread,
                &code_for_thread,
                Uuid::now_v7(),
                152,
            ))
        });
        reached_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("first-phase snapshot was verified and committed");
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "update {}.access_memberships set status='suspended' where account_id=$1",
                    db.schema()
                ),
                &[&db.member],
            )
            .unwrap();
        release_tx.send(()).unwrap();
        assert_invalid(completion.join().unwrap());
        let flow = flow_id(&handle);
        let mut c = db.adapter.connect().unwrap();
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
            "pending"
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.security_receipts where purpose='password_recovery'",
                    db.schema()
                ),
                &[],
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn recovery_completion_two_valid_concurrent_operations_consume_at_most_once() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        install(&db);
        let (handle, code) = started(&db, MEMBER_EMAIL, Uuid::now_v7(), 141);
        let store = FirstPhaseBarrierStore {
            inner: db.store(),
            barrier: Arc::new(Barrier::new(2)),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let results = (0..2)
            .map(|n| {
                let store = store.clone();
                let handle = handle.clone();
                let code = code.clone();
                std::thread::spawn(move || {
                    let service = CoreRecoveryCompletionService::new(
                        mode,
                        store,
                        FixedClock,
                        crypto(),
                        UuidIds,
                        config(),
                        PasswordWorkBudget::default(),
                    )
                    .unwrap();
                    service.complete_recovery(command(&handle, &code, Uuid::now_v7(), 142 + n))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(RecoveryCompleteError::InvalidRecovery)))
                .count(),
            1
        );
        let flow = flow_id(&handle);
        let mut c = db.adapter.connect().unwrap();
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
            "consumed"
        );
        assert_eq!(
            c.query_one(
                &format!(
                    "select count(*) from {}.security_receipts where purpose='password_recovery'",
                    db.schema()
                ),
                &[],
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
    }
}

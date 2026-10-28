use super::*;
use crate::service::password::verify_password;
use crate::{
    AccountSecurityCrypto, SecurityCryptoContext, SecurityEnvelope, SecurityEnvelopePurpose,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const SUBJECT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SESSION: &str = "00000000-0000-4000-8000-000000000001";
const SECRET: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new(seconds: u64) -> Self {
        Self(Arc::new(AtomicU64::new(seconds)))
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Clone)]
struct TestCrypto {
    current: String,
    keys: Arc<HashMap<String, [u8; 32]>>,
}

impl TestCrypto {
    fn new(current: &str, keys: &[(&str, u8)]) -> Self {
        Self {
            current: current.into(),
            keys: Arc::new(
                keys.iter()
                    .map(|(id, byte)| ((*id).to_owned(), [*byte; 32]))
                    .collect(),
            ),
        }
    }

    fn digest_with(
        key: &[u8; 32],
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(key);
        hash.update(match purpose {
            SecurityDigestPurpose::RecoveryHandle => b"handle".as_slice(),
            SecurityDigestPurpose::ReceiptSecret => b"receipt".as_slice(),
            SecurityDigestPurpose::Command => b"command".as_slice(),
            SecurityDigestPurpose::RecoveryCode => b"code".as_slice(),
        });
        hash.update(context.reference_id.as_bytes());
        if let Some(related) = context.related_id {
            hash.update(related.as_bytes());
        }
        hash.update(payload);
        hash.finalize().into()
    }

    fn digest_using(
        &self,
        key_id: &str,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> SecurityDigest {
        let key = self.keys.get(key_id).expect("fixture key");
        SecurityDigest {
            key_id: key_id.into(),
            bytes: Self::digest_with(key, purpose, context, payload),
        }
    }
}

impl AccountSecurityCrypto for TestCrypto {
    fn authority(&self) -> &str {
        "test-host"
    }

    fn random_token(&self) -> Result<SecretString, SecurityCryptoError> {
        Ok(SecretString::new(SECRET))
    }

    fn random_code(&self) -> Result<SecretString, SecurityCryptoError> {
        Ok(SecretString::new("123456"))
    }

    fn subject_digest(&self, _: &str) -> Result<[u8; 32], SecurityCryptoError> {
        Ok([0; 32])
    }

    fn digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> Result<SecurityDigest, SecurityCryptoError> {
        if context.reference_id.is_nil() || context.related_id.is_some_and(|id| id.is_nil()) {
            return Err(SecurityCryptoError::InvalidInput);
        }
        Ok(self.digest_using(&self.current, purpose, context, payload))
    }

    fn verify_digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
        stored: &SecurityDigest,
    ) -> Result<bool, SecurityCryptoError> {
        let key = self
            .keys
            .get(&stored.key_id)
            .ok_or(SecurityCryptoError::UnknownKey)?;
        let expected = Self::digest_with(key, purpose, context, payload);
        Ok(expected
            .iter()
            .zip(stored.bytes.iter())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0)
    }

    fn seal(
        &self,
        _: SecurityEnvelopePurpose,
        _: &SecurityCryptoContext,
        _: &SecretString,
    ) -> Result<SecurityEnvelope, SecurityCryptoError> {
        Err(SecurityCryptoError::Unavailable)
    }

    fn open(
        &self,
        _: SecurityEnvelopePurpose,
        _: &SecurityCryptoContext,
        _: &SecurityEnvelope,
    ) -> Result<SecretString, SecurityCryptoError> {
        Err(SecurityCryptoError::Unavailable)
    }
}

#[derive(Clone)]
struct TestIds(Arc<AtomicU64>);

impl IdGenerator for TestIds {
    fn next_id(&self, _: &str) -> String {
        Uuid::from_u128(self.0.fetch_add(1, Ordering::SeqCst) as u128 + 10).to_string()
    }
}

#[derive(Clone)]
struct MemoryStore(Arc<Mutex<State>>);

#[derive(Clone)]
struct State {
    actor: AccessActor,
    active: bool,
    password_hash: SecretString,
    credential_version: u64,
    receipt: Option<SecurityOperationReceipt>,
    receipt_count: u64,
    retired: bool,
    event_count: u64,
    fail_record: bool,
    change_after_read: bool,
    read_open: bool,
    read_calls: u64,
    write_calls: u64,
}

impl MemoryStore {
    fn new() -> Self {
        let actor = actor();
        Self(Arc::new(Mutex::new(State {
            actor,
            active: true,
            password_hash: SecretString::new(
                hash_password("Current-fixture-123").expect("fixture hash"),
            ),
            credential_version: 7,
            receipt: None,
            receipt_count: 0,
            retired: false,
            event_count: 0,
            fail_record: false,
            change_after_read: false,
            read_open: false,
            read_calls: 0,
            write_calls: 0,
        })))
    }

    fn with_state<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.0.lock().expect("memory store lock"))
    }
}

struct MemoryRead<'a>(&'a mut State);
struct MemoryWrite<'a>(&'a mut State);

fn snapshot(state: &State) -> SelfPasswordCredentialSnapshot {
    SelfPasswordCredentialSnapshot {
        account_id: state.actor.subject_id.clone(),
        password_hash: state.password_hash.clone(),
        credential_version: state.credential_version,
    }
}

fn memory_error() -> StoreError {
    StoreError::Backend("fixture failure".into())
}

impl SelfPasswordChangeReadTransaction for MemoryRead<'_> {
    fn actor_is_active(&mut self, actor: &AccessActor, _: SystemTime) -> Result<bool, StoreError> {
        Ok(self.0.active && *actor == self.0.actor)
    }

    fn credential_snapshot(
        &mut self,
        actor: &AccessActor,
    ) -> Result<Option<SelfPasswordCredentialSnapshot>, StoreError> {
        Ok((actor.subject_id == self.0.actor.subject_id).then(|| snapshot(self.0)))
    }

    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        Ok(self
            .0
            .receipt
            .as_ref()
            .filter(|r| r.purpose == purpose && r.operation_id == operation_id)
            .cloned())
    }
}

impl SelfPasswordChangeReadTransaction for MemoryWrite<'_> {
    fn actor_is_active(&mut self, actor: &AccessActor, _: SystemTime) -> Result<bool, StoreError> {
        Ok(self.0.active && *actor == self.0.actor)
    }

    fn credential_snapshot(
        &mut self,
        actor: &AccessActor,
    ) -> Result<Option<SelfPasswordCredentialSnapshot>, StoreError> {
        Ok((actor.subject_id == self.0.actor.subject_id).then(|| snapshot(self.0)))
    }

    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        Ok(self
            .0
            .receipt
            .as_ref()
            .filter(|r| r.purpose == purpose && r.operation_id == operation_id)
            .cloned())
    }
}

impl SelfPasswordChangeWriteTransaction for MemoryWrite<'_> {
    fn receipt_count(&mut self) -> Result<u64, StoreError> {
        Ok(self.0.receipt_count)
    }

    fn replace_password_and_retire(
        &mut self,
        actor: &AccessActor,
        expected: &SelfPasswordCredentialSnapshot,
        new_password_hash: &SecretString,
        _: SystemTime,
    ) -> Result<(), StoreError> {
        let actual = snapshot(self.0);
        if !self.0.active || actor != &self.0.actor || !snapshots_match(expected, &actual) {
            return Err(StoreError::Conflict("security.credentials_changed"));
        }
        self.0.password_hash = new_password_hash.clone();
        self.0.credential_version += 1;
        self.0.retired = true;
        Ok(())
    }

    fn record_completion(
        &mut self,
        receipt: &SecurityOperationReceipt,
        _: Uuid,
    ) -> Result<(), StoreError> {
        if self.0.fail_record {
            return Err(memory_error());
        }
        self.0.receipt = Some(receipt.clone());
        self.0.receipt_count += 1;
        self.0.event_count += 1;
        Ok(())
    }
}

impl SelfPasswordChangeStore for MemoryStore {
    type ReadTransaction<'a> = MemoryRead<'a>;
    type WriteTransaction<'a> = MemoryWrite<'a>;

    fn password_change_read<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: Option<&AccessActor>,
        run: impl FnOnce(&mut Self::ReadTransaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        if mode != TenancyMode::Enabled || authority != "test-host" {
            return Err(AccessError::ModeMismatch);
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| AccessError::Store(memory_error()))?;
        state.read_calls += 1;
        if actor.is_some_and(|actor| actor != &state.actor) {
            return Err(AccessError::Forbidden);
        }
        state.read_open = true;
        let result = {
            let mut tx = MemoryRead(&mut state);
            run(&mut tx)
        };
        state.read_open = false;
        if state.change_after_read {
            state.change_after_read = false;
            state.password_hash = SecretString::new(
                hash_password("Concurrent-fixture-456").expect("concurrent fixture hash"),
            );
            state.credential_version += 1;
        }
        result
    }

    fn password_change_write<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: &AccessActor,
        run: impl FnOnce(&mut Self::WriteTransaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        if mode != TenancyMode::Enabled || authority != "test-host" {
            return Err(AccessError::ModeMismatch);
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| AccessError::Store(memory_error()))?;
        if actor != &state.actor {
            return Err(AccessError::Forbidden);
        }
        if state.read_open {
            return Err(AccessError::Store(memory_error()));
        }
        state.write_calls += 1;
        let before = state.clone();
        let result = {
            let mut tx = MemoryWrite(&mut state);
            run(&mut tx)
        };
        if result.is_err() {
            *state = before;
        }
        result
    }
}

fn actor() -> AccessActor {
    AccessActor {
        tenant_id: "tenant-a".into(),
        subject_id: SUBJECT.into(),
        session_id: SESSION.into(),
    }
}

fn config() -> AuthConfig {
    AuthConfig {
        allow_local_registration: true,
        access_token_ttl_secs: 60,
        refresh_token_ttl_secs: 120,
        session_ttl_secs: 120,
        verification_code_ttl_secs: 300,
        password_min_length: 8,
        password_max_length: 128,
    }
}

fn service(
    store: MemoryStore,
    clock: TestClock,
    crypto: TestCrypto,
    budget: PasswordWorkBudget,
) -> CoreSelfPasswordChangeService<MemoryStore, TestClock, TestCrypto, TestIds> {
    CoreSelfPasswordChangeService::new(
        TenancyMode::Enabled,
        store,
        clock,
        crypto,
        TestIds(Arc::new(AtomicU64::new(0))),
        config(),
        budget,
    )
    .expect("valid config")
}

fn crypto() -> TestCrypto {
    TestCrypto::new("current", &[("current", 31), ("previous", 17)])
}

fn command(new_password: &str) -> SelfPasswordChangeCommand {
    SelfPasswordChangeCommand {
        current_password: SecretString::new("Current-fixture-123"),
        new_password: SecretString::new(new_password),
        operation_id: Uuid::from_u128(7),
        receipt_secret: SecretString::new(SECRET),
    }
}

fn receipt_for(
    crypto: &TestCrypto,
    key_id: &str,
    actor: &AccessActor,
    operation_id: Uuid,
    new_password: &str,
    completed_at: SystemTime,
) -> SecurityOperationReceipt {
    let subject = Uuid::parse_str(&actor.subject_id).unwrap();
    let actor_session = Uuid::parse_str(&actor.session_id).unwrap();
    SecurityOperationReceipt {
        purpose: SecurityReceiptPurpose::PasswordChange,
        operation_id,
        account_id: actor.subject_id.clone(),
        secret_digest: crypto.digest_using(
            key_id,
            SecurityDigestPurpose::ReceiptSecret,
            &SecurityCryptoContext {
                reference_id: operation_id,
                related_id: None,
            },
            &[1_u8; 32],
        ),
        command_digest: crypto.digest_using(
            key_id,
            SecurityDigestPurpose::Command,
            &SecurityCryptoContext {
                reference_id: operation_id,
                related_id: Some(subject),
            },
            &command_payload(
                actor,
                subject,
                actor_session,
                &SecretString::new(new_password),
            )
            .unwrap(),
        ),
        completed_at,
        expires_at: completed_at + RECEIPT_TTL,
    }
}

#[test]
fn changes_password_retires_sessions_and_records_redacted_success_receipt() {
    let store = MemoryStore::new();
    let svc = service(
        store.clone(),
        TestClock::new(10_000),
        crypto(),
        PasswordWorkBudget::default(),
    );
    svc.change_password(actor(), command("Changed-fixture-456"))
        .unwrap();

    store.with_state(|state| {
        assert!(state.retired);
        assert_eq!(state.credential_version, 8);
        assert_eq!(state.event_count, 1);
        let receipt = state.receipt.as_ref().unwrap();
        assert_eq!(receipt.purpose, SecurityReceiptPurpose::PasswordChange);
        assert_eq!(receipt.operation_id, Uuid::from_u128(7));
        assert_eq!(receipt.account_id, SUBJECT);
        assert_eq!(receipt.expires_at, UNIX_EPOCH + Duration::from_secs(96_400));
        assert!(
            verify_password(state.password_hash.expose_secret(), "Changed-fixture-456").unwrap()
        );
        assert!(
            !verify_password(state.password_hash.expose_secret(), "Current-fixture-123").unwrap()
        );
    });
    let text = format!("{:?}", command("Changed-fixture-456"));
    assert!(!text.contains("Current-fixture-123"));
    assert!(!text.contains("Changed-fixture-456"));
    assert!(!text.contains(SECRET));
}

#[test]
fn wrong_current_password_is_uniform_and_does_not_write() {
    let store = MemoryStore::new();
    let svc = service(
        store.clone(),
        TestClock::new(10_000),
        crypto(),
        PasswordWorkBudget::default(),
    );
    let mut request = command("Changed-fixture-456");
    request.current_password = SecretString::new("wrong-password-123");

    assert_eq!(
        svc.change_password(actor(), request),
        Err(SelfPasswordChangeError::InvalidCredentials)
    );
    store.with_state(|state| {
        assert!(!state.retired);
        assert_eq!(state.credential_version, 7);
        assert_eq!(state.write_calls, 0);
        assert!(state.receipt.is_none());
    });
}

#[test]
fn stale_credential_snapshot_conflicts_after_kdf_and_never_overwrites_newer_password() {
    let store = MemoryStore::new();
    store.with_state(|state| state.change_after_read = true);
    let svc = service(
        store.clone(),
        TestClock::new(10_000),
        crypto(),
        PasswordWorkBudget::default(),
    );

    assert_eq!(
        svc.change_password(actor(), command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::Conflict(
            "security.credentials_changed"
        )))
    );
    store.with_state(|state| {
        assert!(!state.retired);
        assert_eq!(state.credential_version, 8);
        assert!(verify_password(
            state.password_hash.expose_secret(),
            "Concurrent-fixture-456"
        )
        .unwrap());
        assert!(state.receipt.is_none());
    });
}

#[test]
fn full_work_budget_rejects_before_writing() {
    let store = MemoryStore::new();
    let budget = PasswordWorkBudget::default();
    let permits = (0..4)
        .map(|_| budget.try_login().unwrap())
        .collect::<Vec<_>>();
    let svc = service(store.clone(), TestClock::new(10_000), crypto(), budget);

    assert_eq!(
        svc.change_password(actor(), command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::Store(
            StoreError::Backend("password.work_unavailable".into())
        )))
    );
    store.with_state(|state| {
        assert!(!state.retired);
        assert_eq!(state.write_calls, 0);
        assert!(state.receipt.is_none());
    });
    drop(permits);
}

#[test]
fn previous_key_receipt_replay_and_anonymous_result_only_confirm_commit() {
    let store = MemoryStore::new();
    let actor = actor();
    let crypto = crypto();
    let operation_id = Uuid::from_u128(7);
    let secret_bytes = [1_u8; 32];
    let command_payload = command_payload(
        &actor,
        Uuid::parse_str(SUBJECT).unwrap(),
        Uuid::parse_str(SESSION).unwrap(),
        &SecretString::new("Changed-fixture-456"),
    )
    .unwrap();
    let completed_at = UNIX_EPOCH + Duration::from_secs(9_000);
    let receipt = SecurityOperationReceipt {
        purpose: SecurityReceiptPurpose::PasswordChange,
        operation_id,
        account_id: SUBJECT.into(),
        secret_digest: crypto.digest_using(
            "previous",
            SecurityDigestPurpose::ReceiptSecret,
            &SecurityCryptoContext {
                reference_id: operation_id,
                related_id: None,
            },
            &secret_bytes,
        ),
        command_digest: crypto.digest_using(
            "previous",
            SecurityDigestPurpose::Command,
            &SecurityCryptoContext {
                reference_id: operation_id,
                related_id: Some(Uuid::parse_str(SUBJECT).unwrap()),
            },
            &command_payload,
        ),
        completed_at,
        expires_at: completed_at + RECEIPT_TTL,
    };
    store.with_state(|state| state.receipt = Some(receipt));
    let svc = service(
        store.clone(),
        TestClock::new(10_000),
        crypto,
        PasswordWorkBudget::default(),
    );

    svc.change_password(actor, command("Changed-fixture-456"))
        .unwrap();
    store.with_state(|state| {
        assert_eq!(state.write_calls, 0);
        assert!(!state.retired);
    });
    assert!(svc
        .password_change_result(SecurityReceiptQuery {
            operation_id,
            receipt_secret: SecretString::new(SECRET),
        })
        .unwrap());
    assert!(!svc
        .password_change_result(SecurityReceiptQuery {
            operation_id: Uuid::from_u128(8),
            receipt_secret: SecretString::new(SECRET),
        })
        .unwrap());
    assert!(!svc
        .password_change_result(SecurityReceiptQuery {
            operation_id,
            receipt_secret: SecretString::new("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",),
        })
        .unwrap());
}

#[test]
fn event_failure_rolls_back_password_and_receipt_in_transaction_contract() {
    let store = MemoryStore::new();
    store.with_state(|state| state.fail_record = true);
    let svc = service(
        store.clone(),
        TestClock::new(10_000),
        crypto(),
        PasswordWorkBudget::default(),
    );

    assert!(matches!(
        svc.change_password(actor(), command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::Store(_)))
    ));
    store.with_state(|state| {
        assert!(!state.retired);
        assert_eq!(state.credential_version, 7);
        assert!(state.receipt.is_none());
        assert_eq!(state.event_count, 0);
        assert!(
            verify_password(state.password_hash.expose_secret(), "Current-fixture-123").unwrap()
        );
    });
}

#[test]
fn invalid_actor_or_password_policy_fails_before_transaction() {
    let store = MemoryStore::new();
    let svc = service(
        store.clone(),
        TestClock::new(10_000),
        crypto(),
        PasswordWorkBudget::default(),
    );
    let mut invalid_actor = actor();
    invalid_actor.session_id = "not-a-uuid".into();
    assert!(matches!(
        svc.change_password(invalid_actor, command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::InvalidInput(
            "actor"
        )))
    ));
    assert!(matches!(
        svc.change_password(actor(), command("short")),
        Err(SelfPasswordChangeError::Access(AccessError::InvalidInput(
            "password"
        )))
    ));
    let mut malformed_secret = command("Changed-fixture-456");
    malformed_secret.receipt_secret = SecretString::new("not-a-token");
    assert!(matches!(
        svc.change_password(actor(), malformed_secret),
        Err(SelfPasswordChangeError::Access(AccessError::InvalidInput(
            "receipt_secret"
        )))
    ));
    let mut nil_operation = command("Changed-fixture-456");
    nil_operation.operation_id = Uuid::nil();
    assert!(matches!(
        svc.change_password(actor(), nil_operation),
        Err(SelfPasswordChangeError::Access(AccessError::InvalidInput(
            "operation_id"
        )))
    ));
    store.with_state(|state| assert_eq!(state.read_calls, 0));
}

#[test]
fn receipt_capacity_is_shared_and_unknown_key_or_changed_command_fail_closed() {
    let store = MemoryStore::new();
    let svc_crypto = crypto();
    let svc = service(
        store.clone(),
        TestClock::new(10_000),
        svc_crypto.clone(),
        PasswordWorkBudget::default(),
    );
    store.with_state(|state| state.receipt_count = RECEIPT_CAPACITY);
    assert_eq!(
        svc.change_password(actor(), command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::Conflict(
            "security.receipt_capacity"
        )))
    );
    store.with_state(|state| {
        assert!(!state.retired);
        state.receipt_count = 0;
        let mut receipt = receipt_for(
            &svc_crypto,
            "current",
            &state.actor,
            Uuid::from_u128(7),
            "Changed-fixture-456",
            UNIX_EPOCH + Duration::from_secs(9_000),
        );
        receipt.secret_digest.key_id = "unknown-key".into();
        receipt.secret_digest.bytes = [1; 32];
        state.receipt = Some(receipt);
    });
    assert!(matches!(
        svc.change_password(actor(), command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::Store(
            StoreError::Backend(message)
        ))) if message == "account security crypto unavailable"
    ));

    store.with_state(|state| {
        state.receipt = Some(receipt_for(
            &svc_crypto,
            "previous",
            &state.actor,
            Uuid::from_u128(7),
            "Different-fixture-789",
            UNIX_EPOCH + Duration::from_secs(9_000),
        ));
    });
    assert_eq!(
        svc.change_password(actor(), command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::Conflict(
            "security.operation_conflict"
        )))
    );
    store.with_state(|state| {
        assert!(!state.retired);
        assert_eq!(state.write_calls, 1);
    });
}

#[test]
fn expired_result_is_false_and_inactive_actor_cannot_replay_receipt() {
    let store = MemoryStore::new();
    let svc = service(
        store.clone(),
        TestClock::new(100_000),
        crypto(),
        PasswordWorkBudget::default(),
    );
    let operation_id = Uuid::from_u128(7);
    store.with_state(|state| {
        state.receipt = Some(SecurityOperationReceipt {
            purpose: SecurityReceiptPurpose::PasswordChange,
            operation_id,
            account_id: SUBJECT.into(),
            secret_digest: crypto().digest_using(
                "current",
                SecurityDigestPurpose::ReceiptSecret,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: None,
                },
                &[1_u8; 32],
            ),
            command_digest: crypto().digest_using(
                "current",
                SecurityDigestPurpose::Command,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: Some(Uuid::parse_str(SUBJECT).unwrap()),
                },
                &command_payload(
                    &state.actor,
                    Uuid::parse_str(SUBJECT).unwrap(),
                    Uuid::parse_str(SESSION).unwrap(),
                    &SecretString::new("Changed-fixture-456"),
                )
                .unwrap(),
            ),
            completed_at: UNIX_EPOCH + Duration::from_secs(1_000),
            expires_at: UNIX_EPOCH + Duration::from_secs(87_400),
        });
        state.active = false;
    });

    assert!(!svc
        .password_change_result(SecurityReceiptQuery {
            operation_id,
            receipt_secret: SecretString::new(SECRET),
        })
        .unwrap());
    assert_eq!(
        svc.change_password(actor(), command("Changed-fixture-456")),
        Err(SelfPasswordChangeError::Access(AccessError::Forbidden))
    );
}

#[test]
fn store_error_conversion_preserves_existing_access_error_mapping() {
    assert_eq!(
        SelfPasswordChangeError::from(StoreError::Backend("password.work_unavailable".into())),
        SelfPasswordChangeError::Access(AccessError::Store(StoreError::Backend(
            "password.work_unavailable".into()
        )))
    );
    assert_eq!(
        SelfPasswordChangeError::from(StoreError::Conflict("security.credentials_changed")),
        SelfPasswordChangeError::Access(AccessError::Conflict("security.credentials_changed"))
    );
}

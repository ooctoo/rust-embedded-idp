use super::*;
use crate::service::password::verify_password;
use crate::{SecurityDigest, SecurityEnvelope, SecurityEnvelopePurpose};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

const NOW: u64 = 1_800_000_000;
const FLOW_ID: u128 = 0x100;
const ACCOUNT_ID: u128 = 0x200;

#[derive(Clone)]
struct TestClock(Arc<Mutex<u64>>);
impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(*self.0.lock().unwrap())
    }
}

#[derive(Clone, Default)]
struct TestIds(Arc<AtomicUsize>);
impl IdGenerator for TestIds {
    fn next_id(&self, _: &str) -> String {
        Uuid::from_u128(0x500 + self.0.fetch_add(1, Ordering::SeqCst) as u128).to_string()
    }
}

#[derive(Clone, Default)]
struct TestCrypto;
impl TestCrypto {
    fn digest_value(
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"test-key");
        hash.update([purpose as u8]);
        hash.update(context.reference_id.as_bytes());
        if let Some(related) = context.related_id {
            hash.update(related.as_bytes());
        }
        hash.update(payload);
        hash.finalize().into()
    }

    fn stored(
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> SecurityDigest {
        SecurityDigest {
            key_id: "test-key".into(),
            bytes: Self::digest_value(purpose, context, payload),
        }
    }
}
impl AccountSecurityCrypto for TestCrypto {
    fn authority(&self) -> &str {
        "test-host"
    }
    fn random_token(&self) -> Result<SecretString, SecurityCryptoError> {
        Ok(SecretString::new(Base64UrlUnpadded::encode_string(
            &[1; 32],
        )))
    }
    fn random_code(&self) -> Result<SecretString, SecurityCryptoError> {
        Ok(SecretString::new("123456"))
    }
    fn subject_digest(&self, _: &str) -> Result<[u8; 32], SecurityCryptoError> {
        Ok([5; 32])
    }
    fn digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> Result<SecurityDigest, SecurityCryptoError> {
        Ok(Self::stored(purpose, context, payload))
    }
    fn verify_digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
        stored: &SecurityDigest,
    ) -> Result<bool, SecurityCryptoError> {
        Ok(stored.key_id == "test-key"
            && stored.bytes == Self::digest_value(purpose, context, payload))
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
struct MockStore(Arc<Mutex<State>>);
#[derive(Clone)]
struct State {
    flow: RecoveryStartFlow,
    flow_state: RecoveryFlowState,
    failed_attempts: u32,
    budget: RecoveryBudget,
    account: Option<RecoveryAccountSnapshot>,
    receipt: Option<SecurityOperationReceipt>,
    receipt_count: u64,
    new_hash: Option<SecretString>,
    completion_count: usize,
    event_count: usize,
    mutate_after_first: bool,
    membership_false_after_first: bool,
    admin_true_after_first: bool,
    transaction_count: usize,
    context_calls: usize,
}

struct MockTx<'a>(&'a mut State);
impl RecoveryCompletionTransaction for MockTx<'_> {
    fn receipt(
        &mut self,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        Ok(self
            .0
            .receipt
            .as_ref()
            .filter(|r| r.operation_id == operation_id)
            .cloned())
    }
    fn context(&mut self, flow_id: Uuid) -> Result<Option<RecoveryCompletionContext>, StoreError> {
        self.0.context_calls += 1;
        if self.0.flow.id != flow_id {
            return Ok(None);
        }
        Ok(Some(RecoveryCompletionContext {
            flow: self.0.flow.clone(),
            state: self.0.flow_state,
            failed_attempts: self.0.failed_attempts,
            budget: self.0.budget.clone(),
            account: self.0.account.clone(),
        }))
    }
    fn record_failure(
        &mut self,
        flow_id: Uuid,
        budget: &RecoveryBudget,
        failed_attempts: u32,
        _: SystemTime,
        _: Uuid,
    ) -> Result<(), StoreError> {
        assert_eq!(self.0.flow.id, flow_id);
        self.0.budget = budget.clone();
        self.0.failed_attempts = failed_attempts;
        self.0.event_count += 1;
        if failed_attempts >= MAX_FLOW_FAILURES {
            self.0.flow_state = RecoveryFlowState::Invalidated;
        }
        Ok(())
    }
    fn receipt_count(&mut self) -> Result<u64, StoreError> {
        Ok(self.0.receipt_count)
    }
    fn complete(
        &mut self,
        flow_id: Uuid,
        account_id: Uuid,
        expected_version: u64,
        new_hash: &SecretString,
        _: SystemTime,
        receipt: &SecurityOperationReceipt,
        _: Uuid,
    ) -> Result<(), StoreError> {
        assert_eq!(self.0.flow.id, flow_id);
        assert_eq!(self.0.flow_state, RecoveryFlowState::Pending);
        let account = self
            .0
            .account
            .as_ref()
            .ok_or(StoreError::Conflict("missing"))?;
        if account.account_id != account_id || account.credential_version != expected_version {
            return Err(StoreError::Conflict("security.credentials_changed"));
        }
        self.0.flow_state = RecoveryFlowState::Consumed;
        self.0.account.as_mut().unwrap().credential_version += 1;
        self.0.new_hash = Some(new_hash.clone());
        self.0.receipt = Some(receipt.clone());
        self.0.receipt_count += 1;
        self.0.completion_count += 1;
        self.0.event_count += 1;
        Ok(())
    }
}

impl RecoveryCompletionStore for MockStore {
    type Transaction<'a> = MockTx<'a>;
    fn recovery_completion_transaction<R>(
        &self,
        _: TenancyMode,
        _: &str,
        _: Option<Uuid>,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        let mut guard = self.0.lock().unwrap();
        let mut staged = guard.clone();
        staged.transaction_count += 1;
        let output = run(&mut MockTx(&mut staged))?;
        let inject_change = staged.mutate_after_first && staged.transaction_count == 1;
        let revoke_membership =
            staged.membership_false_after_first && staged.transaction_count == 1;
        let grant_admin = staged.admin_true_after_first && staged.transaction_count == 1;
        *guard = staged;
        if inject_change {
            if let Some(account) = guard.account.as_mut() {
                account.credential_version += 1;
            }
        }
        if revoke_membership {
            if let Some(account) = guard.account.as_mut() {
                account.has_active_membership = false;
            }
        }
        if grant_admin {
            if let Some(account) = guard.account.as_mut() {
                account.has_effective_security_admin = true;
            }
        }
        Ok(output)
    }
}

fn account() -> RecoveryAccountSnapshot {
    RecoveryAccountSnapshot {
        account_id: Uuid::from_u128(ACCOUNT_ID),
        email: SecretString::new("user@example.test"),
        credential_version: 1,
        active: true,
        has_active_membership: true,
        has_effective_security_admin: false,
    }
}

fn flow() -> RecoveryStartFlow {
    let flow_id = Uuid::from_u128(FLOW_ID);
    RecoveryStartFlow {
        id: flow_id,
        subject_digest: [5; 32],
        account_id: Some(Uuid::from_u128(ACCOUNT_ID)),
        snapshot_credential_version: Some(1),
        handle_digest: TestCrypto::stored(
            SecurityDigestPurpose::RecoveryHandle,
            &SecurityCryptoContext {
                reference_id: flow_id,
                related_id: None,
            },
            &[1; 32],
        ),
        code_digest: TestCrypto::stored(
            SecurityDigestPurpose::RecoveryCode,
            &SecurityCryptoContext {
                reference_id: flow_id,
                related_id: None,
            },
            b"123456",
        ),
        created_at: UNIX_EPOCH + Duration::from_secs(NOW - 60),
        expires_at: UNIX_EPOCH + Duration::from_secs(NOW + 840),
        retained_until: UNIX_EPOCH + Duration::from_secs(NOW + 86_340),
    }
}

fn dummy_flow() -> RecoveryStartFlow {
    let mut value = flow();
    value.account_id = None;
    value.snapshot_credential_version = None;
    value
}

fn budget(window_start: u64, start_count: u32, failure_count: u32) -> RecoveryBudget {
    RecoveryBudget {
        subject_digest: [5; 32],
        window_start: UNIX_EPOCH + Duration::from_secs(window_start),
        expires_at: UNIX_EPOCH + Duration::from_secs(window_start + 3_600),
        start_count,
        failure_count,
    }
}

fn store() -> MockStore {
    MockStore(Arc::new(Mutex::new(State {
        flow: flow(),
        flow_state: RecoveryFlowState::Pending,
        failed_attempts: 0,
        budget: budget(NOW - 100, 1, 0),
        account: Some(account()),
        receipt: None,
        receipt_count: 0,
        new_hash: None,
        completion_count: 0,
        event_count: 0,
        mutate_after_first: false,
        membership_false_after_first: false,
        admin_true_after_first: false,
        transaction_count: 0,
        context_calls: 0,
    })))
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
    store: MockStore,
    clock: TestClock,
    budget: PasswordWorkBudget,
) -> CoreRecoveryCompletionService<MockStore, TestClock, TestCrypto, TestIds> {
    CoreRecoveryCompletionService::new(
        TenancyMode::Enabled,
        store,
        clock,
        TestCrypto,
        TestIds::default(),
        config(),
        budget,
    )
    .unwrap()
}

fn handle() -> SecretString {
    handle_for(Uuid::from_u128(FLOW_ID), [1; 32])
}

fn handle_for(flow_id: Uuid, secret: [u8; 32]) -> SecretString {
    let mut raw = Vec::from(flow_id.as_bytes().as_slice());
    raw.extend_from_slice(&secret);
    SecretString::new(Base64UrlUnpadded::encode_string(&raw))
}

fn command(code: &str, operation_id: u128) -> RecoveryCompleteCommand {
    RecoveryCompleteCommand {
        handle: handle(),
        code: SecretString::new(code),
        new_password: SecretString::new("New-recovery-123"),
        operation_id: Uuid::from_u128(operation_id),
        receipt_secret: SecretString::new(Base64UrlUnpadded::encode_string(&[9; 32])),
    }
}

fn clock() -> TestClock {
    TestClock(Arc::new(Mutex::new(NOW)))
}

#[test]
fn wrong_code_commits_attempt_and_event_before_invalid_recovery() {
    let store = store();
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    assert_eq!(
        service.complete_recovery(command("000000", 1)),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    let state = store.0.lock().unwrap();
    assert_eq!(state.failed_attempts, 1);
    assert_eq!(state.budget.failure_count, 1);
    assert_eq!(state.event_count, 1);
    assert_eq!(state.flow_state, RecoveryFlowState::Pending);
    assert_eq!(state.completion_count, 0);
}

#[test]
fn expired_budget_is_reset_before_wrong_code_is_counted() {
    let store = store();
    store.0.lock().unwrap().budget = budget(NOW - 3_600, 3, MAX_FAILURES - 1);
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    assert_eq!(
        service.complete_recovery(command("000000", 2)),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    let state = store.0.lock().unwrap();
    assert_eq!(state.budget.window_start, clock().now());
    assert_eq!(state.budget.start_count, 0);
    assert_eq!(state.budget.failure_count, 1);
    assert_eq!(state.failed_attempts, 1);
}

#[test]
fn full_budget_refuses_correct_code_without_consuming_flow() {
    let store = store();
    store.0.lock().unwrap().budget.failure_count = MAX_FAILURES;
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    assert_eq!(
        service.complete_recovery(command("123456", 3)),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    assert_eq!(
        store.0.lock().unwrap().flow_state,
        RecoveryFlowState::Pending
    );
}

#[test]
fn changed_credential_snapshot_between_kdf_transactions_rejects_completion() {
    let store = store();
    store.0.lock().unwrap().mutate_after_first = true;
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    assert_eq!(
        service.complete_recovery(command("123456", 4)),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    let state = store.0.lock().unwrap();
    assert_eq!(state.transaction_count, 2);
    assert_eq!(state.flow_state, RecoveryFlowState::Pending);
    assert_eq!(state.completion_count, 0);
    assert!(state.new_hash.is_none());
}

#[test]
fn membership_revoked_between_kdf_transactions_rejects_completion() {
    let store = store();
    store.0.lock().unwrap().membership_false_after_first = true;
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    assert_eq!(
        service.complete_recovery(command("123456", 41)),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    let state = store.0.lock().unwrap();
    assert_eq!(state.transaction_count, 2);
    assert!(!state.account.as_ref().unwrap().has_active_membership);
    assert_eq!(state.flow_state, RecoveryFlowState::Pending);
    assert_eq!(state.completion_count, 0);
}

#[test]
fn effective_admin_granted_between_kdf_transactions_rejects_completion() {
    let store = store();
    store.0.lock().unwrap().admin_true_after_first = true;
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    assert_eq!(
        service.complete_recovery(command("123456", 42)),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    let state = store.0.lock().unwrap();
    assert_eq!(state.transaction_count, 2);
    assert!(state.account.as_ref().unwrap().has_effective_security_admin);
    assert_eq!(state.flow_state, RecoveryFlowState::Pending);
    assert_eq!(state.completion_count, 0);
}

#[test]
fn receipt_replay_is_idempotent_and_binds_secret_and_command() {
    let store = store();
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    let original = command("123456", 5);
    service.complete_recovery(original.clone()).unwrap();
    assert_eq!(
        store.0.lock().unwrap().flow_state,
        RecoveryFlowState::Consumed
    );
    assert!(verify_password(
        store
            .0
            .lock()
            .unwrap()
            .new_hash
            .as_ref()
            .unwrap()
            .expose_secret(),
        "New-recovery-123"
    )
    .unwrap());
    service.complete_recovery(original.clone()).unwrap();
    assert_eq!(store.0.lock().unwrap().completion_count, 1);

    let mut changed = original.clone();
    changed.new_password = SecretString::new("Another-password-789");
    assert!(matches!(
        service.complete_recovery(changed),
        Err(RecoveryCompleteError::Access(AccessError::Conflict(
            "recovery.operation_conflict"
        )))
    ));
    let mut wrong_secret = original;
    wrong_secret.receipt_secret = SecretString::new(Base64UrlUnpadded::encode_string(&[8; 32]));
    assert!(matches!(
        service.complete_recovery(wrong_secret),
        Err(RecoveryCompleteError::Access(AccessError::Conflict(
            "recovery.operation_conflict"
        )))
    ));
}

#[test]
fn result_query_requires_live_receipt_secret_and_does_not_require_flow() {
    let store = store();
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    let command = command("123456", 6);
    service.complete_recovery(command.clone()).unwrap();
    let query = SecurityReceiptQuery {
        operation_id: command.operation_id,
        receipt_secret: command.receipt_secret.clone(),
    };
    assert!(service.recovery_completion_result(query).unwrap());
    assert_eq!(store.0.lock().unwrap().context_calls, 2);
    let wrong = SecretString::new(Base64UrlUnpadded::encode_string(&[7; 32]));
    assert!(!service
        .recovery_completion_result(SecurityReceiptQuery {
            operation_id: command.operation_id,
            receipt_secret: wrong,
        })
        .unwrap());
}

#[test]
fn expired_completion_receipt_conflicts_on_replay_and_returns_false() {
    let store = store();
    let time = Arc::new(Mutex::new(NOW));
    let service = service(
        store.clone(),
        TestClock(time.clone()),
        PasswordWorkBudget::default(),
    );
    let command = command("123456", 61);
    service.complete_recovery(command.clone()).unwrap();
    *time.lock().unwrap() = NOW + 86_400;

    assert!(matches!(
        service.complete_recovery(command.clone()),
        Err(RecoveryCompleteError::Access(AccessError::Conflict(
            "recovery.operation_conflict"
        )))
    ));
    assert!(!service
        .recovery_completion_result(SecurityReceiptQuery {
            operation_id: command.operation_id,
            receipt_secret: command.receipt_secret,
        })
        .unwrap());
    assert_eq!(store.0.lock().unwrap().completion_count, 1);
}

#[test]
fn wrong_handle_and_unknown_flow_do_not_increment_attempts() {
    let store = store();
    let service = service(store.clone(), clock(), PasswordWorkBudget::default());
    let mut wrong_handle = command("123456", 62);
    wrong_handle.handle = handle_for(Uuid::from_u128(FLOW_ID), [2; 32]);
    assert_eq!(
        service.complete_recovery(wrong_handle),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    assert_eq!(store.0.lock().unwrap().failed_attempts, 0);
    assert_eq!(store.0.lock().unwrap().budget.failure_count, 0);

    let mut unknown_flow = command("123456", 63);
    unknown_flow.handle = handle_for(Uuid::from_u128(FLOW_ID + 1), [1; 32]);
    assert_eq!(
        service.complete_recovery(unknown_flow),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    let state = store.0.lock().unwrap();
    assert_eq!(state.failed_attempts, 0);
    assert_eq!(state.budget.failure_count, 0);
    assert_eq!(state.event_count, 0);
    assert_eq!(state.completion_count, 0);
}

#[test]
fn saturated_password_budget_leaves_flow_untouched_and_recovers_after_release() {
    let store = store();
    let password_work = PasswordWorkBudget::default();
    let held: Vec<_> = (0..4).map(|_| password_work.try_login().unwrap()).collect();
    let service = service(store.clone(), clock(), password_work.clone());
    assert!(matches!(
        service.complete_recovery(command("123456", 7)),
        Err(RecoveryCompleteError::Access(AccessError::Store(
            StoreError::Backend(message)
        ))) if message == "password.work_unavailable"
    ));
    {
        let state = store.0.lock().unwrap();
        assert_eq!(state.flow_state, RecoveryFlowState::Pending);
        assert_eq!(state.failed_attempts, 0);
        assert_eq!(state.completion_count, 0);
        assert!(state.new_hash.is_none());
    }
    drop(held);
    service.complete_recovery(command("123456", 7)).unwrap();
    assert_eq!(
        store.0.lock().unwrap().flow_state,
        RecoveryFlowState::Consumed
    );
}

#[test]
fn guessed_code_on_dummy_flow_never_enters_password_work() {
    let store = store();
    {
        let mut state = store.0.lock().unwrap();
        state.flow = dummy_flow();
        state.account = None;
    }
    let password_work = PasswordWorkBudget::default();
    let service = service(store.clone(), clock(), password_work.clone());
    let held: Vec<_> = (0..4).map(|_| password_work.try_login().unwrap()).collect();
    assert_eq!(
        service.complete_recovery(command("123456", 8)),
        Err(RecoveryCompleteError::InvalidRecovery)
    );
    let state = store.0.lock().unwrap();
    assert_eq!(state.flow_state, RecoveryFlowState::Pending);
    assert_eq!(state.completion_count, 0);
    assert_eq!(state.failed_attempts, 0);
    drop(state);
    drop(held);
}

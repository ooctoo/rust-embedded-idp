use super::*;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

#[derive(Clone)]
struct FixedClock(Arc<Mutex<SystemTime>>);
impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

#[derive(Clone, Default)]
struct SequentialIds(Arc<AtomicUsize>);
impl IdGenerator for SequentialIds {
    fn next_id(&self, _: &str) -> String {
        Uuid::from_u128(self.0.fetch_add(1, Ordering::SeqCst) as u128 + 1).to_string()
    }
}

#[derive(Default)]
struct CryptoControl {
    calls: [usize; 4],
    fail_random_code: bool,
}
#[derive(Clone, Default)]
struct CryptoStats(Arc<Mutex<CryptoControl>>);
#[derive(Clone, Default)]
struct FakeCrypto(CryptoStats);

impl AccountSecurityCrypto for FakeCrypto {
    fn authority(&self) -> &str {
        "test-authority"
    }
    fn random_token(&self) -> Result<SecretString, SecurityCryptoError> {
        self.0 .0.lock().unwrap().calls[0] += 1;
        Ok(SecretString::new(Base64UrlUnpadded::encode_string(
            &[7; 32],
        )))
    }
    fn random_code(&self) -> Result<SecretString, SecurityCryptoError> {
        let mut state = self.0 .0.lock().unwrap();
        state.calls[1] += 1;
        if state.fail_random_code {
            return Err(SecurityCryptoError::Unavailable);
        }
        Ok(SecretString::new("012345"))
    }
    fn subject_digest(&self, _: &str) -> Result<[u8; 32], SecurityCryptoError> {
        Ok([3; 32])
    }
    fn digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> Result<SecurityDigest, SecurityCryptoError> {
        self.0 .0.lock().unwrap().calls[2] += 1;
        Ok(SecurityDigest {
            key_id: "test-key".into(),
            bytes: fake_digest(purpose, context, payload),
        })
    }
    fn verify_digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
        stored: &SecurityDigest,
    ) -> Result<bool, SecurityCryptoError> {
        Ok(stored.key_id == "test-key" && stored.bytes == fake_digest(purpose, context, payload))
    }
    fn seal(
        &self,
        _: SecurityEnvelopePurpose,
        _: &SecurityCryptoContext,
        plaintext: &SecretString,
    ) -> Result<SecurityEnvelope, SecurityCryptoError> {
        self.0 .0.lock().unwrap().calls[3] += 1;
        let mut ciphertext = vec![0; 12];
        ciphertext.extend_from_slice(plaintext.expose_secret().as_bytes());
        ciphertext.extend_from_slice(&[0; 16]);
        Ok(SecurityEnvelope {
            key_id: "test-key".into(),
            ciphertext,
        })
    }
    fn open(
        &self,
        _: SecurityEnvelopePurpose,
        _: &SecurityCryptoContext,
        envelope: &SecurityEnvelope,
    ) -> Result<SecretString, SecurityCryptoError> {
        if envelope.key_id != "test-key" || envelope.ciphertext.len() < 28 {
            return Err(SecurityCryptoError::InvalidCiphertext);
        }
        let payload = &envelope.ciphertext[12..envelope.ciphertext.len() - 16];
        let text =
            std::str::from_utf8(payload).map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        Ok(SecretString::new(text))
    }
}

fn fake_digest(
    purpose: SecurityDigestPurpose,
    context: &SecurityCryptoContext,
    payload: &[u8],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    let related = context.related_id.unwrap_or(Uuid::nil());
    for (i, byte) in payload
        .iter()
        .chain(context.reference_id.as_bytes())
        .chain(related.as_bytes())
        .chain([purpose as u8].iter())
        .enumerate()
    {
        let slot = i % out.len();
        out[slot] = out[slot]
            .wrapping_mul(31)
            .wrapping_add(*byte)
            .wrapping_add(1);
    }
    out
}

#[derive(Clone, Default)]
struct State {
    account: Option<RecoveryAccountSnapshot>,
    budget: Option<RecoveryBudget>,
    receipts: HashMap<Uuid, RecoveryStartReceipt>,
    bundles: Vec<RecoveryStartBundle>,
    flow_count: u64,
    outbox_count: u64,
    budget_count: u64,
}
#[derive(Clone, Default)]
struct MockStore(Arc<Mutex<State>>);
struct MockTx<'a>(&'a mut State);

impl RecoveryStartTransaction for MockTx<'_> {
    fn start_receipt(&mut self, op: Uuid) -> Result<Option<RecoveryStartReceipt>, StoreError> {
        Ok(self.0.receipts.get(&op).cloned())
    }
    fn lock_start_context(
        &mut self,
        _: &str,
        _: &[u8; 32],
    ) -> Result<RecoveryStartContext, StoreError> {
        Ok(RecoveryStartContext {
            account: self.0.account.clone(),
            budget: self.0.budget.clone(),
            flow_count: self.0.flow_count,
            outbox_count: self.0.outbox_count,
            budget_count: self.0.budget_count,
        })
    }
    fn close_subject_flows(&mut self, _: &[u8; 32], _: SystemTime) -> Result<(), StoreError> {
        Ok(())
    }
    fn record_start(&mut self, bundle: &RecoveryStartBundle) -> Result<(), StoreError> {
        self.0.budget = Some(bundle.budget.clone());
        self.0
            .receipts
            .insert(bundle.receipt.operation_id, bundle.receipt.clone());
        self.0.bundles.push(bundle.clone());
        Ok(())
    }
}
impl RecoveryStartStore for MockStore {
    type Transaction<'a> = MockTx<'a>;
    fn recovery_start_transaction<R>(
        &self,
        _: TenancyMode,
        _: &str,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        let mut guard = self.0.lock().unwrap();
        let mut staged = guard.clone();
        let result = run(&mut MockTx(&mut staged))?;
        *guard = staged;
        Ok(result)
    }
}

fn account(active: bool, admin: bool) -> RecoveryAccountSnapshot {
    RecoveryAccountSnapshot {
        account_id: Uuid::from_u128(99),
        email: SecretString::new("person@example.test"),
        credential_version: 4,
        active,
        has_active_membership: true,
        has_effective_security_admin: admin,
    }
}
fn service(
    store: MockStore,
    time: Arc<Mutex<SystemTime>>,
    stats: CryptoStats,
) -> CoreRecoveryStartService<MockStore, FixedClock, FakeCrypto, SequentialIds> {
    CoreRecoveryStartService::new(
        TenancyMode::Disabled,
        store,
        FixedClock(time),
        FakeCrypto(stats),
        SequentialIds::default(),
    )
}
fn command(operation_id: Uuid) -> RecoveryStartCommand {
    RecoveryStartCommand {
        email: SecretString::new(" person@example.test "),
        operation_id,
        receipt_secret: SecretString::new(Base64UrlUnpadded::encode_string(&[9; 32])),
    }
}

#[test]
fn eligible_and_ineligible_requests_share_crypto_and_public_result_shape() {
    let a_stats = CryptoStats::default();
    let a_store = MockStore::default();
    a_store.0.lock().unwrap().account = Some(account(true, false));
    let a = service(
        a_store.clone(),
        Arc::new(Mutex::new(now())),
        a_stats.clone(),
    )
    .start_recovery(command(Uuid::from_u128(1)))
    .unwrap();
    let b_stats = CryptoStats::default();
    let b_store = MockStore::default();
    b_store.0.lock().unwrap().account = Some(account(false, false));
    let b = service(
        b_store.clone(),
        Arc::new(Mutex::new(now())),
        b_stats.clone(),
    )
    .start_recovery(command(Uuid::from_u128(2)))
    .unwrap();
    assert_eq!(a.handle.expose_secret().len(), 64);
    assert_eq!(b.handle.expose_secret().len(), 64);
    assert_eq!(a.expires_at, b.expires_at);
    assert_eq!(
        a_stats.0.lock().unwrap().calls,
        b_stats.0.lock().unwrap().calls
    );
    assert_eq!(a_stats.0.lock().unwrap().calls, [1, 1, 3, 2]);
    assert!(a_store.0.lock().unwrap().bundles[0]
        .outbox
        .envelope
        .is_some());
    assert!(b_store.0.lock().unwrap().bundles[0]
        .outbox
        .envelope
        .is_none());
    assert!(b_store.0.lock().unwrap().bundles[0]
        .flow
        .account_id
        .is_none());
}

#[test]
fn receipt_replay_returns_same_result_without_new_budget_or_crypto() {
    let stats = CryptoStats::default();
    let store = MockStore::default();
    let time = Arc::new(Mutex::new(now() + Duration::from_millis(350)));
    let service = service(store.clone(), time.clone(), stats.clone());
    let command = command(Uuid::from_u128(3));
    let first = service.start_recovery(command.clone()).unwrap();
    let after_first = stats.0.lock().unwrap().calls;
    *time.lock().unwrap() = now() + Duration::from_millis(850);
    let replay = service.start_recovery(command).unwrap();
    assert_eq!(first.handle.expose_secret(), replay.handle.expose_secret());
    assert_eq!(first.expires_at, replay.expires_at);
    assert_eq!(stats.0.lock().unwrap().calls, after_first);
    assert_eq!(store.0.lock().unwrap().bundles.len(), 1);
    assert_eq!(store.0.lock().unwrap().bundles[0].budget.start_count, 1);
}

#[test]
fn expired_receipt_conflicts_but_deleted_receipt_can_start_new_generation() {
    let store = MockStore::default();
    let time = Arc::new(Mutex::new(now()));
    let service = service(store.clone(), time.clone(), CryptoStats::default());
    let command = command(Uuid::from_u128(4));
    service.start_recovery(command.clone()).unwrap();
    *time.lock().unwrap() = now() + FLOW_TTL;
    assert!(matches!(
        service.start_recovery(command.clone()),
        Err(AccessError::Conflict("recovery.operation_conflict"))
    ));
    store
        .0
        .lock()
        .unwrap()
        .receipts
        .remove(&command.operation_id);
    let second = service.start_recovery(command).unwrap();
    assert_eq!(second.expires_at, now() + FLOW_TTL + FLOW_TTL);
    assert_eq!(store.0.lock().unwrap().bundles.len(), 2);
    assert_eq!(store.0.lock().unwrap().bundles[1].budget.start_count, 2);
}

#[test]
fn receipt_operation_reuse_with_different_secret_conflicts() {
    let store = MockStore::default();
    let service = service(
        store.clone(),
        Arc::new(Mutex::new(now())),
        CryptoStats::default(),
    );
    let command = command(Uuid::from_u128(40));
    service.start_recovery(command.clone()).unwrap();
    let mut changed = command;
    changed.receipt_secret = SecretString::new(Base64UrlUnpadded::encode_string(&[8; 32]));
    assert!(matches!(
        service.start_recovery(changed),
        Err(AccessError::Conflict("recovery.operation_conflict"))
    ));
    assert_eq!(store.0.lock().unwrap().bundles.len(), 1);
}

#[test]
fn invalid_input_capacity_and_rate_limit_do_not_record() {
    let stats = CryptoStats::default();
    let store = MockStore::default();
    let service = service(store.clone(), Arc::new(Mutex::new(now())), stats.clone());
    let mut bad = command(Uuid::from_u128(5));
    bad.email = SecretString::new("x\n@example.test");
    assert!(matches!(
        service.start_recovery(bad),
        Err(AccessError::InvalidInput("email"))
    ));
    store.0.lock().unwrap().flow_count = MAX_FLOWS;
    assert!(matches!(
        service.start_recovery(command(Uuid::from_u128(6))),
        Err(AccessError::Conflict("recovery.capacity"))
    ));
    assert_eq!(stats.0.lock().unwrap().calls, [0; 4]);
    store.0.lock().unwrap().flow_count = 0;
    store.0.lock().unwrap().budget = Some(RecoveryBudget {
        subject_digest: [3; 32],
        window_start: now(),
        expires_at: now() + BUDGET_WINDOW,
        start_count: MAX_STARTS,
        failure_count: 0,
    });
    assert!(matches!(
        service.start_recovery(command(Uuid::from_u128(7))),
        Err(AccessError::Conflict("recovery.rate_limited"))
    ));
    assert!(store.0.lock().unwrap().bundles.is_empty());
}

#[test]
fn malformed_projection_email_and_debug_are_rejected_or_redacted() {
    for email in [
        "a@@example.test",
        "a\u{00a0}@example.test",
        "a@.example.test",
    ] {
        assert!(matches!(
            normalize_email(&SecretString::new(email)),
            Err(AccessError::InvalidInput("email"))
        ));
    }
    assert!(matches!(
        normalize_email(&SecretString::new(format!(
            "{}@example.test",
            "x".repeat(245)
        ))),
        Err(AccessError::InvalidInput("email"))
    ));
    let bad = RecoveryStartContext {
        account: Some(RecoveryAccountSnapshot {
            account_id: Uuid::nil(),
            ..account(true, false)
        }),
        budget: None,
        flow_count: 0,
        outbox_count: 0,
        budget_count: 0,
    };
    assert!(matches!(
        validate_context(&bad, "person@example.test", &[3; 32], now()),
        Err(AccessError::InvalidStoreResponse)
    ));
    let debug = format!("{:?}", command(Uuid::from_u128(8)));
    assert!(!debug.contains("person@example.test"));
    assert!(!debug.contains(&Base64UrlUnpadded::encode_string(&[9; 32])));
    let digest_debug = format!(
        "{:?}",
        RecoveryBudget {
            subject_digest: [3; 32],
            window_start: now(),
            expires_at: now() + BUDGET_WINDOW,
            start_count: 1,
            failure_count: 0
        }
    );
    assert!(!digest_debug.contains("3, 3, 3"));
}

#[test]
fn ten_failures_limit_the_next_start() {
    let store = MockStore::default();
    store.0.lock().unwrap().budget = Some(RecoveryBudget {
        subject_digest: [3; 32],
        window_start: now(),
        expires_at: now() + BUDGET_WINDOW,
        start_count: 1,
        failure_count: MAX_FAILURES,
    });
    let service = service(
        store.clone(),
        Arc::new(Mutex::new(now())),
        CryptoStats::default(),
    );

    assert!(matches!(
        service.start_recovery(command(Uuid::from_u128(10))),
        Err(AccessError::Conflict("recovery.rate_limited"))
    ));
    let state = store.0.lock().unwrap();
    assert!(state.bundles.is_empty());
    assert_eq!(state.budget.as_ref().unwrap().start_count, 1);
    assert_eq!(state.budget.as_ref().unwrap().failure_count, MAX_FAILURES);
}

#[test]
fn full_budget_table_rejects_new_key_but_allows_existing_key_update() {
    let store = MockStore::default();
    store.0.lock().unwrap().budget_count = MAX_BUDGETS;
    let service = service(
        store.clone(),
        Arc::new(Mutex::new(now())),
        CryptoStats::default(),
    );

    assert!(matches!(
        service.start_recovery(command(Uuid::from_u128(11))),
        Err(AccessError::Conflict("recovery.capacity"))
    ));
    assert!(store.0.lock().unwrap().bundles.is_empty());

    store.0.lock().unwrap().budget = Some(RecoveryBudget {
        subject_digest: [3; 32],
        window_start: now(),
        expires_at: now() + BUDGET_WINDOW,
        start_count: 1,
        failure_count: 4,
    });
    service
        .start_recovery(command(Uuid::from_u128(12)))
        .unwrap();
    let state = store.0.lock().unwrap();
    assert_eq!(state.bundles.len(), 1);
    assert_eq!(state.budget.as_ref().unwrap().start_count, 2);
    assert_eq!(state.budget.as_ref().unwrap().failure_count, 4);
}

#[test]
fn budget_window_expiring_exactly_now_resets_counts() {
    let store = MockStore::default();
    store.0.lock().unwrap().budget = Some(RecoveryBudget {
        subject_digest: [3; 32],
        window_start: now() - BUDGET_WINDOW,
        expires_at: now(),
        start_count: MAX_STARTS,
        failure_count: MAX_FAILURES,
    });
    let service = service(
        store.clone(),
        Arc::new(Mutex::new(now())),
        CryptoStats::default(),
    );

    service
        .start_recovery(command(Uuid::from_u128(13)))
        .unwrap();
    let state = store.0.lock().unwrap();
    let budget = state.budget.as_ref().unwrap();
    assert_eq!(budget.window_start, now());
    assert_eq!(budget.expires_at, now() + BUDGET_WINDOW);
    assert_eq!(budget.start_count, 1);
    assert_eq!(budget.failure_count, 0);
}

#[test]
fn crypto_failure_returns_backend_without_committing_budget_or_bundle() {
    let store = MockStore::default();
    let stats = CryptoStats::default();
    stats.0.lock().unwrap().fail_random_code = true;
    let service = service(store.clone(), Arc::new(Mutex::new(now())), stats);

    assert!(matches!(
        service.start_recovery(command(Uuid::from_u128(14))),
        Err(AccessError::Store(StoreError::Backend(message)))
            if message == CRYPTO_BACKEND
    ));
    let state = store.0.lock().unwrap();
    assert!(state.bundles.is_empty());
    assert!(state.receipts.is_empty());
    assert!(state.budget.is_none());
}

#[test]
fn wrong_email_and_damaged_receipt_envelope_fail_closed() {
    let store = MockStore::default();
    let service = service(
        store.clone(),
        Arc::new(Mutex::new(now())),
        CryptoStats::default(),
    );
    let original = command(Uuid::from_u128(15));
    service.start_recovery(original.clone()).unwrap();

    let mut wrong_email = original.clone();
    wrong_email.email = SecretString::new("other@example.test");
    assert!(matches!(
        service.start_recovery(wrong_email),
        Err(AccessError::Conflict("recovery.operation_conflict"))
    ));

    store
        .0
        .lock()
        .unwrap()
        .receipts
        .get_mut(&original.operation_id)
        .unwrap()
        .handle_envelope
        .ciphertext
        .clear();
    assert!(matches!(
        service.start_recovery(original),
        Err(AccessError::Store(StoreError::Backend(message)))
            if message == CRYPTO_BACKEND
    ));
    assert_eq!(store.0.lock().unwrap().bundles.len(), 1);
}

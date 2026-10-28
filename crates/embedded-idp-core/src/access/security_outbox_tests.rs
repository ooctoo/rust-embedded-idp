use super::*;
use crate::SecurityDigest;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

const NOW: u64 = 1_800_000_000;
const OUTBOX: u128 = 0x301;
const FLOW: u128 = 0x302;
const ACCOUNT: u128 = 0x303;

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
        Uuid::from_u128(0x700 + self.0.fetch_add(1, Ordering::SeqCst) as u128).to_string()
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
        let mut digest = Sha256::new();
        digest.update(b"test-key");
        digest.update([purpose as u8]);
        digest.update(context.reference_id.as_bytes());
        if let Some(related) = context.related_id {
            digest.update(related.as_bytes());
        }
        digest.update(payload);
        digest.finalize().into()
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

    fn envelope(context: &SecurityCryptoContext, text: &str) -> SecurityEnvelope {
        let mut ciphertext = context.reference_id.as_bytes().to_vec();
        ciphertext.extend_from_slice(context.related_id.unwrap_or(Uuid::nil()).as_bytes());
        ciphertext.push(SecurityEnvelopePurpose::RecoveryEmail as u8);
        ciphertext.extend_from_slice(text.as_bytes());
        SecurityEnvelope {
            key_id: "test-key".into(),
            ciphertext,
        }
    }
}

impl AccountSecurityCrypto for TestCrypto {
    fn authority(&self) -> &str {
        "test-host"
    }
    fn random_token(&self) -> Result<SecretString, SecurityCryptoError> {
        Ok(SecretString::new("unused"))
    }
    fn random_code(&self) -> Result<SecretString, SecurityCryptoError> {
        Ok(SecretString::new("unused"))
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
        Ok(Self::stored(purpose, context, payload))
    }
    fn verify_digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
        stored: &SecurityDigest,
    ) -> Result<bool, SecurityCryptoError> {
        if stored.key_id != "test-key" {
            return Err(SecurityCryptoError::UnknownKey);
        }
        Ok(stored.bytes == Self::digest_value(purpose, context, payload))
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
        purpose: SecurityEnvelopePurpose,
        context: &SecurityCryptoContext,
        envelope: &SecurityEnvelope,
    ) -> Result<SecretString, SecurityCryptoError> {
        if envelope.key_id != "test-key" {
            return Err(SecurityCryptoError::UnknownKey);
        }
        let header_len = 33;
        if envelope.ciphertext.len() < header_len
            || envelope.ciphertext[..16] != context.reference_id.as_bytes()[..]
            || envelope.ciphertext[16..32]
                != context.related_id.unwrap_or(Uuid::nil()).as_bytes()[..]
            || envelope.ciphertext[32] != purpose as u8
        {
            return Err(SecurityCryptoError::InvalidCiphertext);
        }
        let text = std::str::from_utf8(&envelope.ciphertext[header_len..])
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        Ok(SecretString::new(text))
    }
}

#[derive(Clone)]
struct Store(Arc<Mutex<State>>);
#[derive(Clone)]
struct State {
    context: Option<SecurityMailContext>,
    last_outcome: Option<SecurityMailOutcome>,
    events: Vec<Uuid>,
    cleanup_count: u32,
    cleanup_limit: u32,
    cleanup_ids: Vec<Uuid>,
    force_candidate: bool,
}
struct Tx<'a>(&'a mut State);

impl SecurityOutboxTransaction for Tx<'_> {
    fn candidate(&mut self, now: SystemTime) -> Result<Option<SecurityMailContext>, StoreError> {
        Ok(self
            .0
            .context
            .as_ref()
            .filter(|c| {
                c.state == SecurityMailState::Pending
                    && (c.next_attempt_at <= now || self.0.force_candidate)
            })
            .map(clone_context))
    }
    fn current(&mut self, outbox_id: Uuid) -> Result<Option<SecurityMailContext>, StoreError> {
        Ok(self
            .0
            .context
            .as_ref()
            .filter(|c| c.outbox_id == outbox_id)
            .map(clone_context))
    }
    fn transition(
        &mut self,
        outbox_id: Uuid,
        expected_lease: Option<Uuid>,
        change: SecurityMailTransition,
        event_id: Option<Uuid>,
        _: SystemTime,
    ) -> Result<bool, StoreError> {
        let Some(context) = self.0.context.as_mut().filter(|c| c.outbox_id == outbox_id) else {
            return Ok(false);
        };
        match change {
            SecurityMailTransition::Sending {
                lease_token,
                lease_until,
            } => {
                if expected_lease.is_some() || context.state != SecurityMailState::Pending {
                    return Ok(false);
                }
                context.state = SecurityMailState::Sending;
                context.lease_token = Some(lease_token);
                context.lease_until = Some(lease_until);
                context.attempts += 1;
            }
            SecurityMailTransition::Retry { next_attempt_at } => {
                if context.state != SecurityMailState::Sending
                    || context.lease_token != expected_lease
                {
                    return Ok(false);
                }
                context.state = SecurityMailState::Pending;
                context.lease_token = None;
                context.lease_until = None;
                context.next_attempt_at = next_attempt_at;
                self.0.last_outcome = Some(SecurityMailOutcome::NotStarted);
            }
            SecurityMailTransition::Terminal { state, outcome } => {
                if context.state
                    != if expected_lease.is_some() {
                        SecurityMailState::Sending
                    } else {
                        SecurityMailState::Pending
                    }
                    || context.lease_token != expected_lease
                {
                    return Ok(false);
                }
                context.state = match state {
                    SecurityMailTerminal::Accepted => SecurityMailState::Accepted,
                    SecurityMailTerminal::Rejected => SecurityMailState::Rejected,
                    SecurityMailTerminal::Unknown => SecurityMailState::Unknown,
                    SecurityMailTerminal::Cancelled => SecurityMailState::Cancelled,
                    SecurityMailTerminal::Expired => SecurityMailState::Expired,
                };
                context.envelope = None;
                context.lease_token = None;
                context.lease_until = None;
                self.0.last_outcome = outcome;
            }
        }
        if let Some(event_id) = event_id {
            self.0.events.push(event_id);
        }
        Ok(true)
    }
    fn cleanup(
        &mut self,
        _: SystemTime,
        limit: u32,
        event_ids: &[Uuid],
    ) -> Result<u32, StoreError> {
        self.0.cleanup_limit = limit;
        self.0.cleanup_count = limit.min(3);
        self.0.cleanup_ids = event_ids.to_vec();
        Ok(self.0.cleanup_count)
    }
}

impl SecurityOutboxStore for Store {
    type Transaction<'a> = Tx<'a>;
    fn security_outbox_transaction<R>(
        &self,
        _: TenancyMode,
        _: &str,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        let mut guard = self.0.lock().unwrap();
        let mut staged = guard.clone();
        let result = run(&mut Tx(&mut staged))?;
        *guard = staged;
        Ok(result)
    }
}

fn clone_context(context: &SecurityMailContext) -> SecurityMailContext {
    SecurityMailContext {
        outbox_id: context.outbox_id,
        flow_id: context.flow_id,
        state: context.state,
        envelope: context.envelope.clone(),
        created_at: context.created_at,
        expires_at: context.expires_at,
        next_attempt_at: context.next_attempt_at,
        attempts: context.attempts,
        lease_token: context.lease_token,
        lease_until: context.lease_until,
        flow: context.flow.clone(),
        flow_state: context.flow_state,
        failed_attempts: context.failed_attempts,
        account: context.account.clone(),
    }
}

fn account() -> RecoveryAccountSnapshot {
    RecoveryAccountSnapshot {
        account_id: Uuid::from_u128(ACCOUNT),
        email: SecretString::new("person@example.test"),
        credential_version: 2,
        active: true,
        has_active_membership: true,
        has_effective_security_admin: false,
    }
}

fn fixture_context() -> SecurityMailContext {
    let flow_id = Uuid::from_u128(FLOW);
    let outbox_id = Uuid::from_u128(OUTBOX);
    let now = UNIX_EPOCH + Duration::from_secs(NOW);
    let created = now - Duration::from_secs(30);
    let expires = now + Duration::from_secs(870);
    let code_digest = TestCrypto::stored(
        SecurityDigestPurpose::RecoveryCode,
        &SecurityCryptoContext {
            reference_id: flow_id,
            related_id: None,
        },
        b"123456",
    );
    let flow = RecoveryStartFlow {
        id: flow_id,
        subject_digest: [6; 32],
        account_id: Some(Uuid::from_u128(ACCOUNT)),
        snapshot_credential_version: Some(2),
        handle_digest: TestCrypto::stored(
            SecurityDigestPurpose::RecoveryHandle,
            &SecurityCryptoContext {
                reference_id: flow_id,
                related_id: None,
            },
            &[1; 32],
        ),
        code_digest,
        created_at: created,
        expires_at: expires,
        retained_until: created + FLOW_RETENTION,
    };
    let payload = "recovery-email-v1\nperson@example.test\n123456";
    SecurityMailContext {
        outbox_id,
        flow_id,
        state: SecurityMailState::Pending,
        envelope: Some(TestCrypto::envelope(
            &SecurityCryptoContext {
                reference_id: outbox_id,
                related_id: Some(flow_id),
            },
            payload,
        )),
        created_at: created,
        expires_at: expires,
        next_attempt_at: now - Duration::from_secs(1),
        attempts: 0,
        lease_token: None,
        lease_until: None,
        flow,
        flow_state: RecoveryFlowState::Pending,
        failed_attempts: 0,
        account: Some(account()),
    }
}

fn store(context: SecurityMailContext) -> Store {
    Store(Arc::new(Mutex::new(State {
        context: Some(context),
        last_outcome: None,
        events: Vec::new(),
        cleanup_count: 0,
        cleanup_limit: 0,
        cleanup_ids: Vec::new(),
        force_candidate: false,
    })))
}

fn service(
    store: Store,
    clock: TestClock,
) -> CoreSecurityOutboxService<Store, TestClock, TestCrypto, TestIds> {
    CoreSecurityOutboxService::new(
        TenancyMode::Enabled,
        store,
        clock,
        TestCrypto,
        TestIds::default(),
    )
}

fn clock() -> TestClock {
    TestClock(Arc::new(Mutex::new(NOW)))
}

#[test]
fn claim_decrypts_and_validates_aad_email_code_and_redacts_secrets() {
    let store = store(fixture_context());
    let claim = service(store.clone(), clock()).claim().unwrap().unwrap();
    assert_eq!(claim.recipient.expose_secret(), "person@example.test");
    assert_eq!(claim.code.expose_secret(), "123456");
    assert_eq!(
        claim.lease_until,
        UNIX_EPOCH + Duration::from_secs(NOW + 30)
    );
    let debug = format!("{claim:?}");
    assert!(!debug.contains("person@example.test"));
    assert!(!debug.contains("123456"));
    assert!(!debug.contains(&claim.lease_token.to_string()));
    let state = store.0.lock().unwrap();
    let context = state.context.as_ref().unwrap();
    assert_eq!(context.state, SecurityMailState::Sending);
    assert_eq!(context.attempts, 1);
    assert!(state.events.is_empty());
}

#[test]
fn code_digest_mismatch_rejects_without_returning_claim() {
    let mut context = fixture_context();
    context.flow.code_digest = TestCrypto::stored(
        SecurityDigestPurpose::RecoveryCode,
        &SecurityCryptoContext {
            reference_id: context.flow_id,
            related_id: None,
        },
        b"654321",
    );
    let store = store(context);
    assert!(service(store.clone(), clock()).claim().unwrap().is_none());
    let state = store.0.lock().unwrap();
    let context = state.context.as_ref().unwrap();
    assert_eq!(context.state, SecurityMailState::Rejected);
    assert!(context.envelope.is_none());
    assert_eq!(state.last_outcome, Some(SecurityMailOutcome::Rejected));
    assert_eq!(state.events.len(), 1);
}

#[test]
fn unknown_envelope_key_rolls_back_without_consuming_attempt() {
    let mut context = fixture_context();
    context.envelope.as_mut().unwrap().key_id = "unknown-key".into();
    let store = store(context);
    assert!(matches!(
        service(store.clone(), clock()).claim(),
        Err(AccessError::Store(StoreError::Backend(message)))
            if message == CRYPTO_BACKEND
    ));
    let state = store.0.lock().unwrap();
    assert_eq!(
        state.context.as_ref().unwrap().state,
        SecurityMailState::Pending
    );
    assert_eq!(state.context.as_ref().unwrap().attempts, 0);
    assert!(state.events.is_empty());
}

#[test]
fn ineligible_or_expired_candidate_is_terminal_without_send_or_event() {
    let mut ineligible = fixture_context();
    ineligible.account.as_mut().unwrap().has_active_membership = false;
    let ineligible_store = store(ineligible);
    assert!(service(ineligible_store.clone(), clock())
        .claim()
        .unwrap()
        .is_none());
    let state = ineligible_store.0.lock().unwrap();
    assert_eq!(
        state.context.as_ref().unwrap().state,
        SecurityMailState::Cancelled
    );
    assert!(state.context.as_ref().unwrap().envelope.is_none());
    assert!(state.events.is_empty());
    drop(state);

    let mut expired = fixture_context();
    expired.expires_at = UNIX_EPOCH + Duration::from_secs(NOW);
    expired.flow.expires_at = expired.expires_at;
    let expired_store = store(expired);
    assert!(service(expired_store.clone(), clock())
        .claim()
        .unwrap()
        .is_none());
    assert_eq!(
        expired_store
            .0
            .lock()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .state,
        SecurityMailState::Expired
    );
}

#[test]
fn not_started_retries_at_most_three_claims_then_cancels() {
    let store = store(fixture_context());
    let time = Arc::new(Mutex::new(NOW));
    let service = service(store.clone(), TestClock(time.clone()));
    for attempt in 0..3 {
        let claim = service.claim().unwrap().unwrap();
        assert_eq!(
            store.0.lock().unwrap().context.as_ref().unwrap().attempts,
            attempt + 1
        );
        let accepted = service
            .finish(SecurityMailCompletion {
                outbox_id: claim.outbox_id,
                lease_token: claim.lease_token,
                outcome: SecurityMailOutcome::NotStarted,
            })
            .unwrap();
        assert!(accepted);
        if attempt < 2 {
            assert_eq!(
                store.0.lock().unwrap().context.as_ref().unwrap().state,
                SecurityMailState::Pending
            );
            *time.lock().unwrap() += 1;
        }
    }
    let state = store.0.lock().unwrap();
    assert_eq!(
        state.context.as_ref().unwrap().state,
        SecurityMailState::Cancelled
    );
    assert_eq!(state.last_outcome, Some(SecurityMailOutcome::NotStarted));
    assert!(state.context.as_ref().unwrap().envelope.is_none());
    assert_eq!(state.events.len(), 3);
    drop(state);
    assert!(service.claim().unwrap().is_none());
}

#[test]
fn expired_lease_becomes_unknown_and_late_or_duplicate_finish_cannot_override() {
    let store = store(fixture_context());
    let time = Arc::new(Mutex::new(NOW));
    let service = service(store.clone(), TestClock(time.clone()));
    let claim = service.claim().unwrap().unwrap();
    *time.lock().unwrap() = NOW + 30;
    assert!(service
        .finish(SecurityMailCompletion {
            outbox_id: claim.outbox_id,
            lease_token: claim.lease_token,
            outcome: SecurityMailOutcome::Accepted,
        })
        .unwrap());
    assert_eq!(
        store.0.lock().unwrap().context.as_ref().unwrap().state,
        SecurityMailState::Unknown
    );
    assert!(!service
        .finish(SecurityMailCompletion {
            outbox_id: claim.outbox_id,
            lease_token: claim.lease_token,
            outcome: SecurityMailOutcome::Accepted,
        })
        .unwrap());
    assert_eq!(store.0.lock().unwrap().events.len(), 1);
}

#[test]
fn clock_rollback_before_outbox_creation_rejects_finish_without_transition() {
    let store = store(fixture_context());
    let time = Arc::new(Mutex::new(NOW));
    let service = service(store.clone(), TestClock(time.clone()));
    let claim = service.claim().unwrap().unwrap();
    *time.lock().unwrap() = NOW - 31;
    assert!(matches!(
        service.finish(SecurityMailCompletion {
            outbox_id: claim.outbox_id,
            lease_token: claim.lease_token,
            outcome: SecurityMailOutcome::Accepted,
        }),
        Err(AccessError::InvalidStoreResponse)
    ));
    let state = store.0.lock().unwrap();
    assert_eq!(
        state.context.as_ref().unwrap().state,
        SecurityMailState::Sending
    );
    assert!(state.events.is_empty());
}

#[test]
fn cleanup_passes_exactly_one_hundred_distinct_event_ids_and_caps_work() {
    let store = store(fixture_context());
    let result = service(store.clone(), clock()).cleanup().unwrap();
    assert_eq!(result, SecurityCleanupResult { processed: 3 });
    let state = store.0.lock().unwrap();
    assert_eq!(state.cleanup_limit, 100);
    assert_eq!(state.cleanup_count, 3);
    assert_eq!(state.cleanup_ids.len(), 100);
    let mut ids = state.cleanup_ids.clone();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 100);
    assert!(ids.iter().all(|id| !id.is_nil()));
}

#[test]
fn mismatched_flow_outbox_times_and_future_candidate_are_invalid_projections() {
    let mut mismatched_created = fixture_context();
    mismatched_created.created_at += Duration::from_secs(1);
    let created_store = store(mismatched_created);
    assert!(matches!(
        service(created_store.clone(), clock()).claim(),
        Err(AccessError::InvalidStoreResponse)
    ));
    assert_eq!(
        created_store
            .0
            .lock()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .state,
        SecurityMailState::Pending
    );

    let mut mismatched_expiry = fixture_context();
    mismatched_expiry.expires_at -= Duration::from_secs(1);
    let expiry_store = store(mismatched_expiry);
    assert!(matches!(
        service(expiry_store.clone(), clock()).claim(),
        Err(AccessError::InvalidStoreResponse)
    ));
    assert_eq!(
        expiry_store
            .0
            .lock()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .state,
        SecurityMailState::Pending
    );

    let future_store = store(fixture_context());
    {
        let mut state = future_store.0.lock().unwrap();
        state.force_candidate = true;
        state.context.as_mut().unwrap().next_attempt_at += Duration::from_secs(2);
    }
    assert!(matches!(
        service(future_store.clone(), clock()).claim(),
        Err(AccessError::InvalidStoreResponse)
    ));
    assert_eq!(
        future_store
            .0
            .lock()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .state,
        SecurityMailState::Pending
    );
}

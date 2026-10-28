use super::*;
use crate::SessionStatus;
use crate::{SecurityDigestPurpose, SecurityEnvelope, SecurityEnvelopePurpose};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

const SUBJECT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ACTOR_SESSION: &str = "00000000-0000-4000-8000-000000000001";
const TARGET_SESSION: &str = "00000000-0000-4000-8000-000000000002";
const OPERATION: u128 = 7;
const SECRET: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn at(seconds: u64) -> Self {
        Self(Arc::new(AtomicU64::new(seconds)))
    }

    fn set(&self, seconds: u64) {
        self.0.store(seconds, Ordering::SeqCst);
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
                    .map(|(id, key)| ((*id).to_owned(), [*key; 32]))
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
        hash.update([purpose as u8]);
        hash.update(context.reference_id.as_bytes());
        if let Some(related) = context.related_id {
            hash.update(related.as_bytes());
        }
        hash.update(payload);
        hash.finalize().into()
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
        let key = self
            .keys
            .get(&self.current)
            .ok_or(SecurityCryptoError::UnknownKey)?;
        Ok(SecurityDigest {
            key_id: self.current.clone(),
            bytes: Self::digest_with(key, purpose, context, payload),
        })
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
        let actual = Self::digest_with(key, purpose, context, payload);
        Ok(actual
            .iter()
            .zip(stored.bytes.iter())
            .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
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
        let value = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Uuid::from_u128(value as u128).to_string()
    }
}

#[derive(Clone)]
struct MemoryStore(Arc<Mutex<State>>);

#[derive(Clone)]
struct State {
    session: TenantSession,
    actor_active: bool,
    receipts: Vec<SecurityOperationReceipt>,
    revoked: Vec<(String, String)>,
    event_ids: Vec<Uuid>,
    count_override: Option<u64>,
    record_fails: bool,
    trace: Vec<&'static str>,
    clock_to_set_before_callback: Option<TestClock>,
    set_time_before_callback: Option<u64>,
}

impl State {
    fn seeded() -> Self {
        Self {
            session: session(TARGET_SESSION, "tenant-b", SessionStatus::Active),
            actor_active: true,
            receipts: Vec::new(),
            revoked: Vec::new(),
            event_ids: Vec::new(),
            count_override: None,
            record_fails: false,
            trace: Vec::new(),
            clock_to_set_before_callback: None,
            set_time_before_callback: None,
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(State::seeded())))
    }
}

struct MemoryTransaction<'a>(&'a mut State);

impl SelfSessionMutationTransaction for MemoryTransaction<'_> {
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        self.0.trace.push("actor");
        Ok(self.0.actor_active
            && actor.subject_id == SUBJECT
            && actor.tenant_id == "tenant-a"
            && actor.session_id == ACTOR_SESSION
            && now >= UNIX_EPOCH + Duration::from_secs(1000))
    }

    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        self.0.trace.push("receipt");
        Ok(self
            .0
            .receipts
            .iter()
            .find(|receipt| receipt.purpose == purpose && receipt.operation_id == operation_id)
            .cloned())
    }

    fn receipt_count(&mut self) -> Result<u64, StoreError> {
        self.0.trace.push("count");
        Ok(self
            .0
            .count_override
            .unwrap_or(self.0.receipts.len() as u64))
    }

    fn owned_session(
        &mut self,
        actor: &AccessActor,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<Option<TenantSession>, StoreError> {
        self.0.trace.push("target");
        if self.0.session.account_id == actor.subject_id
            && self.0.session.tenant_id == tenant_id
            && self.0.session.id == session_id
        {
            Ok(Some(self.0.session.clone()))
        } else {
            Ok(None)
        }
    }

    fn revoke_session_credentials(
        &mut self,
        _: &AccessActor,
        tenant_id: &str,
        session_id: &str,
        _: SystemTime,
    ) -> Result<(), StoreError> {
        self.0.trace.push("revoke");
        self.0
            .revoked
            .push((tenant_id.to_owned(), session_id.to_owned()));
        Ok(())
    }

    fn record_completion(
        &mut self,
        receipt: &SecurityOperationReceipt,
        event_id: Uuid,
    ) -> Result<(), StoreError> {
        self.0.trace.push("record");
        if self.0.record_fails {
            return Err(StoreError::Backend("synthetic write failure".into()));
        }
        self.0.receipts.push(receipt.clone());
        self.0.event_ids.push(event_id);
        Ok(())
    }
}

impl SelfSessionMutationStore for MemoryStore {
    type Transaction<'a> = MemoryTransaction<'a>;

    fn self_session_mutation<R>(
        &self,
        _: TenancyMode,
        authority: &str,
        actor: Option<&AccessActor>,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        assert_eq!(authority, "test-host");
        let mut state = self.0.lock().unwrap();
        state.trace.push(if actor.is_some() {
            "write-lock"
        } else {
            "read-lock"
        });
        if let (Some(clock), Some(seconds)) = (
            state.clock_to_set_before_callback.clone(),
            state.set_time_before_callback,
        ) {
            clock.set(seconds);
        }
        let backup = state.clone();
        let result = run(&mut MemoryTransaction(&mut state));
        if result.is_err() {
            let trace = state.trace.clone();
            *state = backup;
            state.trace = trace;
        }
        result
    }
}

fn session(id: &str, tenant: &str, status: SessionStatus) -> TenantSession {
    let created = UNIX_EPOCH + Duration::from_secs(900);
    TenantSession {
        purpose: crate::AccessTokenPurpose::Business,
        tenant_id: tenant.into(),
        id: id.into(),
        account_id: SUBJECT.into(),
        client_id: "client-a".into(),
        device_id: None,
        scope: None,
        authenticated_at: created,
        status,
        created_at: created,
        expires_at: UNIX_EPOCH + Duration::from_secs(2000),
        refresh_token_version: 1,
    }
}

fn actor() -> AccessActor {
    AccessActor {
        tenant_id: "tenant-a".into(),
        subject_id: SUBJECT.into(),
        session_id: ACTOR_SESSION.into(),
    }
}

fn command(target: &str) -> SelfSessionRevokeCommand {
    SelfSessionRevokeCommand {
        target_tenant_id: "tenant-b".into(),
        target_session_id: target.into(),
        operation_id: Uuid::from_u128(OPERATION),
        receipt_secret: SecretString::new(SECRET),
    }
}

fn make_service(
    store: MemoryStore,
    clock: TestClock,
    crypto: TestCrypto,
) -> CoreSelfSessionRevocationService<MemoryStore, TestClock, TestCrypto, TestIds> {
    CoreSelfSessionRevocationService::new(
        TenancyMode::Enabled,
        store,
        clock,
        crypto,
        TestIds(Arc::new(AtomicU64::new(100))),
    )
}

fn crypto() -> TestCrypto {
    TestCrypto::new("current", &[("current", 1), ("previous", 2)])
}

#[test]
fn revoke_writes_one_event_and_receipt_then_replays_without_repeating_mutation() {
    let store = MemoryStore::default();
    let service = make_service(store.clone(), TestClock::at(1100), crypto());
    service
        .revoke_session(actor(), command(TARGET_SESSION))
        .unwrap();
    service
        .revoke_session(actor(), command(TARGET_SESSION))
        .unwrap();
    let state = store.0.lock().unwrap();
    assert_eq!(
        state.revoked,
        vec![("tenant-b".into(), TARGET_SESSION.into())]
    );
    assert_eq!(state.receipts.len(), 1);
    assert_eq!(state.event_ids.len(), 1);
    assert_eq!(
        state.receipts[0].expires_at,
        UNIX_EPOCH + Duration::from_secs(87_500)
    );
    assert_eq!(
        state.trace.iter().filter(|step| **step == "actor").count(),
        2
    );
    assert_eq!(
        state
            .trace
            .iter()
            .filter(|step| **step == "receipt")
            .count(),
        2
    );
}

#[test]
fn replay_uses_stored_key_id_and_rejects_wrong_secret_or_command() {
    let store = MemoryStore::default();
    let old_crypto = TestCrypto::new("previous", &[("previous", 2)]);
    let old_service = make_service(store.clone(), TestClock::at(1100), old_crypto);
    old_service
        .revoke_session(actor(), command(TARGET_SESSION))
        .unwrap();
    let new_crypto = TestCrypto::new("current", &[("current", 1), ("previous", 2)]);
    let new_service = make_service(store.clone(), TestClock::at(1200), new_crypto);
    new_service
        .revoke_session(actor(), command(TARGET_SESSION))
        .unwrap();
    assert!(matches!(
        new_service.revoke_session(actor(), command("00000000-0000-4000-8000-000000000003")),
        Err(AccessError::Conflict("security.operation_conflict"))
    ));
    let mut wrong_secret = command(TARGET_SESSION);
    wrong_secret.receipt_secret = SecretString::new("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI");
    assert!(matches!(
        new_service.revoke_session(actor(), wrong_secret),
        Err(AccessError::Conflict("security.operation_conflict"))
    ));
    assert_eq!(store.0.lock().unwrap().event_ids.len(), 1);
}

#[test]
fn result_query_is_anonymous_and_false_does_not_authorize_retry() {
    let store = MemoryStore::default();
    let service = make_service(store.clone(), TestClock::at(1100), crypto());
    service
        .revoke_session(actor(), command(TARGET_SESSION))
        .unwrap();
    let query = |secret: &str| SecurityReceiptQuery {
        operation_id: Uuid::from_u128(OPERATION),
        receipt_secret: SecretString::new(secret),
    };
    assert!(service.session_revocation_result(query(SECRET)).unwrap());
    assert!(!service
        .session_revocation_result(query("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"))
        .unwrap());
    assert_eq!(store.0.lock().unwrap().trace.last(), Some(&"receipt"));
    let mut missing = query(SECRET);
    missing.operation_id = Uuid::from_u128(OPERATION + 1);
    assert!(!service.session_revocation_result(missing).unwrap());
}

#[test]
fn capacity_inactive_actor_invalid_input_unknown_key_and_expired_replay_fail_closed() {
    let store = MemoryStore::default();
    store.0.lock().unwrap().count_override = Some(RECEIPT_CAPACITY);
    let service = make_service(store.clone(), TestClock::at(1100), crypto());
    assert!(matches!(
        service.revoke_session(actor(), command(TARGET_SESSION)),
        Err(AccessError::Conflict("security.receipt_capacity"))
    ));
    assert!(store.0.lock().unwrap().revoked.is_empty());

    store.0.lock().unwrap().count_override = None;
    store.0.lock().unwrap().actor_active = false;
    assert_eq!(
        service.revoke_session(actor(), command(TARGET_SESSION)),
        Err(AccessError::Forbidden)
    );
    store.0.lock().unwrap().actor_active = true;

    let mut malformed = command(TARGET_SESSION);
    malformed.receipt_secret = SecretString::new(format!("{}=", SECRET));
    assert!(matches!(
        service.revoke_session(actor(), malformed),
        Err(AccessError::InvalidInput("receipt_secret"))
    ));
    let mut nil_target = command(TARGET_SESSION);
    nil_target.target_session_id = Uuid::nil().to_string();
    assert!(matches!(
        service.revoke_session(actor(), nil_target),
        Err(AccessError::InvalidInput("target_session_id"))
    ));

    let old_crypto = TestCrypto::new("old", &[("old", 7)]);
    let old = make_service(store.clone(), TestClock::at(1100), old_crypto);
    old.revoke_session(actor(), command(TARGET_SESSION))
        .unwrap();
    let unavailable = make_service(
        store.clone(),
        TestClock::at(1200),
        TestCrypto::new("current", &[("current", 1)]),
    );
    assert_eq!(
        unavailable.revoke_session(actor(), command(TARGET_SESSION)),
        Err(AccessError::Store(StoreError::Backend(
            CRYPTO_BACKEND.into()
        )))
    );
    let expired = make_service(store.clone(), TestClock::at(87_500), crypto());
    assert_eq!(
        expired.revoke_session(actor(), command(TARGET_SESSION)),
        Err(AccessError::Conflict("security.operation_conflict"))
    );
}

#[test]
fn write_errors_roll_back_and_clock_is_sampled_after_the_store_lock() {
    let store = MemoryStore::default();
    let clock = TestClock::at(900);
    {
        let mut state = store.0.lock().unwrap();
        state.record_fails = true;
        state.clock_to_set_before_callback = Some(clock.clone());
        state.set_time_before_callback = Some(1100);
    }
    let service = make_service(store.clone(), clock.clone(), crypto());
    assert!(matches!(
        service.revoke_session(actor(), command(TARGET_SESSION)),
        Err(AccessError::Store(StoreError::Backend(_)))
    ));
    let state = store.0.lock().unwrap();
    assert!(state.revoked.is_empty());
    assert!(state.receipts.is_empty());
    assert!(state.event_ids.is_empty());
    assert_eq!(&state.trace[..3], &["write-lock", "actor", "receipt"]);
}

#[test]
fn accepted_targets_include_expired_and_already_revoked_sessions() {
    for status in [
        SessionStatus::Pending,
        SessionStatus::Expired,
        SessionStatus::Revoked,
    ] {
        let store = MemoryStore::default();
        store.0.lock().unwrap().session = session(TARGET_SESSION, "tenant-b", status);
        let service = make_service(store.clone(), TestClock::at(1100), crypto());
        service
            .revoke_session(actor(), command(TARGET_SESSION))
            .unwrap();
        assert_eq!(store.0.lock().unwrap().revoked.len(), 1);
    }
}

#[test]
fn secret_and_command_payloads_are_canonical_and_domain_bound() {
    let bytes = parse_receipt_secret(&SecretString::new(SECRET)).unwrap();
    assert_eq!(bytes, [1; 32]);
    for bad in [
        "",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(parse_receipt_secret(&SecretString::new(bad)).is_err());
    }
    let payload = command_payload(
        &actor(),
        &command(TARGET_SESSION),
        Uuid::parse_str(SUBJECT).unwrap(),
        Uuid::parse_str(ACTOR_SESSION).unwrap(),
    )
    .unwrap();
    assert!(payload.starts_with(&(COMMAND_DOMAIN.len() as u32).to_be_bytes()));
    assert!(!format!("{:?}", command(TARGET_SESSION)).contains(SECRET));
}

use super::{AccessError, TenancyMode};
use crate::service::contracts::is_valid_email;
use crate::{
    AccountSecurityCrypto, Clock, IdGenerator, SecretString, SecurityCryptoContext,
    SecurityCryptoError, SecurityDigest, SecurityDigestPurpose, SecurityEnvelope,
    SecurityEnvelopePurpose, StoreError,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const FLOW_TTL: Duration = Duration::from_secs(900);
const FLOW_RETENTION: Duration = Duration::from_secs(86_400);
const BUDGET_WINDOW: Duration = Duration::from_secs(3_600);
const MAX_FLOWS: u64 = 10_000;
const MAX_OUTBOX: u64 = 10_000;
const MAX_BUDGETS: u64 = 100_000;
const MAX_STARTS: u32 = 3;
const MAX_FAILURES: u32 = 10;
const REQUEST_DOMAIN: &[u8] = b"embedded-idp/password-recovery-start/v1";
const CRYPTO_BACKEND: &str = "account security crypto unavailable";

#[derive(Debug, Clone)]
pub struct RecoveryStartCommand {
    pub email: SecretString,
    pub operation_id: Uuid,
    pub receipt_secret: SecretString,
}

#[derive(Debug, Clone)]
pub struct RecoveryStartResult {
    pub handle: SecretString,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct RecoveryStartReceipt {
    pub operation_id: Uuid,
    pub flow_id: Uuid,
    pub request_digest: SecurityDigest,
    pub handle_envelope: SecurityEnvelope,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Clone)]
pub struct RecoveryBudget {
    pub subject_digest: [u8; 32],
    pub window_start: SystemTime,
    pub expires_at: SystemTime,
    pub start_count: u32,
    pub failure_count: u32,
}
impl fmt::Debug for RecoveryBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryBudget")
            .field("subject_digest", &"<redacted>")
            .field("window_start", &self.window_start)
            .field("expires_at", &self.expires_at)
            .field("start_count", &self.start_count)
            .field("failure_count", &self.failure_count)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryAccountSnapshot {
    pub account_id: Uuid,
    pub email: SecretString,
    pub credential_version: u64,
    pub active: bool,
    pub has_active_membership: bool,
    pub has_effective_security_admin: bool,
}

#[derive(Debug, Clone)]
pub struct RecoveryStartContext {
    pub account: Option<RecoveryAccountSnapshot>,
    pub budget: Option<RecoveryBudget>,
    pub flow_count: u64,
    pub outbox_count: u64,
    pub budget_count: u64,
}

#[derive(Clone)]
pub struct RecoveryStartFlow {
    pub id: Uuid,
    pub subject_digest: [u8; 32],
    pub account_id: Option<Uuid>,
    pub snapshot_credential_version: Option<u64>,
    pub handle_digest: SecurityDigest,
    pub code_digest: SecurityDigest,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub retained_until: SystemTime,
}
impl fmt::Debug for RecoveryStartFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryStartFlow")
            .field("id", &self.id)
            .field("subject_digest", &"<redacted>")
            .field("account_id", &self.account_id)
            .field(
                "snapshot_credential_version",
                &self.snapshot_credential_version,
            )
            .field("handle_digest", &self.handle_digest)
            .field("code_digest", &self.code_digest)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("retained_until", &self.retained_until)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryStartOutbox {
    pub id: Uuid,
    pub flow_id: Uuid,
    pub envelope: Option<SecurityEnvelope>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct RecoveryStartBundle {
    pub budget: RecoveryBudget,
    pub flow: RecoveryStartFlow,
    pub receipt: RecoveryStartReceipt,
    pub outbox: RecoveryStartOutbox,
    pub event_id: Uuid,
}

pub trait RecoveryStartService: Send + Sync {
    fn start_recovery(
        &self,
        command: RecoveryStartCommand,
    ) -> Result<RecoveryStartResult, AccessError>;
}

pub trait RecoveryStartTransaction {
    fn start_receipt(
        &mut self,
        operation_id: Uuid,
    ) -> Result<Option<RecoveryStartReceipt>, StoreError>;
    fn lock_start_context(
        &mut self,
        email: &str,
        subject_digest: &[u8; 32],
    ) -> Result<RecoveryStartContext, StoreError>;
    fn close_subject_flows(
        &mut self,
        subject_digest: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), StoreError>;
    fn record_start(&mut self, bundle: &RecoveryStartBundle) -> Result<(), StoreError>;
}

pub trait RecoveryStartStore: Send + Sync {
    type Transaction<'a>: RecoveryStartTransaction
    where
        Self: 'a;

    fn recovery_start_transaction<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;
}

pub struct CoreRecoveryStartService<S, C, K, I> {
    mode: TenancyMode,
    store: S,
    clock: C,
    crypto: K,
    ids: I,
}

impl<S, C, K, I> CoreRecoveryStartService<S, C, K, I> {
    pub fn new(mode: TenancyMode, store: S, clock: C, crypto: K, ids: I) -> Self {
        Self {
            mode,
            store,
            clock,
            crypto,
            ids,
        }
    }
}

impl<S, C, K, I> RecoveryStartService for CoreRecoveryStartService<S, C, K, I>
where
    S: RecoveryStartStore,
    C: Clock + Send + Sync,
    K: AccountSecurityCrypto,
    I: IdGenerator + Send + Sync,
{
    fn start_recovery(
        &self,
        command: RecoveryStartCommand,
    ) -> Result<RecoveryStartResult, AccessError> {
        let email = normalize_email(&command.email)?;
        if command.operation_id.is_nil() {
            return Err(AccessError::InvalidInput("operation_id"));
        }
        let secret = parse_secret(&command.receipt_secret)?;
        let subject = self.crypto.subject_digest(&email).map_err(crypto_error)?;

        self.store
            .recovery_start_transaction(self.mode, self.crypto.authority(), |tx| {
                if let Some(receipt) = tx.start_receipt(command.operation_id)? {
                    let now = sample_time(self.clock.now())?;
                    return self.replay(&receipt, command.operation_id, &email, &secret, now);
                }

                let context = tx.lock_start_context(&email, &subject)?;
                let now = sample_time(self.clock.now())?;
                validate_now(now)?;
                validate_context(&context, &email, &subject, now)?;
                if context.flow_count >= MAX_FLOWS || context.outbox_count >= MAX_OUTBOX {
                    return Err(AccessError::Conflict("recovery.capacity"));
                }
                let has_budget = context.budget.is_some();
                if context.budget_count >= MAX_BUDGETS && !has_budget {
                    return Err(AccessError::Conflict("recovery.capacity"));
                }
                let budget = next_budget(context.budget, subject, now)?;

                let eligible = context.account.as_ref().is_some_and(|account| {
                    account.active
                        && account.has_active_membership
                        && !account.has_effective_security_admin
                });
                let account = context.account.as_ref().filter(|_| eligible);

                let flow_id = self.next_id("recovery_flow")?;
                let outbox_id = self.next_id("recovery_outbox")?;
                let event_id = self.next_id("evt")?;
                if flow_id == outbox_id || flow_id == event_id || outbox_id == event_id {
                    return Err(AccessError::InvalidStoreResponse);
                }

                let token = self.crypto.random_token().map_err(crypto_error)?;
                let token_bytes = parse_random_token(&token)?;
                let code = self.crypto.random_code().map_err(crypto_error)?;
                validate_code(&code)?;
                let handle = encode_handle(flow_id, &token_bytes);
                let (flow_expires, retained_until) = checked_flow_times(now)?;
                let receipt_expires = now
                    .checked_add(FLOW_TTL)
                    .ok_or(AccessError::InvalidStoreResponse)?;

                let request_payload = request_payload(&email, &secret)?;
                let request_digest = self
                    .crypto
                    .digest(
                        SecurityDigestPurpose::Command,
                        &SecurityCryptoContext {
                            reference_id: command.operation_id,
                            related_id: Some(flow_id),
                        },
                        &request_payload,
                    )
                    .map_err(crypto_error)?;
                let handle_digest = self
                    .crypto
                    .digest(
                        SecurityDigestPurpose::RecoveryHandle,
                        &SecurityCryptoContext {
                            reference_id: flow_id,
                            related_id: None,
                        },
                        &token_bytes,
                    )
                    .map_err(crypto_error)?;
                let code_digest = self
                    .crypto
                    .digest(
                        SecurityDigestPurpose::RecoveryCode,
                        &SecurityCryptoContext {
                            reference_id: flow_id,
                            related_id: None,
                        },
                        code.expose_secret().as_bytes(),
                    )
                    .map_err(crypto_error)?;
                let handle_envelope = self
                    .crypto
                    .seal(
                        SecurityEnvelopePurpose::RecoveryStartReceipt,
                        &SecurityCryptoContext {
                            reference_id: command.operation_id,
                            related_id: Some(flow_id),
                        },
                        &handle,
                    )
                    .map_err(crypto_error)?;
                let mail_payload =
                    format!("recovery-email-v1\n{}\n{}", email, code.expose_secret());
                let mail_secret = SecretString::new(mail_payload);
                let mail_envelope = self
                    .crypto
                    .seal(
                        SecurityEnvelopePurpose::RecoveryEmail,
                        &SecurityCryptoContext {
                            reference_id: outbox_id,
                            related_id: Some(flow_id),
                        },
                        &mail_secret,
                    )
                    .map_err(crypto_error)?;

                let flow = RecoveryStartFlow {
                    id: flow_id,
                    subject_digest: subject,
                    account_id: account.map(|value| value.account_id),
                    snapshot_credential_version: account.map(|value| value.credential_version),
                    handle_digest,
                    code_digest,
                    created_at: now,
                    expires_at: flow_expires,
                    retained_until,
                };
                let receipt = RecoveryStartReceipt {
                    operation_id: command.operation_id,
                    flow_id,
                    request_digest,
                    handle_envelope,
                    created_at: now,
                    expires_at: receipt_expires,
                };
                let outbox = RecoveryStartOutbox {
                    id: outbox_id,
                    flow_id,
                    envelope: eligible.then_some(mail_envelope),
                    created_at: now,
                    expires_at: flow_expires,
                };
                let bundle = RecoveryStartBundle {
                    budget,
                    flow,
                    receipt,
                    outbox,
                    event_id,
                };
                validate_bundle(&bundle, now)?;
                tx.close_subject_flows(&subject, now)?;
                tx.record_start(&bundle)?;
                Ok(RecoveryStartResult {
                    handle,
                    expires_at: flow_expires,
                })
            })
    }
}

impl<S, C, K, I> CoreRecoveryStartService<S, C, K, I>
where
    K: AccountSecurityCrypto,
{
    fn replay(
        &self,
        receipt: &RecoveryStartReceipt,
        operation_id: Uuid,
        email: &str,
        secret: &[u8; 32],
        now: SystemTime,
    ) -> Result<RecoveryStartResult, AccessError> {
        validate_receipt(receipt, operation_id, now)?;
        if receipt.expires_at <= now {
            return Err(operation_conflict());
        }
        let payload = request_payload(email, secret)?;
        let matches = self
            .crypto
            .verify_digest(
                SecurityDigestPurpose::Command,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: Some(receipt.flow_id),
                },
                &payload,
                &receipt.request_digest,
            )
            .map_err(crypto_error)?;
        if !matches {
            return Err(operation_conflict());
        }
        let handle = self
            .crypto
            .open(
                SecurityEnvelopePurpose::RecoveryStartReceipt,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: Some(receipt.flow_id),
                },
                &receipt.handle_envelope,
            )
            .map_err(crypto_error)?;
        validate_handle(&handle, receipt.flow_id)?;
        Ok(RecoveryStartResult {
            handle,
            expires_at: receipt.expires_at,
        })
    }

    fn next_id(&self, prefix: &str) -> Result<Uuid, AccessError>
    where
        I: IdGenerator,
    {
        let raw = self.ids.next_id(prefix);
        parse_canonical_nonnil_uuid(&raw).ok_or(AccessError::InvalidStoreResponse)
    }
}

fn normalize_email(email: &SecretString) -> Result<String, AccessError> {
    let raw = email.expose_secret();
    let value = raw.trim_matches(' ');
    if value.is_empty()
        || value.len() > 254
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || value.matches('@').count() != 1
        || !value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
        || !is_valid_email(value)
    {
        return Err(AccessError::InvalidInput("email"));
    }
    Ok(value.to_owned())
}

fn parse_secret(secret: &SecretString) -> Result<[u8; 32], AccessError> {
    let encoded = secret.expose_secret();
    if encoded.len() != 43 {
        return Err(AccessError::InvalidInput("receipt_secret"));
    }
    let decoded = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|_| AccessError::InvalidInput("receipt_secret"))?;
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| AccessError::InvalidInput("receipt_secret"))?;
    if bytes.iter().all(|byte| *byte == 0) || Base64UrlUnpadded::encode_string(&bytes) != encoded {
        return Err(AccessError::InvalidInput("receipt_secret"));
    }
    Ok(bytes)
}

fn parse_random_token(token: &SecretString) -> Result<[u8; 32], AccessError> {
    let encoded = token.expose_secret();
    if encoded.len() != 43 {
        return Err(AccessError::InvalidStoreResponse);
    }
    let decoded =
        Base64UrlUnpadded::decode_vec(encoded).map_err(|_| AccessError::InvalidStoreResponse)?;
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| AccessError::InvalidStoreResponse)?;
    if bytes.iter().all(|byte| *byte == 0) || Base64UrlUnpadded::encode_string(&bytes) != encoded {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(bytes)
}

fn validate_code(code: &SecretString) -> Result<(), AccessError> {
    let code = code.expose_secret();
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn validate_now(now: SystemTime) -> Result<(), AccessError> {
    if now < UNIX_EPOCH {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn sample_time(now: SystemTime) -> Result<SystemTime, AccessError> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AccessError::InvalidStoreResponse)?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(AccessError::InvalidStoreResponse)
}

fn validate_context(
    context: &RecoveryStartContext,
    email: &str,
    subject: &[u8; 32],
    now: SystemTime,
) -> Result<(), AccessError> {
    if let Some(account) = &context.account {
        if account.account_id.is_nil()
            || account.email.expose_secret() != email
            || account.credential_version == 0
            || account.credential_version > i64::MAX as u64
        {
            return Err(AccessError::InvalidStoreResponse);
        }
    }
    if let Some(budget) = &context.budget {
        validate_budget(budget, subject, now)?;
    }
    Ok(())
}

fn validate_budget(
    budget: &RecoveryBudget,
    subject: &[u8; 32],
    now: SystemTime,
) -> Result<(), AccessError> {
    if &budget.subject_digest != subject
        || budget.start_count > MAX_STARTS
        || budget.failure_count > MAX_FAILURES
        || budget.window_start < UNIX_EPOCH
        || budget.window_start > now
        || budget.window_start.checked_add(BUDGET_WINDOW) != Some(budget.expires_at)
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn next_budget(
    existing: Option<RecoveryBudget>,
    subject: [u8; 32],
    now: SystemTime,
) -> Result<RecoveryBudget, AccessError> {
    match existing {
        Some(mut budget) if budget.expires_at > now => {
            if budget.start_count >= MAX_STARTS || budget.failure_count >= MAX_FAILURES {
                return Err(AccessError::Conflict("recovery.rate_limited"));
            }
            budget.start_count += 1;
            Ok(budget)
        }
        _ => Ok(RecoveryBudget {
            subject_digest: subject,
            window_start: now,
            expires_at: now
                .checked_add(BUDGET_WINDOW)
                .ok_or(AccessError::InvalidStoreResponse)?,
            start_count: 1,
            failure_count: 0,
        }),
    }
}

fn checked_flow_times(now: SystemTime) -> Result<(SystemTime, SystemTime), AccessError> {
    Ok((
        now.checked_add(FLOW_TTL)
            .ok_or(AccessError::InvalidStoreResponse)?,
        now.checked_add(FLOW_RETENTION)
            .ok_or(AccessError::InvalidStoreResponse)?,
    ))
}

fn request_payload(email: &str, secret: &[u8; 32]) -> Result<Vec<u8>, AccessError> {
    let mut payload = Vec::with_capacity(4 * 3 + REQUEST_DOMAIN.len() + email.len() + secret.len());
    push_field(&mut payload, REQUEST_DOMAIN)?;
    push_field(&mut payload, email.as_bytes())?;
    push_field(&mut payload, secret)?;
    Ok(payload)
}

fn push_field(payload: &mut Vec<u8>, value: &[u8]) -> Result<(), AccessError> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| AccessError::InvalidInput("email"))?;
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(value);
    Ok(())
}

fn encode_handle(flow_id: Uuid, token: &[u8; 32]) -> SecretString {
    let mut bytes = Vec::with_capacity(48);
    bytes.extend_from_slice(flow_id.as_bytes());
    bytes.extend_from_slice(token);
    SecretString::new(Base64UrlUnpadded::encode_string(&bytes))
}

fn validate_handle(handle: &SecretString, flow_id: Uuid) -> Result<(), AccessError> {
    let encoded = handle.expose_secret();
    if encoded.len() != 64 {
        return Err(AccessError::InvalidStoreResponse);
    }
    let decoded =
        Base64UrlUnpadded::decode_vec(encoded).map_err(|_| AccessError::InvalidStoreResponse)?;
    if decoded.len() != 48 || Base64UrlUnpadded::encode_string(&decoded) != encoded {
        return Err(AccessError::InvalidStoreResponse);
    }
    let stored_flow =
        Uuid::from_slice(&decoded[..16]).map_err(|_| AccessError::InvalidStoreResponse)?;
    if stored_flow != flow_id || stored_flow.is_nil() || decoded[16..].iter().all(|byte| *byte == 0)
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn validate_receipt(
    receipt: &RecoveryStartReceipt,
    operation_id: Uuid,
    now: SystemTime,
) -> Result<(), AccessError> {
    if receipt.operation_id != operation_id
        || operation_id.is_nil()
        || receipt.flow_id.is_nil()
        || receipt.created_at < UNIX_EPOCH
        || receipt.created_at > now
        || receipt.expires_at <= receipt.created_at
        || receipt
            .created_at
            .checked_add(FLOW_TTL)
            .is_none_or(|maximum| receipt.expires_at > maximum)
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn validate_bundle(bundle: &RecoveryStartBundle, now: SystemTime) -> Result<(), AccessError> {
    let flow = &bundle.flow;
    let receipt = &bundle.receipt;
    let outbox = &bundle.outbox;
    let eligible = flow.account_id.is_some();
    if flow.id.is_nil()
        || outbox.id.is_nil()
        || bundle.event_id.is_nil()
        || flow.id == outbox.id
        || flow.id == bundle.event_id
        || outbox.id == bundle.event_id
        || outbox.flow_id != flow.id
        || receipt.flow_id != flow.id
        || receipt.operation_id.is_nil()
        || flow.subject_digest != bundle.budget.subject_digest
        || flow.created_at != now
        || outbox.created_at != flow.created_at
        || outbox.expires_at != flow.expires_at
        || flow.expires_at.duration_since(flow.created_at).ok() != Some(FLOW_TTL)
        || flow.retained_until.duration_since(flow.created_at).ok() != Some(FLOW_RETENTION)
        || receipt.created_at != flow.created_at
        || receipt.expires_at.duration_since(receipt.created_at).ok() != Some(FLOW_TTL)
        || flow.account_id.is_some() != flow.snapshot_credential_version.is_some()
        || flow
            .snapshot_credential_version
            .is_some_and(|version| version == 0 || version > i64::MAX as u64)
        || outbox.envelope.is_some() != eligible
        || bundle.budget.start_count == 0
        || bundle.budget.start_count > MAX_STARTS
        || bundle.budget.failure_count > MAX_FAILURES
        || bundle.budget.window_start > now
        || bundle.budget.expires_at
            != bundle
                .budget
                .window_start
                .checked_add(BUDGET_WINDOW)
                .ok_or(AccessError::InvalidStoreResponse)?
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    validate_receipt(receipt, receipt.operation_id, now)?;
    Ok(())
}

fn parse_canonical_nonnil_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
}

fn operation_conflict() -> AccessError {
    AccessError::Conflict("recovery.operation_conflict")
}

fn crypto_error(_: SecurityCryptoError) -> AccessError {
    AccessError::Store(StoreError::Backend(CRYPTO_BACKEND.into()))
}

#[cfg(test)]
#[path = "recovery_start_tests.rs"]
mod tests;

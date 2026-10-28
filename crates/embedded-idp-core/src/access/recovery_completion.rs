use super::{recovery_start::*, self_session_revocation::*, AccessError, TenancyMode};
use crate::service::password::{hash_password, validate_registration_password};
use crate::{
    AccountSecurityCrypto, AuthConfig, Clock, ConfigValidationError, IdGenerator,
    PasswordWorkBudget, SecretString, SecurityCryptoContext, SecurityCryptoError,
    SecurityDigestPurpose, StoreError,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const BUDGET_WINDOW: Duration = Duration::from_secs(3_600);
const RECEIPT_TTL: Duration = Duration::from_secs(86_400);
const RECEIPT_CAPACITY: u64 = 100_000;
const MAX_FAILURES: u32 = 10;
const MAX_FLOW_FAILURES: u32 = 5;
const COMMAND_DOMAIN: &[u8] = b"embedded-idp/password-recovery-complete/v1";
const CRYPTO_BACKEND: &str = "account security crypto unavailable";

#[derive(Debug, Clone)]
pub struct RecoveryCompleteCommand {
    pub handle: SecretString,
    pub code: SecretString,
    pub new_password: SecretString,
    pub operation_id: Uuid,
    pub receipt_secret: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryCompleteError {
    InvalidRecovery,
    Access(AccessError),
}

impl From<AccessError> for RecoveryCompleteError {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}

pub trait RecoveryCompletionService: Send + Sync {
    fn complete_recovery(
        &self,
        command: RecoveryCompleteCommand,
    ) -> Result<(), RecoveryCompleteError>;

    fn recovery_completion_result(&self, query: SecurityReceiptQuery) -> Result<bool, AccessError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryFlowState {
    Pending,
    Consumed,
    Invalidated,
    Expired,
}

#[derive(Debug, Clone)]
pub struct RecoveryCompletionContext {
    pub flow: RecoveryStartFlow,
    pub state: RecoveryFlowState,
    pub failed_attempts: u32,
    pub budget: RecoveryBudget,
    pub account: Option<RecoveryAccountSnapshot>,
}

pub trait RecoveryCompletionTransaction {
    fn receipt(
        &mut self,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError>;
    fn context(&mut self, flow_id: Uuid) -> Result<Option<RecoveryCompletionContext>, StoreError>;
    fn record_failure(
        &mut self,
        flow_id: Uuid,
        budget: &RecoveryBudget,
        failed_attempts: u32,
        now: SystemTime,
        event_id: Uuid,
    ) -> Result<(), StoreError>;
    fn receipt_count(&mut self) -> Result<u64, StoreError>;
    fn complete(
        &mut self,
        flow_id: Uuid,
        account_id: Uuid,
        expected_version: u64,
        new_hash: &SecretString,
        now: SystemTime,
        receipt: &SecurityOperationReceipt,
        event_id: Uuid,
    ) -> Result<(), StoreError>;
}

pub trait RecoveryCompletionStore: Send + Sync {
    type Transaction<'a>: RecoveryCompletionTransaction
    where
        Self: 'a;

    fn recovery_completion_transaction<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        flow_id: Option<Uuid>,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;
}

pub struct CoreRecoveryCompletionService<S, C, K, I> {
    mode: TenancyMode,
    store: S,
    clock: C,
    crypto: K,
    ids: I,
    config: AuthConfig,
    password_work: PasswordWorkBudget,
}

impl<S, C, K, I> CoreRecoveryCompletionService<S, C, K, I> {
    pub fn new(
        mode: TenancyMode,
        store: S,
        clock: C,
        crypto: K,
        ids: I,
        config: AuthConfig,
        password_work: PasswordWorkBudget,
    ) -> Result<Self, ConfigValidationError> {
        config.validate()?;
        Ok(Self {
            mode,
            store,
            clock,
            crypto,
            ids,
            config,
            password_work,
        })
    }
}

impl<S, C, K, I> RecoveryCompletionService for CoreRecoveryCompletionService<S, C, K, I>
where
    S: RecoveryCompletionStore,
    C: Clock + Send + Sync,
    K: AccountSecurityCrypto,
    I: IdGenerator + Send + Sync,
{
    fn complete_recovery(
        &self,
        command: RecoveryCompleteCommand,
    ) -> Result<(), RecoveryCompleteError> {
        let handle = parse_handle(&command.handle)?;
        validate_code(&command.code)?;
        if command.operation_id.is_nil() {
            return Err(AccessError::InvalidInput("operation_id").into());
        }
        let receipt_secret = parse_secret(&command.receipt_secret)?;
        validate_registration_password(&self.config, command.new_password.expose_secret())
            .map_err(|_| AccessError::InvalidInput("password"))?;

        let first = self.store.recovery_completion_transaction(
            self.mode,
            self.crypto.authority(),
            Some(handle.flow_id),
            |tx| {
                let now = sample_time(self.clock.now())?;
                if let Some(receipt) = tx.receipt(command.operation_id)? {
                    self.verify_completion_receipt(
                        &receipt,
                        command.operation_id,
                        &receipt_secret,
                        &command,
                        now,
                    )?;
                    return Ok(FirstPhase::CompleteReplay);
                }
                let Some(context) = tx.context(handle.flow_id)? else {
                    return Ok(FirstPhase::Invalid);
                };
                let Some(checked) = self.check_context(
                    &context,
                    handle.flow_id,
                    &handle.secret,
                    &command.code,
                    now,
                )?
                else {
                    return Ok(FirstPhase::Invalid);
                };
                if !checked.code_matches {
                    let mut budget = checked.budget;
                    budget.failure_count += 1;
                    let failed_attempts = context.failed_attempts + 1;
                    let event_id = self.next_id("evt")?;
                    tx.record_failure(handle.flow_id, &budget, failed_attempts, now, event_id)?;
                    return Ok(FirstPhase::Invalid);
                }
                let Some(account) = checked.account else {
                    return Ok(FirstPhase::Invalid);
                };
                Ok(FirstPhase::Verified(VerifiedSnapshot {
                    flow: context.flow.clone(),
                    account,
                }))
            },
        )?;

        let verified = match first {
            FirstPhase::CompleteReplay => return Ok(()),
            FirstPhase::Invalid => return Err(RecoveryCompleteError::InvalidRecovery),
            FirstPhase::Verified(snapshot) => snapshot,
        };

        let permit = self.password_work.try_login().map_err(AccessError::from)?;
        let new_hash = SecretString::new(
            hash_password(command.new_password.expose_secret()).map_err(AccessError::from)?,
        );
        drop(permit);

        let second = self.store.recovery_completion_transaction(
            self.mode,
            self.crypto.authority(),
            Some(handle.flow_id),
            |tx| {
                let now = sample_time(self.clock.now())?;
                if let Some(receipt) = tx.receipt(command.operation_id)? {
                    self.verify_completion_receipt(
                        &receipt,
                        command.operation_id,
                        &receipt_secret,
                        &command,
                        now,
                    )?;
                    return Ok(SecondPhase::CompleteReplay);
                }
                let Some(context) = tx.context(handle.flow_id)? else {
                    return Ok(SecondPhase::Invalid);
                };
                let Some(checked) = self.check_context(
                    &context,
                    handle.flow_id,
                    &handle.secret,
                    &command.code,
                    now,
                )?
                else {
                    return Ok(SecondPhase::Invalid);
                };
                if !checked.code_matches || checked.account.is_none() {
                    return Ok(SecondPhase::Invalid);
                }
                let Some(account) = checked.account else {
                    return Ok(SecondPhase::Invalid);
                };
                if !same_snapshot(&verified, &context.flow, &account) {
                    return Ok(SecondPhase::Invalid);
                }
                if tx.receipt_count()? >= RECEIPT_CAPACITY {
                    return Err(AccessError::Conflict("recovery.capacity"));
                }
                let expires_at = now
                    .checked_add(RECEIPT_TTL)
                    .ok_or(AccessError::InvalidStoreResponse)?;
                let secret_digest = self
                    .crypto
                    .digest(
                        SecurityDigestPurpose::ReceiptSecret,
                        &SecurityCryptoContext {
                            reference_id: command.operation_id,
                            related_id: None,
                        },
                        &receipt_secret,
                    )
                    .map_err(crypto_error)?;
                let command_digest = self
                    .crypto
                    .digest(
                        SecurityDigestPurpose::Command,
                        &SecurityCryptoContext {
                            reference_id: command.operation_id,
                            related_id: Some(account.account_id),
                        },
                        &completion_payload(&command)?,
                    )
                    .map_err(crypto_error)?;
                let event_id = self.next_id("evt")?;
                let receipt = SecurityOperationReceipt {
                    purpose: SecurityReceiptPurpose::PasswordRecovery,
                    operation_id: command.operation_id,
                    account_id: account.account_id.to_string(),
                    secret_digest,
                    command_digest,
                    completed_at: now,
                    expires_at,
                };
                tx.complete(
                    handle.flow_id,
                    account.account_id,
                    account.credential_version,
                    &new_hash,
                    now,
                    &receipt,
                    event_id,
                )?;
                Ok(SecondPhase::Completed)
            },
        )?;
        match second {
            SecondPhase::CompleteReplay | SecondPhase::Completed => Ok(()),
            SecondPhase::Invalid => Err(RecoveryCompleteError::InvalidRecovery),
        }
    }

    fn recovery_completion_result(&self, query: SecurityReceiptQuery) -> Result<bool, AccessError> {
        if query.operation_id.is_nil() {
            return Err(AccessError::InvalidInput("operation_id"));
        }
        let secret = parse_secret(&query.receipt_secret)?;
        self.store
            .recovery_completion_transaction(self.mode, self.crypto.authority(), None, |tx| {
                let now = sample_time(self.clock.now())?;
                let Some(receipt) = tx.receipt(query.operation_id)? else {
                    return Ok(false);
                };
                validate_receipt(&receipt, query.operation_id, now)?;
                if receipt.expires_at <= now {
                    return Ok(false);
                }
                self.verify_receipt_secret(&receipt, &secret)
            })
    }
}

impl<S, C, K, I> CoreRecoveryCompletionService<S, C, K, I>
where
    K: AccountSecurityCrypto,
    I: IdGenerator,
{
    fn check_context(
        &self,
        context: &RecoveryCompletionContext,
        flow_id: Uuid,
        handle_secret: &[u8; 32],
        code: &SecretString,
        now: SystemTime,
    ) -> Result<Option<CheckedContext>, AccessError> {
        validate_context(context, flow_id, now)?;
        if context.state != RecoveryFlowState::Pending
            || context.flow.expires_at <= now
            || context.failed_attempts >= MAX_FLOW_FAILURES
        {
            return Ok(None);
        }
        let mut budget = context.budget.clone();
        if budget.expires_at <= now {
            budget.window_start = now;
            budget.expires_at = now
                .checked_add(BUDGET_WINDOW)
                .ok_or(AccessError::InvalidStoreResponse)?;
            budget.start_count = 0;
            budget.failure_count = 0;
        }
        if budget.failure_count >= MAX_FAILURES {
            return Ok(None);
        }
        let handle_matches = self
            .crypto
            .verify_digest(
                SecurityDigestPurpose::RecoveryHandle,
                &SecurityCryptoContext {
                    reference_id: flow_id,
                    related_id: None,
                },
                handle_secret,
                &context.flow.handle_digest,
            )
            .map_err(crypto_error)?;
        if !handle_matches {
            return Ok(None);
        }
        let code_matches = self
            .crypto
            .verify_digest(
                SecurityDigestPurpose::RecoveryCode,
                &SecurityCryptoContext {
                    reference_id: flow_id,
                    related_id: None,
                },
                code.expose_secret().as_bytes(),
                &context.flow.code_digest,
            )
            .map_err(crypto_error)?;
        let account = eligible_account(context)?;
        Ok(Some(CheckedContext {
            budget,
            code_matches,
            account,
        }))
    }

    fn verify_completion_receipt(
        &self,
        receipt: &SecurityOperationReceipt,
        operation_id: Uuid,
        secret: &[u8; 32],
        command: &RecoveryCompleteCommand,
        now: SystemTime,
    ) -> Result<(), AccessError> {
        validate_receipt(receipt, operation_id, now)?;
        if receipt.expires_at <= now {
            return Err(operation_conflict());
        }
        if !self.verify_receipt_secret(receipt, secret)? {
            return Err(operation_conflict());
        }
        let account_id = Uuid::parse_str(&receipt.account_id)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == receipt.account_id)
            .ok_or(AccessError::InvalidStoreResponse)?;
        let command_matches = self
            .crypto
            .verify_digest(
                SecurityDigestPurpose::Command,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: Some(account_id),
                },
                &completion_payload(command)?,
                &receipt.command_digest,
            )
            .map_err(crypto_error)?;
        if !command_matches {
            return Err(operation_conflict());
        }
        Ok(())
    }

    fn verify_receipt_secret(
        &self,
        receipt: &SecurityOperationReceipt,
        secret: &[u8; 32],
    ) -> Result<bool, AccessError> {
        self.crypto
            .verify_digest(
                SecurityDigestPurpose::ReceiptSecret,
                &SecurityCryptoContext {
                    reference_id: receipt.operation_id,
                    related_id: None,
                },
                secret,
                &receipt.secret_digest,
            )
            .map_err(crypto_error)
    }

    fn next_id(&self, prefix: &str) -> Result<Uuid, AccessError> {
        let raw = self.ids.next_id(prefix);
        Uuid::parse_str(&raw)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == raw)
            .ok_or(AccessError::InvalidStoreResponse)
    }
}

struct ParsedHandle {
    flow_id: Uuid,
    secret: [u8; 32],
}

struct VerifiedSnapshot {
    flow: RecoveryStartFlow,
    account: RecoveryAccountSnapshot,
}

struct CheckedContext {
    budget: RecoveryBudget,
    code_matches: bool,
    account: Option<RecoveryAccountSnapshot>,
}

enum FirstPhase {
    CompleteReplay,
    Invalid,
    Verified(VerifiedSnapshot),
}

enum SecondPhase {
    CompleteReplay,
    Invalid,
    Completed,
}

fn parse_handle(handle: &SecretString) -> Result<ParsedHandle, AccessError> {
    let encoded = handle.expose_secret();
    if encoded.len() != 64 {
        return Err(AccessError::InvalidInput("handle"));
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(encoded).map_err(|_| AccessError::InvalidInput("handle"))?;
    if bytes.len() != 48 || Base64UrlUnpadded::encode_string(&bytes) != encoded {
        return Err(AccessError::InvalidInput("handle"));
    }
    let flow_id =
        Uuid::from_slice(&bytes[..16]).map_err(|_| AccessError::InvalidInput("handle"))?;
    let secret: [u8; 32] = bytes[16..]
        .try_into()
        .map_err(|_| AccessError::InvalidInput("handle"))?;
    if flow_id.is_nil() || secret.iter().all(|byte| *byte == 0) {
        return Err(AccessError::InvalidInput("handle"));
    }
    Ok(ParsedHandle { flow_id, secret })
}

fn validate_code(code: &SecretString) -> Result<(), AccessError> {
    let code = code.expose_secret();
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AccessError::InvalidInput("code"));
    }
    Ok(())
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

fn sample_time(now: SystemTime) -> Result<SystemTime, AccessError> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AccessError::InvalidStoreResponse)?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(AccessError::InvalidStoreResponse)
}

fn validate_context(
    context: &RecoveryCompletionContext,
    flow_id: Uuid,
    now: SystemTime,
) -> Result<(), AccessError> {
    let flow = &context.flow;
    if flow.id != flow_id
        || flow.id.is_nil()
        || flow.created_at < UNIX_EPOCH
        || flow.created_at > now
        || flow.expires_at <= flow.created_at
        || flow
            .created_at
            .checked_add(Duration::from_secs(900))
            .is_none_or(|max| flow.expires_at > max)
        || flow.retained_until.duration_since(flow.created_at).ok()
            != Some(Duration::from_secs(86_400))
        || context.failed_attempts > MAX_FLOW_FAILURES
        || flow.account_id.is_some() != flow.snapshot_credential_version.is_some()
        || flow
            .snapshot_credential_version
            .is_some_and(|version| version == 0 || version > i64::MAX as u64)
        || context.budget.subject_digest != flow.subject_digest
        || context.budget.start_count > 3
        || context.budget.failure_count > MAX_FAILURES
        || context.budget.window_start < UNIX_EPOCH
        || context.budget.window_start > now
        || context.budget.window_start.checked_add(BUDGET_WINDOW) != Some(context.budget.expires_at)
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    if let Some(account) = &context.account {
        if account.account_id.is_nil()
            || account.credential_version == 0
            || account.credential_version > i64::MAX as u64
            || flow.account_id != Some(account.account_id)
        {
            return Err(AccessError::InvalidStoreResponse);
        }
    }
    if flow.account_id.is_none() && context.account.is_some() {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn eligible_account(
    context: &RecoveryCompletionContext,
) -> Result<Option<RecoveryAccountSnapshot>, AccessError> {
    let Some(account) = &context.account else {
        return Ok(None);
    };
    if context.flow.snapshot_credential_version != Some(account.credential_version) {
        return Ok(None);
    }
    if account.active && account.has_active_membership && !account.has_effective_security_admin {
        Ok(Some(account.clone()))
    } else {
        Ok(None)
    }
}

fn same_snapshot(
    verified: &VerifiedSnapshot,
    current_flow: &RecoveryStartFlow,
    current_account: &RecoveryAccountSnapshot,
) -> bool {
    verified.flow.id == current_flow.id
        && verified.flow.subject_digest == current_flow.subject_digest
        && verified.flow.account_id == current_flow.account_id
        && verified.flow.snapshot_credential_version == current_flow.snapshot_credential_version
        && verified.flow.handle_digest.key_id == current_flow.handle_digest.key_id
        && verified.flow.handle_digest.bytes == current_flow.handle_digest.bytes
        && verified.flow.code_digest.key_id == current_flow.code_digest.key_id
        && verified.flow.code_digest.bytes == current_flow.code_digest.bytes
        && verified.flow.created_at == current_flow.created_at
        && verified.flow.expires_at == current_flow.expires_at
        && verified.flow.retained_until == current_flow.retained_until
        && verified.account.account_id == current_account.account_id
        && verified.account.credential_version == current_account.credential_version
        && verified.account.email.expose_secret() == current_account.email.expose_secret()
        && current_account.active
        && current_account.has_active_membership
        && !current_account.has_effective_security_admin
}

fn completion_payload(command: &RecoveryCompleteCommand) -> Result<Vec<u8>, AccessError> {
    let mut payload = Vec::with_capacity(
        COMMAND_DOMAIN.len()
            + command.handle.expose_secret().len()
            + command.code.expose_secret().len()
            + command.new_password.expose_secret().len()
            + 16,
    );
    push_field(&mut payload, COMMAND_DOMAIN)?;
    push_field(&mut payload, command.handle.expose_secret().as_bytes())?;
    push_field(&mut payload, command.code.expose_secret().as_bytes())?;
    push_field(
        &mut payload,
        command.new_password.expose_secret().as_bytes(),
    )?;
    Ok(payload)
}

fn push_field(payload: &mut Vec<u8>, value: &[u8]) -> Result<(), AccessError> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| AccessError::InvalidInput("command"))?;
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(value);
    Ok(())
}

fn validate_receipt(
    receipt: &SecurityOperationReceipt,
    operation_id: Uuid,
    now: SystemTime,
) -> Result<(), AccessError> {
    if receipt.purpose != SecurityReceiptPurpose::PasswordRecovery
        || receipt.operation_id != operation_id
        || operation_id.is_nil()
        || Uuid::parse_str(&receipt.account_id)
            .ok()
            .is_none_or(|id| id.is_nil() || id.to_string() != receipt.account_id)
        || receipt.completed_at < UNIX_EPOCH
        || receipt.completed_at > now
        || receipt.expires_at <= receipt.completed_at
        || receipt
            .completed_at
            .checked_add(RECEIPT_TTL)
            .is_none_or(|maximum| receipt.expires_at > maximum)
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn operation_conflict() -> AccessError {
    AccessError::Conflict("recovery.operation_conflict")
}

fn crypto_error(_: SecurityCryptoError) -> AccessError {
    AccessError::Store(StoreError::Backend(CRYPTO_BACKEND.into()))
}

#[cfg(test)]
#[path = "recovery_completion_tests.rs"]
mod tests;

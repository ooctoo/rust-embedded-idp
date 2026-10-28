use super::{recovery_completion::RecoveryFlowState, recovery_start::*, AccessError, TenancyMode};
use crate::{
    AccountSecurityCrypto, Clock, IdGenerator, SecretString, SecurityCryptoContext,
    SecurityCryptoError, SecurityDigestPurpose, SecurityEnvelope, SecurityEnvelopePurpose,
    StoreError,
};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const FLOW_TTL: Duration = Duration::from_secs(900);
const FLOW_RETENTION: Duration = Duration::from_secs(86_400);
const LEASE_TTL: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_CLEANUP: u32 = 100;
const MAX_FLOW_FAILURES: u32 = 5;
const CRYPTO_BACKEND: &str = "account security crypto unavailable";

pub struct SecurityMailClaim {
    pub outbox_id: Uuid,
    pub flow_id: Uuid,
    pub lease_token: Uuid,
    pub lease_until: SystemTime,
    pub expires_at: SystemTime,
    pub recipient: SecretString,
    pub code: SecretString,
}

impl fmt::Debug for SecurityMailClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityMailClaim")
            .field("outbox_id", &self.outbox_id)
            .field("flow_id", &self.flow_id)
            .field("lease_token", &"<redacted>")
            .field("lease_until", &self.lease_until)
            .field("expires_at", &self.expires_at)
            .field("recipient", &"<redacted>")
            .field("code", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMailOutcome {
    Accepted,
    Rejected,
    NotStarted,
    Unknown,
}

pub struct SecurityMailCompletion {
    pub outbox_id: Uuid,
    pub lease_token: Uuid,
    pub outcome: SecurityMailOutcome,
}

impl fmt::Debug for SecurityMailCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityMailCompletion")
            .field("outbox_id", &self.outbox_id)
            .field("lease_token", &"<redacted>")
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityCleanupResult {
    pub processed: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMailState {
    Pending,
    Sending,
    Accepted,
    Rejected,
    Unknown,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityMailTerminal {
    Accepted,
    Rejected,
    Unknown,
    Cancelled,
    Expired,
}

pub enum SecurityMailTransition {
    Sending {
        lease_token: Uuid,
        lease_until: SystemTime,
    },
    Retry {
        next_attempt_at: SystemTime,
    },
    Terminal {
        state: SecurityMailTerminal,
        outcome: Option<SecurityMailOutcome>,
    },
}

impl fmt::Debug for SecurityMailTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sending { lease_until, .. } => f
                .debug_struct("Sending")
                .field("lease_token", &"<redacted>")
                .field("lease_until", lease_until)
                .finish(),
            Self::Retry { next_attempt_at } => f
                .debug_struct("Retry")
                .field("next_attempt_at", next_attempt_at)
                .finish(),
            Self::Terminal { state, outcome } => f
                .debug_struct("Terminal")
                .field("state", state)
                .field("outcome", outcome)
                .finish(),
        }
    }
}

#[derive(Clone)]
pub struct SecurityMailContext {
    pub outbox_id: Uuid,
    pub flow_id: Uuid,
    pub state: SecurityMailState,
    pub envelope: Option<SecurityEnvelope>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub next_attempt_at: SystemTime,
    pub attempts: u32,
    pub lease_token: Option<Uuid>,
    pub lease_until: Option<SystemTime>,
    pub flow: RecoveryStartFlow,
    pub flow_state: RecoveryFlowState,
    pub failed_attempts: u32,
    pub account: Option<RecoveryAccountSnapshot>,
}

impl fmt::Debug for SecurityMailContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityMailContext")
            .field("outbox_id", &self.outbox_id)
            .field("flow_id", &self.flow_id)
            .field("state", &self.state)
            .field("envelope", &self.envelope)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("next_attempt_at", &self.next_attempt_at)
            .field("attempts", &self.attempts)
            .field("lease_token", &"<redacted>")
            .field("lease_until", &self.lease_until)
            .field("flow", &self.flow)
            .field("flow_state", &self.flow_state)
            .field("failed_attempts", &self.failed_attempts)
            .field("account", &self.account)
            .finish()
    }
}

pub trait SecurityOutboxService: Send + Sync {
    fn claim(&self) -> Result<Option<SecurityMailClaim>, AccessError>;
    fn finish(&self, completion: SecurityMailCompletion) -> Result<bool, AccessError>;
    fn cleanup(&self) -> Result<SecurityCleanupResult, AccessError>;
}

pub trait SecurityOutboxTransaction {
    fn candidate(&mut self, now: SystemTime) -> Result<Option<SecurityMailContext>, StoreError>;
    fn current(&mut self, outbox_id: Uuid) -> Result<Option<SecurityMailContext>, StoreError>;
    fn transition(
        &mut self,
        outbox_id: Uuid,
        expected_lease: Option<Uuid>,
        change: SecurityMailTransition,
        event_id: Option<Uuid>,
        now: SystemTime,
    ) -> Result<bool, StoreError>;
    fn cleanup(
        &mut self,
        now: SystemTime,
        limit: u32,
        event_ids: &[Uuid],
    ) -> Result<u32, StoreError>;
}

pub trait SecurityOutboxStore: Send + Sync {
    type Transaction<'a>: SecurityOutboxTransaction
    where
        Self: 'a;

    fn security_outbox_transaction<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;
}

pub struct CoreSecurityOutboxService<S, C, K, I> {
    mode: TenancyMode,
    store: S,
    clock: C,
    crypto: K,
    ids: I,
}

impl<S, C, K, I> CoreSecurityOutboxService<S, C, K, I> {
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

impl<S, C, K, I> SecurityOutboxService for CoreSecurityOutboxService<S, C, K, I>
where
    S: SecurityOutboxStore,
    C: Clock + Send + Sync,
    K: AccountSecurityCrypto,
    I: IdGenerator + Send + Sync,
{
    fn claim(&self) -> Result<Option<SecurityMailClaim>, AccessError> {
        self.store
            .security_outbox_transaction(self.mode, self.crypto.authority(), |tx| {
                let now = sample_time(self.clock.now())?;
                let Some(context) = tx.candidate(now)? else {
                    return Ok(None);
                };
                validate_context(&context)?;
                if context.next_attempt_at > now {
                    return Err(AccessError::InvalidStoreResponse);
                }
                if context.state != SecurityMailState::Pending {
                    return Err(AccessError::InvalidStoreResponse);
                }
                if context.expires_at <= now || context.flow.expires_at <= now {
                    self.terminal_without_delivery(
                        tx,
                        &context,
                        SecurityMailTerminal::Expired,
                        now,
                    )?;
                    return Ok(None);
                }
                if !flow_is_usable(&context) {
                    self.terminal_without_delivery(
                        tx,
                        &context,
                        SecurityMailTerminal::Cancelled,
                        now,
                    )?;
                    return Ok(None);
                }
                let Some(account) = eligible_account(&context)? else {
                    self.terminal_without_delivery(
                        tx,
                        &context,
                        SecurityMailTerminal::Cancelled,
                        now,
                    )?;
                    return Ok(None);
                };
                let Some(envelope) = context.envelope.as_ref() else {
                    return Err(AccessError::InvalidStoreResponse);
                };
                let payload = match self.crypto.open(
                    SecurityEnvelopePurpose::RecoveryEmail,
                    &SecurityCryptoContext {
                        reference_id: context.outbox_id,
                        related_id: Some(context.flow_id),
                    },
                    envelope,
                ) {
                    Ok(payload) => payload,
                    Err(SecurityCryptoError::InvalidCiphertext) => {
                        self.reject_corrupt(tx, &context, now)?;
                        return Ok(None);
                    }
                    Err(_) => return Err(crypto_error()),
                };
                let Some((recipient, code)) = parse_mail_payload(&payload) else {
                    self.reject_corrupt(tx, &context, now)?;
                    return Ok(None);
                };
                if recipient != account.email.expose_secret() {
                    self.reject_corrupt(tx, &context, now)?;
                    return Ok(None);
                }
                let matches = match self.crypto.verify_digest(
                    SecurityDigestPurpose::RecoveryCode,
                    &SecurityCryptoContext {
                        reference_id: context.flow_id,
                        related_id: None,
                    },
                    code.as_bytes(),
                    &context.flow.code_digest,
                ) {
                    Ok(matches) => matches,
                    Err(_) => return Err(crypto_error()),
                };
                if !matches {
                    self.reject_corrupt(tx, &context, now)?;
                    return Ok(None);
                }
                let lease_token = self.next_id("security_email_lease")?;
                let lease_until = now
                    .checked_add(LEASE_TTL)
                    .ok_or(AccessError::InvalidStoreResponse)?;
                if !tx.transition(
                    context.outbox_id,
                    None,
                    SecurityMailTransition::Sending {
                        lease_token,
                        lease_until,
                    },
                    None,
                    now,
                )? {
                    return Ok(None);
                }
                Ok(Some(SecurityMailClaim {
                    outbox_id: context.outbox_id,
                    flow_id: context.flow_id,
                    lease_token,
                    lease_until,
                    expires_at: context.expires_at,
                    recipient: SecretString::new(recipient),
                    code: SecretString::new(code),
                }))
            })
    }

    fn finish(&self, completion: SecurityMailCompletion) -> Result<bool, AccessError> {
        if completion.outbox_id.is_nil() || completion.lease_token.is_nil() {
            return Err(AccessError::InvalidInput("completion"));
        }
        self.store
            .security_outbox_transaction(self.mode, self.crypto.authority(), |tx| {
                let Some(context) = tx.current(completion.outbox_id)? else {
                    return Ok(false);
                };
                validate_context(&context)?;
                if context.state != SecurityMailState::Sending
                    || context.lease_token != Some(completion.lease_token)
                {
                    return Ok(false);
                }
                let now = sample_time(self.clock.now())?;
                if now < context.created_at {
                    return Err(AccessError::InvalidStoreResponse);
                }
                let Some(lease_until) = context.lease_until else {
                    return Err(AccessError::InvalidStoreResponse);
                };
                if now >= lease_until {
                    return self.finish_terminal(
                        tx,
                        &context,
                        SecurityMailTerminal::Unknown,
                        Some(SecurityMailOutcome::Unknown),
                        now,
                    );
                }

                let valid = context.expires_at > now
                    && context.flow.expires_at > now
                    && flow_is_usable(&context)
                    && eligible_account(&context)?.is_some();
                if !valid {
                    let terminal = if context.expires_at <= now || context.flow.expires_at <= now {
                        SecurityMailTerminal::Expired
                    } else {
                        SecurityMailTerminal::Cancelled
                    };
                    return self.finish_terminal(
                        tx,
                        &context,
                        terminal,
                        Some(completion.outcome),
                        now,
                    );
                }

                match completion.outcome {
                    SecurityMailOutcome::Accepted => self.finish_terminal(
                        tx,
                        &context,
                        SecurityMailTerminal::Accepted,
                        Some(SecurityMailOutcome::Accepted),
                        now,
                    ),
                    SecurityMailOutcome::Rejected => self.finish_terminal(
                        tx,
                        &context,
                        SecurityMailTerminal::Rejected,
                        Some(SecurityMailOutcome::Rejected),
                        now,
                    ),
                    SecurityMailOutcome::Unknown => self.finish_terminal(
                        tx,
                        &context,
                        SecurityMailTerminal::Unknown,
                        Some(SecurityMailOutcome::Unknown),
                        now,
                    ),
                    SecurityMailOutcome::NotStarted => {
                        let retry_at = now.checked_add(RETRY_DELAY);
                        if context.attempts < 3
                            && retry_at.is_some_and(|next| next < context.expires_at)
                        {
                            let event_id = self.next_id("evt")?;
                            Ok(tx.transition(
                                context.outbox_id,
                                Some(completion.lease_token),
                                SecurityMailTransition::Retry {
                                    next_attempt_at: retry_at.unwrap(),
                                },
                                Some(event_id),
                                now,
                            )?)
                        } else {
                            self.finish_terminal(
                                tx,
                                &context,
                                SecurityMailTerminal::Cancelled,
                                Some(SecurityMailOutcome::NotStarted),
                                now,
                            )
                        }
                    }
                }
            })
    }

    fn cleanup(&self) -> Result<SecurityCleanupResult, AccessError> {
        self.store
            .security_outbox_transaction(self.mode, self.crypto.authority(), |tx| {
                let now = sample_time(self.clock.now())?;
                let mut event_ids = Vec::with_capacity(MAX_CLEANUP as usize);
                for _ in 0..MAX_CLEANUP {
                    let id = self.next_id("evt")?;
                    if event_ids.contains(&id) {
                        return Err(AccessError::InvalidStoreResponse);
                    }
                    event_ids.push(id);
                }
                let processed = tx.cleanup(now, MAX_CLEANUP, &event_ids)?;
                if processed > MAX_CLEANUP {
                    return Err(AccessError::InvalidStoreResponse);
                }
                Ok(SecurityCleanupResult { processed })
            })
    }
}

impl<S, C, K, I> CoreSecurityOutboxService<S, C, K, I>
where
    I: IdGenerator,
{
    fn next_id(&self, prefix: &str) -> Result<Uuid, AccessError> {
        let value = self.ids.next_id(prefix);
        Uuid::parse_str(&value)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == value)
            .ok_or(AccessError::InvalidStoreResponse)
    }

    fn terminal_without_delivery<T: SecurityOutboxTransaction>(
        &self,
        tx: &mut T,
        context: &SecurityMailContext,
        state: SecurityMailTerminal,
        now: SystemTime,
    ) -> Result<(), AccessError> {
        tx.transition(
            context.outbox_id,
            None,
            SecurityMailTransition::Terminal {
                state,
                outcome: Some(SecurityMailOutcome::NotStarted),
            },
            None,
            now,
        )?;
        Ok(())
    }

    fn reject_corrupt<T: SecurityOutboxTransaction>(
        &self,
        tx: &mut T,
        context: &SecurityMailContext,
        now: SystemTime,
    ) -> Result<(), AccessError> {
        let event_id = self.next_id("evt")?;
        tx.transition(
            context.outbox_id,
            None,
            SecurityMailTransition::Terminal {
                state: SecurityMailTerminal::Rejected,
                outcome: Some(SecurityMailOutcome::Rejected),
            },
            Some(event_id),
            now,
        )?;
        Ok(())
    }

    fn finish_terminal<T: SecurityOutboxTransaction>(
        &self,
        tx: &mut T,
        context: &SecurityMailContext,
        state: SecurityMailTerminal,
        outcome: Option<SecurityMailOutcome>,
        now: SystemTime,
    ) -> Result<bool, AccessError> {
        let event_id = self.next_id("evt")?;
        let transitioned = tx.transition(
            context.outbox_id,
            context.lease_token,
            SecurityMailTransition::Terminal { state, outcome },
            Some(event_id),
            now,
        )?;
        Ok(transitioned)
    }
}

fn sample_time(now: SystemTime) -> Result<SystemTime, AccessError> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AccessError::InvalidStoreResponse)?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(AccessError::InvalidStoreResponse)
}

fn validate_context(context: &SecurityMailContext) -> Result<(), AccessError> {
    if context.outbox_id.is_nil()
        || context.flow_id.is_nil()
        || context.flow.id != context.flow_id
        || context.flow.id.is_nil()
        || context.flow.created_at < UNIX_EPOCH
        || context.created_at != context.flow.created_at
        || context.flow.expires_at <= context.flow.created_at
        || context
            .flow
            .created_at
            .checked_add(FLOW_TTL)
            .is_none_or(|max| context.flow.expires_at > max)
        || context
            .flow
            .retained_until
            .duration_since(context.flow.created_at)
            .ok()
            != Some(FLOW_RETENTION)
        || context.flow.account_id.is_some() != context.flow.snapshot_credential_version.is_some()
        || context
            .flow
            .snapshot_credential_version
            .is_some_and(|v| v == 0 || v > i64::MAX as u64)
        || context.failed_attempts > MAX_FLOW_FAILURES
        || context.attempts > 3
        || context.created_at < UNIX_EPOCH
        || context.expires_at <= context.created_at
        || context
            .created_at
            .checked_add(FLOW_TTL)
            .is_none_or(|max| context.expires_at > max)
        || context.expires_at != context.flow.expires_at
        || context.next_attempt_at < context.created_at
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    match context.state {
        SecurityMailState::Pending => {
            if context.attempts >= 3
                || context.lease_token.is_some()
                || context.lease_until.is_some()
                || context.envelope.is_none()
            {
                return Err(AccessError::InvalidStoreResponse);
            }
        }
        SecurityMailState::Sending => {
            if context.attempts == 0
                || context.lease_token.is_none_or(|id| id.is_nil())
                || context.lease_until.is_none_or(|t| t <= context.created_at)
                || context.envelope.is_none()
            {
                return Err(AccessError::InvalidStoreResponse);
            }
        }
        _ => {
            if context.lease_token.is_some()
                || context.lease_until.is_some()
                || context.envelope.is_some()
            {
                return Err(AccessError::InvalidStoreResponse);
            }
        }
    }
    if let Some(account) = &context.account {
        if account.account_id.is_nil()
            || account.credential_version == 0
            || account.credential_version > i64::MAX as u64
            || context.flow.account_id != Some(account.account_id)
        {
            return Err(AccessError::InvalidStoreResponse);
        }
    } else if context.flow.account_id.is_none() {
        // A dummy flow has no account projection, which is valid.
    }
    Ok(())
}

fn flow_is_usable(context: &SecurityMailContext) -> bool {
    context.flow_state == RecoveryFlowState::Pending && context.failed_attempts < MAX_FLOW_FAILURES
}

fn eligible_account(
    context: &SecurityMailContext,
) -> Result<Option<&RecoveryAccountSnapshot>, AccessError> {
    let Some(account) = context.account.as_ref() else {
        return Ok(None);
    };
    if context.flow.account_id != Some(account.account_id) {
        return Err(AccessError::InvalidStoreResponse);
    }
    if context.flow.snapshot_credential_version != Some(account.credential_version)
        || !account.active
        || !account.has_active_membership
        || account.has_effective_security_admin
    {
        return Ok(None);
    }
    Ok(Some(account))
}

fn parse_mail_payload(payload: &SecretString) -> Option<(String, String)> {
    let mut lines = payload.expose_secret().split('\n');
    if lines.next()? != "recovery-email-v1" {
        return None;
    }
    let email = lines.next()?;
    let code = lines.next()?;
    if lines.next().is_some()
        || email.is_empty()
        || email.len() > 254
        || email.chars().any(char::is_control)
        || code.len() != 6
        || !code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((email.to_owned(), code.to_owned()))
}

fn crypto_error() -> AccessError {
    AccessError::Store(StoreError::Backend(CRYPTO_BACKEND.into()))
}

#[cfg(test)]
#[path = "security_outbox_tests.rs"]
mod tests;

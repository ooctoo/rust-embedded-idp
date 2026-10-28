use super::{query::validate_id, AccessActor, AccessError, TenancyMode, TenantSession};
use crate::{
    AccountSecurityCrypto, Clock, IdGenerator, SecretString, SecurityCryptoContext,
    SecurityCryptoError, SecurityDigest, SecurityDigestPurpose, StoreError,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

const RECEIPT_TTL: Duration = Duration::from_secs(86_400);
const RECEIPT_CAPACITY: u64 = 100_000;
const COMMAND_DOMAIN: &[u8] = b"embedded-idp/self-session-revoke/v1";
const CRYPTO_BACKEND: &str = "account security crypto unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityReceiptPurpose {
    SessionRevoke,
    PasswordChange,
    PasswordRecovery,
}

impl SecurityReceiptPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionRevoke => "session_revoke",
            Self::PasswordChange => "password_change",
            Self::PasswordRecovery => "password_recovery",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityOperationReceipt {
    pub purpose: SecurityReceiptPurpose,
    pub operation_id: Uuid,
    pub account_id: String,
    pub secret_digest: SecurityDigest,
    pub command_digest: SecurityDigest,
    pub completed_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct SecurityReceiptQuery {
    pub operation_id: Uuid,
    pub receipt_secret: SecretString,
}

#[derive(Debug, Clone)]
pub struct SelfSessionRevokeCommand {
    pub target_tenant_id: String,
    pub target_session_id: String,
    pub operation_id: Uuid,
    pub receipt_secret: SecretString,
}

pub trait SelfSessionRevocationService: Send + Sync {
    fn revoke_session(
        &self,
        actor: AccessActor,
        command: SelfSessionRevokeCommand,
    ) -> Result<(), AccessError>;

    fn session_revocation_result(&self, query: SecurityReceiptQuery) -> Result<bool, AccessError>;
}

pub trait SelfSessionMutationTransaction {
    fn actor_is_active(&mut self, actor: &AccessActor, now: SystemTime)
        -> Result<bool, StoreError>;
    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError>;
    fn receipt_count(&mut self) -> Result<u64, StoreError>;
    fn owned_session(
        &mut self,
        actor: &AccessActor,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<Option<TenantSession>, StoreError>;
    fn revoke_session_credentials(
        &mut self,
        actor: &AccessActor,
        tenant_id: &str,
        session_id: &str,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    fn record_completion(
        &mut self,
        receipt: &SecurityOperationReceipt,
        event_id: Uuid,
    ) -> Result<(), StoreError>;
}

pub trait SelfSessionMutationStore: Send + Sync {
    type Transaction<'a>: SelfSessionMutationTransaction
    where
        Self: 'a;

    fn self_session_mutation<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: Option<&AccessActor>,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;
}

pub struct CoreSelfSessionRevocationService<S, C, K, I> {
    mode: TenancyMode,
    store: S,
    clock: C,
    crypto: K,
    ids: I,
}

impl<S, C, K, I> CoreSelfSessionRevocationService<S, C, K, I> {
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

impl<S, C, K, I> SelfSessionRevocationService for CoreSelfSessionRevocationService<S, C, K, I>
where
    S: SelfSessionMutationStore,
    C: Clock + Send + Sync,
    K: AccountSecurityCrypto,
    I: IdGenerator + Send + Sync,
{
    fn revoke_session(
        &self,
        actor: AccessActor,
        command: SelfSessionRevokeCommand,
    ) -> Result<(), AccessError> {
        validate_actor(self.mode, &actor)?;
        validate_target(self.mode, &command)?;
        let secret = parse_receipt_secret(&command.receipt_secret)?;
        let subject = parse_canonical_nonnil_uuid(&actor.subject_id)
            .ok_or(AccessError::InvalidInput("actor_subject_id"))?;
        let actor_session = parse_canonical_nonnil_uuid(&actor.session_id)
            .ok_or(AccessError::InvalidInput("actor_session_id"))?;

        self.store
            .self_session_mutation(self.mode, self.crypto.authority(), Some(&actor), |tx| {
                let now = self.clock.now();
                if !tx.actor_is_active(&actor, now)? {
                    return Err(AccessError::Forbidden);
                }
                if let Some(receipt) =
                    tx.receipt(SecurityReceiptPurpose::SessionRevoke, command.operation_id)?
                {
                    validate_receipt(
                        &receipt,
                        SecurityReceiptPurpose::SessionRevoke,
                        command.operation_id,
                        now,
                    )?;
                    if receipt.account_id != actor.subject_id || receipt.expires_at <= now {
                        return Err(operation_conflict());
                    }
                    if !self.verify_secret(&receipt.secret_digest, command.operation_id, &secret)?
                        || !self.verify_command(
                            &receipt.command_digest,
                            command.operation_id,
                            subject,
                            &actor,
                            &command,
                            actor_session,
                        )?
                    {
                        return Err(operation_conflict());
                    }
                    return Ok(());
                }

                let target = tx
                    .owned_session(
                        &actor,
                        &command.target_tenant_id,
                        &command.target_session_id,
                    )?
                    .ok_or(AccessError::NotFound("session"))?;
                validate_owned_session(
                    &target,
                    &actor,
                    &command.target_tenant_id,
                    &command.target_session_id,
                )?;
                if tx.receipt_count()? >= RECEIPT_CAPACITY {
                    return Err(AccessError::Conflict("security.receipt_capacity"));
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
                        &secret,
                    )
                    .map_err(crypto_error)?;
                let command_payload = command_payload(&actor, &command, subject, actor_session)?;
                let command_digest = self
                    .crypto
                    .digest(
                        SecurityDigestPurpose::Command,
                        &SecurityCryptoContext {
                            reference_id: command.operation_id,
                            related_id: Some(subject),
                        },
                        &command_payload,
                    )
                    .map_err(crypto_error)?;
                let event_id = self.ids.next_id("evt");
                let event_id = parse_canonical_uuid(&event_id)
                    .filter(|id| !id.is_nil())
                    .ok_or(AccessError::InvalidStoreResponse)?;
                let receipt = SecurityOperationReceipt {
                    purpose: SecurityReceiptPurpose::SessionRevoke,
                    operation_id: command.operation_id,
                    account_id: actor.subject_id.clone(),
                    secret_digest,
                    command_digest,
                    completed_at: now,
                    expires_at,
                };
                tx.revoke_session_credentials(
                    &actor,
                    &command.target_tenant_id,
                    &command.target_session_id,
                    now,
                )?;
                tx.record_completion(&receipt, event_id)?;
                Ok(())
            })
    }

    fn session_revocation_result(&self, query: SecurityReceiptQuery) -> Result<bool, AccessError> {
        if query.operation_id.is_nil() {
            return Err(AccessError::InvalidInput("operation_id"));
        }
        let secret = parse_receipt_secret(&query.receipt_secret)?;
        self.store
            .self_session_mutation(self.mode, self.crypto.authority(), None, |tx| {
                let now = self.clock.now();
                let Some(receipt) =
                    tx.receipt(SecurityReceiptPurpose::SessionRevoke, query.operation_id)?
                else {
                    return Ok(false);
                };
                validate_receipt(
                    &receipt,
                    SecurityReceiptPurpose::SessionRevoke,
                    query.operation_id,
                    now,
                )?;
                if receipt.expires_at <= now {
                    return Ok(false);
                }
                self.verify_secret(&receipt.secret_digest, query.operation_id, &secret)
            })
    }
}

impl<S, C, K, I> CoreSelfSessionRevocationService<S, C, K, I>
where
    K: AccountSecurityCrypto,
{
    fn verify_secret(
        &self,
        stored: &SecurityDigest,
        operation_id: Uuid,
        secret: &[u8; 32],
    ) -> Result<bool, AccessError> {
        self.crypto
            .verify_digest(
                SecurityDigestPurpose::ReceiptSecret,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: None,
                },
                secret,
                stored,
            )
            .map_err(crypto_error)
    }

    fn verify_command(
        &self,
        stored: &SecurityDigest,
        operation_id: Uuid,
        subject: Uuid,
        actor: &AccessActor,
        command: &SelfSessionRevokeCommand,
        actor_session: Uuid,
    ) -> Result<bool, AccessError> {
        let payload = command_payload(actor, command, subject, actor_session)?;
        self.crypto
            .verify_digest(
                SecurityDigestPurpose::Command,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: Some(subject),
                },
                &payload,
                stored,
            )
            .map_err(crypto_error)
    }
}

fn validate_actor(mode: TenancyMode, actor: &AccessActor) -> Result<(), AccessError> {
    actor.validate(mode)?;
    if parse_canonical_nonnil_uuid(&actor.subject_id).is_none()
        || parse_canonical_nonnil_uuid(&actor.session_id).is_none()
    {
        return Err(AccessError::InvalidInput("actor"));
    }
    Ok(())
}

fn validate_target(
    mode: TenancyMode,
    command: &SelfSessionRevokeCommand,
) -> Result<(), AccessError> {
    validate_id(&command.target_tenant_id, 128, "tenant")?;
    if mode == TenancyMode::Disabled && command.target_tenant_id != "0" {
        return Err(AccessError::ModeMismatch);
    }
    if parse_canonical_nonnil_uuid(&command.target_session_id).is_none() {
        return Err(AccessError::InvalidInput("target_session_id"));
    }
    if command.operation_id.is_nil() {
        return Err(AccessError::InvalidInput("operation_id"));
    }
    Ok(())
}

fn validate_owned_session(
    session: &TenantSession,
    actor: &AccessActor,
    tenant_id: &str,
    session_id: &str,
) -> Result<(), AccessError> {
    if session.tenant_id != tenant_id
        || session.id != session_id
        || session.account_id != actor.subject_id
        || validate_id(&session.tenant_id, 128, "tenant").is_err()
        || parse_canonical_nonnil_uuid(&session.id).is_none()
        || parse_canonical_nonnil_uuid(&session.account_id).is_none()
        || session.created_at < std::time::UNIX_EPOCH
        || session.expires_at <= session.created_at
        || session.authenticated_at > session.created_at
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn parse_canonical_uuid(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| id.to_string() == value)
}

fn parse_canonical_nonnil_uuid(value: &str) -> Option<Uuid> {
    parse_canonical_uuid(value).filter(|id| !id.is_nil())
}

fn parse_receipt_secret(secret: &SecretString) -> Result<[u8; 32], AccessError> {
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

fn validate_receipt(
    receipt: &SecurityOperationReceipt,
    purpose: SecurityReceiptPurpose,
    operation_id: Uuid,
    now: SystemTime,
) -> Result<(), AccessError> {
    if receipt.purpose != purpose
        || receipt.operation_id != operation_id
        || parse_canonical_nonnil_uuid(&receipt.account_id).is_none()
        || receipt.completed_at < std::time::UNIX_EPOCH
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

fn command_payload(
    actor: &AccessActor,
    command: &SelfSessionRevokeCommand,
    subject: Uuid,
    actor_session: Uuid,
) -> Result<Vec<u8>, AccessError> {
    let mut payload = Vec::with_capacity(128);
    push_field(&mut payload, COMMAND_DOMAIN)?;
    push_field(&mut payload, actor.tenant_id.as_bytes())?;
    push_field(&mut payload, subject.as_bytes())?;
    push_field(&mut payload, actor_session.as_bytes())?;
    push_field(&mut payload, command.target_tenant_id.as_bytes())?;
    let target_session = parse_canonical_nonnil_uuid(&command.target_session_id)
        .ok_or(AccessError::InvalidInput("target_session_id"))?;
    push_field(&mut payload, target_session.as_bytes())?;
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

fn operation_conflict() -> AccessError {
    AccessError::Conflict("security.operation_conflict")
}

fn crypto_error(_: SecurityCryptoError) -> AccessError {
    AccessError::Store(StoreError::Backend(CRYPTO_BACKEND.into()))
}

#[cfg(test)]
#[path = "self_session_revocation_tests.rs"]
mod tests;

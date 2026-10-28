use super::{self_session_revocation::*, AccessActor, AccessError, TenancyMode};
use crate::service::password::{
    hash_password, validate_registration_password, verify_password_or_dummy,
};
use crate::{
    AccountSecurityCrypto, AuthConfig, Clock, ConfigValidationError, IdGenerator,
    PasswordWorkBudget, SecretString, SecurityCryptoContext, SecurityCryptoError, SecurityDigest,
    SecurityDigestPurpose, StoreError,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const RECEIPT_TTL: Duration = Duration::from_secs(86_400);
const RECEIPT_CAPACITY: u64 = 100_000;
const COMMAND_DOMAIN: &[u8] = b"embedded-idp/self-password-change/v1";
const CRYPTO_BACKEND: &str = "account security crypto unavailable";

#[derive(Debug, Clone)]
pub struct SelfPasswordChangeCommand {
    pub current_password: SecretString,
    pub new_password: SecretString,
    pub operation_id: Uuid,
    pub receipt_secret: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfPasswordChangeError {
    InvalidCredentials,
    Access(AccessError),
}

impl From<AccessError> for SelfPasswordChangeError {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}

impl From<StoreError> for SelfPasswordChangeError {
    fn from(error: StoreError) -> Self {
        Self::Access(AccessError::from(error))
    }
}

pub trait SelfPasswordChangeService: Send + Sync {
    fn change_password(
        &self,
        actor: AccessActor,
        command: SelfPasswordChangeCommand,
    ) -> Result<(), SelfPasswordChangeError>;

    fn password_change_result(
        &self,
        query: SecurityReceiptQuery,
    ) -> Result<bool, SelfPasswordChangeError>;
}

#[derive(Clone)]
pub struct SelfPasswordCredentialSnapshot {
    pub account_id: String,
    pub password_hash: SecretString,
    pub credential_version: u64,
}

pub trait SelfPasswordChangeReadTransaction {
    fn actor_is_active(&mut self, actor: &AccessActor, now: SystemTime)
        -> Result<bool, StoreError>;
    fn credential_snapshot(
        &mut self,
        actor: &AccessActor,
    ) -> Result<Option<SelfPasswordCredentialSnapshot>, StoreError>;
    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError>;
}

pub trait SelfPasswordChangeWriteTransaction: SelfPasswordChangeReadTransaction {
    fn receipt_count(&mut self) -> Result<u64, StoreError>;
    fn replace_password_and_retire(
        &mut self,
        actor: &AccessActor,
        snapshot: &SelfPasswordCredentialSnapshot,
        new_password_hash: &SecretString,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    fn record_completion(
        &mut self,
        receipt: &SecurityOperationReceipt,
        event_id: Uuid,
    ) -> Result<(), StoreError>;
}

pub trait SelfPasswordChangeStore: Send + Sync {
    type ReadTransaction<'a>: SelfPasswordChangeReadTransaction
    where
        Self: 'a;
    type WriteTransaction<'a>: SelfPasswordChangeWriteTransaction
    where
        Self: 'a;

    fn password_change_read<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: Option<&AccessActor>,
        run: impl FnOnce(&mut Self::ReadTransaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;

    fn password_change_write<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: &AccessActor,
        run: impl FnOnce(&mut Self::WriteTransaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;
}

pub struct CoreSelfPasswordChangeService<S, C, K, I> {
    mode: TenancyMode,
    store: S,
    clock: C,
    crypto: K,
    ids: I,
    config: AuthConfig,
    password_work: PasswordWorkBudget,
}

impl<S, C, K, I> CoreSelfPasswordChangeService<S, C, K, I> {
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

impl<S, C, K, I> SelfPasswordChangeService for CoreSelfPasswordChangeService<S, C, K, I>
where
    S: SelfPasswordChangeStore,
    C: Clock + Send + Sync,
    K: AccountSecurityCrypto,
    I: IdGenerator + Send + Sync,
{
    fn change_password(
        &self,
        actor: AccessActor,
        command: SelfPasswordChangeCommand,
    ) -> Result<(), SelfPasswordChangeError> {
        validate_actor(self.mode, &actor)?;
        if command.operation_id.is_nil() {
            return Err(AccessError::InvalidInput("operation_id").into());
        }
        if command.current_password.expose_secret().is_empty()
            || command.current_password.expose_secret().chars().count()
                > self.config.password_max_length
        {
            return Err(SelfPasswordChangeError::InvalidCredentials);
        }
        validate_registration_password(&self.config, command.new_password.expose_secret())
            .map_err(|_| AccessError::InvalidInput("password"))?;
        let secret = parse_receipt_secret(&command.receipt_secret)?;
        let subject = parse_canonical_nonnil_uuid(&actor.subject_id)
            .ok_or(AccessError::InvalidInput("actor_subject_id"))?;
        let actor_session = parse_canonical_nonnil_uuid(&actor.session_id)
            .ok_or(AccessError::InvalidInput("actor_session_id"))?;

        let initial = self.store.password_change_read(
            self.mode,
            self.crypto.authority(),
            Some(&actor),
            |tx| {
                let now = self.clock.now();
                if !tx.actor_is_active(&actor, now)? {
                    return Err(AccessError::Forbidden);
                }
                if let Some(receipt) =
                    tx.receipt(SecurityReceiptPurpose::PasswordChange, command.operation_id)?
                {
                    self.validate_replay(
                        &receipt,
                        &actor,
                        subject,
                        actor_session,
                        &command,
                        command.operation_id,
                        &secret,
                        now,
                    )?;
                    return Ok(None);
                }
                let snapshot = tx
                    .credential_snapshot(&actor)?
                    .ok_or(AccessError::InvalidStoreResponse)?;
                validate_snapshot(&snapshot, &actor)?;
                Ok(Some(snapshot))
            },
        )?;
        let Some(initial) = initial else {
            return Ok(());
        };

        let permit = self.password_work.try_login().map_err(AccessError::from)?;
        let current_valid = verify_password_or_dummy(
            Some(initial.password_hash.expose_secret()),
            command.current_password.expose_secret(),
        )
        .map_err(AccessError::from)?;
        if !current_valid {
            return Err(SelfPasswordChangeError::InvalidCredentials);
        }
        let new_hash = SecretString::new(
            hash_password(command.new_password.expose_secret()).map_err(AccessError::from)?,
        );
        drop(permit);

        self.store
            .password_change_write(self.mode, self.crypto.authority(), &actor, |tx| {
                let now = self.clock.now();
                if !tx.actor_is_active(&actor, now)? {
                    return Err(AccessError::Forbidden);
                }
                if let Some(receipt) =
                    tx.receipt(SecurityReceiptPurpose::PasswordChange, command.operation_id)?
                {
                    self.validate_replay(
                        &receipt,
                        &actor,
                        subject,
                        actor_session,
                        &command,
                        command.operation_id,
                        &secret,
                        now,
                    )?;
                    return Ok(());
                }

                let current = tx
                    .credential_snapshot(&actor)?
                    .ok_or(AccessError::InvalidStoreResponse)?;
                validate_snapshot(&current, &actor)?;
                if !snapshots_match(&initial, &current) {
                    return Err(AccessError::Conflict("security.credentials_changed"));
                }
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
                let command_digest = self
                    .crypto
                    .digest(
                        SecurityDigestPurpose::Command,
                        &SecurityCryptoContext {
                            reference_id: command.operation_id,
                            related_id: Some(subject),
                        },
                        &command_payload(&actor, subject, actor_session, &command.new_password)?,
                    )
                    .map_err(crypto_error)?;
                let event_id = self.ids.next_id("evt");
                let event_id = parse_canonical_nonnil_uuid(&event_id)
                    .ok_or(AccessError::InvalidStoreResponse)?;
                let receipt = SecurityOperationReceipt {
                    purpose: SecurityReceiptPurpose::PasswordChange,
                    operation_id: command.operation_id,
                    account_id: actor.subject_id.clone(),
                    secret_digest,
                    command_digest,
                    completed_at: now,
                    expires_at,
                };

                tx.replace_password_and_retire(&actor, &current, &new_hash, now)?;
                tx.record_completion(&receipt, event_id)?;
                Ok(())
            })?;
        Ok(())
    }

    fn password_change_result(
        &self,
        query: SecurityReceiptQuery,
    ) -> Result<bool, SelfPasswordChangeError> {
        if query.operation_id.is_nil() {
            return Err(AccessError::InvalidInput("operation_id").into());
        }
        let secret = parse_receipt_secret(&query.receipt_secret)?;
        self.store
            .password_change_read(self.mode, self.crypto.authority(), None, |tx| {
                let now = self.clock.now();
                let Some(receipt) =
                    tx.receipt(SecurityReceiptPurpose::PasswordChange, query.operation_id)?
                else {
                    return Ok(false);
                };
                validate_receipt(
                    &receipt,
                    SecurityReceiptPurpose::PasswordChange,
                    query.operation_id,
                    now,
                )?;
                if receipt.expires_at <= now {
                    return Ok(false);
                }
                self.verify_secret(&receipt.secret_digest, query.operation_id, &secret)
            })
            .map_err(SelfPasswordChangeError::from)
    }
}

impl<S, C, K, I> CoreSelfPasswordChangeService<S, C, K, I>
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

    fn validate_replay(
        &self,
        receipt: &SecurityOperationReceipt,
        actor: &AccessActor,
        subject: Uuid,
        actor_session: Uuid,
        command: &SelfPasswordChangeCommand,
        operation_id: Uuid,
        secret: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), AccessError> {
        validate_receipt(
            receipt,
            SecurityReceiptPurpose::PasswordChange,
            operation_id,
            now,
        )?;
        if receipt.account_id != actor.subject_id || receipt.expires_at <= now {
            return Err(operation_conflict());
        }
        if !self.verify_secret(&receipt.secret_digest, operation_id, secret)? {
            return Err(operation_conflict());
        }
        let payload = command_payload(actor, subject, actor_session, &command.new_password)?;
        let matches = self
            .crypto
            .verify_digest(
                SecurityDigestPurpose::Command,
                &SecurityCryptoContext {
                    reference_id: operation_id,
                    related_id: Some(subject),
                },
                &payload,
                &receipt.command_digest,
            )
            .map_err(crypto_error)?;
        if !matches {
            return Err(operation_conflict());
        }
        Ok(())
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

fn validate_snapshot(
    snapshot: &SelfPasswordCredentialSnapshot,
    actor: &AccessActor,
) -> Result<(), AccessError> {
    if snapshot.account_id != actor.subject_id
        || parse_canonical_nonnil_uuid(&snapshot.account_id).is_none()
        || snapshot.password_hash.expose_secret().is_empty()
        || snapshot.credential_version == 0
    {
        return Err(AccessError::InvalidStoreResponse);
    }
    Ok(())
}

fn snapshots_match(
    expected: &SelfPasswordCredentialSnapshot,
    actual: &SelfPasswordCredentialSnapshot,
) -> bool {
    expected.account_id == actual.account_id
        && expected.password_hash.expose_secret() == actual.password_hash.expose_secret()
        && expected.credential_version == actual.credential_version
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

fn command_payload(
    actor: &AccessActor,
    subject: Uuid,
    actor_session: Uuid,
    new_password: &SecretString,
) -> Result<Vec<u8>, AccessError> {
    let mut payload = Vec::with_capacity(128 + new_password.expose_secret().len());
    push_field(&mut payload, COMMAND_DOMAIN)?;
    push_field(&mut payload, actor.tenant_id.as_bytes())?;
    push_field(&mut payload, subject.as_bytes())?;
    push_field(&mut payload, actor_session.as_bytes())?;
    push_field(&mut payload, new_password.expose_secret().as_bytes())?;
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
#[path = "self_password_change_tests.rs"]
mod tests;

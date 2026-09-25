use std::time::{Duration, SystemTime};

use super::{
    AccessError, MembershipStatus, TenancyMode, Tenant, TenantMembership, TenantRegistration,
    TenantRegistrationStore, TenantStatus,
};
use crate::service::{
    contracts::is_valid_email,
    password::{hash_password, validate_registration_password},
};
use crate::{
    Account, AccountStatus, AuthConfig, Clock, ConfigValidationError, ContractValidationError,
    EmailVerificationCode, IdGenerator, SecretString, StoreError, VerificationCodeGenerator,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterTenantAccountCommand {
    pub tenant_id: String,
    pub email: String,
    pub password: SecretString,
    pub display_name: Option<String>,
}

/// Trusted host delivery result. Send the code through the email adapter, never
/// return it in a public registration response. Contains no password hash or token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRegistrationResult {
    pub tenant_id: String,
    pub account_id: String,
    pub email: String,
    pub verification_code: SecretString,
    pub verification_expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyTenantEmailCommand {
    pub tenant_id: String,
    pub email: String,
    pub verification_code: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResendTenantVerificationCommand {
    pub tenant_id: String,
    pub email: String,
}

/// A locked account and its membership in the requested registration tenant.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantVerificationAccount {
    pub account_id: String,
    pub email: String,
    pub registration_tenant_id: String,
    pub tenant: Tenant,
    pub membership: TenantMembership,
    pub pending_verification: bool,
}

/// Verification activates the identity only. Login must independently validate
/// the chosen tenant and create its session; verification grants no session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantEmailVerificationResult {
    pub tenant_id: String,
    pub account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantRegistrationError {
    Access(AccessError),
    InvalidContract(ContractValidationError),
    RegistrationDisabled,
    InvalidVerificationCode,
    VerificationCodeExpired,
    Store(StoreError),
}
impl From<StoreError> for TenantRegistrationError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
impl From<AccessError> for TenantRegistrationError {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}

/// A locked projection; non-pending accounts include active, disabled and closed.
/// The backend must not decode a closed account as an active account.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantEmailVerificationState {
    pub registration_tenant_id: String,
    pub tenant: Tenant,
    pub membership: TenantMembership,
    pub account_pending_verification: bool,
    pub verification: EmailVerificationCode,
}

pub trait TenantEmailVerificationTransaction {
    /// Same tenant -> account -> membership locking as verification; never loads
    /// another tenant's membership. None also covers a missing tenant/account.
    fn load_verification_account(
        &mut self,
        email: &str,
    ) -> Result<Option<TenantVerificationAccount>, StoreError>;
    /// Under the account lock, retire previous unconsumed records in this tenant
    /// and insert the replacement. An insert failure rolls back retirement too.
    fn replace_verification(&mut self, code: &EmailVerificationCode) -> Result<(), StoreError>;
    /// Lock the account identified by email, then load ONLY the transaction's
    /// tenant membership and matching code. No account/member/code means None.
    /// Account lock serializes verification in different tenants for one identity.
    fn load_verification(
        &mut self,
        email: &str,
        code: &str,
    ) -> Result<Option<TenantEmailVerificationState>, StoreError>;
    /// Atomically consume this tenant's unconsumed code and change a pending
    /// account to active. Compare expected state; failure must roll back both.
    fn activate_verified_account(
        &mut self,
        account_id: &str,
        verification_id: &str,
        now: SystemTime,
    ) -> Result<(), StoreError>;
}

pub trait TenantRegistrationService: Send + Sync {
    fn tenancy_mode(&self) -> TenancyMode;
    fn register_account(
        &self,
        command: RegisterTenantAccountCommand,
    ) -> Result<TenantRegistrationResult, TenantRegistrationError>;
    fn verify_email(
        &self,
        command: VerifyTenantEmailCommand,
    ) -> Result<TenantEmailVerificationResult, TenantRegistrationError>;
    /// None means no eligible pending account. Public HTTP must give the same
    /// response for None and a delivered result, without account metadata.
    fn resend_verification(
        &self,
        command: ResendTenantVerificationCommand,
    ) -> Result<Option<TenantRegistrationResult>, TenantRegistrationError>;
}

pub trait TenantEmailVerificationStore: Send + Sync {
    type Transaction<'a>: TenantEmailVerificationTransaction
    where
        Self: 'a;
    /// Read Committed: verify configured/persisted mode + bootstrap; shared state
    /// lock, then shared tenant lock BEFORE callback (including inactive tenants).
    /// Commit only on Ok; any error or panic rolls back. No tokens/devices issued.
    fn verification_transaction<T, F>(
        &self,
        tenant_id: &str,
        operation: F,
    ) -> Result<T, TenantRegistrationError>
    where
        F: FnOnce(&mut Self::Transaction<'_>) -> Result<T, TenantRegistrationError>;
}

pub struct CoreTenantRegistrationService<S, K, I, V> {
    mode: TenancyMode,
    config: AuthConfig,
    store: S,
    clock: K,
    ids: I,
    codes: V,
}
impl<S, K, I, V> CoreTenantRegistrationService<S, K, I, V> {
    pub fn new(
        mode: TenancyMode,
        config: AuthConfig,
        store: S,
        clock: K,
        ids: I,
        codes: V,
    ) -> Result<Self, ConfigValidationError> {
        config.validate()?;
        Ok(Self {
            mode,
            config,
            store,
            clock,
            ids,
            codes,
        })
    }
}
impl<S, K, I, V> CoreTenantRegistrationService<S, K, I, V>
where
    S: TenantRegistrationStore + TenantEmailVerificationStore,
    K: Clock,
    I: IdGenerator,
    V: VerificationCodeGenerator,
{
    pub fn register_account(
        &self,
        command: RegisterTenantAccountCommand,
    ) -> Result<TenantRegistrationResult, TenantRegistrationError> {
        self.mode.validate_business_tenant(&command.tenant_id)?;
        validate_email(&command.email)?;
        if !self.config.allow_local_registration {
            return Err(TenantRegistrationError::RegistrationDisabled);
        }
        validate_registration_password(&self.config, command.password.expose_secret())
            .map_err(TenantRegistrationError::InvalidContract)?;
        let password_hash = hash_password(command.password.expose_secret())?;
        let now = self.clock.now();
        let expires_at = now
            .checked_add(Duration::from_secs(self.config.verification_code_ttl_secs))
            .ok_or(AccessError::InvalidInput("verification_expiry"))?;
        let code = self.codes.generate_code();
        if code.trim().is_empty() {
            return Err(AccessError::InvalidInput("verification_code").into());
        }
        let account_id = self.ids.next_id("acct");
        let verification = EmailVerificationCode {
            id: self.ids.next_id("mailver"),
            account_id: account_id.clone(),
            email: command.email.clone(),
            code: code.clone(),
            issued_at: now,
            expires_at,
            consumed_at: None,
        };
        let registration = TenantRegistration::new(
            self.mode,
            command.tenant_id.clone(),
            Account {
                id: account_id.clone(),
                email: command.email.clone(),
                password_hash,
                display_name: command.display_name,
                status: AccountStatus::PendingVerification,
                created_at: now,
            },
            verification,
        )?;
        self.store.create_registered_account(&registration)?;
        Ok(TenantRegistrationResult {
            tenant_id: command.tenant_id,
            account_id,
            email: command.email,
            verification_code: SecretString::new(code),
            verification_expires_at: expires_at,
        })
    }

    pub fn verify_email(
        &self,
        command: VerifyTenantEmailCommand,
    ) -> Result<TenantEmailVerificationResult, TenantRegistrationError> {
        self.mode.validate_business_tenant(&command.tenant_id)?;
        validate_email(&command.email)?;
        if command.verification_code.expose_secret().trim().is_empty() {
            return Err(TenantRegistrationError::InvalidVerificationCode);
        }
        self.store
            .verification_transaction(&command.tenant_id, |tx| {
                let state = tx
                    .load_verification(&command.email, command.verification_code.expose_secret())?
                    .ok_or(TenantRegistrationError::InvalidVerificationCode)?;
                // Observe time only AFTER waiting for tenant/account locks.
                let now = self.clock.now();
                let code = &state.verification;
                if state.registration_tenant_id != command.tenant_id
                    || state.tenant.id != command.tenant_id
                    || state.tenant.status != TenantStatus::Active
                    || state.membership.tenant_id != command.tenant_id
                    || state.membership.status != MembershipStatus::Active
                    || !state.account_pending_verification
                    || state.membership.subject_id != code.account_id
                    || code.email != command.email
                    || code.code != command.verification_code.expose_secret()
                    || code.consumed_at.is_some()
                    || code.issued_at > now
                {
                    return Err(TenantRegistrationError::InvalidVerificationCode);
                }
                if code.expires_at <= now {
                    return Err(TenantRegistrationError::VerificationCodeExpired);
                }
                tx.activate_verified_account(&code.account_id, &code.id, now)?;
                Ok(TenantEmailVerificationResult {
                    tenant_id: command.tenant_id.clone(),
                    account_id: code.account_id.clone(),
                })
            })
    }

    pub fn resend_verification(
        &self,
        command: ResendTenantVerificationCommand,
    ) -> Result<Option<TenantRegistrationResult>, TenantRegistrationError> {
        self.mode.validate_business_tenant(&command.tenant_id)?;
        validate_email(&command.email)?;
        self.store
            .verification_transaction(&command.tenant_id, |tx| {
                let Some(account) = tx.load_verification_account(&command.email)? else {
                    return Ok(None);
                };
                if account.registration_tenant_id != command.tenant_id
                    || account.tenant.id != command.tenant_id
                    || account.tenant.status != TenantStatus::Active
                    || account.membership.tenant_id != command.tenant_id
                    || account.membership.status != MembershipStatus::Active
                    || account.membership.subject_id != account.account_id
                    || account.email != command.email
                    || !account.pending_verification
                {
                    return Ok(None);
                }
                // Registration admission does not prevent existing pending users
                // from verifying. Observe time only after acquiring all locks.
                let now = self.clock.now();
                let expires_at = now
                    .checked_add(Duration::from_secs(self.config.verification_code_ttl_secs))
                    .ok_or(AccessError::InvalidInput("verification_expiry"))?;
                let code = self.codes.generate_code();
                if code.trim().is_empty() {
                    return Err(AccessError::InvalidInput("verification_code").into());
                }
                tx.replace_verification(&EmailVerificationCode {
                    id: self.ids.next_id("mailver"),
                    account_id: account.account_id.clone(),
                    email: account.email.clone(),
                    code: code.clone(),
                    issued_at: now,
                    expires_at,
                    consumed_at: None,
                })?;
                Ok(Some(TenantRegistrationResult {
                    tenant_id: command.tenant_id.clone(),
                    account_id: account.account_id,
                    email: account.email,
                    verification_code: SecretString::new(code),
                    verification_expires_at: expires_at,
                }))
            })
    }
}

impl<S, K, I, V> TenantRegistrationService for CoreTenantRegistrationService<S, K, I, V>
where
    S: TenantRegistrationStore + TenantEmailVerificationStore,
    K: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    V: VerificationCodeGenerator + Send + Sync,
{
    fn tenancy_mode(&self) -> TenancyMode {
        self.mode
    }
    fn register_account(
        &self,
        command: RegisterTenantAccountCommand,
    ) -> Result<TenantRegistrationResult, TenantRegistrationError> {
        self.register_account(command)
    }
    fn verify_email(
        &self,
        command: VerifyTenantEmailCommand,
    ) -> Result<TenantEmailVerificationResult, TenantRegistrationError> {
        self.verify_email(command)
    }
    fn resend_verification(
        &self,
        command: ResendTenantVerificationCommand,
    ) -> Result<Option<TenantRegistrationResult>, TenantRegistrationError> {
        self.resend_verification(command)
    }
}
fn validate_email(email: &str) -> Result<(), TenantRegistrationError> {
    if !is_valid_email(email) {
        return Err(TenantRegistrationError::InvalidContract(
            ContractValidationError::InvalidEmail,
        ));
    }
    Ok(())
}

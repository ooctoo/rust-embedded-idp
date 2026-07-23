use std::time::{Duration, SystemTime};

use crate::{
    AccountStatus, AuthConfig, EmailVerificationCode, IdGenerator, StoreError,
    VerificationCodeGenerator,
};

use super::ServiceError;

pub(crate) fn require_active_account_status(status: &AccountStatus) -> Result<(), StoreError> {
    match status {
        AccountStatus::Active => Ok(()),
        AccountStatus::PendingVerification => {
            Err(StoreError::Conflict("account.pending_verification"))
        }
        AccountStatus::Disabled => Err(StoreError::Conflict("account.disabled")),
    }
}

pub(crate) fn map_account_status_conflict(error: &StoreError) -> Option<ServiceError> {
    match error {
        StoreError::Conflict("account.pending_verification") => {
            Some(ServiceError::AccountPendingVerification)
        }
        StoreError::Conflict("account.disabled") | StoreError::Conflict("account.status") => {
            Some(ServiceError::AccountDisabled)
        }
        _ => None,
    }
}

pub(crate) fn build_email_verification_code<G, I>(
    config: &AuthConfig,
    code_generator: &G,
    id_generator: &I,
    account_id: &str,
    email: &str,
    now: SystemTime,
) -> EmailVerificationCode
where
    G: VerificationCodeGenerator + ?Sized,
    I: IdGenerator + ?Sized,
{
    EmailVerificationCode {
        id: id_generator.next_id("mailver"),
        account_id: account_id.to_string(),
        email: email.to_string(),
        code: code_generator.generate_code(),
        issued_at: now,
        expires_at: now + Duration::from_secs(config.verification_code_ttl_secs),
        consumed_at: None,
    }
}

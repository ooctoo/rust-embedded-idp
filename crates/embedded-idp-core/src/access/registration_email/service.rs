use super::*;
use crate::{PasswordWorkBudget, SecretString};

pub const REGISTRATION_EMAIL_PROFILE: &str = "idp-registration-email-v1";
pub const REGISTRATION_EMAIL_PROFILE_HEADER: &str = "x-idp-registration-profile";
#[derive(Debug)]
pub struct RegistrationEmailCommand {
    pub operation: Uuid,
    pub email: SecretString,
    pub password: SecretString,
    pub display_name: Option<SecretString>,
}
#[derive(Clone, Debug)]
pub struct RegistrationEmailPreparationClaim {
    pub context_id: Uuid,
    pub sequence: i64,
    pub claim_token: Uuid,
    pub lease_until: i64,
}
#[derive(Debug)]
pub struct RegistrationEmailMessage {
    pub email: SecretString,
    pub code: SecretString,
    pub expires_at_unix_secs: i64,
    pub lease_remaining_millis: u64,
}
#[derive(Clone, Debug, Default)]
pub struct RegistrationEmailRuntimeFacts {
    pub store_ready: bool,
    pub accepting: bool,
    pub overdue_processing: u64,
    pub unresolved_delivery: u64,
}
/// Trusted in-process IDP boundary, never expose work/claim/message methods as business HTTP.
pub trait RegistrationEmailService: Send + Sync {
    fn scope(&self) -> &RegistrationEmailScope;
    fn policy(&self) -> &RegistrationEmailPolicy;
    fn password_work_budget(&self) -> PasswordWorkBudget;
    fn runtime_facts(&self) -> Result<RegistrationEmailRuntimeFacts, RegistrationEmailError>;
    fn is_replay(
        &self,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
    ) -> Result<bool, RegistrationEmailError>;
    fn register_command(
        &self,
        command: RegistrationEmailCommand,
    ) -> Result<RegistrationEmailAccepted, RegistrationEmailError>;
    fn resend_command(&self, operation: Uuid, token: &str) -> Result<(), RegistrationEmailError>;
    fn verify_command(
        &self,
        operation: Uuid,
        token: &str,
        code: &str,
    ) -> Result<RegistrationEmailVerification, RegistrationEmailError>;
    fn claim_preparation(
        &self,
    ) -> Result<Option<RegistrationEmailPreparationClaim>, RegistrationEmailError>;
    fn prepare_claimed(
        &self,
        claim: &RegistrationEmailPreparationClaim,
    ) -> Result<RegistrationEmailPreparation, RegistrationEmailError>;
    fn next_delivery(&self) -> Result<Option<Uuid>, RegistrationEmailError>;
    fn claim_delivery(
        &self,
        effect: Uuid,
    ) -> Result<Option<RegistrationEmailDeliveryClaim>, RegistrationEmailError>;
    fn delivery_message(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
    ) -> Result<Option<RegistrationEmailMessage>, RegistrationEmailError>;
    fn finish_delivery(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
        result: RegistrationEmailDeliveryResult,
    ) -> Result<(), RegistrationEmailError>;
    fn confirm_delivery_stopped(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
    ) -> Result<(), RegistrationEmailError>;
    fn pause_registration(&self) -> Result<(), RegistrationEmailError>;
    /// Trusted operator action after health inspection. No anonymous route may invoke this.
    fn resume_registration(&self) -> Result<(), RegistrationEmailError>;
    fn maintain_runtime(&self) -> Result<(), RegistrationEmailError>;
}

/// Independent public waiting noise, never derived from mailbox state.
pub fn registration_response_jitter_millis() -> u64 {
    use rand_core::{OsRng, RngCore};
    u64::from(OsRng.next_u32()) % 51
}

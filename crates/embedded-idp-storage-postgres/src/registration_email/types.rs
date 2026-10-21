use embedded_idp_core::{access::Uuid, SecretString};
/// Public acceptance facts only. The HTTP adapter must explicitly project these fields.
#[derive(Debug, Clone)]
pub struct RegistrationEmailAccepted {
    pub verification_context: SecretString,
    pub accepted_at_unix_secs: i64,
    pub context_lifetime_secs: i64,
    pub resend_after_secs: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationEmailVerification {
    Verified,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationEmailPreparation {
    Prepared,
    Suppressed,
    Superseded,
}
#[derive(Debug, Clone)]
pub struct RegistrationEmailDeliveryClaim {
    pub effect_id: Uuid,
    pub context_id: Uuid,
    pub sequence: i64,
    pub claim_token: Uuid,
    pub lease_until: i64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationEmailDeliveryResult {
    Sent,
    Failed,
    Unknown,
}

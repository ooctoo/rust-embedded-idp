use std::{
    fmt,
    time::{Instant, SystemTime},
};
/// Plaintext exists only inside the trusted, same-process mail adapter.
/// Implementations must not log these fields or start detached/background sends.
pub struct RegistrationEmailDeliveryRequest {
    pub email: String,
    pub code: String,
    pub expires_at: SystemTime,
}
impl fmt::Debug for RegistrationEmailDeliveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrationEmailDeliveryRequest(<redacted>)")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationEmailSendOutcome {
    Sent,
    Rejected,
    Unknown,
}
/// A return means this physical call ended. Honour the absolute deadline and close
/// its network resources. The supervisor quarantines the slot if this contract
/// is violated; a timeout never authorizes another dispatch of the same effect.
pub trait RegistrationEmailDeliveryService: Send + Sync {
    fn send_registration_email(
        &self,
        request: RegistrationEmailDeliveryRequest,
        deadline: Instant,
    ) -> RegistrationEmailSendOutcome;
}

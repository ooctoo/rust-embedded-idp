use std::{fmt, future::Future, pin::Pin, time::Instant};

/// A security-sensitive email with a deliberately fixed purpose.
pub struct SecurityEmail {
    pub purpose: SecurityEmailPurpose,
    pub recipient: String,
    pub text_body: String,
}

impl fmt::Debug for SecurityEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityEmail")
            .field("purpose", &self.purpose)
            .field("recipient", &"[REDACTED]")
            .field("text_body", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEmailPurpose {
    PasswordRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEmailDeliveryOutcome {
    Accepted,
    /// A terminal local rejection, such as invalid configuration or unsupported mode.
    Rejected,
    /// No helper was started; the caller may retry later.
    NotStarted,
    /// A started helper did not return a conclusive result.
    Unknown,
}

pub trait SecurityEmailDeliveryService: Send + Sync {
    fn send<'a>(
        &'a self,
        email: SecurityEmail,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = SecurityEmailDeliveryOutcome> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::{SecurityEmail, SecurityEmailPurpose};

    #[test]
    fn debug_redacts_recipient_and_body() {
        let email = SecurityEmail {
            purpose: SecurityEmailPurpose::PasswordRecovery,
            recipient: "person@example.test".into(),
            text_body: "secret-code-123456".into(),
        };
        let debug = format!("{email:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("person@example.test"));
        assert!(!debug.contains("secret-code-123456"));
    }
}

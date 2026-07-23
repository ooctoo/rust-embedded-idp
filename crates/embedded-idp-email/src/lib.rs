use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailRecipient {
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundEmail {
    pub to: Vec<EmailRecipient>,
    pub subject: String,
    pub text_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailSendError {
    pub message: String,
}

impl EmailSendError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait EmailSenderProvider: Send + Sync {
    fn send(&self, email: OutboundEmail) -> Result<(), EmailSendError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEmailRequest {
    pub email: String,
    pub code: String,
    pub expires_at: SystemTime,
}

pub trait VerificationEmailService: Send + Sync {
    fn send_verification_email(
        &self,
        request: VerificationEmailRequest,
    ) -> Result<(), EmailSendError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEmailConfig {
    pub from_email: String,
    pub from_name: Option<String>,
    pub subject: String,
}

pub struct DefaultVerificationEmailService<P> {
    sender: P,
    config: VerificationEmailConfig,
}

impl<P> DefaultVerificationEmailService<P> {
    pub fn new(sender: P, config: VerificationEmailConfig) -> Self {
        Self { sender, config }
    }
}

impl<P> VerificationEmailService for DefaultVerificationEmailService<P>
where
    P: EmailSenderProvider,
{
    fn send_verification_email(
        &self,
        request: VerificationEmailRequest,
    ) -> Result<(), EmailSendError> {
        self.sender.send(OutboundEmail {
            to: vec![EmailRecipient {
                email: request.email,
                display_name: None,
            }],
            subject: self.config.subject.clone(),
            text_body: build_verification_text_body(
                &self.config.from_email,
                self.config.from_name.as_deref(),
                &request.code,
                request.expires_at,
            ),
        })
    }
}

fn build_verification_text_body(
    from_email: &str,
    from_name: Option<&str>,
    code: &str,
    expires_at: SystemTime,
) -> String {
    let sender = match from_name {
        Some(name) if !name.trim().is_empty() => format!("{name} <{from_email}>"),
        _ => from_email.to_string(),
    };
    let expires_at_unix_secs = expires_at
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default();

    format!(
        "Verification code: {code}\nExpires at unix timestamp: {expires_at_unix_secs}\nSender: {sender}\n"
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use super::{
        DefaultVerificationEmailService, EmailSendError, EmailSenderProvider, OutboundEmail,
        VerificationEmailConfig, VerificationEmailRequest, VerificationEmailService,
    };

    #[derive(Default)]
    struct RecordingSender {
        emails: Mutex<Vec<OutboundEmail>>,
    }

    impl EmailSenderProvider for RecordingSender {
        fn send(&self, email: OutboundEmail) -> Result<(), EmailSendError> {
            self.emails.lock().unwrap().push(email);
            Ok(())
        }
    }

    #[test]
    fn verification_service_builds_plain_text_email() {
        let sender = RecordingSender::default();
        let service = DefaultVerificationEmailService::new(
            sender,
            VerificationEmailConfig {
                from_email: "noreply@example.com".to_string(),
                from_name: Some("Embedded IDP".to_string()),
                subject: "Verify your email".to_string(),
            },
        );

        service
            .send_verification_email(VerificationEmailRequest {
                email: "user@example.com".to_string(),
                code: "123456".to_string(),
                expires_at: SystemTime::UNIX_EPOCH + Duration::from_secs(900),
            })
            .expect("verification email should be sent");

        let emails = service.sender.emails.lock().unwrap();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].to[0].email, "user@example.com");
        assert_eq!(emails[0].subject, "Verify your email");
        assert!(emails[0].text_body.contains("123456"));
    }
}

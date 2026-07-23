use std::io::Write;
use std::process::{Command, Stdio};

use embedded_idp_email::{EmailSendError, EmailSenderProvider, OutboundEmail};
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{SmtpTransport, Transport};

use crate::config::{EmailDeliveryConfig, EmailDeliveryMode, SmtpEmailDeliveryConfig, SmtpTlsMode};

#[derive(Debug, Clone)]
pub struct AppEmailSenderProvider {
    config: EmailDeliveryConfig,
}

impl AppEmailSenderProvider {
    pub fn new(config: EmailDeliveryConfig) -> Self {
        Self { config }
    }
}

impl EmailSenderProvider for AppEmailSenderProvider {
    fn send(&self, email: OutboundEmail) -> Result<(), EmailSendError> {
        match self.config.mode {
            EmailDeliveryMode::Log => {
                eprintln!(
                    "[embedded-idp] outbound_email to={:?} subject={} body={}",
                    email
                        .to
                        .iter()
                        .map(|recipient| recipient.email.as_str())
                        .collect::<Vec<_>>(),
                    email.subject,
                    email.text_body
                );
                Ok(())
            }
            EmailDeliveryMode::Sendmail => {
                send_via_sendmail(&self.config, email).map_err(EmailSendError::new)
            }
            EmailDeliveryMode::Smtp => {
                send_via_smtp(&self.config, email).map_err(EmailSendError::new)
            }
        }
    }
}

fn send_via_smtp(config: &EmailDeliveryConfig, email: OutboundEmail) -> Result<(), String> {
    let message = build_message(config, &email)?;
    let mut builder = SmtpTransport::builder_dangerous(&config.smtp.host).port(config.smtp.port);
    let tls_parameters = TlsParameters::new(config.smtp.host.clone())
        .map_err(|error| format!("build smtp tls parameters failed: {error}"))?;
    builder = match config.smtp.tls_mode {
        SmtpTlsMode::StartTls => builder.tls(Tls::Required(tls_parameters)),
        SmtpTlsMode::ImplicitTls => builder.tls(Tls::Wrapper(tls_parameters)),
        SmtpTlsMode::Plain => builder.tls(Tls::None),
    };

    if let Some(credentials) = smtp_credentials(&config.smtp) {
        builder = builder.credentials(credentials);
    }

    builder
        .build()
        .send(&message)
        .map_err(|error| format!("smtp send failed: {error}"))?;
    Ok(())
}

fn send_via_sendmail(config: &EmailDeliveryConfig, email: OutboundEmail) -> Result<(), String> {
    let message = build_message(config, &email)?;
    let body = message.formatted();

    let mut child = Command::new(&config.sendmail_command)
        .arg("-t")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn sendmail failed: {error}"))?;

    {
        let Some(stdin) = child.stdin.as_mut() else {
            return Err("sendmail stdin unavailable".to_string());
        };
        stdin
            .write_all(&body)
            .map_err(|error| format!("write sendmail payload failed: {error}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("wait sendmail failed: {error}"))?;
    if output.status.success() {
        return Ok(());
    }

    Err(format!(
        "sendmail exited with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn build_message(config: &EmailDeliveryConfig, email: &OutboundEmail) -> Result<Message, String> {
    let from = mailbox(config.from_email.clone(), config.from_name.clone())?;
    let mut builder = Message::builder()
        .from(from)
        .date_now()
        .message_id(None)
        .subject(&email.subject);

    for recipient in &email.to {
        builder = builder.to(mailbox(
            recipient.email.clone(),
            recipient.display_name.clone(),
        )?);
    }

    builder
        .body(email.text_body.clone())
        .map_err(|error| format!("build email message failed: {error}"))
}

fn mailbox(email: String, display_name: Option<String>) -> Result<Mailbox, String> {
    let address = email
        .parse()
        .map_err(|error| format!("invalid email address {email}: {error}"))?;
    Ok(Mailbox::new(display_name, address))
}

fn smtp_credentials(config: &SmtpEmailDeliveryConfig) -> Option<Credentials> {
    match (config.username.clone(), config.password.clone()) {
        (Some(username), Some(password)) => Some(Credentials::new(username, password)),
        _ => None,
    }
}

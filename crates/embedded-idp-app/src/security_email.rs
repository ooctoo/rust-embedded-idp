use std::{
    collections::HashMap,
    future::Future,
    io::Read,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use embedded_idp_email::{
    EmailRecipient, OutboundEmail, SecurityEmail, SecurityEmailDeliveryOutcome,
    SecurityEmailDeliveryService, SecurityEmailPurpose,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::{oneshot, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};

use crate::{
    config::{EmailDeliveryConfig, EmailDeliveryMode, SmtpEmailDeliveryConfig, SmtpTlsMode},
    email_sender::{send_security_via_smtp, SecuritySmtpError},
};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const SEND_LIMIT: Duration = Duration::from_secs(15);
const CLEANUP_LIMIT: Duration = Duration::from_secs(2);
const MAX_SENDS: usize = 4;

#[derive(Serialize, Deserialize)]
struct HelperRequest {
    purpose: String,
    recipient: String,
    body: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_tls: String,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    from_email: String,
    from_name: Option<String>,
    subject: String,
}

impl HelperRequest {
    fn from_config(config: &EmailDeliveryConfig, email: SecurityEmail) -> Result<Vec<u8>, ()> {
        if config.mode != EmailDeliveryMode::Smtp
            || email.recipient.is_empty()
            || email.recipient.len() > 1024
            || email.text_body.len() > 12 * 1024
            || email.purpose != SecurityEmailPurpose::PasswordRecovery
        {
            return Err(());
        }
        let result = Self {
            purpose: "password_recovery".into(),
            recipient: email.recipient,
            body: email.text_body,
            smtp_host: config.smtp.host.clone(),
            smtp_port: config.smtp.port,
            smtp_tls: match config.smtp.tls_mode {
                SmtpTlsMode::StartTls => "starttls",
                SmtpTlsMode::ImplicitTls => "implicit_tls",
                SmtpTlsMode::Plain => "plain",
            }
            .into(),
            smtp_username: config.smtp.username.clone(),
            smtp_password: config.smtp.password.clone(),
            from_email: config.from_email.clone(),
            from_name: config.from_name.clone(),
            subject: config.subject.clone(),
        };
        let encoded = serde_json::to_vec(&result).map_err(|_| ())?;
        if encoded.len() > MAX_INPUT_BYTES {
            return Err(());
        }
        Ok(encoded)
    }

    fn into_config_and_email(self) -> Result<(EmailDeliveryConfig, OutboundEmail), ()> {
        if self.purpose != "password_recovery" || self.recipient.is_empty() {
            return Err(());
        }
        let tls_mode = match self.smtp_tls.as_str() {
            "starttls" => SmtpTlsMode::StartTls,
            "implicit_tls" => SmtpTlsMode::ImplicitTls,
            "plain" => SmtpTlsMode::Plain,
            _ => return Err(()),
        };
        let config = EmailDeliveryConfig {
            mode: EmailDeliveryMode::Smtp,
            sendmail_command: String::new(),
            smtp: SmtpEmailDeliveryConfig {
                host: self.smtp_host,
                port: self.smtp_port,
                tls_mode,
                username: self.smtp_username,
                password: self.smtp_password,
            },
            from_email: self.from_email,
            from_name: self.from_name,
            subject: self.subject,
        };
        let email = OutboundEmail {
            to: vec![EmailRecipient {
                email: self.recipient,
                display_name: None,
            }],
            subject: config.subject.clone(),
            text_body: self.body,
        };
        Ok((config, email))
    }
}

struct Registry {
    closing: bool,
    next_id: u64,
    tasks: HashMap<u64, JoinHandle<()>>,
}

struct SenderInner {
    config: EmailDeliveryConfig,
    executable: PathBuf,
    slots: Arc<Semaphore>,
    registry: Mutex<Registry>,
}

/// A reference-host SMTP adapter whose capacity tracks actual helper processes.
pub struct ProcessSecurityEmailSender {
    inner: Arc<SenderInner>,
}

impl ProcessSecurityEmailSender {
    pub fn new(config: EmailDeliveryConfig, executable: PathBuf) -> Self {
        Self {
            inner: Arc::new(SenderInner {
                config,
                executable,
                slots: Arc::new(Semaphore::new(MAX_SENDS)),
                registry: Mutex::new(Registry {
                    closing: false,
                    next_id: 0,
                    tasks: HashMap::new(),
                }),
            }),
        }
    }

    /// Prevents new sends and waits for registered supervisors' bounded cleanup.
    pub async fn shutdown(&self) {
        let tasks = match self.inner.registry.lock() {
            Ok(mut registry) => {
                registry.closing = true;
                std::mem::take(&mut registry.tasks)
            }
            Err(poisoned) => {
                let mut registry = poisoned.into_inner();
                registry.closing = true;
                std::mem::take(&mut registry.tasks)
            }
        };
        for (_, task) in tasks {
            let _ = task.await;
        }
    }
}

impl SecurityEmailDeliveryService for ProcessSecurityEmailSender {
    fn send<'a>(
        &'a self,
        email: SecurityEmail,
        deadline: Instant,
    ) -> Pin<Box<dyn Future<Output = SecurityEmailDeliveryOutcome> + Send + 'a>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let deadline = deadline.min(Instant::now() + SEND_LIMIT);
            if Instant::now() >= deadline {
                return SecurityEmailDeliveryOutcome::NotStarted;
            }
            let input = match HelperRequest::from_config(&inner.config, email) {
                Ok(input) => input,
                Err(()) => return SecurityEmailDeliveryOutcome::Rejected,
            };
            let permit = match inner.slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => return SecurityEmailDeliveryOutcome::NotStarted,
            };

            let result_rx = {
                let mut registry = match inner.registry.lock() {
                    Ok(registry) => registry,
                    Err(_) => return SecurityEmailDeliveryOutcome::NotStarted,
                };
                registry.tasks.retain(|_, task| !task.is_finished());
                if registry.closing || Instant::now() >= deadline {
                    return SecurityEmailDeliveryOutcome::NotStarted;
                }
                let id = registry.next_id;
                registry.next_id = registry.next_id.wrapping_add(1);
                let (result_tx, result_rx) = oneshot::channel();
                let inner_task = Arc::clone(&inner);
                let task = tokio::spawn(async move {
                    let outcome = supervise(inner_task, input, deadline, permit).await;
                    let _ = result_tx.send(outcome);
                });
                registry.tasks.insert(id, task);
                result_rx
            };
            result_rx
                .await
                .unwrap_or(SecurityEmailDeliveryOutcome::Unknown)
        })
    }
}

async fn supervise(
    inner: Arc<SenderInner>,
    input: Vec<u8>,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
) -> SecurityEmailDeliveryOutcome {
    let mut command = Command::new(&inner.executable);
    command
        .arg("__security-email-helper")
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return SecurityEmailDeliveryOutcome::NotStarted,
    };
    let run_result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        let stdin = child.stdin.as_mut().ok_or(())?;
        stdin.write_all(&input).await.map_err(|_| ())?;
        drop(child.stdin.take());
        child.wait().await.map_err(|_| ())
    })
    .await;

    match run_result {
        Ok(Ok(status)) => {
            drop(permit);
            if status.success() {
                SecurityEmailDeliveryOutcome::Accepted
            } else if status.code() == Some(2) {
                SecurityEmailDeliveryOutcome::Rejected
            } else {
                SecurityEmailDeliveryOutcome::Unknown
            }
        }
        _ => {
            if !kill_and_reap(&mut child).await {
                permit.forget();
            } else {
                drop(permit);
            }
            SecurityEmailDeliveryOutcome::Unknown
        }
    }
}

async fn kill_and_reap(child: &mut Child) -> bool {
    tokio::time::timeout(CLEANUP_LIMIT, async {
        if child.kill().await.is_ok() {
            return true;
        }
        child.wait().await.is_ok()
    })
    .await
    .unwrap_or(false)
}

/// Internal executable entrypoint, called before host configuration is loaded.
pub(crate) fn helper_main() -> i32 {
    let mut input = Vec::new();
    if std::io::Read::take(std::io::stdin(), (MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .is_err()
        || input.len() > MAX_INPUT_BYTES
    {
        return 2;
    }
    let request: HelperRequest = match serde_json::from_slice(&input) {
        Ok(request) => request,
        Err(_) => return 2,
    };
    let (config, email) = match request.into_config_and_email() {
        Ok(values) => values,
        Err(()) => return 2,
    };
    match send_security_via_smtp(&config, email) {
        Ok(()) => 0,
        Err(SecuritySmtpError::BeforeSend) => 2,
        Err(SecuritySmtpError::DuringSend) => 3,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        process::Command,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use embedded_idp_email::{
        SecurityEmail, SecurityEmailDeliveryOutcome, SecurityEmailDeliveryService,
        SecurityEmailPurpose,
    };

    use crate::config::{
        EmailDeliveryConfig, EmailDeliveryMode, SmtpEmailDeliveryConfig, SmtpTlsMode,
    };

    use super::{HelperRequest, ProcessSecurityEmailSender, MAX_INPUT_BYTES};

    fn config() -> EmailDeliveryConfig {
        EmailDeliveryConfig {
            mode: EmailDeliveryMode::Smtp,
            sendmail_command: String::new(),
            smtp: SmtpEmailDeliveryConfig {
                host: "localhost".into(),
                port: 25,
                tls_mode: SmtpTlsMode::Plain,
                username: None,
                password: None,
            },
            from_email: "sender@example.test".into(),
            from_name: None,
            subject: "Security notice".into(),
        }
    }

    fn helper(script: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("idp-mail-helper-{}", randless_id()));
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn randless_id() -> String {
        let ticks = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{}-{ticks}", std::process::id())
    }

    fn request() -> SecurityEmail {
        SecurityEmail {
            purpose: SecurityEmailPurpose::PasswordRecovery,
            recipient: "private@example.test".into(),
            text_body: "private-code-123456".into(),
        }
    }

    #[tokio::test]
    async fn exit_code_contract_and_shutdown_closing() {
        // Exit-code mapping is independent of startup scheduling under parallel
        // builds. Timeout/kill/reap has a separate short-deadline test below.
        for (code, expected) in [
            (0, SecurityEmailDeliveryOutcome::Accepted),
            (2, SecurityEmailDeliveryOutcome::Rejected),
            (3, SecurityEmailDeliveryOutcome::Unknown),
            (7, SecurityEmailDeliveryOutcome::Unknown),
        ] {
            let path = helper(&format!("/bin/cat >/dev/null\nexit {code}"));
            let sender = ProcessSecurityEmailSender::new(config(), path.clone());
            assert_eq!(
                sender
                    .send(request(), Instant::now() + Duration::from_secs(10))
                    .await,
                expected
            );
            sender.shutdown().await;
            assert_eq!(
                sender
                    .send(request(), Instant::now() + Duration::from_secs(10))
                    .await,
                SecurityEmailDeliveryOutcome::NotStarted
            );
            let _ = fs::remove_file(path);
        }
    }

    #[tokio::test]
    async fn timeout_kills_and_reaps_helper_before_slot_is_reused() {
        let pid_path = std::env::temp_dir().join(format!("idp-mail-pid-{}", randless_id()));
        let path = helper(&format!(
            "echo $$ > {}\n/bin/cat >/dev/null\nexec /bin/sleep 30",
            pid_path.display()
        ));
        let sender = std::sync::Arc::new(ProcessSecurityEmailSender::new(config(), path.clone()));
        let send_sender = std::sync::Arc::clone(&sender);
        let send = tokio::spawn(async move {
            send_sender
                .send(request(), Instant::now() + Duration::from_secs(10))
                .await
        });
        tokio::time::timeout(Duration::from_secs(9), async {
            while !pid_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("helper did not write its PID to {}", pid_path.display()));
        assert_eq!(send.await.unwrap(), SecurityEmailDeliveryOutcome::Unknown);
        let pid = fs::read_to_string(&pid_path).unwrap();
        let status = Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "helper PID must no longer exist after send returns"
        );
        assert_eq!(sender.inner.slots.available_permits(), 4);
        sender.shutdown().await;
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(pid_path);
    }

    #[tokio::test]
    async fn invalid_oversized_expired_unsupported_and_spawn_failure_are_classified() {
        let path = helper("/bin/cat >/dev/null\nexit 0");
        let sender = ProcessSecurityEmailSender::new(config(), path.clone());

        let mut empty_recipient = request();
        empty_recipient.recipient.clear();
        assert_eq!(
            sender
                .send(empty_recipient, Instant::now() + Duration::from_secs(1))
                .await,
            SecurityEmailDeliveryOutcome::Rejected
        );

        let mut oversized_body = request();
        oversized_body.text_body = "x".repeat(12 * 1024 + 1);
        assert_eq!(
            sender
                .send(oversized_body, Instant::now() + Duration::from_secs(1))
                .await,
            SecurityEmailDeliveryOutcome::Rejected
        );

        let mut oversized_config = config();
        oversized_config.subject = "x".repeat(MAX_INPUT_BYTES);
        assert!(HelperRequest::from_config(&oversized_config, request()).is_err());

        assert_eq!(
            sender
                .send(request(), Instant::now() - Duration::from_millis(1))
                .await,
            SecurityEmailDeliveryOutcome::NotStarted
        );

        let mut unsupported_config = config();
        unsupported_config.mode = EmailDeliveryMode::Log;
        let unsupported = ProcessSecurityEmailSender::new(unsupported_config, path.clone());
        assert_eq!(
            unsupported
                .send(request(), Instant::now() + Duration::from_secs(1))
                .await,
            SecurityEmailDeliveryOutcome::Rejected
        );

        let missing = ProcessSecurityEmailSender::new(config(), path.with_extension("missing"));
        assert_eq!(
            missing
                .send(request(), Instant::now() + Duration::from_secs(1))
                .await,
            SecurityEmailDeliveryOutcome::NotStarted
        );
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn caller_cancellation_does_not_release_helper_slot() {
        let path = helper("/bin/cat >/dev/null\nexec /bin/sleep 2");
        let sender = std::sync::Arc::new(ProcessSecurityEmailSender::new(config(), path.clone()));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let task_sender = std::sync::Arc::clone(&sender);
            tasks.push(tokio::spawn(async move {
                task_sender
                    .send(request(), Instant::now() + Duration::from_secs(5))
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while sender.inner.slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all four requests should hold their process permits");
        for task in tasks {
            task.abort();
        }
        assert_eq!(
            sender
                .send(request(), Instant::now() + Duration::from_secs(1))
                .await,
            SecurityEmailDeliveryOutcome::NotStarted
        );
        sender.shutdown().await;
        assert_eq!(sender.inner.slots.available_permits(), 4);
        let _ = fs::remove_file(path);
    }
}

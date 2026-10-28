use serde_json::json;
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const HELPER: &str = env!("CARGO_BIN_EXE_embedded-idp-app");
const RECIPIENT: &str = "synthetic-recipient@example.test";
const RECOVERY_CODE: &str = "synthetic-recovery-code-9a0";

#[derive(Debug, Default)]
struct SmtpObservation {
    commands: Vec<String>,
    message: String,
}

struct SmtpFake {
    address: std::net::SocketAddr,
    observation: Arc<Mutex<SmtpObservation>>,
    task: thread::JoinHandle<()>,
}

impl SmtpFake {
    fn start(accept_after_data: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let observation = Arc::new(Mutex::new(SmtpObservation::default()));
        let observed = Arc::clone(&observation);
        let task = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            observed
                                .lock()
                                .unwrap()
                                .commands
                                .push("accept deadline elapsed".into());
                            return;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => {
                        observed
                            .lock()
                            .unwrap()
                            .commands
                            .push(format!("accept error: {error}"));
                        return;
                    }
                }
            };
            observed
                .lock()
                .unwrap()
                .commands
                .push("accepted connection".into());
            if stream.set_nonblocking(false).is_err()
                || stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .is_err()
                || stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .is_err()
            {
                return;
            }
            let reader_stream = match stream.try_clone() {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let mut reader = BufReader::new(reader_stream);
            if let Err(error) = write_reply(&mut stream, "220 localhost ESMTP test\r\n") {
                observed
                    .lock()
                    .unwrap()
                    .commands
                    .push(format!("greeting write error: {error}"));
                return;
            }
            observed
                .lock()
                .unwrap()
                .commands
                .push("greeting sent".into());
            while Instant::now() < deadline {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        observed
                            .lock()
                            .unwrap()
                            .commands
                            .push("client closed".into());
                        return;
                    }
                    Err(error) => {
                        observed
                            .lock()
                            .unwrap()
                            .commands
                            .push(format!("client read error: {error}"));
                        return;
                    }
                    Ok(_) => {}
                }
                let command = line.trim_end().to_owned();
                observed.lock().unwrap().commands.push(command.clone());
                let upper = command.to_ascii_uppercase();
                if upper.starts_with("EHLO ") || upper.starts_with("HELO ") {
                    if write_reply(&mut stream, "250 localhost\r\n").is_err() {
                        return;
                    }
                } else if upper.starts_with("MAIL FROM:") || upper.starts_with("RCPT TO:") {
                    if write_reply(&mut stream, "250 accepted\r\n").is_err() {
                        return;
                    }
                } else if upper == "DATA" {
                    if write_reply(&mut stream, "354 end with dot\r\n").is_err() {
                        return;
                    }
                    let mut message = String::new();
                    loop {
                        let mut data_line = String::new();
                        match reader.read_line(&mut data_line) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        if data_line == ".\r\n" || data_line == ".\n" {
                            break;
                        }
                        if message.len() + data_line.len() > 32 * 1024 {
                            return;
                        }
                        message.push_str(&data_line);
                    }
                    observed.lock().unwrap().message = message;
                    let response = if accept_after_data {
                        "250 queued\r\n"
                    } else {
                        "451 temporary failure after DATA\r\n"
                    };
                    if write_reply(&mut stream, response).is_err() {
                        return;
                    }
                    if !accept_after_data {
                        continue;
                    }
                } else if upper == "QUIT" {
                    let _ = write_reply(&mut stream, "221 bye\r\n");
                    return;
                } else if write_reply(&mut stream, "250 ok\r\n").is_err() {
                    return;
                }
            }
        });
        Self {
            address,
            observation,
            task,
        }
    }

    fn input(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "purpose": "password_recovery",
            "recipient": RECIPIENT,
            "body": format!("Use recovery code {RECOVERY_CODE}"),
            "smtp_host": "127.0.0.1",
            "smtp_port": self.address.port(),
            "smtp_tls": "plain",
            "smtp_username": null,
            "smtp_password": null,
            "from_email": "sender@example.test",
            "from_name": null,
            "subject": "Security notice"
        }))
        .unwrap()
    }

    fn finish(self) -> SmtpObservation {
        self.task.join().expect("bounded SMTP fake thread panicked");
        Arc::try_unwrap(self.observation)
            .expect("SMTP fake observation still shared")
            .into_inner()
            .unwrap()
    }
}

fn write_reply(stream: &mut TcpStream, reply: &str) -> std::io::Result<()> {
    stream.write_all(reply.as_bytes())?;
    stream.flush()
}

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_helper(input: &[u8]) -> Output {
    let child = Command::new(HELPER)
        .env_clear()
        .arg("__security-email-helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn compiled embedded-idp-app helper");
    let mut guard = ChildGuard(Some(child));
    let child = guard.0.as_mut().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input)
        .expect("write helper request");
    drop(child.stdin.take());

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().expect("poll helper").is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "helper exceeded its 10s deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
    guard
        .0
        .take()
        .unwrap()
        .wait_with_output()
        .expect("collect helper output")
}

fn assert_output_does_not_leak(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(RECIPIENT), "helper leaked recipient");
        assert!(!text.contains(RECOVERY_CODE), "helper leaked recovery code");
    }
}

#[test]
fn compiled_helper_reports_smtp_acceptance_without_leaking_recipient_or_code() {
    let smtp = SmtpFake::start(true);
    let output = run_helper(&smtp.input());
    let observed = smtp.finish();

    assert_eq!(
        output.status.code(),
        Some(0),
        "helper did not report SMTP acceptance ({} SMTP commands observed)",
        observed.commands.len()
    );
    assert_output_does_not_leak(&output);
    assert!(observed
        .commands
        .iter()
        .any(|line| line.starts_with("MAIL FROM:")));
    assert!(observed
        .commands
        .iter()
        .any(|line| line.starts_with("RCPT TO:")));
    assert!(observed.commands.iter().any(|line| line == "DATA"));
    assert!(observed.message.contains(RECIPIENT));
    assert!(observed.message.contains(RECOVERY_CODE));
}

#[test]
fn compiled_helper_reports_failure_after_smtp_data_as_exit_three_without_leaks() {
    let smtp = SmtpFake::start(false);
    let output = run_helper(&smtp.input());
    let observed = smtp.finish();

    assert_eq!(
        output.status.code(),
        Some(3),
        "helper did not report post-DATA failure ({} SMTP commands observed)",
        observed.commands.len()
    );
    assert_output_does_not_leak(&output);
    assert!(
        observed.commands.iter().any(|line| line == "DATA"),
        "SMTP DATA command was not observed"
    );
    assert!(observed.message.contains(RECIPIENT));
    assert!(observed.message.contains(RECOVERY_CODE));
}

#[test]
fn compiled_helper_rejects_malformed_and_oversized_json_with_exit_two() {
    let malformed =
        format!(r#"{{"recipient":"{RECIPIENT}","body":"{RECOVERY_CODE}","#).into_bytes();
    let mut oversized = format!(
        r#"{{"purpose":"password_recovery","recipient":"{RECIPIENT}","body":"{RECOVERY_CODE}","smtp_host":"127.0.0.1","smtp_port":25,"smtp_tls":"plain","smtp_username":null,"smtp_password":null,"from_email":"sender@example.test","from_name":null,"subject":"Security","padding":""#
    )
    .into_bytes();
    oversized.extend(vec![b'x'; 16 * 1024 + 1]);
    oversized.extend_from_slice(br#""}"#);

    for input in [malformed, oversized] {
        let output = run_helper(&input);
        assert_eq!(output.status.code(), Some(2));
        assert_output_does_not_leak(&output);
    }
}

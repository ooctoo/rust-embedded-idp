use embedded_idp_email::{
    RegistrationEmailDeliveryRequest, RegistrationEmailDeliveryService,
    RegistrationEmailSendOutcome,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedMail {
    pub recipient: String,
    pub code: String,
    pub raw: String,
}

pub struct SmtpSink {
    addr: SocketAddr,
    messages: Arc<Mutex<Vec<CapturedMail>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SmtpSink {
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let messages = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_messages = Arc::clone(&messages);
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_connection(stream, &thread_messages);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            messages,
            stopping,
            thread: Some(thread),
        })
    }

    pub fn delivery_service(&self) -> TcpSmtpDelivery {
        TcpSmtpDelivery { addr: self.addr }
    }

    pub fn messages(&self) -> Vec<CapturedMail> {
        self.messages.lock().unwrap().clone()
    }

    pub async fn wait_for_count(&self, count: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.messages.lock().unwrap().len() >= count {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for SmtpSink {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.addr).and_then(|stream| stream.shutdown(Shutdown::Both));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
pub struct TcpSmtpDelivery {
    addr: SocketAddr,
}

impl RegistrationEmailDeliveryService for TcpSmtpDelivery {
    fn send_registration_email(
        &self,
        request: RegistrationEmailDeliveryRequest,
        deadline: Instant,
    ) -> RegistrationEmailSendOutcome {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return RegistrationEmailSendOutcome::Unknown;
        }
        let timeout = remaining.min(Duration::from_secs(3));
        let Ok(mut stream) = TcpStream::connect_timeout(&self.addr, timeout) else {
            return RegistrationEmailSendOutcome::Unknown;
        };
        if !read_reply(&mut stream, "220", deadline)
            || !write_command(&mut stream, "EHLO local.test\r\n", deadline)
            || !read_reply(&mut stream, "250", deadline)
            || !write_command(&mut stream, "MAIL FROM:<idp@local.test>\r\n", deadline)
            || !read_reply(&mut stream, "250", deadline)
            || !write_command(
                &mut stream,
                &format!("RCPT TO:<{}>\r\n", request.email),
                deadline,
            )
            || !read_reply(&mut stream, "250", deadline)
            || !write_command(&mut stream, "DATA\r\n", deadline)
            || !read_reply(&mut stream, "354", deadline)
        {
            return RegistrationEmailSendOutcome::Unknown;
        }
        let body = format!(
            "From: idp@local.test\r\nTo: {}\r\nSubject: Verify\r\nX-Verification-Code: {}\r\n\r\nVerification code: {}\r\nExpires at: {:?}\r\n.\r\n",
            request.email, request.code, request.code, request.expires_at
        );
        if !write_command(&mut stream, &body, deadline)
            || !read_reply(&mut stream, "250", deadline)
            || !write_command(&mut stream, "QUIT\r\n", deadline)
            || !read_reply(&mut stream, "221", deadline)
            || Instant::now() > deadline
        {
            return RegistrationEmailSendOutcome::Unknown;
        }
        RegistrationEmailSendOutcome::Sent
    }
}

fn write_command(stream: &mut TcpStream, value: &str, deadline: Instant) -> bool {
    let remaining = deadline.saturating_duration_since(Instant::now());
    !remaining.is_zero()
        && stream
            .set_write_timeout(Some(remaining.min(Duration::from_secs(3))))
            .is_ok()
        && stream.write_all(value.as_bytes()).is_ok()
        && stream.flush().is_ok()
}

fn read_reply(stream: &mut TcpStream, expected: &str, deadline: Instant) -> bool {
    let mut response = Vec::with_capacity(64);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || response.len() >= 512 {
            return false;
        }
        if stream
            .set_read_timeout(Some(remaining.min(Duration::from_secs(3))))
            .is_err()
        {
            return false;
        }
        let mut bytes = [0; 64];
        let Ok(size) = stream.read(&mut bytes) else {
            return false;
        };
        if size == 0 {
            return false;
        }
        response.extend_from_slice(&bytes[..size]);
        if response.len() > 512 {
            return false;
        }
        let Some(end) = response.windows(2).position(|window| window == b"\r\n") else {
            continue;
        };
        return std::str::from_utf8(&response[..end])
            .is_ok_and(|value| value.starts_with(expected));
    }
}

fn handle_connection(
    mut stream: TcpStream,
    messages: &Arc<Mutex<Vec<CapturedMail>>>,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"220 local.test\r\n")?;
    stream.flush()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let mut recipient = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let command = line.trim_end_matches(['\r', '\n']);
        if command.starts_with("EHLO") || command.starts_with("HELO") {
            stream.write_all(b"250 local.test\r\n")?;
        } else if let Some(value) = command.strip_prefix("RCPT TO:<") {
            recipient = value.trim_end_matches('>').to_owned();
            stream.write_all(b"250 accepted\r\n")?;
        } else if command.starts_with("MAIL FROM:") {
            stream.write_all(b"250 accepted\r\n")?;
        } else if command == "DATA" {
            stream.write_all(b"354 end with dot\r\n")?;
            stream.flush()?;
            let mut raw = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line)? == 0 {
                    return Ok(());
                }
                if line == ".\r\n" || line == ".\n" {
                    break;
                }
                raw.push_str(&line);
            }
            let code = raw
                .lines()
                .find_map(|value| value.strip_prefix("X-Verification-Code: "))
                .unwrap_or_default()
                .trim()
                .to_owned();
            messages.lock().unwrap().push(CapturedMail {
                recipient: recipient.clone(),
                code,
                raw,
            });
            stream.write_all(b"250 queued\r\n")?;
        } else if command == "QUIT" {
            stream.write_all(b"221 closing\r\n")?;
            stream.flush()?;
            break;
        } else {
            stream.write_all(b"250 accepted\r\n")?;
        }
        stream.flush()?;
    }
    Ok(())
}

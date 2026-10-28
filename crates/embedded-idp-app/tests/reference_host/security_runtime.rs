use super::*;
use base64ct::Base64UrlUnpadded;
use embedded_idp_core::{
    AccountSecurityCrypto, SecretString, SecurityCryptoContext, SecurityEnvelope,
    SecurityEnvelopePurpose,
};
use embedded_idp_security::{AccountSecurityKeySet, RingAccountSecurityCrypto};
use std::{
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::Output,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const AUTHORITY: &str = "phase-one-host-test";
const RECIPIENT: &str = "recovery-recipient@example.test";
const OTHER_RECIPIENT: &str = "cleanup-recipient@example.test";
const ORDINARY_EMAIL: &str = "ordinary-recovery@example.test";
const OLD_PASSWORD: &str = "Recovery-Old-Password-1!";
const NEW_PASSWORD: &str = "Recovery-New-Password-2!";

#[derive(Clone, Copy)]
enum SmtpBehavior {
    Accept,
    Unknown,
    HoldForShutdown,
}

#[derive(Debug, Default)]
struct SmtpObservation {
    connections: usize,
    data_messages: usize,
    last_message: String,
    command_categories: Vec<&'static str>,
    last_io_error: Option<String>,
}

struct LocalSmtp {
    address: SocketAddr,
    observation: Arc<(Mutex<SmtpObservation>, Condvar)>,
    data_seen: Mutex<mpsc::Receiver<()>>,
    release: Option<mpsc::Sender<()>>,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl LocalSmtp {
    fn start(behavior: SmtpBehavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let observation = Arc::new((Mutex::new(SmtpObservation::default()), Condvar::new()));
        let server_observation = Arc::clone(&observation);
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let (data_tx, data_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release = matches!(behavior, SmtpBehavior::HoldForShutdown).then_some(release_tx);
        let task = thread::spawn(move || {
            while !server_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        {
                            let (lock, changed) = &*server_observation;
                            lock.lock().unwrap().connections += 1;
                            changed.notify_all();
                        }
                        if let Err(error) = serve_smtp_connection(
                            stream,
                            behavior,
                            &server_observation,
                            &data_tx,
                            &release_rx,
                        ) {
                            server_observation.0.lock().unwrap().last_io_error =
                                Some(format!("{:?}", error.kind()));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            address,
            observation,
            data_seen: Mutex::new(data_rx),
            release,
            stop,
            task: Some(task),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn wait_for_data(&self, timeout: Duration, db: &Db, outbox: Uuid) {
        if self
            .data_seen
            .lock()
            .unwrap()
            .recv_timeout(timeout)
            .is_err()
        {
            let (state, attempts, outcome) = outbox_diagnostics(db, outbox);
            panic!(
                "synthetic SMTP did not receive DATA; outbox_state={state}, attempts={attempts}, last_outcome={outcome:?}, smtp_connections={}, command_categories={:?}, last_io_error={:?}",
                self.connection_count(),
                self.command_categories(),
                self.last_io_error()
            );
        }
    }

    fn connection_count(&self) -> usize {
        self.observation.0.lock().unwrap().connections
    }

    fn command_categories(&self) -> Vec<&'static str> {
        self.observation
            .0
            .lock()
            .unwrap()
            .command_categories
            .clone()
    }

    fn last_io_error(&self) -> Option<String> {
        self.observation.0.lock().unwrap().last_io_error.clone()
    }

    fn captured_message(&self) -> Option<String> {
        let state = self.observation.0.lock().unwrap();
        (state.data_messages > 0).then(|| state.last_message.clone())
    }

    fn wait_for_second_connection(&self, timeout: Duration) -> bool {
        let (lock, changed) = &*self.observation;
        let mut state = lock.lock().unwrap();
        let deadline = Instant::now() + timeout;
        while state.connections < 2 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, result) = changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if result.timed_out() {
                return state.connections >= 2;
            }
        }
        true
    }

    fn release_after_shutdown(&self) {
        self.release
            .as_ref()
            .expect("only the shutdown SMTP fixture has a release gate")
            .send(())
            .expect("SMTP helper is still waiting for its final reply");
    }

    fn finish(mut self) -> SmtpObservation {
        self.stop.store(true, Ordering::SeqCst);
        self.task
            .take()
            .unwrap()
            .join()
            .expect("SMTP fixture thread");
        let (lock, _) = &*self.observation;
        let observation = std::mem::take(&mut *lock.lock().unwrap());
        observation
    }
}

impl Drop for LocalSmtp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn serve_smtp_connection(
    mut stream: TcpStream,
    behavior: SmtpBehavior,
    observation: &Arc<(Mutex<SmtpObservation>, Condvar)>,
    data_seen: &mpsc::Sender<()>,
    release: &mpsc::Receiver<()>,
) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    smtp_reply(&mut stream, "220 localhost ESMTP test\r\n")?;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let command = line.trim_end().to_ascii_uppercase();
        let category = if command.starts_with("EHLO ") || command.starts_with("HELO ") {
            "EHLO"
        } else if command.starts_with("MAIL FROM:") {
            "MAIL"
        } else if command.starts_with("RCPT TO:") {
            "RCPT"
        } else if command == "DATA" {
            "DATA"
        } else if command == "QUIT" {
            "QUIT"
        } else {
            "OTHER"
        };
        observation
            .0
            .lock()
            .unwrap()
            .command_categories
            .push(category);
        if command.starts_with("EHLO ") || command.starts_with("HELO ") {
            smtp_reply(&mut stream, "250 localhost\r\n")?;
        } else if command.starts_with("MAIL FROM:") || command.starts_with("RCPT TO:") {
            smtp_reply(&mut stream, "250 accepted\r\n")?;
        } else if command == "DATA" {
            smtp_reply(&mut stream, "354 end with dot\r\n")?;
            let mut message = String::new();
            loop {
                let mut data_line = String::new();
                if reader.read_line(&mut data_line)? == 0 {
                    return Ok(());
                }
                if data_line == ".\r\n" || data_line == ".\n" {
                    break;
                }
                if message.len() + data_line.len() > 32 * 1024 {
                    return Ok(());
                }
                message.push_str(&data_line);
            }
            {
                let (lock, changed) = &**observation;
                let mut state = lock.lock().unwrap();
                state.data_messages += 1;
                state.last_message = message;
                changed.notify_all();
            }
            let _ = data_seen.send(());
            if matches!(behavior, SmtpBehavior::HoldForShutdown) {
                let _ = release.recv_timeout(Duration::from_secs(20));
            }
            match behavior {
                SmtpBehavior::Accept | SmtpBehavior::HoldForShutdown => {
                    smtp_reply(&mut stream, "250 queued\r\n")?;
                }
                SmtpBehavior::Unknown => {
                    smtp_reply(&mut stream, "451 temporary failure after DATA\r\n")?;
                }
            }
        } else if command == "QUIT" {
            smtp_reply(&mut stream, "221 bye\r\n")?;
            return Ok(());
        } else {
            smtp_reply(&mut stream, "250 ok\r\n")?;
        }
    }
}

fn smtp_reply(stream: &mut TcpStream, reply: &str) -> std::io::Result<()> {
    stream.write_all(reply.as_bytes())?;
    stream.flush()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn crypto() -> RingAccountSecurityCrypto {
    RingAccountSecurityCrypto::new(
        AUTHORITY.into(),
        [201; 32],
        AccountSecurityKeySet::new("current".into(), [21; 32], [22; 32], [23; 32], [24; 32]),
        None,
    )
    .unwrap()
}

fn write_keys(db: &Db) {
    write_private(&db.dir.join("account-subject.key"), &[201; 32]);
    let mut keyset = Vec::with_capacity(128);
    for byte in 21..25 {
        keyset.extend_from_slice(&[byte; 32]);
    }
    write_private(&db.dir.join("account-current.keys"), &keyset);
}

fn build_runtime_config(
    db: &Db,
    recovery_email: Option<bool>,
    smtp_port: u16,
) -> (u16, std::path::PathBuf, Value) {
    write_keys(db);
    let bind_port = free_port();
    let _ = db.explicit_command(bind_port, db.mode, "/identity", "");
    let config_path = db.dir.join("explicit.json");
    let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    let mut account_security = json!({
        "authority":AUTHORITY,
        "subject_key_file":"account-subject.key",
        "current":{"key_id":"current","key_file":"account-current.keys"}
    });
    if let Some(enabled) = recovery_email {
        account_security["recovery_email"] = json!(enabled);
    }
    config["runtime"]["account_security"] = account_security;
    config["runtime"]["email"] = json!({
        "mode":"smtp",
        "smtp":{"host":"127.0.0.1","port":smtp_port,"tls_mode":"plain"},
        "from_email":"sender@example.test",
        "subject":"Password recovery"
    });
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    (bind_port, config_path, config)
}

fn preparation_cli(path: &std::path::Path, command: &str, args: &[&str], db: &Db) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"));
    for (key, _) in env::vars().filter(|(key, _)| key.starts_with("EMBEDDED_IDP_APP_")) {
        child.env_remove(key);
    }
    child
        .arg(command)
        .arg("--config")
        .arg(path)
        .args(args)
        .env("IDP_TEST_DATABASE_URI", &db.uri)
        .output()
        .unwrap()
}

fn install_security(path: &std::path::Path, db: &Db) {
    for extension in ["foundation", "runtime"] {
        let plan = preparation_cli(path, "security-plan", &["--extension", extension], db);
        assert!(
            plan.status.success(),
            "security plan failed: {}",
            String::from_utf8_lossy(&plan.stderr)
        );
        let plan: Value = serde_json::from_slice(&plan.stdout).unwrap();
        let apply = preparation_cli(
            path,
            "security-apply",
            &[
                "--extension",
                extension,
                "--fingerprint",
                plan["fingerprint"].as_str().unwrap(),
            ],
            db,
        );
        assert!(
            apply.status.success(),
            "security apply failed: {}",
            String::from_utf8_lossy(&apply.stderr)
        );
        let check = preparation_cli(path, "security-check", &["--extension", extension], db);
        assert!(
            check.status.success(),
            "security check failed: {}",
            String::from_utf8_lossy(&check.stderr)
        );
    }
}

fn start_host(db: &Db, bind_port: u16, config: Value, capture_stderr: bool) -> Host {
    let mut command = db.explicit_command_from_config(config);
    if capture_stderr {
        command.stderr(Stdio::piped());
    }
    db.start_command(bind_port, &mut command)
}

fn start_recovery(db: &Db, email: &str) -> (Uuid, Uuid) {
    let account = Uuid::now_v7();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut client = db.adapter.connect().unwrap();
    let mut tx = client.transaction().unwrap();
    tx.execute(
        &format!("insert into {}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,'0',$2,'synthetic-test-hash','active',$3)", db.adapter.schema_name()),
        &[&account, &email, &now],
    )
    .unwrap();
    tx.execute(
        &format!("insert into {}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('0',$1,'active',$2)", db.adapter.schema_name()),
        &[&account, &now],
    )
    .unwrap();
    tx.commit().unwrap();

    let store = PostgresAccessStore::new(db.adapter.clone(), db.mode).unwrap();
    let service =
        CoreRecoveryStartService::new(db.mode, store, SystemClock, crypto(), UuidV7IdGenerator);
    let operation = Uuid::now_v7();
    let receipt_secret = Base64UrlUnpadded::encode_string(&[202; 32]);
    let result = service
        .start_recovery(RecoveryStartCommand {
            email: SecretString::new(email),
            operation_id: operation,
            receipt_secret: SecretString::new(receipt_secret),
        })
        .unwrap();
    let decoded = Base64UrlUnpadded::decode_vec(result.handle.expose_secret()).unwrap();
    let flow = Uuid::from_slice(&decoded[..16]).unwrap();
    (account, flow)
}

fn outbox_id(db: &Db, flow: Uuid) -> Uuid {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select id from {}.security_email_outbox where flow_id=$1",
                db.adapter.schema_name()
            ),
            &[&flow],
        )
        .unwrap()
        .get(0)
}

fn outbox_state(db: &Db, outbox: Uuid) -> (String, Option<String>, Option<Vec<u8>>) {
    let row = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select state,envelope_key_id,ciphertext from {}.security_email_outbox where id=$1",
                db.adapter.schema_name()
            ),
            &[&outbox],
        )
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

fn outbox_diagnostics(db: &Db, outbox: Uuid) -> (String, i32, Option<String>) {
    let row = db
        .adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select state,attempts,last_outcome from {}.security_email_outbox where id=$1",
                db.adapter.schema_name()
            ),
            &[&outbox],
        )
        .unwrap();
    (row.get(0), row.get(1), row.get(2))
}

fn wait_for_state(db: &Db, outbox: Uuid, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state: String = db
            .adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select state from {}.security_email_outbox where id=$1",
                    db.adapter.schema_name()
                ),
                &[&outbox],
            )
            .unwrap()
            .get(0);
        if state == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "outbox did not reach {expected}; current state is {state}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn recovery_code(db: &Db, flow: Uuid) -> String {
    let row = db.adapter.connect().unwrap().query_one(
        &format!("select id,envelope_key_id,ciphertext from {}.security_email_outbox where flow_id=$1",db.adapter.schema_name()),
        &[&flow],
    ).unwrap();
    let outbox: Uuid = row.get(0);
    let opened = crypto()
        .open(
            SecurityEnvelopePurpose::RecoveryEmail,
            &SecurityCryptoContext {
                reference_id: outbox,
                related_id: Some(flow),
            },
            &SecurityEnvelope {
                key_id: row.get(1),
                ciphertext: row.get(2),
            },
        )
        .unwrap();
    opened
        .expose_secret()
        .split('\n')
        .nth(2)
        .unwrap()
        .to_owned()
}

fn mark_sending_lease_expired(db: &Db, flow: Uuid) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let created = now - 50;
    let expires = now + 850;
    let retained = created + 86_400;
    let lease_until = now - 1;
    let lease = Uuid::now_v7();
    let mut client = db.adapter.connect().unwrap();
    let mut tx = client.transaction().unwrap();
    tx.execute(
        &format!("update {}.password_recovery_flows set created_at_epoch=$2,expires_at_epoch=$3,retained_until_epoch=$4 where id=$1",db.adapter.schema_name()),
        &[&flow,&created,&expires,&retained],
    ).unwrap();
    tx.execute(
        &format!("update {}.security_email_outbox set state='sending',created_at_epoch=$2,expires_at_epoch=$3,next_attempt_at_epoch=$2,attempts=1,lease_token=$4,lease_until_epoch=$5 where flow_id=$1",db.adapter.schema_name()),
        &[&flow,&created,&expires,&lease,&lease_until],
    ).unwrap();
    tx.commit().unwrap();
}

fn assert_terminal_redacted(db: &Db, outbox: Uuid, state: &str, outcome: &str) {
    let row = db.adapter.connect().unwrap().query_one(
        &format!("select state,last_outcome,envelope_key_id,ciphertext,lease_token,lease_until_epoch from {}.security_email_outbox where id=$1",db.adapter.schema_name()),
        &[&outbox],
    ).unwrap();
    assert_eq!(row.get::<_, String>(0), state);
    assert_eq!(row.get::<_, String>(1), outcome);
    assert!(row.get::<_, Option<String>>(2).is_none());
    assert!(row.get::<_, Option<Vec<u8>>>(3).is_none());
    assert!(row.get::<_, Option<Uuid>>(4).is_none());
    assert!(row.get::<_, Option<i64>>(5).is_none());
}

fn recovery_start_body(email: &str, operation: Uuid, receipt_secret: &[u8; 32]) -> Value {
    json!({
        "email": email,
        "operation_id": operation.to_string(),
        "receipt_secret": Base64UrlUnpadded::encode_string(receipt_secret)
    })
}

fn recovery_complete_body(
    handle: &str,
    code: &str,
    new_password: &str,
    operation: Uuid,
    receipt_secret: &[u8; 32],
) -> Value {
    json!({
        "handle": handle,
        "code": code,
        "new_password": new_password,
        "operation_id": operation.to_string(),
        "receipt_secret": Base64UrlUnpadded::encode_string(receipt_secret)
    })
}

fn recovery_result_body(operation: Uuid, receipt_secret: &[u8; 32]) -> Value {
    json!({
        "operation_id": operation.to_string(),
        "receipt_secret": Base64UrlUnpadded::encode_string(receipt_secret)
    })
}

fn raw_request(
    host: &Host,
    path: &str,
    headers: &[(&str, String)],
    body: &Value,
) -> (u16, String, Value) {
    let encoded = body.to_string();
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        host.port,
        encoded.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&encoded);
    let mut stream = TcpStream::connect(("127.0.0.1", host.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (headers, body) = response.split_once("\r\n\r\n").unwrap();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (
        status,
        headers.to_owned(),
        serde_json::from_str(body).unwrap_or(Value::Null),
    )
}

fn safe_recovery_headers(headers: &str) {
    let lower = headers.to_ascii_lowercase();
    assert!(lower.contains("cache-control: no-store"), "{headers}");
    assert!(!lower.contains("set-cookie:"), "{headers}");
}

fn start_receipt_flow(db: &Db, operation: Uuid) -> Uuid {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select flow_id from {}.password_recovery_start_receipts where operation_id=$1",
                db.adapter.schema_name()
            ),
            &[&operation],
        )
        .unwrap()
        .get(0)
}

fn smtp_recovery_code(message: &str) -> String {
    message
        .lines()
        .find_map(|line| line.strip_prefix("Your password recovery code is: "))
        .expect("SMTP message contains the recovery code line")
        .trim()
        .to_owned()
}

fn prepare_recovery_host(db: &Db) -> (String, String) {
    prepare_recovery_host_with_credentials(
        db,
        "admin@example.test",
        "Runtime-Admin123",
        ORDINARY_EMAIL,
        OLD_PASSWORD,
    )
}

fn prepare_recovery_host_with_credentials(
    db: &Db,
    admin_email: &str,
    admin_password: &str,
    ordinary_email: &str,
    ordinary_password: &str,
) -> (String, String) {
    let setup = db.start_explicit("/identity", "");
    let admin = setup.json(
        "POST",
        "/identity/admin/auth/login",
        None,
        None,
        Some(json!({"email":admin_email,"password":admin_password})),
        200,
    );
    let admin_token = token(&admin);
    for client in ["recovery-one", "recovery-two"] {
        setup.json(
            "POST",
            "/identity/admin/clients/upsert",
            Some(admin_token),
            None,
            Some(json!({
                "client_id":client,
                "client_name":client,
                "redirect_uris":["http://127.0.0.1/callback"],
                "client_type":"public_desktop",
                "pkce_required":true
            })),
            200,
        );
    }
    let tenant = if db.mode == TenancyMode::Enabled {
        setup.json(
            "POST",
            "/identity/admin/tenants",
            Some(admin_token),
            None,
            Some(json!({
                "tenant_id":"recovery-domain",
                "name":"Recovery test",
                "allow_registration":false,
                "administrator":{"kind":"existing","subject_id":admin["session"]["account_id"]}
            })),
            201,
        );
        "recovery-domain"
    } else {
        "0"
    };
    let created = setup.json(
        "POST",
        "/identity/admin/platform/accounts",
        Some(admin_token),
        None,
        Some(json!({"tenant_id":tenant,"email":ordinary_email,"password":ordinary_password})),
        200,
    );
    assert_eq!(created["account"]["status"], "active");
    (
        tenant.to_owned(),
        created["account"]["account_id"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

fn recovery_config(db: &Db, enabled: bool, smtp_port: u16) -> (u16, Value, std::path::PathBuf) {
    let (port, config_path, mut config) = build_runtime_config(db, Some(enabled), smtp_port);
    config["runtime"]["abuse"] = json!({"account":{"period_ms":1000,"burst":100}});
    let tenant = if db.mode == TenancyMode::Enabled {
        "recovery-domain"
    } else {
        "0"
    };
    config["business_entries"] = json!([
        {"login_entry":"recovery-one","client_id":"recovery-one","tenant_policy":{"kind":"fixed","tenant_id":tenant},"mount_prefix":"/one","browser":{"cookie_name":"recovery_one"}},
        {"login_entry":"recovery-two","client_id":"recovery-two","tenant_policy":{"kind":"fixed","tenant_id":tenant},"mount_prefix":"/two","browser":{"cookie_name":"recovery_two"}}
    ]);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    (port, config, config_path)
}

fn bootstrap_fixture_admin(db: &Db, password: &str) {
    CoreAccessBootstrapService::new(db.mode, db.adapter.clone(), SystemClock, UuidV7IdGenerator)
        .initialize_administrator(
            &AuthConfig {
                allow_local_registration: true,
                access_token_ttl_secs: 900,
                refresh_token_ttl_secs: 86400,
                session_ttl_secs: 604800,
                verification_code_ttl_secs: 900,
                password_min_length: 8,
                password_max_length: 128,
            },
            BootstrapAdministrator {
                email: "admin@example.test".into(),
                display_name: None,
                password: SecretString::new(password),
                request_id: "c2-browser-fixture".into(),
            },
        )
        .unwrap();
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn reference_host_recovery_worker_sends_and_clears_outbox_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();
        let smtp = LocalSmtp::start(SmtpBehavior::Accept);
        let (bind_port, config_path, config) = build_runtime_config(&db, Some(true), smtp.port());
        install_security(&config_path, &db);
        let (_, flow) = start_recovery(&db, RECIPIENT);
        let code = recovery_code(&db, flow);
        let outbox = outbox_id(&db, flow);
        let mut command = db.explicit_command_from_config(config);
        command.stderr(Stdio::inherit());
        let mut host = db.start_command(bind_port, &mut command);
        smtp.wait_for_data(Duration::from_secs(15), &db, outbox);
        wait_for_state(&db, outbox, "accepted");
        let observation = smtp.finish();
        assert_eq!(observation.connections, 1);
        assert_eq!(observation.data_messages, 1);
        assert!(observation.last_message.contains(RECIPIENT));
        assert!(observation.last_message.contains(&code));
        assert_terminal_redacted(&db, outbox, "accepted", "accepted");
        host.terminate_gracefully();
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn reference_host_recovery_unknown_result_is_not_resent_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();
        let smtp = LocalSmtp::start(SmtpBehavior::Unknown);
        let (bind_port, config_path, config) = build_runtime_config(&db, Some(true), smtp.port());
        install_security(&config_path, &db);
        let (_, flow) = start_recovery(&db, RECIPIENT);
        let outbox = outbox_id(&db, flow);
        let mut command = db.explicit_command_from_config(config);
        command.stderr(Stdio::inherit());
        let mut host = db.start_command(bind_port, &mut command);
        smtp.wait_for_data(Duration::from_secs(15), &db, outbox);
        wait_for_state(&db, outbox, "unknown");
        // Two one-second worker intervals leave time for an accidental retry to
        // reach this still-listening synthetic SMTP server.
        assert!(!smtp.wait_for_second_connection(Duration::from_millis(2500)));
        let observation = smtp.finish();
        assert_eq!(observation.connections, 1);
        assert_eq!(observation.data_messages, 1);
        assert_terminal_redacted(&db, outbox, "unknown", "unknown");
        host.terminate_gracefully();
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn reference_host_without_recovery_email_still_runs_cleanup_without_sending() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();
        let smtp = LocalSmtp::start(SmtpBehavior::Accept);
        let (bind_port, config_path, config) = build_runtime_config(&db, None, smtp.port());
        install_security(&config_path, &db);
        let (_, send_flow) = start_recovery(&db, RECIPIENT);
        let pending_outbox = outbox_id(&db, send_flow);
        let (_, cleanup_flow) = start_recovery(&db, OTHER_RECIPIENT);
        let cleanup_outbox = outbox_id(&db, cleanup_flow);
        mark_sending_lease_expired(&db, cleanup_flow);
        let mut host = start_host(&db, bind_port, config, false);
        wait_for_state(&db, cleanup_outbox, "unknown");
        assert_eq!(outbox_state(&db, pending_outbox).0, "pending");
        assert_terminal_redacted(&db, cleanup_outbox, "unknown", "unknown");
        host.terminate_gracefully();
        let observation = smtp.finish();
        assert_eq!(observation.connections, 0);
        assert_eq!(observation.data_messages, 0);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn reference_host_shutdown_drains_an_inflight_recovery_send_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();
        let smtp = LocalSmtp::start(SmtpBehavior::HoldForShutdown);
        let (bind_port, config_path, config) = build_runtime_config(&db, Some(true), smtp.port());
        install_security(&config_path, &db);
        let (_, flow) = start_recovery(&db, RECIPIENT);
        let outbox = outbox_id(&db, flow);
        let mut command = db.explicit_command_from_config(config);
        command.stderr(Stdio::piped());
        let mut host = db.start_command(bind_port, &mut command);
        smtp.wait_for_data(Duration::from_secs(15), &db, outbox);

        let stderr = host
            .child
            .stderr
            .take()
            .expect("captured reference-host stderr");
        let (line_tx, line_rx) = mpsc::channel();
        let stderr_reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if line_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let pid = host.child.id().to_string();
        let signal = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("send SIGTERM to reference host");
        assert!(signal.success());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut saw_drain = false;
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match line_rx.recv_timeout(remaining) {
                Ok(line) if line == "security runtime stopping" => {
                    saw_drain = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert!(saw_drain, "host did not announce security-runtime drain");
        assert!(
            host.child.try_wait().unwrap().is_none(),
            "host exited before SMTP was released"
        );
        smtp.release_after_shutdown();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = host.child.try_wait().unwrap() {
                assert!(status.success(), "host shutdown failed: {status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "host did not drain after SMTP reply"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let _ = stderr_reader.join();
        let observation = smtp.finish();
        assert_eq!(observation.connections, 1);
        assert_eq!(observation.data_messages, 1);
        assert_terminal_redacted(&db, outbox, "accepted", "accepted");
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn s03_b3_recovery_http_is_opt_in_anonymous_and_revokes_credentials_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.bootstrap();
        db.seed_management_client();
        let (tenant, account_id) = prepare_recovery_host(&db);
        let smtp = LocalSmtp::start(SmtpBehavior::Accept);
        let (port, mut config, config_path) = recovery_config(&db, false, smtp.port());
        install_security(&config_path, &db);

        let mut host = start_host(&db, port, config.clone(), false);
        let off_body = recovery_start_body("unknown@example.test", Uuid::now_v7(), &[211; 32]);
        for path in [
            "/identity/admin/auth/password-recovery/start",
            "/one/auth/password-recovery/start",
            "/one/auth/browser/password-recovery/start",
            "/identity/admin/auth/password-recovery/complete",
            "/one/auth/password-recovery/complete",
            "/one/auth/browser/password-recovery/complete",
            "/identity/admin/auth/password-recovery/result",
            "/one/auth/password-recovery/result",
            "/one/auth/browser/password-recovery/result",
        ] {
            let body = if path.ends_with("/complete") {
                recovery_complete_body(
                    "invalid",
                    "invalid",
                    "Password-Recovery-2!",
                    Uuid::now_v7(),
                    &[211; 32],
                )
            } else if path.ends_with("/result") {
                recovery_result_body(Uuid::now_v7(), &[211; 32])
            } else {
                off_body.clone()
            };
            assert_eq!(raw_request(&host, path, &[], &body).0, 404, "{path}");
        }
        host.terminate_gracefully();

        config["runtime"]["account_security"]["recovery_email"] = json!(true);
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let mut host = start_host(&db, port, config, false);

        // Unknown identities receive the same public response shape and create
        // no outbox mail. This does not reveal the ordinary account's existence.
        let dummy_body = recovery_start_body("unknown@example.test", Uuid::now_v7(), &[212; 32]);
        let (dummy_status, dummy_headers, dummy) = raw_request(
            &host,
            "/identity/admin/auth/password-recovery/start",
            &[],
            &dummy_body,
        );
        assert_eq!(dummy_status, 200, "{dummy}");
        safe_recovery_headers(&dummy_headers);
        assert!(dummy["handle"].as_str().is_some());
        assert!(dummy["expires_at_unix_secs"].as_u64().is_some());
        assert_eq!(dummy.as_object().unwrap().len(), 2);
        let business_dummy_body =
            recovery_start_body("business-unknown@example.test", Uuid::now_v7(), &[217; 32]);
        let (status, headers, business_dummy) = raw_request(
            &host,
            "/two/auth/password-recovery/start",
            &[],
            &business_dummy_body,
        );
        assert_eq!(status, 200, "{business_dummy}");
        safe_recovery_headers(&headers);
        assert_eq!(business_dummy.as_object().unwrap().len(), 2);
        assert_eq!(smtp.connection_count(), 0);

        // Browser protection checks the exact configured Origin, but no browser
        // cookie is needed for this anonymous recovery action.
        let browser_body =
            recovery_start_body("browser-unknown@example.test", Uuid::now_v7(), &[213; 32]);
        let browser_headers = [
            ("Origin", "https://wrong-origin.example".to_owned()),
            ("X-Embedded-Idp-Browser", "1".to_owned()),
        ];
        let (status, headers, _) = raw_request(
            &host,
            "/one/auth/browser/password-recovery/start",
            &browser_headers,
            &browser_body,
        );
        assert_eq!(status, 403);
        safe_recovery_headers(&headers);
        let browser_headers = [
            ("Origin", format!("http://127.0.0.1:{port}")),
            ("X-Embedded-Idp-Browser", "1".to_owned()),
        ];
        let (status, headers, value) = raw_request(
            &host,
            "/one/auth/browser/password-recovery/start",
            &browser_headers,
            &browser_body,
        );
        assert_eq!(status, 200, "{value}");
        safe_recovery_headers(&headers);
        assert_eq!(smtp.connection_count(), 0);

        let one_old = host.json(
            "POST",
            "/one/auth/login",
            None,
            None,
            Some(json!({"email":ORDINARY_EMAIL,"password":OLD_PASSWORD})),
            200,
        );
        let two_old = host.json(
            "POST",
            "/two/auth/login",
            None,
            None,
            Some(json!({"email":ORDINARY_EMAIL,"password":OLD_PASSWORD})),
            200,
        );
        assert_eq!(one_old["session"]["account_id"], account_id);
        assert_eq!(two_old["session"]["tenant_id"], tenant);

        let start_operation = Uuid::now_v7();
        let start_secret = [214; 32];
        let start_body = recovery_start_body(ORDINARY_EMAIL, start_operation, &start_secret);
        let (status, headers, started) =
            raw_request(&host, "/one/auth/password-recovery/start", &[], &start_body);
        assert_eq!(status, 200, "{started}");
        safe_recovery_headers(&headers);
        let handle = started["handle"].as_str().unwrap().to_owned();
        let (status, headers, replayed_start) =
            raw_request(&host, "/two/auth/password-recovery/start", &[], &start_body);
        assert_eq!(status, 200, "{replayed_start}");
        safe_recovery_headers(&headers);
        assert_eq!(replayed_start["handle"], handle);
        let browser_headers = [
            ("Origin", format!("http://127.0.0.1:{port}")),
            ("X-Embedded-Idp-Browser", "1".to_owned()),
        ];
        let (status, headers, browser_start) = raw_request(
            &host,
            "/one/auth/browser/password-recovery/start",
            &browser_headers,
            &start_body,
        );
        assert_eq!(status, 200, "{browser_start}");
        safe_recovery_headers(&headers);
        assert_eq!(browser_start["handle"], handle);

        let flow = start_receipt_flow(&db, start_operation);
        let outbox = outbox_id(&db, flow);
        smtp.wait_for_data(Duration::from_secs(15), &db, outbox);
        wait_for_state(&db, outbox, "accepted");
        let observation = smtp.finish();
        assert_eq!(observation.connections, 1);
        assert_eq!(observation.data_messages, 1);
        assert!(observation.last_message.contains(ORDINARY_EMAIL));
        let code = smtp_recovery_code(&observation.last_message);
        assert_terminal_redacted(&db, outbox, "accepted", "accepted");

        let completion_operation = Uuid::now_v7();
        let completion_secret = [215; 32];
        let complete_body = recovery_complete_body(
            &handle,
            &code,
            NEW_PASSWORD,
            completion_operation,
            &completion_secret,
        );
        let (status, headers, completed) = raw_request(
            &host,
            "/two/auth/password-recovery/complete",
            &[],
            &complete_body,
        );
        assert_eq!(status, 200, "{completed}");
        assert_eq!(completed["completed"], true);
        safe_recovery_headers(&headers);

        let browser_headers = [
            ("Origin", format!("http://127.0.0.1:{port}")),
            ("X-Embedded-Idp-Browser", "1".to_owned()),
        ];
        let (status, headers, browser_completed) = raw_request(
            &host,
            "/two/auth/browser/password-recovery/complete",
            &browser_headers,
            &complete_body,
        );
        assert_eq!(status, 200, "{browser_completed}");
        assert_eq!(browser_completed["completed"], true);
        safe_recovery_headers(&headers);

        let (status, headers, replayed_completion) = raw_request(
            &host,
            "/identity/admin/auth/password-recovery/complete",
            &[],
            &complete_body,
        );
        assert_eq!(status, 200, "{replayed_completion}");
        assert_eq!(replayed_completion["completed"], true);
        safe_recovery_headers(&headers);
        let (status, headers, result) = raw_request(
            &host,
            "/identity/admin/auth/password-recovery/result",
            &[],
            &recovery_result_body(completion_operation, &completion_secret),
        );
        assert_eq!(status, 200, "{result}");
        assert_eq!(result["completed"], true);
        safe_recovery_headers(&headers);
        let (status, headers, incorrect_receipt) = raw_request(
            &host,
            "/two/auth/password-recovery/result",
            &[],
            &recovery_result_body(completion_operation, &[216; 32]),
        );
        assert_eq!(status, 200, "{incorrect_receipt}");
        assert_eq!(incorrect_receipt["completed"], false);
        safe_recovery_headers(&headers);
        let (status, headers, browser_result) = raw_request(
            &host,
            "/one/auth/browser/password-recovery/result",
            &browser_headers,
            &recovery_result_body(completion_operation, &completion_secret),
        );
        assert_eq!(status, 200, "{browser_result}");
        assert_eq!(browser_result["completed"], true);
        safe_recovery_headers(&headers);

        for (path, access_token) in [
            ("/one/auth/session", token(&one_old)),
            ("/two/auth/session", token(&two_old)),
        ] {
            assert_eq!(host.raw("GET", path, Some(access_token), None, None).0, 401);
        }
        assert_eq!(
            host.raw(
                "POST",
                "/one/auth/login",
                None,
                None,
                Some(json!({"email":ORDINARY_EMAIL,"password":OLD_PASSWORD}))
            )
            .0,
            401
        );
        let new_login = host.json(
            "POST",
            "/two/auth/login",
            None,
            None,
            Some(json!({"email":ORDINARY_EMAIL,"password":NEW_PASSWORD})),
            200,
        );
        assert_eq!(new_login["session"]["account_id"], account_id);
        host.terminate_gracefully();
    }
}

#[test]
#[ignore = "requires explicit PostgreSQL URI and IDP_C2_BROWSER_FIXTURE=1"]
fn c2_browser_fixture_runs_until_stop_file_and_keeps_secrets_private() {
    assert_eq!(
        env::var("IDP_C2_BROWSER_FIXTURE").as_deref(),
        Ok("1"),
        "set IDP_C2_BROWSER_FIXTURE=1 only for the isolated browser fixture"
    );
    let mode = match env::var("IDP_C2_MODE").as_deref() {
        Ok("enabled") => TenancyMode::Enabled,
        Ok("disabled") => TenancyMode::Disabled,
        _ => panic!("IDP_C2_MODE must be enabled or disabled"),
    };
    assert!(env::var_os("EMBEDDED_IDP_TEST_PG_CONNECTION_URI").is_some());

    let db = Db::new(mode);
    let admin_password = format!("FixtureAdmin-{}!Aa1", Uuid::now_v7());
    let ordinary_password = format!("FixtureUser-{}!Aa1", Uuid::now_v7());
    let ordinary_email = format!("ordinary-{}@example.test", Uuid::now_v7());
    bootstrap_fixture_admin(&db, &admin_password);
    db.seed_management_client();
    let (tenant, account_id) = prepare_recovery_host_with_credentials(
        &db,
        "admin@example.test",
        &admin_password,
        &ordinary_email,
        &ordinary_password,
    );

    let smtp = LocalSmtp::start(SmtpBehavior::Accept);
    let (port, mut config, config_path) = recovery_config(&db, true, smtp.port());
    config["management"]["ui"] = json!({"base_path":"/console"});
    config["runtime"]["http"]["browser_origin"] = json!("http://127.0.0.1:4187");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    install_security(&config_path, &db);

    let credentials_path = db.dir.join("browser-credentials.json");
    write_private(
        &credentials_path,
        &serde_json::to_vec(&json!({
            "management":{"email":"admin@example.test","password":admin_password},
            "ordinary":{"email":ordinary_email,"password":ordinary_password,"tenant_id":tenant,"account_id":account_id}
        }))
        .unwrap(),
    );
    let code_path = db.dir.join("smtp-recovery-code");
    let stop_path = db.dir.join("stop-fixture");
    let metadata_path = db.dir.join("browser-fixture.json");
    let upstream = format!("http://127.0.0.1:{port}");
    let browser_origin = "http://127.0.0.1:4187";
    write_private(
        &metadata_path,
        &serde_json::to_vec(&json!({
            "mode": if mode == TenancyMode::Enabled { "enabled" } else { "disabled" },
            "browser_origin": browser_origin,
            "management_ui": {
                "browser":format!("{browser_origin}/console/"),
                "upstream":format!("{upstream}/console/")
            },
            "management_api":{"browser":format!("{browser_origin}/identity"),"upstream":format!("{upstream}/identity")},
            "business_apis":{
                "recovery_one":{"browser":format!("{browser_origin}/one"),"upstream":format!("{upstream}/one")},
                "recovery_two":{"browser":format!("{browser_origin}/two"),"upstream":format!("{upstream}/two")}
            },
            "credentials_file":credentials_path,
            "smtp_code_file":code_path,
            "stop_file":stop_path
        }))
        .unwrap(),
    );

    let mut host = start_host(&db, port, config, false);
    println!(
        "C2_BROWSER_FIXTURE_METADATA={}",
        serde_json::to_string(&json!({
            "metadata_file":metadata_path,
            "management_ui":format!("{browser_origin}/console/"),
            "business_api_one":format!("{browser_origin}/one"),
            "business_api_two":format!("{browser_origin}/two")
        }))
        .unwrap()
    );

    let deadline = Instant::now() + Duration::from_secs(20 * 60);
    let mut code_written = false;
    loop {
        if !code_written {
            if let Some(message) = smtp.captured_message() {
                let code = smtp_recovery_code(&message);
                write_private(&code_path, code.as_bytes());
                code_written = true;
            }
        }
        if stop_path.exists() {
            break;
        }
        assert!(
            host.child.try_wait().unwrap().is_none(),
            "reference host exited before fixture stop"
        );
        assert!(
            Instant::now() < deadline,
            "browser fixture exceeded its 20-minute limit"
        );
        thread::sleep(Duration::from_millis(200));
    }
    host.terminate_gracefully();
    if !code_written {
        if let Some(message) = smtp.captured_message() {
            let code = smtp_recovery_code(&message);
            write_private(&code_path, code.as_bytes());
        }
    }
    let _ = smtp.finish();
}

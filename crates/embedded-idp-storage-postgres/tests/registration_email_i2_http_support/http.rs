use axum::Router;
use embedded_idp_axum::{
    registration_email_router, tenant_auth_router, with_anonymous_login_budget,
    RegistrationEmailHttpConfig, RegistrationEmailRuntime, RegistrationEmailWorkers,
};
use embedded_idp_core::access::RegistrationEmailService;
use embedded_idp_core::PasswordWorkBudget;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::{auth_service, install_runtime, AccountLockGuard, Fixture, FixtureGuard, SmtpSink};

pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone, Copy)]
pub struct WorkerDiagnosticSnapshot {
    pub status: u16,
    pub worker_running: bool,
    pub store_ready: bool,
    pub accepting: bool,
    pub overdue_processing: i64,
    pub unresolved_delivery: i64,
    pub snapshot_available: bool,
    pub intent_reserved: i64,
    pub delivery_reserved: i64,
    pub delivery_claimed: i64,
    pub delivery_unknown: i64,
    pub paused: bool,
    pub event_register: i64,
    pub event_resend: i64,
    pub event_verify: i64,
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

pub struct Harness {
    fixture: FixtureGuard,
    pub smtp: SmtpSink,
    pub runtime: Arc<RegistrationEmailRuntime>,
    pub workers: Option<RegistrationEmailWorkers>,
    pub server: ServerHandle,
}

pub async fn worker_diagnostic_snapshot(
    harness: &Harness,
    status: u16,
) -> WorkerDiagnosticSnapshot {
    let runtime = harness.runtime.clone();
    let worker_running = runtime.worker_running();
    let service = runtime.service();
    let adapter = harness.fixture.get().adapter.clone();
    let schema = harness.fixture.get().schema.clone();
    let authority = harness.fixture.get().scope.authority.clone();
    let product = harness.fixture.get().scope.product.clone();
    tokio::task::spawn_blocking(move || {
        let facts = RegistrationEmailService::runtime_facts(&*service).ok();
        let Some(facts) = facts else {
            return WorkerDiagnosticSnapshot {
                status,
                worker_running,
                ..WorkerDiagnosticSnapshot::unavailable(status, worker_running)
            };
        };
        let Ok(mut client) = adapter.connect() else {
            return WorkerDiagnosticSnapshot {
                status,
                worker_running,
                ..WorkerDiagnosticSnapshot::unavailable(status, worker_running)
            };
        };
        let Ok(row) = client.query_one(
            &format!(
                "select \
                    (select count(*) from {schema}.registration_email_intents where status='reserved'), \
                    (select count(*) from {schema}.registration_email_deliveries where status='reserved'), \
                    (select count(*) from {schema}.registration_email_deliveries where status='claimed'), \
                    (select count(*) from {schema}.registration_email_deliveries where status='unknown'), \
                    (select paused from {schema}.registration_email_runtime_state where authority=$1), \
                    (select count(*) filter (where kind='register') from {schema}.registration_email_events where authority=$1 and product=$2), \
                    (select count(*) filter (where kind='resend') from {schema}.registration_email_events where authority=$1 and product=$2), \
                    (select count(*) filter (where kind='verify') from {schema}.registration_email_events where authority=$1 and product=$2)"
            ),
            &[&authority, &product],
        ) else {
            return WorkerDiagnosticSnapshot {
                status,
                worker_running,
                ..WorkerDiagnosticSnapshot::unavailable(status, worker_running)
            };
        };
        WorkerDiagnosticSnapshot {
            status,
            worker_running,
            store_ready: facts.store_ready,
            accepting: facts.accepting,
            overdue_processing: facts.overdue_processing as i64,
            unresolved_delivery: facts.unresolved_delivery as i64,
            snapshot_available: true,
            intent_reserved: row.get(0),
            delivery_reserved: row.get(1),
            delivery_claimed: row.get(2),
            delivery_unknown: row.get(3),
            paused: row.get(4),
            event_register: row.get(5),
            event_resend: row.get(6),
            event_verify: row.get(7),
        }
    })
    .await
    .unwrap_or_else(|_| WorkerDiagnosticSnapshot::unavailable(status, worker_running))
}

impl WorkerDiagnosticSnapshot {
    fn unavailable(status: u16, worker_running: bool) -> Self {
        Self {
            status,
            worker_running,
            store_ready: false,
            accepting: false,
            overdue_processing: 0,
            unresolved_delivery: 0,
            snapshot_available: false,
            intent_reserved: 0,
            delivery_reserved: 0,
            delivery_claimed: 0,
            delivery_unknown: 0,
            paused: false,
            event_register: 0,
            event_resend: 0,
            event_verify: 0,
        }
    }
}

pub async fn start_harness(fixture: Fixture, start_workers: bool, resume: bool) -> Harness {
    let budget = PasswordWorkBudget::default();
    let store_budget = budget.clone();
    let auth_budget = budget.clone();
    let (fixture, store, auth) = tokio::task::spawn_blocking(move || {
        install_runtime(&fixture);
        let store = fixture.store().with_password_work_budget(store_budget);
        let auth = auth_service(&fixture, auth_budget);
        (fixture, store, auth)
    })
    .await
    .expect("runtime migration task");
    let fixture = FixtureGuard::new(fixture);
    let service: Arc<dyn RegistrationEmailService> = Arc::new(store);
    let smtp = SmtpSink::start().expect("local SMTP sink");
    let runtime =
        RegistrationEmailRuntime::new(service, Arc::new(smtp.delivery_service()), budget.clone())
            .expect("runtime composition");
    let registration =
        registration_email_router(runtime.clone(), RegistrationEmailHttpConfig::default())
            .expect("registration router");
    let router = with_anonymous_login_budget(
        registration.merge(tenant_auth_router(auth)),
        runtime.login_http_budget(),
    );
    let server = ServerHandle::start(router).await;
    let workers = if start_workers {
        Some(runtime.start().await.expect("runtime start"))
    } else {
        None
    };
    if resume {
        runtime
            .resume_after_operator_check()
            .await
            .expect("trusted resume");
    }
    Harness {
        fixture,
        smtp,
        runtime,
        workers,
        server,
    }
}

impl ServerHandle {
    pub async fn start(router: Router) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("HTTP listener");
        let addr = listener.local_addr().expect("HTTP address");
        let (stop, receive) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = receive.await;
                })
                .await;
        });
        Self {
            addr,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("HTTP server task");
        }
    }
}

impl Harness {
    pub fn hold_account_lock(&self, email: &str) -> AccountLockGuard {
        super::hold_account_lock(self.fixture.get(), email)
    }

    pub async fn shutdown(mut self) -> embedded_idp_axum::RegistrationEmailShutdown {
        self.server.shutdown().await;
        let result = self
            .workers
            .take()
            .map(|workers| async move { workers.shutdown(Duration::from_secs(5)).await });
        let result = match result {
            Some(result) => result.await,
            None => embedded_idp_axum::RegistrationEmailShutdown {
                drained: true,
                unresolved_processing: 0,
                unresolved_delivery: 0,
                unresolved_storage: 0,
                unresolved_requests: 0,
                failed: false,
            },
        };
        drop(self.runtime);
        drop(self.fixture);
        result
    }
}

pub async fn post_json(addr: SocketAddr, path: &str, body: &str, profile: bool) -> HttpResponse {
    let path = path.to_owned();
    let body = body.to_owned();
    tokio::task::spawn_blocking(move || request(addr, &path, &body, profile))
        .await
        .expect("HTTP request task")
}

pub async fn post_without_profile(addr: SocketAddr, path: &str, body: &str) -> HttpResponse {
    post_json(addr, path, body, false).await
}

fn request(addr: SocketAddr, path: &str, body: &str, profile: bool) -> HttpResponse {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(3)).expect("HTTP connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("HTTP read timeout");
    let profile_header = if profile {
        "x-idp-registration-profile: idp-registration-email-v1\r\n"
    } else {
        ""
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{profile_header}\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .expect("HTTP request write");
    stream.flush().expect("HTTP request flush");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("HTTP response read");
    parse_response(&bytes)
}

fn parse_response(bytes: &[u8]) -> HttpResponse {
    let separator = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response headers");
    let head = std::str::from_utf8(&bytes[..separator]).expect("HTTP response header UTF-8");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .expect("HTTP status");
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let payload = &bytes[separator + 4..];
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked(payload)
    } else {
        payload.to_vec()
    };
    HttpResponse {
        status,
        headers,
        body: String::from_utf8(body).expect("HTTP body UTF-8"),
    }
}

fn decode_chunked(mut bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let Some(end) = bytes.windows(2).position(|window| window == b"\r\n") else {
            break;
        };
        let size = usize::from_str_radix(
            std::str::from_utf8(&bytes[..end]).expect("chunk size UTF-8"),
            16,
        )
        .expect("chunk size");
        bytes = &bytes[end + 2..];
        if size == 0 {
            break;
        }
        output.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
    output
}

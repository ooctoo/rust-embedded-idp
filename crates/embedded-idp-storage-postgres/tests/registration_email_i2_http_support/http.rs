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

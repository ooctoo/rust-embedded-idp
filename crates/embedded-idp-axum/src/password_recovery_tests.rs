use super::*;
use axum::{
    body::{Body, Bytes},
    http::Request,
};
use embedded_idp_core::access::{RecoveryCompleteError, RecoveryStartResult};
use embedded_idp_core::AccessTokenPurpose;
use serde_json::json;
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    task::{Context, Poll},
    time::UNIX_EPOCH,
};
use tower::ServiceExt;

#[derive(Default)]
struct FakeRecovery {
    starts: AtomicUsize,
    completions: AtomicUsize,
    results: AtomicUsize,
    start_result: Mutex<Option<Result<RecoveryStartResult, AccessError>>>,
    completion_result: Mutex<Option<Result<(), RecoveryCompleteError>>>,
    receipt_result: Mutex<Option<Result<bool, AccessError>>>,
    start_command: Mutex<Option<(String, String, String)>>,
    complete_command: Mutex<Option<(String, String, String, String, String)>>,
    result_query: Mutex<Option<(String, String)>>,
}

impl RecoveryStartService for FakeRecovery {
    fn start_recovery(
        &self,
        command: RecoveryStartCommand,
    ) -> Result<RecoveryStartResult, AccessError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        *self.start_command.lock().unwrap() = Some((
            command.email.expose_secret().to_owned(),
            command.operation_id.to_string(),
            command.receipt_secret.expose_secret().to_owned(),
        ));
        self.start_result.lock().unwrap().take().unwrap_or_else(|| {
            Ok(RecoveryStartResult {
                handle: SecretString::new("handle-secret"),
                expires_at: UNIX_EPOCH + Duration::from_secs(1234),
            })
        })
    }
}

impl RecoveryCompletionService for FakeRecovery {
    fn complete_recovery(
        &self,
        command: RecoveryCompleteCommand,
    ) -> Result<(), RecoveryCompleteError> {
        self.completions.fetch_add(1, Ordering::SeqCst);
        *self.complete_command.lock().unwrap() = Some((
            command.handle.expose_secret().to_owned(),
            command.code.expose_secret().to_owned(),
            command.new_password.expose_secret().to_owned(),
            command.operation_id.to_string(),
            command.receipt_secret.expose_secret().to_owned(),
        ));
        self.completion_result
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok(()))
    }

    fn recovery_completion_result(&self, query: SecurityReceiptQuery) -> Result<bool, AccessError> {
        self.results.fetch_add(1, Ordering::SeqCst);
        *self.result_query.lock().unwrap() = Some((
            query.operation_id.to_string(),
            query.receipt_secret.expose_secret().to_owned(),
        ));
        self.receipt_result
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok(false))
    }
}

fn routers(fake: Arc<FakeRecovery>) -> Router {
    password_recovery_router(fake.clone(), fake)
}

fn json_request(path: &str, body: &'static str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn body_json(response: Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
}

#[tokio::test]
async fn start_complete_and_result_use_fixed_shapes_without_cookie_auth() {
    let fake = Arc::new(FakeRecovery::default());
    let response = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/start",
            r#"{"email":"person@example.test","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"receipt-secret"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(
        body_json(response).await,
        json!({"handle":"handle-secret","expires_at_unix_secs":1234})
    );

    let response = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/complete",
            r#"{"handle":"opaque-handle","code":"012345","new_password":"NewPassword123!","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"receipt-secret"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, json!({"completed":true}));

    let response = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/result",
            r#"{"operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"receipt-secret"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, json!({"completed":false}));
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fake.completions.load(Ordering::SeqCst), 1);
    assert_eq!(fake.results.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fake.start_command.lock().unwrap(),
        Some((
            "person@example.test".into(),
            "00000000-0000-0000-0000-000000000001".into(),
            "receipt-secret".into(),
        ))
    );
    assert_eq!(
        *fake.complete_command.lock().unwrap(),
        Some((
            "opaque-handle".into(),
            "012345".into(),
            "NewPassword123!".into(),
            "00000000-0000-0000-0000-000000000001".into(),
            "receipt-secret".into(),
        ))
    );
    assert_eq!(
        *fake.result_query.lock().unwrap(),
        Some((
            "00000000-0000-0000-0000-000000000001".into(),
            "receipt-secret".into(),
        ))
    );

    let method_not_allowed = routers(fake)
        .oneshot(
            Request::get("/auth/password-recovery/start")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(method_not_allowed.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        method_not_allowed.headers()[header::CACHE_CONTROL],
        "no-store"
    );
}

#[tokio::test]
async fn strict_json_query_selectors_and_uuid_reject_before_core_calls() {
    let fake = Arc::new(FakeRecovery::default());
    let router = routers(fake.clone());
    let unknown = router
        .clone()
        .oneshot(json_request(
            "/auth/password-recovery/start",
            r#"{"email":"x","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s","extra":true}"#,
        ))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    let query = router
        .clone()
        .oneshot(json_request(
            "/auth/password-recovery/start?email=secret@example.test",
            r#"{"email":"x","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(query.status(), StatusCode::BAD_REQUEST);

    let selected = Request::post("/admin/auth/password-recovery/start")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-embedded-idp-business-id", "selected")
        .body(Body::from(
            r#"{"email":"x","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .unwrap();
    assert_eq!(
        management_password_recovery_router(fake.clone(), fake.clone())
            .oneshot(selected)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let bad_uuid = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/result",
            r#"{"operation_id":"not-a-uuid","receipt_secret":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(bad_uuid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
    assert_eq!(fake.results.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn body_size_timeout_and_content_type_have_fixed_http_errors() {
    let large = format!("{{\"email\":\"{}\"}}", "x".repeat(BODY_LIMIT));
    let response = routers(Arc::new(FakeRecovery::default()))
        .oneshot(
            Request::post("/auth/password-recovery/start")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(large))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body_json(response).await["code"], "request_too_large");

    let unsupported = routers(Arc::new(FakeRecovery::default()))
        .oneshot(
            Request::post("/auth/password-recovery/start")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);

    let timed_out = match decode_json::<ResultBody>(
        Request::post("/auth/password-recovery/result")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::new(PendingBody))
            .unwrap(),
        Duration::from_millis(10),
    )
    .await
    {
        Err(response) => response,
        Ok(_) => panic!("pending body read should time out"),
    };
    assert_eq!(timed_out.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn browser_origin_guard_runs_before_body_read_and_valid_request_needs_no_cookie() {
    let fake = Arc::new(FakeRecovery::default());
    let config = BrowserSessionHttpConfig::new(
        "https://idp.example.test",
        "idp_session",
        "/auth/browser",
        AccessTokenPurpose::Business,
    )
    .unwrap();
    let browser = browser_password_recovery_router(fake.clone(), fake.clone(), config);

    let rejected = Request::post("/auth/browser/password-recovery/start")
        .header(header::ORIGIN, "https://attacker.example.test")
        .body(Body::new(PendingBody))
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(1), browser.clone().oneshot(rejected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(body_json(response).await["code"], "browser_origin_rejected");
    assert_eq!(fake.starts.load(Ordering::SeqCst), 0);

    let accepted = Request::post("/auth/browser/password-recovery/start")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "https://idp.example.test")
        .header("x-embedded-idp-browser", "1")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            r#"{"email":"person@example.test","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .unwrap();
    let response = browser.oneshot(accepted).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn core_error_mapping_is_fixed_and_unknown_conflicts_fail_closed() {
    let fake = Arc::new(FakeRecovery::default());
    *fake.start_result.lock().unwrap() = Some(Err(AccessError::Conflict("recovery.rate_limited")));
    let rate_limited = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/start",
            r#"{"email":"x","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(rate_limited).await["code"], "rate_limited");

    *fake.start_result.lock().unwrap() =
        Some(Err(AccessError::Conflict("recovery.operation_conflict")));
    let conflict = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/start",
            r#"{"email":"x","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(conflict).await["code"], "operation_conflict");

    *fake.start_result.lock().unwrap() = Some(Err(AccessError::Conflict("unknown.marker")));
    let unknown = management_password_recovery_router(fake.clone(), fake.clone())
        .oneshot(json_request(
            "/admin/auth/password-recovery/start",
            r#"{"email":"x","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(unknown).await["code"], "security_unavailable");

    *fake.completion_result.lock().unwrap() = Some(Err(RecoveryCompleteError::InvalidRecovery));
    let invalid_recovery = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/complete",
            r#"{"handle":"h","code":"000000","new_password":"bad","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(invalid_recovery.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(invalid_recovery).await["code"],
        "invalid_recovery"
    );

    *fake.start_result.lock().unwrap() = Some(Ok(RecoveryStartResult {
        handle: SecretString::new("should-not-be-returned"),
        expires_at: UNIX_EPOCH - Duration::from_secs(1),
    }));
    let invalid_time = routers(fake.clone())
        .oneshot(json_request(
            "/auth/password-recovery/start",
            r#"{"email":"x","operation_id":"00000000-0000-0000-0000-000000000001","receipt_secret":"s"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(invalid_time.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(invalid_time).await["code"],
        "security_unavailable"
    );
}

struct PendingBody;

impl http_body::Body for PendingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::default()
    }
}

use super::*;
use axum::body::Body;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tower::ServiceExt;

const OP: &str = "00000000-0000-4000-8000-000000000011";
const SECRET: &str = "synthetic-receipt-secret";
const CURRENT: &str = "Current-fixture-123";
const NEXT: &str = "New-fixture-456";
const ACCOUNT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SESSION: &str = "00000000-0000-4000-8000-000000000001";

#[derive(Default)]
struct Seen {
    identity: AtomicUsize,
    change: AtomicUsize,
    result: AtomicUsize,
    error: Mutex<Option<SelfPasswordChangeError>>,
    expected: Mutex<Option<BrowserSessionIdentity>>,
}

struct Identity(Arc<Seen>, AccessTokenPurpose, Option<u64>);
impl SelfSecurityBrowserIdentityService for Identity {
    fn self_security_browser_purpose(&self) -> AccessTokenPurpose {
        self.1
    }
    fn self_security_browser_lifetime_secs(&self) -> Option<u64> {
        self.2
    }
    fn authenticate_self_security_browser(
        &self,
        cookie: SecretString,
        expected: BrowserSessionIdentity,
    ) -> Result<AccessActor, TenantAuthError> {
        assert_eq!(cookie.expose_secret(), "synthetic-cookie");
        self.0.identity.fetch_add(1, Ordering::SeqCst);
        let actor = AccessActor {
            tenant_id: expected.tenant_id.clone(),
            subject_id: expected.account_id.clone(),
            session_id: expected.session_id.clone(),
        };
        *self.0.expected.lock().unwrap() = Some(expected);
        Ok(actor)
    }
}

struct Service(Arc<Seen>);
impl SelfPasswordChangeService for Service {
    fn change_password(
        &self,
        _: AccessActor,
        command: SelfPasswordChangeCommand,
    ) -> Result<(), SelfPasswordChangeError> {
        assert_eq!(command.current_password.expose_secret(), CURRENT);
        assert_eq!(command.new_password.expose_secret(), NEXT);
        assert_eq!(command.operation_id.to_string(), OP);
        assert_eq!(command.receipt_secret.expose_secret(), SECRET);
        self.0.change.fetch_add(1, Ordering::SeqCst);
        if let Some(error) = self.0.error.lock().unwrap().clone() {
            Err(error)
        } else {
            Ok(())
        }
    }
    fn password_change_result(
        &self,
        query: SecurityReceiptQuery,
    ) -> Result<bool, SelfPasswordChangeError> {
        assert_eq!(query.operation_id.to_string(), OP);
        assert_eq!(query.receipt_secret.expose_secret(), SECRET);
        self.0.result.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

fn config(purpose: AccessTokenPurpose) -> BrowserSessionHttpConfig {
    let (cookie, path) = match purpose {
        AccessTokenPurpose::Business => ("business_cookie", "/auth/browser"),
        AccessTokenPurpose::Management => ("management_cookie", "/admin/auth/browser"),
    };
    BrowserSessionHttpConfig::new("https://idp.example", cookie, path, purpose).unwrap()
}
fn body() -> String {
    format!(
        r#"{{"current_password":"{CURRENT}","new_password":"{NEXT}","operation_id":"{OP}","receipt_secret":"{SECRET}","expected":{{"tenant_id":"tenant-a","account_id":"{ACCOUNT}","session_id":"{SESSION}","client_id":"client-a"}}}}"#
    )
}
fn result_body() -> String {
    format!(r#"{{"operation_id":"{OP}","receipt_secret":"{SECRET}"}}"#)
}
fn request(path: &str, body: impl Into<Body>) -> axum::http::Request<Body> {
    axum::http::Request::post(path)
        .header("origin", "https://idp.example")
        .header("x-embedded-idp-browser", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}

#[tokio::test]
async fn browser_change_binds_expected_identity_and_result_needs_no_cookie_or_auth_call() {
    let seen = Arc::new(Seen::default());
    let app = browser_self_password_change_router(
        Arc::new(Identity(seen.clone(), AccessTokenPurpose::Business, None)),
        Arc::new(Service(seen.clone())),
        config(AccessTokenPurpose::Business),
    )
    .unwrap();
    let mut change_request = request("/auth/browser/security/password", Body::from(body()));
    change_request.headers_mut().insert(
        header::COOKIE,
        "business_cookie=synthetic-cookie".parse().unwrap(),
    );
    let response = app.clone().oneshot(change_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(seen.identity.load(Ordering::SeqCst), 1);
    assert_eq!(seen.change.load(Ordering::SeqCst), 1);
    let expected = seen.expected.lock().unwrap().as_ref().unwrap().clone();
    assert_eq!(expected.tenant_id, "tenant-a");
    assert_eq!(expected.account_id, ACCOUNT);
    assert_eq!(expected.session_id, SESSION);
    assert_eq!(expected.client_id, "client-a");

    let response = app
        .clone()
        .oneshot(request(
            "/auth/browser/security/password/result",
            Body::from(result_body()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(seen.identity.load(Ordering::SeqCst), 1);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn browser_boundary_rejects_origin_selector_and_missing_cookie_before_service() {
    let seen = Arc::new(Seen::default());
    let app = browser_self_password_change_router(
        Arc::new(Identity(seen.clone(), AccessTokenPurpose::Business, None)),
        Arc::new(Service(seen.clone())),
        config(AccessTokenPurpose::Business),
    )
    .unwrap();
    let wrong_origin = axum::http::Request::post("/auth/browser/security/password")
        .header("origin", "https://attacker.example")
        .header("x-embedded-idp-browser", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body()))
        .unwrap();
    let response = app.clone().oneshot(wrong_origin).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let response = app
        .clone()
        .oneshot(request(
            "/auth/browser/security/password",
            Body::from(body()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let mut selector_request = request("/auth/browser/security/password", Body::from(body()));
    selector_request.headers_mut().insert(
        header::COOKIE,
        "business_cookie=synthetic-cookie".parse().unwrap(),
    );
    selector_request
        .headers_mut()
        .insert("x-embedded-idp-business-id", "other".parse().unwrap());
    let response = app.clone().oneshot(selector_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(seen.identity.load(Ordering::SeqCst), 0);
    assert_eq!(seen.change.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn browser_json_rejections_are_fixed_and_constructor_checks_identity_configuration() {
    let seen = Arc::new(Seen::default());
    assert!(browser_self_password_change_router(
        Arc::new(Identity(seen.clone(), AccessTokenPurpose::Management, None)),
        Arc::new(Service(seen.clone())),
        config(AccessTokenPurpose::Business),
    )
    .is_err());
    let app = browser_self_password_change_router(
        Arc::new(Identity(seen.clone(), AccessTokenPurpose::Business, None)),
        Arc::new(Service(seen.clone())),
        config(AccessTokenPurpose::Business),
    )
    .unwrap();
    let cases = vec![
        ("{".to_owned(), StatusCode::BAD_REQUEST, "invalid_request"),
        (
            r#"{"operation_id":"x","operation_id":"y"}"#.to_owned(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "x".repeat(16_385),
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
        ),
    ];
    for (body, expected_status, code) in cases {
        let response = app
            .clone()
            .oneshot(request(
                "/auth/browser/security/password/result",
                Body::from(body),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["code"], code);
        assert!(!value.to_string().contains("operation_id"));
    }
    assert_eq!(seen.identity.load(Ordering::SeqCst), 0);
    assert_eq!(seen.result.load(Ordering::SeqCst), 0);
}

use super::*;

use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderMap, Request, StatusCode},
    response::Response,
    Router,
};
use embedded_idp_core::access::{
    BrowserSessionIdentity, BrowserSessionService, TenantAuthError, TenantLoginOutcome,
    TenantLoginSession, TenantPasswordLogin, TenantRefreshOutcome, TenantSelectionTicket,
    TenantSession,
};
use embedded_idp_core::{
    AccessTokenPurpose, IssuedAccessToken, IssuedTokenBundle, SecretString, SessionStatus,
};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tower::ServiceExt;

#[derive(Default, Debug, Clone)]
struct Calls {
    login: usize,
    select: usize,
    refresh: usize,
    logout: usize,
    last_expected: Option<BrowserSessionIdentity>,
    last_token: Option<String>,
}

#[derive(Clone)]
struct Fake {
    purpose: AccessTokenPurpose,
    calls: Arc<Mutex<Calls>>,
    login_selection: bool,
    refresh_error: Option<TenantAuthError>,
    logout_error: Option<TenantAuthError>,
}

impl Fake {
    fn new(purpose: AccessTokenPurpose) -> Self {
        Self {
            purpose,
            calls: Arc::new(Mutex::new(Calls::default())),
            login_selection: false,
            refresh_error: None,
            logout_error: None,
        }
    }
    fn authenticated(&self, tenant: &str) -> TenantLoginSession {
        let now = SystemTime::now();
        TenantLoginSession {
            session: TenantSession {
                purpose: self.purpose,
                tenant_id: tenant.into(),
                id: "session-1".into(),
                account_id: "account-1".into(),
                client_id: "browser-client".into(),
                device_id: None,
                scope: None,
                authenticated_at: now,
                status: SessionStatus::Active,
                created_at: now,
                expires_at: now + Duration::from_secs(3600),
                refresh_token_version: 1,
            },
            tokens: IssuedTokenBundle {
                access_token: SecretString::new("access-token"),
                refresh_token: SecretString::new("refresh-token"),
                access_expires_at: now + Duration::from_secs(300),
                refresh_expires_at: now + Duration::from_secs(1800),
                refresh_token_version: 1,
            },
        }
    }
}

impl BrowserSessionService for Fake {
    fn browser_purpose(&self) -> AccessTokenPurpose {
        self.purpose
    }
    fn browser_login(
        &self,
        command: TenantPasswordLogin,
    ) -> Result<TenantLoginOutcome, TenantAuthError> {
        assert_eq!(command.email, "user@example.com");
        assert_eq!(command.password.expose_secret(), "password");
        self.calls.lock().unwrap().login += 1;
        if self.login_selection {
            Ok(TenantLoginOutcome::SelectionRequired(
                TenantSelectionTicket {
                    ticket: SecretString::new("selection-ticket"),
                    issued_at: SystemTime::now(),
                    expires_at: SystemTime::now() + Duration::from_secs(60),
                },
            ))
        } else {
            Ok(TenantLoginOutcome::Authenticated(
                self.authenticated("tenant-a"),
            ))
        }
    }
    fn browser_select(
        &self,
        ticket: SecretString,
        tenant: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.calls.lock().unwrap().select += 1;
        assert_eq!(ticket.expose_secret(), "selection-ticket");
        Ok(self.authenticated(&tenant))
    }
    fn browser_refresh(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        let mut calls = self.calls.lock().unwrap();
        calls.refresh += 1;
        calls.last_token = Some(token.expose_secret().into());
        calls.last_expected = expected;
        if let Some(error) = &self.refresh_error {
            return Err(error.clone());
        }
        let result = self.authenticated("tenant-a");
        Ok(TenantRefreshOutcome::Rotated {
            session: result.session,
            tokens: embedded_idp_core::ProofBoundTokenResult {
                access_token: IssuedAccessToken {
                    token: result.tokens.access_token,
                    expires_at: result.tokens.access_expires_at,
                },
                refresh_token: result.tokens.refresh_token,
                refresh_expires_at: result.tokens.refresh_expires_at,
                refresh_token_version: result.tokens.refresh_token_version,
            },
        })
    }
    fn browser_logout(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<(), TenantAuthError> {
        let mut calls = self.calls.lock().unwrap();
        calls.logout += 1;
        calls.last_token = Some(token.expose_secret().into());
        calls.last_expected = expected;
        if let Some(error) = &self.logout_error {
            Err(error.clone())
        } else {
            Ok(())
        }
    }
}

fn app(fake: Fake, purpose: AccessTokenPurpose, name: &str, path: &str) -> Router {
    browser_session_router(
        Arc::new(fake),
        BrowserSessionHttpConfig::new("https://idp.example", name, path, purpose).unwrap(),
    )
    .unwrap()
}
fn headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("origin", "https://idp.example".parse().unwrap());
    h.insert("x-embedded-idp-browser", "1".parse().unwrap());
    h
}
async fn send(app: &Router, path: &str, body: &str, extra: &[(&str, &str)]) -> Response {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    for (key, value) in headers().iter() {
        request = request.header(key, value);
    }
    for (key, value) in extra {
        request = request.header(*key, *value);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap()
}
async fn body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap())
        .unwrap_or(Value::Null)
}
fn cookie(response: &Response) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .into()
}
fn expected() -> &'static str {
    r#"{"expected_session":{"tenant_id":"tenant-a","account_id":"account-1","session_id":"session-1","client_id":"browser-client"}}"#
}

#[tokio::test]
async fn browser_flow_hides_refresh_and_sets_scoped_cookie() {
    let fake = Fake::new(AccessTokenPurpose::Business);
    let calls = fake.calls.clone();
    let app = app(
        fake,
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    let response = send(
        &app,
        "/auth/browser/login",
        r#"{"email":"user@example.com","password":"password"}"#,
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = cookie(&response);
    assert!(set_cookie.contains("business_cookie=refresh-token"));
    assert!(set_cookie.contains("Path=/auth/browser"));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    assert!(set_cookie.contains("Secure"));
    assert!(!body(response).await.to_string().contains("refresh_token"));
    let response = send(
        &app,
        "/auth/browser/restore",
        "{}",
        &[("cookie", "business_cookie=refresh-token")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!body(response).await.to_string().contains("refresh_token"));
    assert_eq!(calls.lock().unwrap().refresh, 1);
    let response = send(
        &app,
        "/auth/browser/logout",
        expected(),
        &[("cookie", "business_cookie=refresh-token")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(cookie(&response).contains("Max-Age=0"));
    assert_eq!(calls.lock().unwrap().logout, 1);
}

#[tokio::test]
async fn selection_sets_cookie_and_forwards_ticket() {
    let mut fake = Fake::new(AccessTokenPurpose::Business);
    fake.login_selection = true;
    let calls = fake.calls.clone();
    let app = app(
        fake,
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    let response = send(
        &app,
        "/auth/browser/login",
        r#"{"email":"user@example.com","password":"password"}"#,
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(body(response).await["status"], "tenant_selection_required");
    let response = send(
        &app,
        "/auth/browser/tenant-selection/complete",
        r#"{"tenant_id":"tenant-b"}"#,
        &[("authorization", "TenantSelection selection-ticket")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(cookie(&response).contains("business_cookie=refresh-token"));
    assert_eq!(calls.lock().unwrap().select, 1);
}

#[tokio::test]
async fn request_guard_rejects_csrf_and_ambiguous_headers_before_service() {
    let fake = Fake::new(AccessTokenPurpose::Business);
    let calls = fake.calls.clone();
    let app = app(
        fake,
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    for (name, value) in [
        ("origin", "https://evil.example"),
        ("x-embedded-idp-browser", "0"),
        ("sec-fetch-site", "cross-site"),
    ] {
        let response = send(&app, "/auth/browser/login", "{}", &[(name, value)]).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    for origin in [None, Some("null")] {
        let mut request = Request::post("/auth/browser/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-embedded-idp-browser", "1");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let request = Request::post("/auth/browser/login")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-embedded-idp-browser", "1")
        .header("origin", "https://idp.example")
        .header("origin", "https://idp.example");
    let response = app
        .clone()
        .oneshot(request.body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = send(
        &app,
        "/auth/browser/login",
        "{}",
        &[("x-embedded-idp-tenant-id", "tenant-a")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.lock().unwrap().login, 0);
}

#[tokio::test]
async fn malformed_json_cookie_and_content_type_are_rejected() {
    let fake = Fake::new(AccessTokenPurpose::Business);
    let calls = fake.calls.clone();
    let app = app(
        fake,
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    let response = send(
        &app,
        "/auth/browser/login",
        r#"{"email":"user@example.com","password":"password","extra":1}"#,
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = send(
        &app,
        "/auth/browser/restore",
        r#"{"expected_session":null,"expected_session":null}"#,
        &[("cookie", "business_cookie=refresh-token")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = send(
        &app,
        "/auth/browser/restore",
        "{}",
        &[(
            "cookie",
            "business_cookie=refresh-token; business_cookie=other",
        )],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/browser/restore")
                .header("origin", "https://idp.example")
                .header("x-embedded-idp-browser", "1")
                .header("content-type", "text/plain")
                .header("cookie", "business_cookie=refresh-token")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(calls.lock().unwrap().refresh, 0);
}

#[tokio::test]
async fn expected_session_and_failures_preserve_cookie() {
    let mut fake = Fake::new(AccessTokenPurpose::Business);
    fake.refresh_error = Some(TenantAuthError::Access(AccessError::InvalidInput(
        "browser_session_changed",
    )));
    let calls = fake.calls.clone();
    let changed_app = app(
        fake,
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    let response = send(
        &changed_app,
        "/auth/browser/refresh",
        expected(),
        &[("cookie", "business_cookie=refresh-token")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        calls
            .lock()
            .unwrap()
            .last_expected
            .as_ref()
            .unwrap()
            .tenant_id,
        "tenant-a"
    );
    let mut fake = Fake::new(AccessTokenPurpose::Business);
    fake.refresh_error = Some(TenantAuthError::Store(
        embedded_idp_core::StoreError::Backend("db".into()),
    ));
    let error_app = app(
        fake,
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    let response = send(
        &error_app,
        "/auth/browser/restore",
        "{}",
        &[("cookie", "business_cookie=refresh-token")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}

#[test]
fn purpose_and_cookie_scope_are_isolated() {
    let fake = Fake::new(AccessTokenPurpose::Business);
    assert!(browser_session_router(
        Arc::new(fake),
        BrowserSessionHttpConfig::new(
            "https://idp.example",
            "management_cookie",
            "/admin/auth/browser",
            AccessTokenPurpose::Management
        )
        .unwrap()
    )
    .is_err());
    assert!(BrowserSessionHttpConfig::new(
        "https://idp.example",
        "business_cookie",
        "/auth/browser",
        AccessTokenPurpose::Business
    )
    .is_ok());
    assert!(BrowserSessionHttpConfig::new(
        "https://idp.example",
        "management_cookie",
        "/admin/auth/browser",
        AccessTokenPurpose::Management
    )
    .is_ok());
}

#[tokio::test]
async fn management_and_business_routes_use_separate_cookie_names_and_paths() {
    let business = app(
        Fake::new(AccessTokenPurpose::Business),
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    let management = app(
        Fake::new(AccessTokenPurpose::Management),
        AccessTokenPurpose::Management,
        "management_cookie",
        "/admin/auth/browser",
    );
    let business_cookie = cookie(
        &send(
            &business,
            "/auth/browser/login",
            r#"{"email":"user@example.com","password":"password"}"#,
            &[],
        )
        .await,
    );
    let management_cookie = cookie(
        &send(
            &management,
            "/admin/auth/browser/login",
            r#"{"email":"user@example.com","password":"password"}"#,
            &[],
        )
        .await,
    );
    assert!(business_cookie.starts_with("business_cookie=refresh-token; Path=/auth/browser"));
    assert!(
        management_cookie.starts_with("management_cookie=refresh-token; Path=/admin/auth/browser")
    );
}

#[tokio::test]
async fn browser_guard_does_not_capture_merged_router_fallbacks() {
    let router = Router::new().merge(app(
        Fake::new(AccessTokenPurpose::Business),
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    ));
    let response = router
        .oneshot(
            Request::builder()
                .uri("/unmounted-route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(BrowserSessionHttpConfig::new(
        "https://:443",
        "business_cookie",
        "/auth/browser",
        AccessTokenPurpose::Business
    )
    .is_err());
}

#[tokio::test]
async fn refresh_requires_identity_before_touching_the_cookie() {
    let service = Fake::new(AccessTokenPurpose::Business);
    let calls = service.calls.clone();
    let router = app(
        service,
        AccessTokenPurpose::Business,
        "business_cookie",
        "/auth/browser",
    );
    let response = send(
        &router,
        "/auth/browser/refresh",
        "{}",
        &[("cookie", "business_cookie=refresh-token")],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(calls.lock().unwrap().refresh, 0);
}

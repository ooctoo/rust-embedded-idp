use super::*;
use axum::{body::Body, http::Request};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const COOKIE: &str = "synthetic-refresh-secret";
const ACCOUNT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SESSION: &str = "00000000-0000-4000-8000-000000000001";

#[derive(Default)]
struct Observed {
    identity_calls: usize,
    service_calls: usize,
    expected: Option<BrowserSessionIdentity>,
    cookie: Option<String>,
    identity_error: bool,
}

#[derive(Clone)]
struct Identity {
    state: Arc<Mutex<Observed>>,
    purpose: AccessTokenPurpose,
    lifetime: Option<u64>,
}

impl SelfSecurityBrowserIdentityService for Identity {
    fn self_security_browser_purpose(&self) -> AccessTokenPurpose {
        self.purpose
    }
    fn self_security_browser_lifetime_secs(&self) -> Option<u64> {
        self.lifetime
    }
    fn authenticate_self_security_browser(
        &self,
        cookie: SecretString,
        expected: BrowserSessionIdentity,
    ) -> Result<AccessActor, TenantAuthError> {
        let mut observed = self.state.lock().unwrap();
        observed.identity_calls += 1;
        observed.cookie = Some(cookie.expose_secret().to_owned());
        observed.expected = Some(expected);
        if observed.identity_error {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(AccessActor {
            tenant_id: "tenant-a".into(),
            subject_id: ACCOUNT.into(),
            session_id: SESSION.into(),
        })
    }
}

#[derive(Clone)]
struct Sessions(Arc<Mutex<Observed>>);

impl SelfSessionService for Sessions {
    fn list_sessions(
        &self,
        _: AccessActor,
        _: SelfSessionPageRequest,
    ) -> Result<SelfSessionPage, AccessError> {
        self.0.lock().unwrap().service_calls += 1;
        Ok(SelfSessionPage {
            items: vec![],
            next_cursor: None,
        })
    }
}

fn config(purpose: AccessTokenPurpose) -> BrowserSessionHttpConfig {
    let (name, path) = match purpose {
        AccessTokenPurpose::Business => ("business_cookie", "/auth/browser"),
        AccessTokenPurpose::Management => ("management_cookie", "/admin/auth/browser"),
    };
    BrowserSessionHttpConfig::new("https://idp.example", name, path, purpose).unwrap()
}

fn app(state: Arc<Mutex<Observed>>, purpose: AccessTokenPurpose, lifetime: Option<u64>) -> Router {
    browser_self_session_router(
        Arc::new(Identity {
            state: state.clone(),
            purpose,
            lifetime,
        }),
        Arc::new(Sessions(state)),
        config(purpose),
    )
    .unwrap()
}

fn valid_json() -> String {
    serde_json::json!({
        "expected": {
            "tenant_id": "tenant-a",
            "account_id": ACCOUNT,
            "session_id": SESSION,
            "client_id": "browser-client"
        },
        "limit": 2,
        "cursor": null
    })
    .to_string()
}

fn request(body: String) -> Request<Body> {
    Request::post("/auth/browser/security/sessions")
        .header("origin", "https://idp.example")
        .header("x-embedded-idp-browser", "1")
        .header("cookie", format!("business_cookie={COOKIE}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn send(app: Router, request: Request<Body>) -> Response {
    app.oneshot(request).await.unwrap()
}

#[tokio::test]
async fn configuration_requires_matching_purpose_and_lifetime() {
    let state = Arc::new(Mutex::new(Observed::default()));
    let wrong_purpose = browser_self_session_router(
        Arc::new(Identity {
            state: state.clone(),
            purpose: AccessTokenPurpose::Management,
            lifetime: None,
        }),
        Arc::new(Sessions(state.clone())),
        config(AccessTokenPurpose::Business),
    );
    assert!(wrong_purpose.is_err());
    let wrong_lifetime = browser_self_session_router(
        Arc::new(Identity {
            state: state.clone(),
            purpose: AccessTokenPurpose::Business,
            lifetime: Some(900),
        }),
        Arc::new(Sessions(state)),
        config(AccessTokenPurpose::Business),
    );
    assert!(wrong_lifetime.is_err());
}

#[tokio::test]
async fn browser_security_read_checks_origin_headers_identity_and_no_store() {
    let state = Arc::new(Mutex::new(Observed::default()));
    let app = app(state.clone(), AccessTokenPurpose::Business, None);
    let response = send(app.clone(), request(valid_json())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let response_body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let text = String::from_utf8(response_body.to_vec()).unwrap();
    assert!(!text.contains(COOKIE));
    assert!(!text.contains("refresh_token"));
    let observed = state.lock().unwrap();
    assert_eq!(observed.identity_calls, 1);
    assert_eq!(observed.service_calls, 1);
    assert_eq!(observed.cookie.as_deref(), Some(COOKIE));
    assert_eq!(
        observed.expected,
        Some(BrowserSessionIdentity {
            tenant_id: "tenant-a".into(),
            account_id: ACCOUNT.into(),
            session_id: SESSION.into(),
            client_id: "browser-client".into(),
        })
    );
    drop(observed);

    let mut wrong_origin = request(valid_json());
    wrong_origin
        .headers_mut()
        .insert("origin", "https://attacker.example".parse().unwrap());
    let response = send(app.clone(), wrong_origin).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let mut missing_browser_header = request(valid_json());
    missing_browser_header
        .headers_mut()
        .remove("x-embedded-idp-browser");
    assert_eq!(
        send(app.clone(), missing_browser_header).await.status(),
        StatusCode::FORBIDDEN
    );

    let mut cross_site = request(valid_json());
    cross_site
        .headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    assert_eq!(
        send(app.clone(), cross_site).await.status(),
        StatusCode::FORBIDDEN
    );

    let mut business_header = request(valid_json());
    business_header
        .headers_mut()
        .insert("x-embedded-idp-business-id", "business-a".parse().unwrap());
    assert_eq!(
        send(app.clone(), business_header).await.status(),
        StatusCode::FORBIDDEN
    );

    let calls_before = state.lock().unwrap().identity_calls;
    let too_large = request(format!("{}{}", valid_json(), " ".repeat(20 * 1024)));
    let response = send(app, too_large).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let observed = state.lock().unwrap();
    assert_eq!(observed.identity_calls, calls_before);
    assert_eq!(observed.service_calls, 1);
}

#[tokio::test]
async fn invalid_browser_identity_never_queries_session_service() {
    let state = Arc::new(Mutex::new(Observed {
        identity_error: true,
        ..Observed::default()
    }));
    let response = send(
        app(state.clone(), AccessTokenPurpose::Business, None),
        request(valid_json()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let observed = state.lock().unwrap();
    assert_eq!(observed.identity_calls, 1);
    assert_eq!(observed.service_calls, 0);
}

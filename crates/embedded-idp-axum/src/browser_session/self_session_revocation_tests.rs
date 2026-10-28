use super::*;
use axum::{body::Body, http::Request};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

const OP: &str = "00000000-0000-4000-8000-000000000011";
const SECRET: &str = "synthetic-receipt";

#[derive(Default)]
struct Seen {
    identity: AtomicUsize,
    revoke: AtomicUsize,
    result: AtomicUsize,
}
struct Identity(Arc<Seen>);
impl SelfSecurityBrowserIdentityService for Identity {
    fn self_security_browser_purpose(&self) -> AccessTokenPurpose {
        AccessTokenPurpose::Business
    }
    fn self_security_browser_lifetime_secs(&self) -> Option<u64> {
        None
    }
    fn authenticate_self_security_browser(
        &self,
        cookie: SecretString,
        expected: BrowserSessionIdentity,
    ) -> Result<AccessActor, TenantAuthError> {
        assert_eq!(cookie.expose_secret(), "synthetic-cookie");
        assert_eq!(expected.account_id, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        self.0.identity.fetch_add(1, Ordering::SeqCst);
        Ok(AccessActor {
            tenant_id: expected.tenant_id,
            subject_id: expected.account_id,
            session_id: expected.session_id,
        })
    }
}
struct Service(Arc<Seen>);
impl SelfSessionRevocationService for Service {
    fn revoke_session(
        &self,
        _: AccessActor,
        command: SelfSessionRevokeCommand,
    ) -> Result<(), AccessError> {
        assert_eq!(command.operation_id.to_string(), OP);
        assert_eq!(command.receipt_secret.expose_secret(), SECRET);
        self.0.revoke.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn session_revocation_result(&self, query: SecurityReceiptQuery) -> Result<bool, AccessError> {
        assert_eq!(query.operation_id.to_string(), OP);
        assert_eq!(query.receipt_secret.expose_secret(), SECRET);
        self.0.result.fetch_add(1, Ordering::SeqCst);
        Ok(false)
    }
}
fn config() -> BrowserSessionHttpConfig {
    BrowserSessionHttpConfig::new(
        "https://idp.example",
        "business_cookie",
        "/auth/browser",
        AccessTokenPurpose::Business,
    )
    .unwrap()
}
fn body() -> &'static str {
    r#"{"target_tenant_id":"tenant-a","target_session_id":"00000000-0000-4000-8000-000000000002","operation_id":"00000000-0000-4000-8000-000000000011","receipt_secret":"synthetic-receipt","expected":{"tenant_id":"tenant-a","account_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","session_id":"00000000-0000-4000-8000-000000000001","client_id":"client-a"}}"#
}
fn result_body() -> &'static str {
    r#"{"operation_id":"00000000-0000-4000-8000-000000000011","receipt_secret":"synthetic-receipt"}"#
}
fn request(path: &str, body: &'static str) -> Request<Body> {
    Request::post(path)
        .header("origin", "https://idp.example")
        .header("x-embedded-idp-browser", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn browser_revoke_requires_boundary_cookie_and_expected_but_result_does_not_authenticate() {
    let seen = Arc::new(Seen::default());
    let service = Arc::new(Service(seen.clone()));
    let app =
        browser_self_session_revocation_router(Arc::new(Identity(seen.clone())), service, config())
            .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/browser/security/sessions/revoke/result")
                .header("origin", "https://attacker.example")
                .header("x-embedded-idp-browser", "1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(result_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(seen.result.load(Ordering::SeqCst), 0);
    let no_cookie = app
        .clone()
        .oneshot(request("/auth/browser/security/sessions/revoke", body()))
        .await
        .unwrap();
    assert_eq!(no_cookie.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(no_cookie.headers()[header::CACHE_CONTROL], "no-store");
    let error = axum::body::to_bytes(no_cookie.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&error).unwrap()["code"],
        "invalid_session"
    );
    assert_eq!(seen.identity.load(Ordering::SeqCst), 0);

    let mut revoke = request("/auth/browser/security/sessions/revoke", body());
    revoke.headers_mut().insert(
        header::COOKIE,
        "business_cookie=synthetic-cookie".parse().unwrap(),
    );
    let response = app.clone().oneshot(revoke).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(seen.identity.load(Ordering::SeqCst), 1);
    assert_eq!(seen.revoke.load(Ordering::SeqCst), 1);

    let response = app
        .clone()
        .oneshot(request(
            "/auth/browser/security/sessions/revoke/result",
            result_body(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.identity.load(Ordering::SeqCst), 1);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);

    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/browser/security/sessions/revoke/result")
                .header("x-embedded-idp-browser", "1")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(result_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);

    let response = app
        .oneshot(
            Request::post("/auth/browser/security/sessions/revoke/result")
                .header("origin", "https://idp.example")
                .header("x-embedded-idp-browser", "1")
                .header("x-embedded-idp-business-id", "other")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(result_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);
}

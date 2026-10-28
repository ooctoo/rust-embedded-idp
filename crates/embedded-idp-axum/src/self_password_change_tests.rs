use super::*;
use axum::{body::Body, http::Request};
use embedded_idp_core::StoreError;
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tower::ServiceExt;

const TOKEN: &str = "synthetic-access-token";
const OP: &str = "00000000-0000-4000-8000-000000000011";
const SECRET: &str = "synthetic-receipt-secret";
const CURRENT: &str = "Current-fixture-123";
const NEXT: &str = "New-fixture-456";

#[derive(Default)]
struct Seen {
    auth: AtomicUsize,
    change: AtomicUsize,
    result: AtomicUsize,
    error: Mutex<Option<SelfPasswordChangeError>>,
    actor: Mutex<Option<AccessActor>>,
}

#[derive(Clone)]
struct Auth(Arc<Seen>);

fn actor() -> AccessActor {
    AccessActor {
        tenant_id: "tenant-a".into(),
        subject_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        session_id: "00000000-0000-4000-8000-000000000001".into(),
    }
}

impl TenantAuthenticationService for Auth {
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        TenantLoginCapabilities {
            mode: TenancyMode::Enabled,
            policy: LoginTenantPolicy::ChooseAfterAuthentication,
        }
    }
    fn login(&self, _: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        unreachable!()
    }
    fn list_tenants(
        &self,
        _: SecretString,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        unreachable!()
    }
    fn select_tenant(
        &self,
        _: SecretString,
        _: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        unreachable!()
    }
    fn authenticate(&self, token: SecretString) -> Result<AccessActor, TenantAuthError> {
        assert_eq!(token.expose_secret(), TOKEN);
        self.0.auth.fetch_add(1, Ordering::SeqCst);
        Ok(actor())
    }
    fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        unreachable!()
    }
}

impl ManagementAuthenticationService for Auth {
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        TenantAuthenticationService::login_capabilities(self)
    }
    fn login(&self, _: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        unreachable!()
    }
    fn list_tenants(
        &self,
        _: SecretString,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        unreachable!()
    }
    fn select_tenant(
        &self,
        _: SecretString,
        _: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        unreachable!()
    }
    fn authenticate(
        &self,
        token: SecretString,
        _: String,
    ) -> Result<AccessAdminContext, TenantAuthError> {
        let mut actor = actor();
        actor.tenant_id = "0".into();
        self.0.auth.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token.expose_secret(), TOKEN);
        Ok(AccessAdminContext {
            actor,
            authentication_source: "test".into(),
            request_id: "request".into(),
        })
    }
    fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        unreachable!()
    }
    fn rotate_refresh(&self, _: SecretString) -> Result<TenantRefreshOutcome, TenantAuthError> {
        unreachable!()
    }
    fn logout(&self, _: SecretString) -> Result<(), TenantAuthError> {
        unreachable!()
    }
}

impl SelfPasswordChangeService for Auth {
    fn change_password(
        &self,
        actor: AccessActor,
        command: SelfPasswordChangeCommand,
    ) -> Result<(), SelfPasswordChangeError> {
        assert_eq!(command.current_password.expose_secret(), CURRENT);
        assert_eq!(command.new_password.expose_secret(), NEXT);
        assert_eq!(command.operation_id.to_string(), OP);
        assert_eq!(command.receipt_secret.expose_secret(), SECRET);
        *self.0.actor.lock().unwrap() = Some(actor);
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
        Ok(false)
    }
}

fn change_body() -> String {
    format!(
        r#"{{"current_password":"{CURRENT}","new_password":"{NEXT}","operation_id":"{OP}","receipt_secret":"{SECRET}"}}"#
    )
}
fn result_body() -> String {
    format!(r#"{{"operation_id":"{OP}","receipt_secret":"{SECRET}"}}"#)
}
fn bearer_request(path: &str, body: impl Into<Body>) -> Request<Body> {
    Request::post(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .unwrap()
}
async fn response_json(response: Response) -> (StatusCode, HeaderMap, serde_json::Value) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 32 * 1024)
        .await
        .unwrap();
    (status, headers, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn business_and_management_routes_change_and_capability_result_does_not_authenticate() {
    let seen = Arc::new(Seen::default());
    let business =
        self_password_change_router(Arc::new(Auth(seen.clone())), Arc::new(Auth(seen.clone())));
    let mut request = bearer_request("/auth/security/password", Body::from(change_body()));
    request
        .headers_mut()
        .insert("x-embedded-idp-tenant-id", "tenant-a".parse().unwrap());
    let response = business.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(seen.auth.load(Ordering::SeqCst), 1);
    assert_eq!(seen.change.load(Ordering::SeqCst), 1);
    assert_eq!(
        seen.actor.lock().unwrap().as_ref().unwrap().tenant_id,
        "tenant-a"
    );

    let management = management_self_password_change_router(
        Arc::new(Auth(seen.clone())),
        Arc::new(Auth(seen.clone())),
    );
    let response = management
        .oneshot(bearer_request(
            "/admin/auth/security/password",
            Body::from(change_body()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.auth.load(Ordering::SeqCst), 2);
    assert_eq!(seen.change.load(Ordering::SeqCst), 2);
    assert_eq!(seen.actor.lock().unwrap().as_ref().unwrap().tenant_id, "0");

    let response = business
        .oneshot(bearer_request(
            "/auth/security/password/result",
            Body::from(result_body()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        json!({"completed":false})
    );
    assert_eq!(seen.auth.load(Ordering::SeqCst), 2);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn selectors_and_json_rejections_are_fixed_no_store_and_do_not_call_service() {
    let seen = Arc::new(Seen::default());
    let app =
        self_password_change_router(Arc::new(Auth(seen.clone())), Arc::new(Auth(seen.clone())));
    let cases = vec![
        ("{".to_owned(), "application/json", StatusCode::BAD_REQUEST, "invalid_request"),
        (r#"{"current_password":"x","new_password":"x","operation_id":"x","receipt_secret":"x","extra":1}"#.to_owned(), "application/json", StatusCode::BAD_REQUEST, "invalid_request"),
        (r#"{"current_password":"x","new_password":"x","operation_id":"x"}"#.to_owned(), "application/json", StatusCode::BAD_REQUEST, "invalid_request"),
        ("{}".to_owned(), "text/plain", StatusCode::BAD_REQUEST, "invalid_request"),
        ("x".repeat(16_385), "application/json", StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
    ];
    for (body, content_type, expected_status, expected_code) in cases {
        let response = app
            .clone()
            .oneshot(
                Request::post("/auth/security/password")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, headers, value) = response_json(response).await;
        assert_eq!(status, expected_status);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert!(headers.get(header::SET_COOKIE).is_none());
        assert_eq!(value["code"], expected_code);
        assert_eq!(
            value["message"],
            if expected_status == StatusCode::PAYLOAD_TOO_LARGE {
                "request body is too large"
            } else {
                "request is invalid"
            }
        );
        assert!(!value.to_string().contains("current_password"));
        assert!(!value.to_string().contains(NEXT));
    }

    let mut request = bearer_request("/auth/security/password/result", Body::from(result_body()));
    request
        .headers_mut()
        .insert("x-embedded-idp-tenant-id", "tenant-a".parse().unwrap());
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(seen.result.load(Ordering::SeqCst), 0);
    assert_eq!(seen.auth.load(Ordering::SeqCst), 0);

    let response = app
        .oneshot(
            Request::post("/auth/security/password")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header("x-embedded-idp-business-id", "other")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(change_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(seen.auth.load(Ordering::SeqCst), 0);
    assert_eq!(seen.change.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn service_errors_use_frozen_codes_without_leaking_values() {
    let seen = Arc::new(Seen::default());
    let app =
        self_password_change_router(Arc::new(Auth(seen.clone())), Arc::new(Auth(seen.clone())));
    for (error, status, code) in [
        (
            SelfPasswordChangeError::InvalidCredentials,
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
        ),
        (
            AccessError::Conflict("security.credentials_changed").into(),
            StatusCode::CONFLICT,
            "credentials_changed",
        ),
        (
            AccessError::Conflict("security.operation_conflict").into(),
            StatusCode::CONFLICT,
            "operation_conflict",
        ),
        (
            AccessError::Conflict("security.receipt_capacity").into(),
            StatusCode::SERVICE_UNAVAILABLE,
            "security_unavailable",
        ),
        (
            AccessError::Store(StoreError::Backend("password.work_unavailable".into())).into(),
            StatusCode::SERVICE_UNAVAILABLE,
            "security_unavailable",
        ),
        (
            AccessError::InvalidStoreResponse.into(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
        ),
        (
            AccessError::InvalidInput("password").into(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            AccessError::InvalidInput("actor").into(),
            StatusCode::UNAUTHORIZED,
            "invalid_session",
        ),
        (
            AccessError::InvalidInput("actor_tenant_id").into(),
            StatusCode::UNAUTHORIZED,
            "invalid_session",
        ),
        (
            AccessError::InvalidInput("actor_subject_id").into(),
            StatusCode::UNAUTHORIZED,
            "invalid_session",
        ),
        (
            AccessError::InvalidInput("actor_session_id").into(),
            StatusCode::UNAUTHORIZED,
            "invalid_session",
        ),
        (
            AccessError::ModeMismatch.into(),
            StatusCode::UNAUTHORIZED,
            "invalid_session",
        ),
    ] {
        *seen.error.lock().unwrap() = Some(error);
        let response = app
            .clone()
            .oneshot(bearer_request(
                "/auth/security/password",
                Body::from(change_body()),
            ))
            .await
            .unwrap();
        let (actual, headers, value) = response_json(response).await;
        assert_eq!(actual, status);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert!(headers.get(header::SET_COOKIE).is_none());
        assert_eq!(value["code"], code);
        assert!(!value.to_string().contains("security.credentials_changed"));
        assert!(!value.to_string().contains("password.work_unavailable"));
        assert!(!value.to_string().contains(NEXT));
    }
}

use super::*;
use axum::{body::Body, http::Request};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tower::ServiceExt;

const TOKEN: &str = "synthetic-access-token";
const OP: &str = "00000000-0000-4000-8000-000000000011";

#[derive(Default)]
struct Seen {
    auth: AtomicUsize,
    revoke: AtomicUsize,
    result: AtomicUsize,
    actor: Mutex<Option<AccessActor>>,
}
#[derive(Clone)]
struct AuthSvc(Arc<Seen>);
impl TenantAuthenticationService for AuthSvc {
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
impl ManagementAuthenticationService for AuthSvc {
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
        Ok(AccessAdminContext {
            actor: TenantAuthenticationService::authenticate(self, token)?,
            authentication_source: "test".into(),
            request_id: "test".into(),
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
impl SelfSessionRevocationService for AuthSvc {
    fn revoke_session(
        &self,
        actor: AccessActor,
        command: SelfSessionRevokeCommand,
    ) -> Result<(), AccessError> {
        assert_eq!(command.operation_id.to_string(), OP);
        assert_eq!(command.receipt_secret.expose_secret(), "synthetic-receipt");
        *self.0.actor.lock().unwrap() = Some(actor);
        self.0.revoke.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn session_revocation_result(&self, query: SecurityReceiptQuery) -> Result<bool, AccessError> {
        assert_eq!(query.operation_id.to_string(), OP);
        assert_eq!(query.receipt_secret.expose_secret(), "synthetic-receipt");
        self.0.result.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

fn actor() -> AccessActor {
    AccessActor {
        tenant_id: "tenant-a".into(),
        subject_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        session_id: "00000000-0000-4000-8000-000000000001".into(),
    }
}
fn revoke_body() -> &'static str {
    r#"{"target_tenant_id":"tenant-a","target_session_id":"00000000-0000-4000-8000-000000000002","operation_id":"00000000-0000-4000-8000-000000000011","receipt_secret":"synthetic-receipt"}"#
}
fn result_body() -> &'static str {
    r#"{"operation_id":"00000000-0000-4000-8000-000000000011","receipt_secret":"synthetic-receipt"}"#
}

#[tokio::test]
async fn bearer_revoke_authenticates_and_result_is_capability_only() {
    let seen = Arc::new(Seen::default());
    let app = self_session_revocation_router(
        Arc::new(AuthSvc(seen.clone())),
        Arc::new(AuthSvc(seen.clone())),
    );
    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/security/sessions/revoke")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header("x-embedded-idp-tenant-id", "tenant-a")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(revoke_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(seen.auth.load(Ordering::SeqCst), 1);
    assert_eq!(seen.revoke.load(Ordering::SeqCst), 1);

    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/security/sessions/revoke/result")
                .header(header::AUTHORIZATION, "Bearer malformed-but-ignored")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(result_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.auth.load(Ordering::SeqCst), 1);
    assert_eq!(seen.revoke.load(Ordering::SeqCst), 1);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);

    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/security/sessions/revoke/result")
                .header("x-embedded-idp-tenant-id", "tenant-a")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(result_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);

    let response = app
        .oneshot(
            Request::post("/auth/security/sessions/revoke/result")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"operation_id":"00000000-0000-4000-8000-000000000011","receipt_secret":"synthetic-receipt","target_tenant_id":"tenant-a"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(seen.result.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bearer_revoke_rejects_selector_and_invalid_operation_without_service_call() {
    let seen = Arc::new(Seen::default());
    let app = self_session_revocation_router(
        Arc::new(AuthSvc(seen.clone())),
        Arc::new(AuthSvc(seen.clone())),
    );
    let req = Request::post("/auth/security/sessions/revoke")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("x-embedded-idp-business-id", "other")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(revoke_body()))
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let req = Request::post("/auth/security/sessions/revoke")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("x-embedded-idp-tenant-id", "tenant-other")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(revoke_body()))
        .unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let req = Request::post("/auth/security/sessions/revoke")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            revoke_body().replace(OP, "00000000-0000-0000-0000-000000000000"),
        ))
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(seen.revoke.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn result_extractor_errors_are_bounded_and_no_store() {
    let seen = Arc::new(Seen::default());
    let app = self_session_revocation_router(
        Arc::new(AuthSvc(seen.clone())),
        Arc::new(AuthSvc(seen.clone())),
    );
    let duplicate = r#"{"operation_id":"00000000-0000-4000-8000-000000000011","operation_id":"00000000-0000-4000-8000-000000000011","receipt_secret":"synthetic-receipt"}"#;
    let response = app
        .clone()
        .oneshot(
            Request::post("/auth/security/sessions/revoke/result")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(duplicate))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(seen.result.load(Ordering::SeqCst), 0);

    let mut oversized = result_body().to_owned();
    oversized.push_str(&" ".repeat(16_385));
    let response = app
        .oneshot(
            Request::post("/auth/security/sessions/revoke/result")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(seen.result.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn management_route_uses_management_authenticator_and_route_root() {
    let seen = Arc::new(Seen::default());
    let app = management_self_session_revocation_router(
        Arc::new(AuthSvc(seen.clone())),
        Arc::new(AuthSvc(seen.clone())),
    );
    let response = app
        .oneshot(
            Request::post("/admin/auth/security/sessions/revoke")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(revoke_body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(seen.auth.load(Ordering::SeqCst), 1);
    assert_eq!(seen.revoke.load(Ordering::SeqCst), 1);
}

#[test]
fn schema_conflicts_are_unavailable_not_request_replay_conflicts() {
    for field in [
        "security_runtime.binding_mismatch",
        "security_foundation.layout_drift",
        "security.receipt_capacity",
    ] {
        assert_eq!(
            revocation_error(AccessError::Conflict(field)).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(
        revocation_error(AccessError::Conflict("security.operation_conflict")).status(),
        StatusCode::CONFLICT
    );
}

use crate::{
    proof_http::AUTH_DEVICE_BODY_LIMIT_BYTES,
    tenant_auth::{call, no_store, tenant_error},
    tenant_device_auth::{has_proof, raw_json, refresh_response, RefreshRequest},
};
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    middleware,
    response::Response,
    routing::post,
    Router,
};
use embedded_idp_core::{access::TenantRefreshService, SecretString};
use std::sync::Arc;

/// Ordinary bearer refresh only. No device challenge, login or OIDC routes.
/// The service must reject proof-required entries and device-bound sessions.
pub fn tenant_refresh_router(service: Arc<dyn TenantRefreshService>) -> Router {
    Router::new()
        .route("/auth/refresh", post(refresh))
        .with_state(service)
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}
async fn refresh(
    State(service): State<Arc<dyn TenantRefreshService>>,
    request: Request,
) -> Response {
    let (body, headers, _, _) = match raw_json::<RefreshRequest>(request).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    // The credential selects its tenant; never ignore assertions or partial proof.
    if has_proof(&headers) || headers.contains_key("x-embedded-idp-tenant-id") {
        return tenant_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request is invalid",
        );
    }
    refresh_response(
        call(move || service.refresh_ordinary(SecretString::new(body.refresh_token))).await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{header, Request},
    };
    use embedded_idp_core::access::{TenantAuthError, TenantRefreshOutcome};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    #[derive(Default)]
    struct Refresh(AtomicUsize);
    impl TenantRefreshService for Refresh {
        fn refresh_ordinary(
            &self,
            token: SecretString,
        ) -> Result<TenantRefreshOutcome, TenantAuthError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(token.expose_secret(), "synthetic");
            Ok(TenantRefreshOutcome::ReuseDetected {
                tenant_id: "t1".into(),
                session_id: "s1".into(),
            })
        }
    }
    struct Rotating;
    impl TenantRefreshService for Rotating {
        fn refresh_ordinary(
            &self,
            _: SecretString,
        ) -> Result<TenantRefreshOutcome, TenantAuthError> {
            use embedded_idp_core::{
                access::TenantSession, AccessTokenPurpose, IssuedAccessToken,
                ProofBoundTokenResult, SessionStatus,
            };
            use std::time::{Duration, UNIX_EPOCH};
            let at = |secs| UNIX_EPOCH + Duration::from_secs(secs);
            Ok(TenantRefreshOutcome::Rotated {
                session: TenantSession {
                    purpose: AccessTokenPurpose::Business,
                    tenant_id: "t1".into(),
                    id: "s1".into(),
                    account_id: "a1".into(),
                    client_id: "desktop".into(),
                    device_id: None,
                    scope: None,
                    authenticated_at: at(100),
                    status: SessionStatus::Active,
                    created_at: at(100),
                    expires_at: at(500),
                    refresh_token_version: 2,
                },
                tokens: ProofBoundTokenResult {
                    access_token: IssuedAccessToken {
                        token: SecretString::new("access-fixture"),
                        expires_at: at(200),
                    },
                    refresh_token: SecretString::new("refresh-fixture"),
                    refresh_expires_at: at(500),
                    refresh_token_version: 2,
                },
            })
        }
    }
    #[tokio::test]
    async fn ordinary_refresh_success_keeps_existing_wire_shape() {
        let response = tenant_refresh_router(Arc::new(Rotating))
            .oneshot(
                Request::post("/auth/refresh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"refresh_token":"synthetic"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "status":"authenticated",
                "session":{"tenant_id":"t1","account_id":"a1","session_id":"s1","client_id":"desktop","expires_at_unix_secs":500},
                "tokens":{"access_token":"access-fixture","refresh_token":"refresh-fixture","access_expires_at_unix_secs":200,"refresh_expires_at_unix_secs":500}
            })
        );
    }
    #[tokio::test]
    async fn ordinary_refresh_rejects_context_and_proof_before_service_and_preserves_reuse_response(
    ) {
        let service = Arc::new(Refresh::default());
        let router = tenant_refresh_router(service.clone());
        for header_name in [
            "x-embedded-idp-tenant-id",
            crate::proof_http::DEVICE_ID_HEADER,
            crate::proof_http::DEVICE_KEY_ID_HEADER,
            crate::proof_http::DEVICE_CHALLENGE_HEADER,
            crate::proof_http::DEVICE_SIGNATURE_HEADER,
            crate::proof_http::DEVICE_SIGNED_AT_HEADER,
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::post("/auth/refresh")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header_name, "synthetic")
                        .body(Body::from(r#"{"refresh_token":"synthetic"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        assert_eq!(service.0.load(Ordering::SeqCst), 0);
        let response = router
            .clone()
            .oneshot(
                Request::post("/auth/refresh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"refresh_token":"synthetic"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["code"], "refresh_token_reuse_detected");
        assert_eq!(service.0.load(Ordering::SeqCst), 1);
        for path in ["/devices/proof/challenges", "/auth/login", "/oidc/token"] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(Request::post(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }
    #[tokio::test]
    async fn ordinary_refresh_enforces_json_contract_and_limit() {
        let service = Arc::new(Refresh::default());
        let router = tenant_refresh_router(service.clone());
        for (content_type, body, expected) in [
            (
                "text/plain",
                "{}".into(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "application/json",
                r#"{"refresh_token":"synthetic","tenant_id":"t1"}"#.into(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "application/json",
                r#"{"refresh_token":"a","refresh_token":"b"}"#.into(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "application/json",
                "x".repeat(AUTH_DEVICE_BODY_LIMIT_BYTES + 1),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::post("/auth/refresh")
                        .header(header::CONTENT_TYPE, content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        assert_eq!(service.0.load(Ordering::SeqCst), 0);
    }
}

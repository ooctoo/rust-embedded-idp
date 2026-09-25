use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request as HttpRequest},
    Extension,
};
use embedded_idp_core::StoreError;
use serde_json::Value;
use tower::ServiceExt;

struct Fake {
    mode: TenancyMode,
    policy: LoginTenantPolicy,
}
impl ManagementAuthenticationService for Fake {
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        TenantLoginCapabilities {
            mode: self.mode,
            policy: self.policy.clone(),
        }
    }
    fn login(&self, _: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        Err(TenantAuthError::InvalidCredentials)
    }
    fn list_tenants(
        &self,
        _: SecretString,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn select_tenant(
        &self,
        _: SecretString,
        _: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn authenticate(
        &self,
        token: SecretString,
        request_id: String,
    ) -> Result<AccessAdminContext, TenantAuthError> {
        match token.expose_secret() {
            "management-token" => Ok(AccessAdminContext {
                actor: AccessActor {
                    tenant_id: "0".into(),
                    subject_id: "verified".into(),
                    session_id: "session".into(),
                },
                authentication_source: "management_access".into(),
                request_id,
            }),
            "store-error" => Err(TenantAuthError::Store(StoreError::Backend(
                "private-db-details".into(),
            ))),
            _ => Err(TenantAuthError::InvalidSession),
        }
    }
    fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        Err(TenantAuthError::InvalidSession)
    }
    fn rotate_refresh(&self, _: SecretString) -> Result<TenantRefreshOutcome, TenantAuthError> {
        Ok(TenantRefreshOutcome::ReuseDetected {
            tenant_id: "0".into(),
            session_id: "hidden".into(),
        })
    }
    fn logout(&self, _: SecretString) -> Result<(), TenantAuthError> {
        Err(TenantAuthError::InvalidSession)
    }
}

fn fake(mode: TenancyMode, policy: LoginTenantPolicy) -> Arc<Fake> {
    Arc::new(Fake { mode, policy })
}
async fn context(Extension(c): Extension<AccessAdminContext>) -> Json<Value> {
    Json(json!({"subject":c.actor.subject_id,"tenant":c.actor.tenant_id,"request_id":c.request_id}))
}
async fn send(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = HttpRequest::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn middleware_rejects_ambiguous_credentials_and_overwrites_unverified_identity() {
    let app = management_router(
        fake(
            TenancyMode::Disabled,
            LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
        ),
        Router::new().route("/admin/probe", get(context)),
    )
    .layer(Extension(AccessAdminContext {
        actor: AccessActor {
            tenant_id: "forged".into(),
            subject_id: "attacker".into(),
            session_id: "forged".into(),
        },
        authentication_source: "header".into(),
        request_id: "attacker".into(),
    }));
    for headers in [
        vec![],
        vec![("cookie", "session=management-token")],
        vec![
            ("x-embedded-idp-subject", "verified"),
            ("x-api-key", "management-token"),
        ],
        vec![("authorization", "Bearer business-token")],
        vec![("authorization", "TenantSelection management-token")],
        vec![
            ("authorization", "Bearer management-token"),
            ("authorization", "Bearer management-token"),
        ],
        vec![(
            "authorization",
            "Bearer management-token, Bearer business-token",
        )],
        vec![("authorization", "Bearer  management-token")],
    ] {
        assert_eq!(
            send(&app, "GET", "/admin/probe", &headers, "").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (status, headers, body) = send(
        &app,
        "GET",
        "/admin/probe",
        &[
            ("authorization", "bearer management-token"),
            ("x-request-id", "attacker"),
            ("x-embedded-idp-tenant-id", "target"),
        ],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["subject"], "verified");
    assert_eq!(body["tenant"], "0");
    assert_ne!(body["request_id"], "attacker");
    assert_eq!(
        body["request_id"].as_str().unwrap(),
        headers["x-request-id"].to_str().unwrap()
    );
    let (status, _, body) = send(
        &app,
        "GET",
        "/admin/probe",
        &[("authorization", "Bearer store-error")],
        "",
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!body.to_string().contains("private-db-details"));
}

#[tokio::test]
async fn management_http_mounts_only_configured_selection_and_bounds_inputs() {
    for (mode, policy, selects) in [
        (
            TenancyMode::Disabled,
            LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
            false,
        ),
        (
            TenancyMode::Enabled,
            LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
            false,
        ),
        (
            TenancyMode::Enabled,
            LoginTenantPolicy::ChooseAfterAuthentication,
            true,
        ),
    ] {
        let app = management_router(fake(mode, policy), Router::new());
        assert_eq!(
            send(&app, "GET", "/admin/auth/capabilities", &[], "")
                .await
                .2["tenancy_enabled"],
            mode == TenancyMode::Enabled
        );
        for (method, path) in [
            ("GET", "/admin/auth/tenant-selection/tenants"),
            ("POST", "/admin/auth/tenant-selection/complete"),
            ("POST", "/admin/auth/me/tenant-selection"),
        ] {
            assert_eq!(
                send(&app, method, path, &[], r#"{"tenant_id":"t1"}"#)
                    .await
                    .0,
                if selects {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::NOT_FOUND
                }
            );
        }
        assert_eq!(
            send(
                &app,
                "POST",
                "/admin/auth/login",
                &[],
                r#"{"email":"a@example.test","password":"synthetic","client_id":"attacker"}"#
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            send(
                &app,
                "POST",
                "/admin/auth/login",
                &[],
                &format!(
                    r#"{{"email":"{}","password":"synthetic"}}"#,
                    "x".repeat(20000)
                )
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            send(
                &app,
                "POST",
                "/admin/auth/refresh",
                &[("x-embedded-idp-tenant-id", "0")],
                r#"{"refresh_token":"synthetic"}"#
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                &app,
                "POST",
                "/admin/auth/refresh",
                &[],
                r#"{"refresh_token":"a","refresh_token":"b"}"#
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let (status, _, body) = send(
            &app,
            "POST",
            "/admin/auth/refresh",
            &[],
            r#"{"refresh_token":"synthetic"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "refresh_token_reuse_detected");
        assert!(!body.to_string().contains("hidden"));
    }
}

use crate::{
    account_admin::account,
    role_binding_admin::binding_json,
    tenant_admin::{error, platform_context, target},
    tenant_auth::{call, no_store},
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, Method, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use embedded_idp_core::access::*;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct AdminState {
    mode: TenancyMode,
    service: Arc<dyn SecurityAdminService>,
}
/// Dedicated protected-role appointment routes; host verifies management credentials.
/// Core determines role kind from the target domain and requires platform access.manage.
pub fn security_admin_router(mode: TenancyMode, service: Arc<dyn SecurityAdminService>) -> Router {
    Router::new()
        .route(
            "/admin/access/security-admins/:subject_id",
            post(tenant_change).delete(tenant_change).get(tenant_detail),
        )
        .route(
            "/admin/platform/security-admins/:subject_id",
            post(platform_change)
                .delete(platform_change)
                .get(platform_detail),
        )
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
async fn tenant_detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    detail(state, context, tenant, subject).await
}
async fn platform_detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    detail(state, context, SYSTEM_TENANT_ID.into(), subject).await
}
async fn detail(
    state: AdminState,
    context: AccessAdminContext,
    tenant: String,
    subject: String,
) -> Response {
    match call(move || state.service.get_security_administrator(context, tenant, subject)).await {
        Ok(value) => Json(json!({
            "tenant_id":value.tenant.id,
            "tenant_status":match value.tenant.status { TenantStatus::Active=>"active",TenantStatus::Suspended=>"suspended",TenantStatus::Archived=>"archived" },
            "account":account(value.account),
            "role":{"tenant_id":value.role.tenant_id,"business_id":value.role.business_id,"role_id":value.role.id,"key":value.role.key,"name":value.role.name,"version":value.role.version,
                "status":match value.role.status {RoleStatus::Active=>"active",RoleStatus::Disabled=>"disabled"},
                "kind":match value.role.kind {RoleKind::SystemAdmin=>"system_admin",RoleKind::TenantSecurityAdmin=>"tenant_security_admin",RoleKind::Business=>"business",RoleKind::BusinessAdmin=>"business_admin"}},
            "binding":value.binding.map(binding_json),
        })).into_response(),
        Err(e) => error(e),
    }
}
async fn tenant_change(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    method: Method,
    body: Bytes,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    change(state, context, tenant, subject, method, body).await
}
async fn platform_change(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    method: Method,
    body: Bytes,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    change(
        state,
        context,
        SYSTEM_TENANT_ID.into(),
        subject,
        method,
        body,
    )
    .await
}
async fn change(
    state: AdminState,
    context: AccessAdminContext,
    tenant_id: String,
    subject_id: String,
    method: Method,
    body: Bytes,
) -> Response {
    if !body.is_empty() {
        return error(AccessError::InvalidInput("body_not_allowed"));
    }
    let appointed = method == Method::POST;
    match call(move || {
        state.service.execute(
            context,
            AccessAdminCommand {
                tenant_id,
                mutation: AccessAdminMutation::SetSecurityAdmin {
                    subject_id,
                    appointed,
                },
            },
        )
    })
    .await
    {
        Ok(event) => match event.change {
            AccessChange::Binding { after, .. } => (
                if appointed {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                Json(json!({"binding":after.map(binding_json),"audit_id":event.id})),
            )
                .into_response(),
            _ => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[derive(Default)]
    struct Service(Mutex<Vec<AccessAdminCommand>>);
    impl AccessAdminService for Service {
        fn execute(
            &self,
            _: AccessAdminContext,
            command: AccessAdminCommand,
        ) -> Result<AccessAuditEvent, AccessError> {
            self.0.lock().unwrap().push(command);
            Err(AccessError::Forbidden)
        }
    }
    impl SecurityAdminService for Service {
        fn get_security_administrator(
            &self,
            _: AccessAdminContext,
            _: String,
            _: String,
        ) -> Result<SecurityAdministrator, AccessError> {
            Err(AccessError::Forbidden)
        }
    }
    #[tokio::test]
    async fn appointments_use_explicit_domains_and_reject_request_body_authority() {
        for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
            let service = Arc::new(Service::default());
            let router =
                security_admin_router(mode, service.clone()).layer(Extension(AccessAdminContext {
                    actor: AccessActor {
                        tenant_id: "0".into(),
                        subject_id: "actor".into(),
                        session_id: "session".into(),
                    },
                    authentication_source: "test".into(),
                    request_id: "request".into(),
                }));
            for (path, target_domain, header) in [
                ("/admin/platform/security-admins/member", "0", None),
                (
                    "/admin/access/security-admins/member",
                    if mode == TenancyMode::Enabled {
                        "t1"
                    } else {
                        "0"
                    },
                    Some(if mode == TenancyMode::Enabled {
                        "t1"
                    } else {
                        "0"
                    }),
                ),
            ] {
                for method in [Method::POST, Method::DELETE] {
                    let mut request = Request::builder().method(method.clone()).uri(path);
                    if let Some(t) = header {
                        request = request.header("x-embedded-idp-tenant-id", t);
                    }
                    let response = router
                        .clone()
                        .oneshot(request.body(Body::empty()).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::FORBIDDEN);
                    assert_eq!(response.headers()["cache-control"], "no-store");
                    assert_eq!(
                        service.0.lock().unwrap().last(),
                        Some(&AccessAdminCommand {
                            tenant_id: target_domain.into(),
                            mutation: AccessAdminMutation::SetSecurityAdmin {
                                subject_id: "member".into(),
                                appointed: method == Method::POST
                            },
                        })
                    );
                }
            }
            let count = service.0.lock().unwrap().len();
            for method in [Method::POST, Method::DELETE] {
                for body in [r#"{"role_id":"custom","tenant_id":"t1"}"#, "{}"] {
                    let response = router
                        .clone()
                        .oneshot(
                            Request::builder()
                                .method(method.clone())
                                .uri("/admin/platform/security-admins/member")
                                .body(Body::from(body))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                }
            }
            let oversized = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/platform/security-admins/member")
                        .body(Body::from(vec![b' '; 16385]))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
            let wrong_target = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/platform/security-admins/member")
                        .header("x-embedded-idp-tenant-id", "t1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(wrong_target.status(), StatusCode::BAD_REQUEST);
            assert_eq!(service.0.lock().unwrap().len(), count);
        }
    }
}

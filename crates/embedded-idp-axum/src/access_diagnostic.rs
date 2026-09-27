use crate::{
    tenant_admin::{business_target, error},
    tenant_auth::{call, no_store},
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::HeaderMap,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use embedded_idp_core::access::*;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct DiagnosticState {
    mode: TenancyMode,
    service: Arc<dyn AccessDiagnosticService>,
}
/// Requires host-verified management authentication; does not authorize resource access.
pub fn access_diagnostic_router(
    mode: TenancyMode,
    service: Arc<dyn AccessDiagnosticService>,
) -> Router {
    Router::new()
        .route("/admin/access/check", post(check))
        .with_state(DiagnosticState { mode, service })
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    subject_id: String,
    resource_type: String,
    action: String,
    resource_id: Option<String>,
}
async fn check(
    State(state): State<DiagnosticState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Json(body): Json<Check>,
) -> Response {
    let (context, tenant_id, business_id) =
        match business_target(state.mode, context, &headers, false) {
            Ok(v) => v,
            Err(e) => return e,
        };
    let query = AccessQuery {
        business_id,
        tenant_id,
        subject_id: body.subject_id,
        resource_type: body.resource_type,
        action: body.action,
        resource_id: body.resource_id,
    };
    match call(move || state.service.diagnose_permission(context, query)).await {
        Ok(event) => match event.change {
            AccessChange::PermissionChecked { query, decision } => Json(json!({
                "audit_id":event.id,
                "tenant_id":query.tenant_id,
                "business_id":query.business_id,
                "subject_id":query.subject_id,
                "resource_type":query.resource_type,
                "action":query.action,
                "resource_id":query.resource_id,
                "decision":match decision {AccessDecision::Allow=>"allow",AccessDecision::Deny=>"deny"}
            })).into_response(),
            _ => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_body_cannot_override_authority_or_decision() {
        let body = json!({"subject_id":"u1","resource_type":"report","action":"read"});
        assert!(serde_json::from_value::<Check>(body.clone())
            .unwrap()
            .resource_id
            .is_none());
        for (key, value) in [
            ("tenant_id", json!("t2")),
            ("actor_id", json!("admin")),
            ("decision", json!("allow")),
            ("checked_at", json!(1)),
        ] {
            let mut invalid = body.clone();
            invalid[key] = value;
            assert!(serde_json::from_value::<Check>(invalid).is_err());
        }
    }
}

use crate::{
    account_admin::{account, Status},
    tenant_admin::{error, platform_context},
    tenant_auth::{call, no_store},
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::HeaderMap,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use embedded_idp_core::{access::*, SecretString};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
/// Compose only in the host's trusted management group, alongside account queries.
pub fn account_security_admin_router(service: Arc<dyn AccountSecurityService>) -> Router {
    Router::new()
        .route("/admin/platform/accounts", post(create))
        .route("/admin/platform/accounts/:account_id/status", post(status))
        .route(
            "/admin/platform/accounts/:account_id/password",
            post(password),
        )
        .with_state(service)
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    tenant_id: String,
    email: String,
    password: String,
    display_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetStatus {
    status: Status,
    expected_status: Status,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Password {
    new_password: String,
}
fn response(result: Result<AccessAuditEvent, AccessError>) -> Response {
    match result {
        Ok(event) => match event.change {
            AccessChange::AccountCreated { after }
            | AccessChange::AccountSecurity { after, .. } => {
                Json(json!({"account":account(after),"audit_id":event.id})).into_response()
            }
            _ => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}
async fn create(
    State(service): State<Arc<dyn AccountSecurityService>>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Json(body): Json<Create>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    response(
        call(move || {
            service.create_account(
                context,
                AdminCreateAccount {
                    tenant_id: body.tenant_id,
                    email: body.email,
                    password: SecretString::new(body.password),
                    display_name: body.display_name,
                },
            )
        })
        .await,
    )
}
async fn status(
    State(service): State<Arc<dyn AccountSecurityService>>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(body): Json<SetStatus>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    response(
        call(move || {
            service.set_account_status(
                context,
                AdminSetAccountStatus {
                    account_id,
                    status: body.status.core(),
                    expected_status: body.expected_status.core(),
                },
            )
        })
        .await,
    )
}
async fn password(
    State(service): State<Arc<dyn AccountSecurityService>>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(account_id): Path<String>,
    Json(body): Json<Password>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    response(
        call(move || {
            service.set_account_password(
                context,
                AdminSetAccountPassword {
                    account_id,
                    new_password: SecretString::new(body.new_password),
                },
            )
        })
        .await,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_security_bodies_require_initial_tenant_and_forbid_authority_overrides() {
        assert!(serde_json::from_str::<Create>(
            r#"{"email":"a@example.test","password":"Fixture123"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Password>(
            r#"{"new_password":"Fixture123","password_hash":"override"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<SetStatus>(
            r#"{"status":"disabled","expected_status":"active","actor_id":"override"}"#
        )
        .is_err());
    }
}

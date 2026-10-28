use axum::{
    extract::{DefaultBodyLimit, Json, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use embedded_idp_core::{access::*, IdGenerator, SecretString, UuidV7IdGenerator};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::{
    http_support::bearer_token,
    tenant_auth::{call, map_tenant_auth_error, no_store, tenant_error, tenant_header_matches},
    AUTH_DEVICE_BODY_LIMIT_BYTES,
};

#[derive(Clone)]
enum Auth {
    Business(Arc<dyn TenantAuthenticationService>),
    Management(Arc<dyn ManagementAuthenticationService>),
}

#[derive(Clone)]
struct StateData {
    auth: Auth,
    service: Arc<dyn SelfSessionRevocationService>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    target_tenant_id: String,
    target_session_id: String,
    operation_id: String,
    receipt_secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultBody {
    operation_id: String,
    receipt_secret: String,
}

pub fn self_session_revocation_router(
    auth: Arc<dyn TenantAuthenticationService>,
    service: Arc<dyn SelfSessionRevocationService>,
) -> Router {
    router(
        "/auth/security/sessions/revoke",
        Auth::Business(auth),
        service,
    )
}

pub fn management_self_session_revocation_router(
    auth: Arc<dyn ManagementAuthenticationService>,
    service: Arc<dyn SelfSessionRevocationService>,
) -> Router {
    router(
        "/admin/auth/security/sessions/revoke",
        Auth::Management(auth),
        service,
    )
}

fn router(path: &str, auth: Auth, service: Arc<dyn SelfSessionRevocationService>) -> Router {
    let state = StateData { auth, service };
    Router::new()
        .route(path, post(revoke))
        .route(&format!("{path}/result"), post(result))
        .with_state(state)
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}

async fn revoke(
    State(state): State<StateData>,
    headers: HeaderMap,
    Json(body): Json<RevokeBody>,
) -> Response {
    if headers.contains_key("x-embedded-idp-business-id")
        || headers.get_all(header::AUTHORIZATION).iter().count() != 1
    {
        return auth_error();
    }
    let Some(token) = bearer_token(&headers)
        .filter(|token| token.len() <= 16_384)
        .map(str::to_owned)
    else {
        return auth_error();
    };
    let actor = call(move || match state.auth {
        Auth::Business(auth) => auth.authenticate(SecretString::new(token)),
        Auth::Management(auth) => auth
            .authenticate(
                SecretString::new(token),
                UuidV7IdGenerator.next_id("self-revoke"),
            )
            .map(|context| context.actor),
    })
    .await;
    let actor = match actor {
        Ok(actor) if tenant_header_matches(&headers, &actor.tenant_id) => actor,
        Ok(_) => return auth_error(),
        Err(error) => return revocation_auth_error(error),
    };
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let command = SelfSessionRevokeCommand {
        target_tenant_id: body.target_tenant_id,
        target_session_id: body.target_session_id,
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.service.revoke_session(actor, command)).await {
        Ok(()) => completed(true),
        Err(error) => revocation_error(error),
    }
}

async fn result(
    State(state): State<StateData>,
    headers: HeaderMap,
    Json(body): Json<ResultBody>,
) -> Response {
    if !valid_selectors(&headers) {
        return invalid_request();
    }
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let query = SecurityReceiptQuery {
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.service.session_revocation_result(query)).await {
        Ok(value) => completed(value),
        Err(error) => revocation_error(error),
    }
}

fn valid_selectors(headers: &HeaderMap) -> bool {
    !headers.contains_key("x-embedded-idp-business-id")
        && !headers.contains_key("x-embedded-idp-tenant-id")
}

pub(crate) fn parse_operation_id(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil() && id.to_string() == value)
}

pub(crate) fn completed(completed: bool) -> Response {
    (StatusCode::OK, axum::Json(json!({"completed": completed}))).into_response()
}

pub(crate) fn auth_error() -> Response {
    tenant_error(
        StatusCode::UNAUTHORIZED,
        "invalid_session",
        "a current session is required",
    )
}

pub(crate) fn revocation_auth_error(error: TenantAuthError) -> Response {
    match error {
        TenantAuthError::InvalidSession | TenantAuthError::Access(AccessError::Forbidden) => {
            auth_error()
        }
        other => map_tenant_auth_error(other),
    }
}

pub(crate) fn invalid_request() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "request is invalid",
    )
}

pub(crate) fn revocation_error(error: AccessError) -> Response {
    match error {
        AccessError::Forbidden => auth_error(),
        AccessError::NotFound("session") => tenant_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "session was not found",
        ),
        AccessError::Conflict("security.receipt_capacity") => tenant_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_unavailable",
            "security operation is temporarily unavailable",
        ),
        AccessError::Conflict("security.operation_conflict") => tenant_error(
            StatusCode::CONFLICT,
            "operation_conflict",
            "operation conflicts with an existing request",
        ),
        AccessError::Conflict(_) => tenant_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_unavailable",
            "security operation is temporarily unavailable",
        ),
        AccessError::InvalidInput(_) | AccessError::ModeMismatch => invalid_request(),
        AccessError::Store(embedded_idp_core::StoreError::Backend(_)) => tenant_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_unavailable",
            "security operation is temporarily unavailable",
        ),
        _ => tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be completed",
        ),
    }
}

#[cfg(test)]
#[path = "self_session_revocation_tests.rs"]
mod tests;

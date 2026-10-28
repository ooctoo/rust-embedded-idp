use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Json, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::Response,
    routing::post,
    Router,
};
use embedded_idp_core::{access::*, IdGenerator, SecretString, UuidV7IdGenerator};
use serde::Deserialize;
use std::sync::Arc;

use crate::{
    http_support::bearer_token,
    self_session_revocation::{
        auth_error, completed, invalid_request, parse_operation_id, revocation_auth_error,
    },
    tenant_auth::{call, no_store, tenant_error, tenant_header_matches},
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
    service: Arc<dyn SelfPasswordChangeService>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeBody {
    current_password: String,
    new_password: String,
    operation_id: String,
    receipt_secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultBody {
    operation_id: String,
    receipt_secret: String,
}

pub fn self_password_change_router(
    auth: Arc<dyn TenantAuthenticationService>,
    service: Arc<dyn SelfPasswordChangeService>,
) -> Router {
    router("/auth/security/password", Auth::Business(auth), service)
}

pub fn management_self_password_change_router(
    auth: Arc<dyn ManagementAuthenticationService>,
    service: Arc<dyn SelfPasswordChangeService>,
) -> Router {
    router(
        "/admin/auth/security/password",
        Auth::Management(auth),
        service,
    )
}

fn router(path: &str, auth: Auth, service: Arc<dyn SelfPasswordChangeService>) -> Router {
    Router::new()
        .route(path, post(change))
        .route(&format!("{path}/result"), post(result))
        .with_state(StateData { auth, service })
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}

async fn change(
    State(state): State<StateData>,
    headers: HeaderMap,
    body: Result<Json<ChangeBody>, JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return json_rejection(error),
    };
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
                UuidV7IdGenerator.next_id("self-password-change"),
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
    let command = SelfPasswordChangeCommand {
        current_password: SecretString::new(body.current_password),
        new_password: SecretString::new(body.new_password),
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.service.change_password(actor, command)).await {
        Ok(()) => completed(true),
        Err(error) => change_error(error),
    }
}

async fn result(
    State(state): State<StateData>,
    headers: HeaderMap,
    body: Result<Json<ResultBody>, JsonRejection>,
) -> Response {
    if !valid_selectors(&headers) {
        return invalid_request();
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return json_rejection(error),
    };
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let query = SecurityReceiptQuery {
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.service.password_change_result(query)).await {
        Ok(value) => completed(value),
        Err(error) => change_error(error),
    }
}

fn valid_selectors(headers: &HeaderMap) -> bool {
    !headers.contains_key("x-embedded-idp-business-id")
        && !headers.contains_key("x-embedded-idp-tenant-id")
}

pub(crate) fn json_rejection(error: JsonRejection) -> Response {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        tenant_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "request body is too large",
        )
    } else {
        invalid_request()
    }
}

pub(crate) fn change_error(error: SelfPasswordChangeError) -> Response {
    match error {
        SelfPasswordChangeError::InvalidCredentials => tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        ),
        SelfPasswordChangeError::Access(AccessError::Forbidden) => auth_error(),
        SelfPasswordChangeError::Access(
            AccessError::InvalidInput(
                "actor" | "actor_tenant_id" | "actor_subject_id" | "actor_session_id",
            )
            | AccessError::ModeMismatch,
        ) => auth_error(),
        SelfPasswordChangeError::Access(AccessError::InvalidInput(_)) => invalid_request(),
        SelfPasswordChangeError::Access(AccessError::Conflict("security.credentials_changed")) => {
            tenant_error(
                StatusCode::CONFLICT,
                "credentials_changed",
                "credentials changed",
            )
        }
        SelfPasswordChangeError::Access(AccessError::Conflict("security.operation_conflict")) => {
            tenant_error(
                StatusCode::CONFLICT,
                "operation_conflict",
                "operation conflicts with an existing request",
            )
        }
        SelfPasswordChangeError::Access(AccessError::Conflict("security.receipt_capacity"))
        | SelfPasswordChangeError::Access(AccessError::Store(_)) => tenant_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "security_unavailable",
            "security operation is temporarily unavailable",
        ),
        SelfPasswordChangeError::Access(AccessError::InvalidStoreResponse) => tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be completed",
        ),
        SelfPasswordChangeError::Access(_) => tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the request could not be completed",
        ),
    }
}

#[cfg(test)]
#[path = "self_password_change_tests.rs"]
mod tests;

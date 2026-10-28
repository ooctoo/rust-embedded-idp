use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use embedded_idp_core::{access::*, AccessTokenPurpose, SecretString, StoreError};
use http_body_util::LengthLimitError;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use tokio::time::timeout;

use crate::{
    browser_session::BrowserSessionHttpConfig,
    self_session_revocation::{completed, parse_operation_id},
    tenant_auth::{call, no_store, tenant_error},
};

const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 16 * 1024;
const UNAVAILABLE_CODE: &str = "security_unavailable";
const UNAVAILABLE_MESSAGE: &str = "security operation is temporarily unavailable";

#[derive(Clone)]
struct RecoveryState {
    start: Arc<dyn RecoveryStartService>,
    complete: Arc<dyn RecoveryCompletionService>,
}

#[derive(Clone)]
struct GuardState {
    browser: Option<BrowserSessionHttpConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartBody {
    email: String,
    operation_id: String,
    receipt_secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteBody {
    handle: String,
    code: String,
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

#[derive(Serialize)]
struct StartResponse {
    handle: String,
    expires_at_unix_secs: u64,
}

enum CompleteCallError {
    Service(RecoveryCompleteError),
    Store,
}

impl From<StoreError> for CompleteCallError {
    fn from(_: StoreError) -> Self {
        Self::Store
    }
}

pub fn password_recovery_router(
    start: Arc<dyn RecoveryStartService>,
    complete: Arc<dyn RecoveryCompletionService>,
) -> Router {
    router("/auth/password-recovery", start, complete, None)
}

pub fn management_password_recovery_router(
    start: Arc<dyn RecoveryStartService>,
    complete: Arc<dyn RecoveryCompletionService>,
) -> Router {
    router("/admin/auth/password-recovery", start, complete, None)
}

pub fn browser_password_recovery_router(
    start: Arc<dyn RecoveryStartService>,
    complete: Arc<dyn RecoveryCompletionService>,
    config: BrowserSessionHttpConfig,
) -> Router {
    let root = match config.purpose() {
        AccessTokenPurpose::Business => "/auth/browser/password-recovery",
        AccessTokenPurpose::Management => "/admin/auth/browser/password-recovery",
    };
    router(root, start, complete, Some(config))
}

fn router(
    root: &str,
    start: Arc<dyn RecoveryStartService>,
    complete: Arc<dyn RecoveryCompletionService>,
    browser: Option<BrowserSessionHttpConfig>,
) -> Router {
    let state = RecoveryState { start, complete };
    Router::new()
        .route(&format!("{root}/start"), post(start_handler))
        .route(&format!("{root}/complete"), post(complete_handler))
        .route(&format!("{root}/result"), post(result_handler))
        .with_state(state)
        .route_layer(middleware::from_fn_with_state(
            GuardState { browser },
            request_guard,
        ))
        .layer(middleware::from_fn(no_store))
        .layer(middleware::from_fn_with_state(
            crate::AnonymousLoginBudget::default(),
            crate::anonymous_login::admit,
        ))
}

async fn request_guard(State(state): State<GuardState>, request: Request, next: Next) -> Response {
    if let Some(config) = &state.browser {
        if !crate::browser_session::browser_headers_valid(request.headers(), config) {
            return tenant_error(
                StatusCode::FORBIDDEN,
                "browser_origin_rejected",
                "browser request rejected",
            );
        }
    }
    let headers = request.headers();
    if request.uri().query().is_some()
        || headers.contains_key("x-embedded-idp-business-id")
        || headers.contains_key("x-embedded-idp-tenant-id")
    {
        return invalid_request();
    }
    next.run(request).await
}

async fn start_handler(State(state): State<RecoveryState>, request: Request) -> Response {
    let body: StartBody = match decode_json(request, BODY_TIMEOUT).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let command = RecoveryStartCommand {
        email: SecretString::new(body.email),
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.start.start_recovery(command)).await {
        Ok(result) => match result.expires_at.duration_since(UNIX_EPOCH) {
            Ok(expires_at) => Json(StartResponse {
                handle: result.handle.into_exposed(),
                expires_at_unix_secs: expires_at.as_secs(),
            })
            .into_response(),
            Err(_) => unavailable(),
        },
        Err(error) => access_error(error),
    }
}

async fn complete_handler(State(state): State<RecoveryState>, request: Request) -> Response {
    let body: CompleteBody = match decode_json(request, BODY_TIMEOUT).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let command = RecoveryCompleteCommand {
        handle: SecretString::new(body.handle),
        code: SecretString::new(body.code),
        new_password: SecretString::new(body.new_password),
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    let result = call(move || {
        state
            .complete
            .complete_recovery(command)
            .map_err(CompleteCallError::Service)
    })
    .await;
    match result {
        Ok(()) => completed(true),
        Err(CompleteCallError::Service(RecoveryCompleteError::InvalidRecovery)) => {
            recovery_invalid()
        }
        Err(CompleteCallError::Service(RecoveryCompleteError::Access(error))) => {
            access_error(error)
        }
        Err(CompleteCallError::Store) => unavailable(),
    }
}

async fn result_handler(State(state): State<RecoveryState>, request: Request) -> Response {
    let body: ResultBody = match decode_json(request, BODY_TIMEOUT).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(operation_id) = parse_operation_id(&body.operation_id) else {
        return invalid_request();
    };
    let query = SecurityReceiptQuery {
        operation_id,
        receipt_secret: SecretString::new(body.receipt_secret),
    };
    match call(move || state.complete.recovery_completion_result(query)).await {
        Ok(value) => completed(value),
        Err(error) => access_error(error),
    }
}

async fn decode_json<T: for<'de> Deserialize<'de>>(
    request: Request,
    read_timeout: Duration,
) -> Result<T, Response> {
    if !is_json_content_type(request.headers()) {
        return Err(invalid_request());
    }
    let body = match timeout(read_timeout, to_bytes(request.into_body(), BODY_LIMIT)).await {
        Err(_) => {
            return Err(tenant_error(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "request body read timed out",
            ))
        }
        Ok(Ok(body)) => body,
        Ok(Err(error)) if is_length_limit_error(&error) => {
            return Err(tenant_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "request body exceeds the configured limit",
            ));
        }
        Ok(Err(_)) => return Err(invalid_request()),
    };
    serde_json::from_slice(&body).map_err(|_| invalid_request())
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none()
        && value.to_str().is_ok_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
}

fn is_length_limit_error(error: &(dyn Error + 'static)) -> bool {
    let mut source = Some(error);
    while let Some(error) = source {
        if error.downcast_ref::<LengthLimitError>().is_some() {
            return true;
        }
        source = error.source();
    }
    false
}

fn access_error(error: AccessError) -> Response {
    match error {
        AccessError::InvalidInput(_) => invalid_request(),
        AccessError::Conflict("recovery.operation_conflict") => tenant_error(
            StatusCode::CONFLICT,
            "operation_conflict",
            "operation conflicts with an existing request",
        ),
        AccessError::Conflict("recovery.rate_limited") => tenant_error(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "request rate limit exceeded",
        ),
        _ => unavailable(),
    }
}

fn invalid_request() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "request is invalid",
    )
}

fn recovery_invalid() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_recovery",
        "recovery request is invalid",
    )
}

fn unavailable() -> Response {
    tenant_error(
        StatusCode::SERVICE_UNAVAILABLE,
        UNAVAILABLE_CODE,
        UNAVAILABLE_MESSAGE,
    )
}

#[cfg(test)]
#[path = "password_recovery_tests.rs"]
mod tests;

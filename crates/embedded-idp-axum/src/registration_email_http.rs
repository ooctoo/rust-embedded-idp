//! HTTP adapter for the frozen `idp-registration-email-v1` profile.
//!
//! This module is intentionally a transport-only boundary.  Registration
//! identity, password work, idempotency, budgets, and delivery state remain in
//! `embedded-idp-core` and the injected IDP runtime.  The adapter only checks
//! the profile/transport envelope, validates the JSON shape, and projects the
//! small public response contract.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use embedded_idp_core::access::{
    RegistrationEmailCommand, RegistrationEmailError, RegistrationEmailOperationKind,
    RegistrationEmailService, RegistrationEmailVerification, REGISTRATION_EMAIL_PROFILE,
    REGISTRATION_EMAIL_PROFILE_HEADER,
};
use embedded_idp_core::SecretString;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

const REGISTER_PATH: &str = "/auth/register";
const RESEND_PATH: &str = "/auth/resend-verification";
const VERIFY_PATH: &str = "/auth/verify-email";
const MAX_BODY_BYTES: usize = 16 * 1024;
const ACCEPTED_CONTEXT_LIFETIME_SECS: i64 = 900;
const ACCEPTED_RESEND_AFTER_SECS: i64 = 60;

mod routes;
mod validation;
use routes::{register, resend, verify};
use validation::*;

/// Trusted transport configuration for one registration profile.
///
/// Origins are an allow-list for the request's `Origin` header.  A missing
/// Origin is allowed because native clients may not send one; no CORS headers
/// are emitted by this adapter.  HTTP origins are rejected unless the host is
/// a loopback address and `allow_loopback_http` is explicitly enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEmailHttpConfig {
    pub allowed_origins: Vec<String>,
    pub allow_loopback_http: bool,
}

impl RegistrationEmailHttpConfig {
    pub fn new(
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
        allow_loopback_http: bool,
    ) -> Result<Self, RegistrationEmailError> {
        let config = Self {
            allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
            allow_loopback_http,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), RegistrationEmailError> {
        for (index, origin) in self.allowed_origins.iter().enumerate() {
            validate_origin(origin).map_err(|_| {
                RegistrationEmailError::InvalidInput(if index == 0 {
                    "allowed_origin"
                } else {
                    "allowed_origins"
                })
            })?;
            if self.allowed_origins[..index]
                .iter()
                .any(|existing| existing == origin)
            {
                return Err(RegistrationEmailError::InvalidInput("allowed_origins"));
            }
            let is_http = origin
                .split_once("://")
                .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("http"));
            if is_http && !self.allow_loopback_http {
                return Err(RegistrationEmailError::InvalidInput("allowed_origin"));
            }
        }
        Ok(())
    }
}

impl Default for RegistrationEmailHttpConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allow_loopback_http: false,
        }
    }
}

/// Build the three fixed registration routes for a trusted IDP runtime.
pub fn registration_email_router(
    runtime: Arc<crate::RegistrationEmailRuntime>,
    config: RegistrationEmailHttpConfig,
) -> Result<Router, RegistrationEmailError> {
    config.validate()?;
    let state = RegistrationEmailHttpState { runtime, config };
    Ok(Router::new()
        .route(REGISTER_PATH, post(register))
        .route(RESEND_PATH, post(resend))
        .route(VERIFY_PATH, post(verify))
        .layer(middleware::from_fn(no_store_all))
        .with_state(state))
}

#[derive(Clone)]
struct RegistrationEmailHttpState {
    runtime: Arc<crate::RegistrationEmailRuntime>,
    config: RegistrationEmailHttpConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    tenant_id: String,
    #[serde(deserialize_with = "deserialize_secret")]
    email: SecretString,
    #[serde(deserialize_with = "deserialize_secret")]
    password: SecretString,
    #[serde(default, deserialize_with = "deserialize_optional_secret")]
    display_name: Option<SecretString>,
    client_operation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResendRequest {
    tenant_id: String,
    #[serde(deserialize_with = "deserialize_secret")]
    verification_context: SecretString,
    client_operation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    tenant_id: String,
    #[serde(deserialize_with = "deserialize_secret")]
    verification_context: SecretString,
    #[serde(deserialize_with = "deserialize_secret")]
    verification_code: SecretString,
    client_operation_id: String,
}

#[derive(Debug, Serialize)]
struct RegisterAcceptedResponse {
    status: &'static str,
    verification_context: String,
    accepted_at_unix_secs: i64,
    context_lifetime_secs: i64,
    resend_after_secs: i64,
}

#[derive(Debug, Serialize)]
struct ResendAcceptedResponse {
    status: &'static str,
    resend_after_secs: i64,
}

#[derive(Debug, Serialize)]
struct VerifySuccessResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: ErrorCode,
}

#[derive(Debug, Serialize)]
struct ErrorCode {
    code: &'static str,
}

fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(SecretString::new)
}

fn deserialize_optional_secret<'de, D>(deserializer: D) -> Result<Option<SecretString>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)
        .map(SecretString::new)
        .map(Some)
}

fn accepted_response(accepted: embedded_idp_core::access::RegistrationEmailAccepted) -> Response {
    if accepted.context_lifetime_secs != ACCEPTED_CONTEXT_LIFETIME_SECS
        || accepted.resend_after_secs != ACCEPTED_RESEND_AFTER_SECS
        || accepted.accepted_at_unix_secs < 0
        || !is_valid_context(accepted.verification_context.expose_secret())
    {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    with_no_store(
        (
            StatusCode::ACCEPTED,
            Json(RegisterAcceptedResponse {
                status: "verification_requested",
                verification_context: accepted.verification_context.into_exposed(),
                accepted_at_unix_secs: accepted.accepted_at_unix_secs,
                context_lifetime_secs: accepted.context_lifetime_secs,
                resend_after_secs: accepted.resend_after_secs,
            }),
        )
            .into_response(),
    )
}

fn accepted_resend_response() -> Response {
    with_no_store(
        (
            StatusCode::ACCEPTED,
            Json(ResendAcceptedResponse {
                status: "verification_requested",
                resend_after_secs: ACCEPTED_RESEND_AFTER_SECS,
            }),
        )
            .into_response(),
    )
}

fn is_valid_context(value: &str) -> bool {
    validate_context(value).is_ok()
}

async fn delayed_error(start: Instant, error: RegistrationEmailError) -> Response {
    crate::anonymous_response_delay(start).await;
    error_response_for(error)
}

fn error_response_for(error: RegistrationEmailError) -> Response {
    match error {
        RegistrationEmailError::InvalidInput(field) if field == "tenant" => {
            error_response(StatusCode::BAD_REQUEST, "invalid_tenant")
        }
        RegistrationEmailError::InvalidInput(_) => {
            error_response(StatusCode::BAD_REQUEST, "invalid_registration")
        }
        RegistrationEmailError::RequestExpired => {
            error_response(StatusCode::BAD_REQUEST, "request_expired")
        }
        RegistrationEmailError::RequestConflict => {
            error_response(StatusCode::CONFLICT, "request_conflict")
        }
        RegistrationEmailError::RegistrationClosed => {
            error_response(StatusCode::FORBIDDEN, "registration_closed")
        }
        RegistrationEmailError::Unavailable | RegistrationEmailError::Store(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
    }
}

fn error_response(status: StatusCode, code: &'static str) -> Response {
    let response = (
        status,
        Json(ErrorResponse {
            error: ErrorCode { code },
        }),
    )
        .into_response();
    with_no_store(response)
}

fn with_no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.remove(header::SET_COOKIE);
    headers.remove(header::LOCATION);
    headers.remove(header::WWW_AUTHENTICATE);
    headers.remove("access-control-allow-origin");
    headers.remove("access-control-allow-credentials");
    response
}

async fn no_store_all(request: Request, next: Next) -> Response {
    with_no_store(next.run(request).await)
}

#[cfg(test)]
mod tests;

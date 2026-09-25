use crate::{
    delivery_status,
    http_support::unix_time_secs,
    proof_http::AUTH_DEVICE_BODY_LIMIT_BYTES,
    send_verification_email,
    tenant_auth::{call, no_store, tenant_error, tenant_header_matches},
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use embedded_idp_core::{access::*, PendingEmailVerification, SecretString, StoreError};
use embedded_idp_email::VerificationEmailService;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct RegistrationState {
    service: Arc<dyn TenantRegistrationService>,
    email: Arc<dyn VerificationEmailService>,
    mode: TenancyMode,
    policy: LoginTenantPolicy,
}
/// Mount instead of the original single-domain registration routes. Policy is
/// trusted host configuration; registration always supplies an explicit tenant.
pub fn tenant_registration_router(
    service: Arc<dyn TenantRegistrationService>,
    policy: LoginTenantPolicy,
    email: Arc<dyn VerificationEmailService>,
) -> Result<Router, AccessError> {
    let mode = service.tenancy_mode();
    policy.validate(mode)?;
    Ok(Router::new()
        .route("/auth/register", post(register))
        .route("/auth/verify-email", post(verify))
        .route("/auth/resend-verification", post(resend))
        .with_state(RegistrationState {
            service,
            email,
            mode,
            policy,
        })
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    tenant_id: String,
    email: String,
    password: String,
    display_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyBody {
    tenant_id: String,
    email: String,
    verification_code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResendBody {
    tenant_id: String,
    email: String,
}
fn valid_tenant(state: &RegistrationState, headers: &HeaderMap, tenant: &str) -> bool {
    headers.get_all("x-embedded-idp-tenant-id").iter().count() <= 1
        && tenant_header_matches(headers, tenant)
        && state.policy.validate_selection(state.mode, tenant).is_ok()
}
async fn register(
    State(state): State<RegistrationState>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Response {
    if !valid_tenant(&state, &headers, &body.tenant_id) {
        return invalid_tenant();
    }
    match call(move || {
        state
            .service
            .register_account(RegisterTenantAccountCommand {
                tenant_id: body.tenant_id,
                email: body.email,
                password: SecretString::new(body.password),
                display_name: body.display_name,
            })
    })
    .await
    {
        Ok(result) => {
            let sent = deliver(state.email, &result).await;
            (StatusCode::ACCEPTED, Json(json!({
                "tenant_id":result.tenant_id,
                "account_id":result.account_id,
                "account_status":"pending_verification",
                "verification_channel":"email",
                "verification_expires_at_unix_secs":unix_time_secs(result.verification_expires_at),
                "delivery_status":sent,
            }))).into_response()
        }
        Err(error) => registration_error(error),
    }
}
async fn verify(
    State(state): State<RegistrationState>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Response {
    if !valid_tenant(&state, &headers, &body.tenant_id) {
        return invalid_tenant();
    }
    match call(move || state.service.verify_email(VerifyTenantEmailCommand {
        tenant_id:body.tenant_id,
        email:body.email,
        verification_code:SecretString::new(body.verification_code),
    })).await {
        Ok(result) => Json(json!({"tenant_id":result.tenant_id,"account_id":result.account_id,"account_status":"active"})).into_response(),
        Err(error) => registration_error(error),
    }
}
async fn resend(
    State(state): State<RegistrationState>,
    headers: HeaderMap,
    Json(body): Json<ResendBody>,
) -> Response {
    if !valid_tenant(&state, &headers, &body.tenant_id) {
        return invalid_tenant();
    }
    match call(move || {
        state
            .service
            .resend_verification(ResendTenantVerificationCommand {
                tenant_id: body.tenant_id,
                email: body.email,
            })
    })
    .await
    {
        Ok(result) => {
            if let Some(result) = result {
                deliver(state.email, &result).await;
            }
            // No account/tenant membership or delivery status disclosure.
            (
                StatusCode::ACCEPTED,
                Json(json!({"status":"verification_requested"})),
            )
                .into_response()
        }
        Err(error) => registration_error(error),
    }
}
async fn deliver(
    email: Arc<dyn VerificationEmailService>,
    result: &TenantRegistrationResult,
) -> &'static str {
    delivery_status(
        send_verification_email(
            email,
            &PendingEmailVerification {
                account_id: result.account_id.clone(),
                email: result.email.clone(),
                code: result.verification_code.expose_secret().into(),
                expires_at: result.verification_expires_at,
            },
        )
        .await,
    )
}
fn invalid_tenant() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_tenant",
        "tenant does not match this registration entry",
    )
}
fn registration_error(error: TenantRegistrationError) -> Response {
    let (status, code, message) = match error {
        TenantRegistrationError::InvalidContract(_) => (
            StatusCode::BAD_REQUEST,
            "invalid_registration",
            "registration input is invalid",
        ),
        TenantRegistrationError::RegistrationDisabled
        | TenantRegistrationError::Store(
            StoreError::NotFound("tenant") | StoreError::Conflict("tenant.registration_closed"),
        ) => (
            StatusCode::FORBIDDEN,
            "registration_disabled",
            "registration is not available",
        ),
        TenantRegistrationError::InvalidVerificationCode => (
            StatusCode::UNAUTHORIZED,
            "invalid_verification_code",
            "verification code is invalid",
        ),
        TenantRegistrationError::VerificationCodeExpired => (
            StatusCode::UNAUTHORIZED,
            "verification_code_expired",
            "verification code has expired",
        ),
        TenantRegistrationError::Store(StoreError::Conflict("access.unique" | "account.email")) => {
            (
                StatusCode::CONFLICT,
                "registration_conflict",
                "registration conflicts with an existing account",
            )
        }
        TenantRegistrationError::Access(
            AccessError::InvalidInput(_) | AccessError::ModeMismatch | AccessError::Forbidden,
        ) => return invalid_tenant(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ),
    };
    tenant_error(status, code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use embedded_idp_email::{EmailSendError, VerificationEmailRequest};
    use tower::ServiceExt;
    struct Unreachable;
    impl TenantRegistrationService for Unreachable {
        fn tenancy_mode(&self) -> TenancyMode {
            TenancyMode::Disabled
        }
        fn register_account(
            &self,
            _: RegisterTenantAccountCommand,
        ) -> Result<TenantRegistrationResult, TenantRegistrationError> {
            panic!("unvalidated request reached core")
        }
        fn verify_email(
            &self,
            _: VerifyTenantEmailCommand,
        ) -> Result<TenantEmailVerificationResult, TenantRegistrationError> {
            panic!("unvalidated request reached core")
        }
        fn resend_verification(
            &self,
            _: ResendTenantVerificationCommand,
        ) -> Result<Option<TenantRegistrationResult>, TenantRegistrationError> {
            panic!("unvalidated request reached core")
        }
    }
    impl VerificationEmailService for Unreachable {
        fn send_verification_email(
            &self,
            _: VerificationEmailRequest,
        ) -> Result<(), EmailSendError> {
            panic!("unvalidated request sent mail")
        }
    }
    #[tokio::test]
    async fn registration_http_rejects_ambiguous_input_and_wrong_entry_tenants() {
        assert!(tenant_registration_router(
            Arc::new(Unreachable),
            LoginTenantPolicy::ChooseAfterAuthentication,
            Arc::new(Unreachable)
        )
        .is_err());
        let app = tenant_registration_router(
            Arc::new(Unreachable),
            LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
            Arc::new(Unreachable),
        )
        .unwrap();
        for (path, body, status) in [
            (
                "/auth/register",
                r#"{"email":"x@example.test","password":"password-1"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/auth/register",
                r#"{"tenant_id":"0","tenant_id":"t1","email":"x@example.test","password":"password-1"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/auth/register",
                r#"{"tenant_id":"t1","email":"x@example.test","password":"password-1"}"#,
                StatusCode::BAD_REQUEST,
            ),
            (
                "/auth/verify-email",
                r#"{"tenant_id":"0","email":"x@example.test","verification_code":"123456","client_id":"web"}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/auth/resend-verification",
                r#"{"tenant_id":"t1","email":"x@example.test"}"#,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/resend-verification")
                    .header("content-type", "application/json")
                    .header("x-embedded-idp-tenant-id", "0")
                    .header("x-embedded-idp-tenant-id", "t1")
                    .body(Body::from(r#"{"tenant_id":"0","email":"x@example.test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from("x".repeat(16385)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}

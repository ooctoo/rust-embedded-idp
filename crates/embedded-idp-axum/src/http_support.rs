use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use embedded_idp_core::{
    ContractValidationError, IntrospectTokenResult, JwksDocument, ServiceError, StoreError,
};
use tokio::task;

use crate::dto::{ErrorHttpResponse, IntrospectionHttpResponse, JwkHttpResponse, JwksHttpResponse};

pub(crate) fn map_service_error(error: ServiceError) -> Response {
    let (status, code) = match error {
        ServiceError::InvalidContract(_) => (StatusCode::BAD_REQUEST, "invalid_contract"),
        ServiceError::RegistrationDisabled => (StatusCode::FORBIDDEN, "registration_disabled"),
        ServiceError::AccountNotFound => (StatusCode::NOT_FOUND, "account_not_found"),
        ServiceError::ClientNotFound => (StatusCode::NOT_FOUND, "client_not_found"),
        ServiceError::InvalidClientConfig(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "invalid_client_config")
        }
        ServiceError::RedirectUriMismatch => (StatusCode::BAD_REQUEST, "redirect_uri_mismatch"),
        ServiceError::EmailAlreadyExists => (StatusCode::CONFLICT, "email_already_exists"),
        ServiceError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
        ServiceError::AccountPendingVerification => {
            (StatusCode::FORBIDDEN, "account_pending_verification")
        }
        ServiceError::AccountDisabled => (StatusCode::FORBIDDEN, "account_disabled"),
        ServiceError::InvalidVerificationCode => {
            (StatusCode::UNAUTHORIZED, "invalid_verification_code")
        }
        ServiceError::VerificationCodeExpired => {
            (StatusCode::UNAUTHORIZED, "verification_code_expired")
        }
        ServiceError::SessionNotFound => (StatusCode::NOT_FOUND, "session_not_found"),
        ServiceError::SessionExpired => (StatusCode::UNAUTHORIZED, "session_expired"),
        ServiceError::SessionRevoked => (StatusCode::UNAUTHORIZED, "session_revoked"),
        ServiceError::UnsupportedResponseType => {
            (StatusCode::BAD_REQUEST, "unsupported_response_type")
        }
        ServiceError::UnsupportedGrantType => (StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        ServiceError::InvalidToken => (StatusCode::UNAUTHORIZED, "invalid_token"),
        ServiceError::AuthorizationCodeNotFound => {
            (StatusCode::NOT_FOUND, "authorization_code_not_found")
        }
        ServiceError::AuthorizationCodeExpired => {
            (StatusCode::UNAUTHORIZED, "authorization_code_expired")
        }
        ServiceError::AuthorizationCodeConsumed => {
            (StatusCode::UNAUTHORIZED, "authorization_code_consumed")
        }
        ServiceError::PkceRequired => (StatusCode::BAD_REQUEST, "pkce_required"),
        ServiceError::InvalidCodeVerifier => (StatusCode::UNAUTHORIZED, "invalid_code_verifier"),
        ServiceError::UnsupportedCodeChallengeMethod => {
            (StatusCode::BAD_REQUEST, "unsupported_code_challenge_method")
        }
        ServiceError::ClientAuthenticationRequired => {
            (StatusCode::UNAUTHORIZED, "client_authentication_required")
        }
        ServiceError::InvalidClientAuthentication => {
            (StatusCode::UNAUTHORIZED, "invalid_client_authentication")
        }
        ServiceError::DeviceNotFound => (StatusCode::NOT_FOUND, "device_not_found"),
        ServiceError::DeviceBindingNotFound => (StatusCode::NOT_FOUND, "device_binding_not_found"),
        ServiceError::DeviceDisabled => (StatusCode::FORBIDDEN, "device_disabled"),
        ServiceError::DeviceClientMismatch => (StatusCode::CONFLICT, "device_client_mismatch"),
        ServiceError::InvalidDeviceChallenge => {
            (StatusCode::BAD_REQUEST, "invalid_device_challenge")
        }
        ServiceError::DeviceRegistrationStateInvalid => {
            (StatusCode::CONFLICT, "device_registration_state_invalid")
        }
        ServiceError::DeviceProofRejected(_) => (StatusCode::UNAUTHORIZED, "device_proof_rejected"),
        ServiceError::Store(_) | ServiceError::Token(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    };

    (
        status,
        Json(ErrorHttpResponse {
            code,
            message: service_error_message(&error),
        }),
    )
        .into_response()
}

fn service_error_message(error: &ServiceError) -> String {
    match error {
        ServiceError::InvalidContract(validation_error) => match validation_error {
            ContractValidationError::MissingEmail => "Email is required.".to_string(),
            ContractValidationError::InvalidEmail => "Email format is invalid.".to_string(),
            ContractValidationError::MissingPassword => "Password is required.".to_string(),
            ContractValidationError::PasswordTooShort { min_length } => {
                format!("Password must be at least {min_length} characters.")
            }
            ContractValidationError::PasswordTooLong { max_length } => {
                format!("Password must be at most {max_length} characters.")
            }
            ContractValidationError::PasswordRequiresLetter => {
                "Password must include at least one letter.".to_string()
            }
            ContractValidationError::PasswordRequiresNumber => {
                "Password must include at least one number.".to_string()
            }
            _ => format!("{validation_error:?}"),
        },
        ServiceError::EmailAlreadyExists => "Email is already registered.".to_string(),
        ServiceError::InvalidCredentials => "Email or password is incorrect.".to_string(),
        _ => format!("{error:?}"),
    }
}

pub(crate) fn unix_time(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(value)
}

pub(crate) fn unix_time_secs(value: SystemTime) -> u64 {
    unix_timestamp(value).unwrap_or_default()
}

fn unix_timestamp(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
}

pub(crate) fn authorization_redirect_location(
    redirect_uri: &str,
    authorization_code: &str,
    state: Option<&str>,
) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    match state {
        Some(state) => format!("{redirect_uri}{separator}code={authorization_code}&state={state}"),
        None => format!("{redirect_uri}{separator}code={authorization_code}"),
    }
}

pub(crate) fn jwks_response(document: JwksDocument) -> JwksHttpResponse {
    JwksHttpResponse {
        keys: document
            .keys
            .into_iter()
            .map(|key| JwkHttpResponse {
                kid: key.key_id,
                kty: key.key_type,
                alg: key.algorithm,
                public_key_use: key.public_key_use,
                crv: key.curve,
                n: key.modulus,
                e: key.exponent,
                x: key.x,
                y: key.y,
            })
            .collect(),
    }
}

pub(crate) fn introspection_response(result: IntrospectTokenResult) -> IntrospectionHttpResponse {
    IntrospectionHttpResponse {
        active: result.active,
        sub: result.subject_account_id,
        client_id: result.client_id,
        scope: result.scope,
        token_type: result.token_type,
        sid: result.session_id,
        exp: result.expires_at.and_then(unix_timestamp),
        iat: result.issued_at.and_then(unix_timestamp),
    }
}

pub(crate) fn missing_authenticated_subject_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorHttpResponse {
            code: "missing_authenticated_subject",
            message: "missing authenticated subject context".to_string(),
        }),
    )
        .into_response()
}

pub(crate) fn missing_bearer_token_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorHttpResponse {
            code: "invalid_token",
            message: "missing bearer access token".to_string(),
        }),
    )
        .into_response()
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|value| !value.trim().is_empty())
}

pub(crate) async fn run_service_call<R>(
    run: impl FnOnce() -> Result<R, ServiceError> + Send + 'static,
) -> Result<R, ServiceError>
where
    R: Send + 'static,
{
    task::spawn_blocking(run)
        .await
        .map_err(|error| ServiceError::Store(StoreError::Backend(error.to_string())))?
}

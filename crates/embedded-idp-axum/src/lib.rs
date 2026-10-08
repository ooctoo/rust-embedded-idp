mod browser_session;
pub use browser_session::{browser_session_router, BrowserSessionHttpConfig};
mod device_scan_login;
pub use device_scan_login::{scan_browser_router, scan_device_router, ScanDeviceHttpConfig};
mod management_auth;
pub use management_auth::management_router;
mod access_diagnostic;
pub use access_diagnostic::access_diagnostic_router;
mod audit_admin;
pub use audit_admin::audit_admin_router;
mod security_admin;
pub use security_admin::security_admin_router;
mod permission_admin;
pub use permission_admin::permission_admin_router;
mod role_binding_admin;
pub use role_binding_admin::role_binding_admin_router;
mod role_admin;
pub use role_admin::role_admin_router;
mod tenant_management_admin;
pub use tenant_management_admin::tenant_management_admin_router;
mod account_security_admin;
pub use account_security_admin::account_security_admin_router;
mod account_admin;
pub use account_admin::account_admin_router;
mod client_admin;
pub use client_admin::client_admin_router;
mod admin_api;
mod admin_dto;
mod admin_paging;
mod dto;
mod http_paths;
mod http_support;
mod proof_http;
mod tenant_admin;
mod tenant_auth;
mod tenant_device_admin;
mod tenant_device_auth;
mod tenant_devices;
mod tenant_oidc_authorization;
mod tenant_oidc_resource;
mod tenant_registration;
mod tenant_self;
mod tenant_session_admin;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::SystemTime;

use axum::body::to_bytes;
use axum::extract::{DefaultBodyLimit, Extension, Form, OriginalUri, Path, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dto::{
    AuthHttpResponse, AuthorizeHttpRequest, BindDeviceHttpRequest,
    CompleteDeviceKeyRegistrationHttpRequest, DeviceBindingHttpResponse, DeviceDetailHttpResponse,
    DeviceHeartbeatHttpRequest, DeviceHttpResponse, DeviceKeyHttpResponse, DeviceListHttpResponse,
    DeviceProofChallengeHttpResponse, DiscoveryHttpResponse, ErrorHttpResponse,
    IntrospectTokenHttpRequest, IssueDeviceProofChallengeHttpRequest,
    LegacyCompleteDeviceRegistrationHttpRequest, LoginHttpRequest, LogoutHttpRequest,
    OidcTokenHttpResponse, PendingVerificationHttpResponse, ProvisionDeviceHttpRequest,
    ProvisionDeviceHttpResponse, RefreshHttpRequest, RegisterAccountHttpRequest,
    ResendVerificationCodeHttpRequest, RevokeTokenHttpRequest, RotateDeviceProofKeyHttpRequest,
    SecureProvisionDeviceHttpResponse, TokenHttpRequest, UnbindDeviceHttpRequest,
    UserInfoHttpResponse, VerifyEmailHttpRequest,
};
use embedded_idp_core::{
    AccountDeviceBinding, AccountDeviceBindingStatus, AdminService, AuthService,
    BindDeviceToAccountCommand, Clock, CompleteDeviceKeyRegistrationCommand,
    CompleteDeviceRegistrationCommand, DeviceHeartbeatCommand, DeviceProof, DeviceProofPurpose,
    DeviceRecord, DeviceSecurityError, DeviceSecurityService, DeviceService, DeviceStatus,
    ExchangeAuthorizationCodeCommand, GetDeviceCommand, GetUserInfoCommand, IntrospectTokenCommand,
    IssueDeviceProofChallengeCommand, ListDevicesCommand, LogoutSessionCommand,
    OidcAuthorizationService, OidcMetadataService, ProofBoundRefreshError,
    ProofBoundRefreshService, ProvisionPendingDeviceCommand, RegisterAccountCommand,
    ResendVerificationCodeCommand, RevokeTokenCommand, RotateDeviceProofKeyCommand,
    RotateProofBoundRefreshCommand, RotateProofBoundRefreshOutcome, RotateRefreshTokenCommand,
    SecretString, StartAuthorizationCommand, TokenIntrospectionService, TokenManagementService,
    UnbindDeviceFromAccountCommand, UserInfoService, VerifyEmailCommand, OIDC_AUTHORIZE_PATH,
    OIDC_INTROSPECT_PATH, OIDC_JWKS_PATH, OIDC_REVOKE_PATH, OIDC_TOKEN_PATH, OIDC_USERINFO_PATH,
};
use embedded_idp_email::{VerificationEmailRequest, VerificationEmailService};
pub use http_paths::{RouteMountPlan, ADMIN_API_PREFIX, AUTH_API_PREFIX, DEVICE_API_PREFIX};
use http_paths::{
    AUTH_LOGIN_PATH, AUTH_LOGOUT_PATH, AUTH_REFRESH_PATH, AUTH_REGISTER_PATH,
    AUTH_RESEND_VERIFICATION_PATH, AUTH_VERIFY_EMAIL_PATH, DEVICE_BIND_PATH, DEVICE_COMPLETE_PATH,
    DEVICE_DETAIL_PATH_TEMPLATE, DEVICE_HEARTBEAT_PATH, DEVICE_PROOF_CHALLENGE_PATH,
    DEVICE_PROVISION_PATH, DEVICE_ROTATE_KEY_PATH, DEVICE_UNBIND_PATH,
};
use http_support::{
    authorization_redirect_location, bearer_token, introspection_response, jwks_response,
    map_service_error, missing_authenticated_subject_response, missing_bearer_token_response,
    run_service_call, unix_time, unix_time_secs,
};
pub use proof_http::{
    parse_device_proof_headers, ProofHttpError, ProtectedRouteConfig, AUTH_DEVICE_BODY_LIMIT_BYTES,
    DEVICE_CHALLENGE_HEADER, DEVICE_ID_HEADER, DEVICE_KEY_ID_HEADER, DEVICE_SIGNATURE_HEADER,
    DEVICE_SIGNED_AT_HEADER,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
pub use tenant_auth::tenant_auth_router;
pub use tenant_device_admin::tenant_device_admin_router;
pub use tenant_device_auth::{tenant_device_auth_router, TenantDeviceAuthHttpConfig};
pub use tenant_devices::{tenant_device_router, TenantDeviceHttpConfig};
pub use tenant_oidc_authorization::{tenant_oidc_authorization_router, TenantOidcHttpConfig};
pub use tenant_oidc_resource::tenant_oidc_resource_router;
pub use tenant_registration::tenant_registration_router;
pub use tenant_self::tenant_self_router;
pub use tenant_session_admin::tenant_session_admin_router;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSubject {
    pub tenant_id: String,
    pub account_id: String,
}

impl AuthenticatedSubject {
    pub fn new(tenant_id: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            account_id: account_id.into(),
        }
    }
}

#[derive(Clone)]
pub struct EmbeddedIdpHttpState {
    pub issuer: String,
    pub route_mount_plan: RouteMountPlan,
    pub admin_service: Arc<dyn AdminService>,
    pub auth_service: Arc<dyn AuthService>,
    pub verification_email_service: Arc<dyn VerificationEmailService>,
    pub device_service: Arc<dyn DeviceService>,
    pub oidc_authorization_service: Arc<dyn OidcAuthorizationService>,
    pub oidc_metadata_service: Arc<dyn OidcMetadataService>,
    pub token_management_service: Arc<dyn TokenManagementService>,
    pub user_info_service: Arc<dyn UserInfoService>,
    pub token_introspection_service: Arc<dyn TokenIntrospectionService>,
    pub refresh_security: RefreshHttpSecurity,
    pub device_security: DeviceHttpSecurity,
    pub clock: Arc<dyn Clock + Send + Sync>,
}

#[derive(Clone)]
pub enum RefreshHttpSecurity {
    /// Explicit opt-in for the reference development application only.
    LegacyDevelopmentOnly,
    ProofBound(ProofBoundRefreshHttpConfig),
}

#[derive(Clone)]
pub enum DeviceHttpSecurity {
    LegacyDevelopmentOnly,
    ProofBound(Arc<dyn DeviceSecurityService>),
}

#[derive(Clone)]
pub struct ProofBoundRefreshHttpConfig {
    service: Arc<dyn ProofBoundRefreshService>,
    route: ProtectedRouteConfig,
}

impl ProofBoundRefreshHttpConfig {
    pub fn new(service: Arc<dyn ProofBoundRefreshService>, route: ProtectedRouteConfig) -> Self {
        Self { service, route }
    }
}

pub fn public_router(state: EmbeddedIdpHttpState) -> Router {
    public_routes().with_state(state)
}

pub fn subject_router(state: EmbeddedIdpHttpState) -> Router {
    subject_routes().with_state(state)
}

pub fn token_router(state: EmbeddedIdpHttpState) -> Router {
    token_routes().with_state(state)
}

pub fn client_authenticated_router(state: EmbeddedIdpHttpState) -> Router {
    client_authenticated_routes().with_state(state)
}

pub fn admin_router(state: EmbeddedIdpHttpState) -> Router {
    admin_api::routes().with_state(state)
}

pub fn router(state: EmbeddedIdpHttpState) -> Router {
    Router::new()
        .merge(public_routes())
        .merge(subject_routes())
        .merge(token_routes())
        .merge(client_authenticated_routes())
        .merge(admin_api::routes())
        .with_state(state)
}

fn public_routes() -> Router<EmbeddedIdpHttpState> {
    Router::new()
        .route(AUTH_REGISTER_PATH, post(register_account))
        .route(AUTH_VERIFY_EMAIL_PATH, post(verify_email))
        .route(
            AUTH_RESEND_VERIFICATION_PATH,
            post(resend_verification_code),
        )
        .route(AUTH_LOGIN_PATH, post(login))
        .route(DEVICE_PROVISION_PATH, post(provision_device))
        .route(
            DEVICE_PROOF_CHALLENGE_PATH,
            post(issue_device_proof_challenge),
        )
        .route(DEVICE_COMPLETE_PATH, post(complete_device_registration))
        .route(DEVICE_HEARTBEAT_PATH, post(device_heartbeat))
        .route(OIDC_TOKEN_PATH, post(exchange_token))
        .route(OIDC_JWKS_PATH, get(jwks))
        .route(embedded_idp_core::OIDC_DISCOVERY_PATH, get(discovery))
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
}

fn subject_routes() -> Router<EmbeddedIdpHttpState> {
    Router::new()
        .route(DEVICE_API_PREFIX, get(list_devices))
        .route(DEVICE_DETAIL_PATH_TEMPLATE, get(get_device))
        .route(DEVICE_BIND_PATH, post(bind_device_to_account))
        .route(DEVICE_UNBIND_PATH, post(unbind_device_from_account))
        .route(DEVICE_ROTATE_KEY_PATH, post(rotate_device_proof_key))
        .route(OIDC_AUTHORIZE_PATH, get(authorize))
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
}

fn token_routes() -> Router<EmbeddedIdpHttpState> {
    Router::new()
        .route(AUTH_REFRESH_PATH, post(rotate_refresh_token))
        .route(AUTH_LOGOUT_PATH, post(logout))
        .route(OIDC_USERINFO_PATH, get(user_info).post(user_info))
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
}

fn client_authenticated_routes() -> Router<EmbeddedIdpHttpState> {
    Router::new()
        .route(OIDC_REVOKE_PATH, post(revoke_token))
        .route(OIDC_INTROSPECT_PATH, post(introspect_token))
}

async fn register_account(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<RegisterAccountHttpRequest>,
) -> Response {
    let auth_service = state.auth_service.clone();
    match run_service_call(move || {
        auth_service.register_account(RegisterAccountCommand {
            email: request.email,
            password: request.password,
            display_name: request.display_name,
            client_id: request.client_id,
            device_id: request.device_id,
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::ACCEPTED,
            Json(PendingVerificationHttpResponse {
                account_id: result.account.id,
                account_status: "pending_verification",
                verification_channel: "email",
                verification_expires_at_unix_secs: unix_time_secs(result.verification.expires_at),
                delivery_status: delivery_status(
                    send_verification_email(
                        state.verification_email_service.clone(),
                        &result.verification,
                    )
                    .await,
                ),
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn verify_email(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<VerifyEmailHttpRequest>,
) -> Response {
    let auth_service = state.auth_service.clone();
    match run_service_call(move || {
        auth_service.verify_email(VerifyEmailCommand {
            email: request.email,
            verification_code: request.verification_code,
            client_id: request.client_id,
            device_id: request.device_id,
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(AuthHttpResponse {
                account_id: result.account.id,
                session_id: result.session.id,
                device_id: result.session.device_id,
                access_token: result.tokens.access_token.into_exposed(),
                refresh_token: result.tokens.refresh_token.into_exposed(),
                refresh_token_version: result.tokens.refresh_token_version,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn resend_verification_code(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<ResendVerificationCodeHttpRequest>,
) -> Response {
    let auth_service = state.auth_service.clone();
    match run_service_call(move || {
        auth_service.resend_verification_code(ResendVerificationCodeCommand {
            email: request.email,
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::ACCEPTED,
            Json(PendingVerificationHttpResponse {
                account_id: result.account.id,
                account_status: "pending_verification",
                verification_channel: "email",
                verification_expires_at_unix_secs: unix_time_secs(result.verification.expires_at),
                delivery_status: delivery_status(
                    send_verification_email(
                        state.verification_email_service.clone(),
                        &result.verification,
                    )
                    .await,
                ),
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn login(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<LoginHttpRequest>,
) -> Response {
    let auth_service = state.auth_service.clone();
    match run_service_call(move || {
        auth_service.login(embedded_idp_core::LoginCommand {
            email: request.email,
            password: request.password,
            client_id: request.client_id,
            device_id: request.device_id,
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(AuthHttpResponse {
                account_id: result.account.id,
                session_id: result.session.id,
                device_id: result.session.device_id,
                access_token: result.tokens.access_token.into_exposed(),
                refresh_token: result.tokens.refresh_token.into_exposed(),
                refresh_token_version: result.tokens.refresh_token_version,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn rotate_refresh_token(
    State(state): State<EmbeddedIdpHttpState>,
    OriginalUri(original_uri): OriginalUri,
    request: Request,
) -> Response {
    if !is_json_content_type(request.headers()) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "request content type must be application/json",
        );
    }

    let method = request.method().clone();
    let proof_bound = match &state.refresh_security {
        RefreshHttpSecurity::LegacyDevelopmentOnly => None,
        RefreshHttpSecurity::ProofBound(config) => {
            let proof = match parse_device_proof_headers(request.headers()) {
                Ok(proof) => proof,
                Err(error) => return map_proof_http_error(error),
            };
            Some((config.clone(), proof))
        }
    };
    let body = match to_bytes(request.into_body(), AUTH_DEVICE_BODY_LIMIT_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                "request body exceeds the configured limit",
            )
        }
    };
    let request: RefreshHttpRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            let status = match error.classify() {
                serde_json::error::Category::Data => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::BAD_REQUEST,
            };
            return error_response(
                status,
                "invalid_json",
                "request body is not valid for this endpoint",
            );
        }
    };

    let Some((config, proof)) = proof_bound else {
        return rotate_legacy_refresh(state.auth_service, request).await;
    };
    let binding = match config.route.binding_for_request(
        "0",
        &method,
        &original_uri,
        Sha256::digest(&body).into(),
    ) {
        Ok(binding) => binding,
        Err(error) => return map_proof_http_error(error),
    };
    let command = RotateProofBoundRefreshCommand {
        refresh_token: SecretString::new(request.refresh_token),
        proof,
        binding,
    };
    let service = config.service;
    match tokio::task::spawn_blocking(move || service.rotate_proof_bound_refresh(command)).await {
        Ok(Ok(RotateProofBoundRefreshOutcome::Rotated { session, tokens })) => (
            StatusCode::OK,
            Json(AuthHttpResponse {
                account_id: session.account_id,
                session_id: session.id,
                device_id: session.device_id,
                access_token: tokens.access_token.token.into_exposed(),
                refresh_token: tokens.refresh_token.into_exposed(),
                refresh_token_version: tokens.refresh_token_version,
            }),
        )
            .into_response(),
        Ok(Ok(RotateProofBoundRefreshOutcome::ReuseDetected { .. })) => error_response(
            StatusCode::UNAUTHORIZED,
            "refresh_token_reuse_detected",
            "refresh token reuse was detected",
        ),
        Ok(Err(error)) => map_proof_bound_refresh_error(error),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ),
    }
}

async fn rotate_legacy_refresh(
    auth_service: Arc<dyn AuthService>,
    request: RefreshHttpRequest,
) -> Response {
    match run_service_call(move || {
        auth_service.rotate_refresh_token(RotateRefreshTokenCommand {
            refresh_token: request.refresh_token,
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(AuthHttpResponse {
                account_id: result.session.account_id,
                session_id: result.session.id,
                device_id: result.session.device_id,
                access_token: result.tokens.access_token.into_exposed(),
                refresh_token: result.tokens.refresh_token.into_exposed(),
                refresh_token_version: result.tokens.refresh_token_version,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    let essence = content_type.split(';').next().unwrap_or_default().trim();
    essence.eq_ignore_ascii_case("application/json")
        || essence
            .rsplit_once('/')
            .is_some_and(|(_, subtype)| subtype.ends_with("+json"))
}

fn map_proof_http_error(error: ProofHttpError) -> Response {
    match error {
        ProofHttpError::ProofRequired => error_response(
            StatusCode::UNAUTHORIZED,
            "device_proof_required",
            "device proof is required",
        ),
        ProofHttpError::ProofInvalid
        | ProofHttpError::MethodMismatch
        | ProofHttpError::PathMismatch
        | ProofHttpError::QueryUnsupported => error_response(
            StatusCode::UNAUTHORIZED,
            "device_proof_invalid",
            "device proof is invalid",
        ),
    }
}

fn map_proof_bound_refresh_error(error: ProofBoundRefreshError) -> Response {
    let (status, code, message) = match error {
        ProofBoundRefreshError::InvalidToken
        | ProofBoundRefreshError::SessionInactive
        | ProofBoundRefreshError::AccountInactive => (
            StatusCode::UNAUTHORIZED,
            "refresh_token_invalid",
            "refresh token is invalid",
        ),
        ProofBoundRefreshError::InvalidProof => (
            StatusCode::UNAUTHORIZED,
            "device_proof_invalid",
            "device proof is invalid",
        ),
        ProofBoundRefreshError::ExpiredProof => (
            StatusCode::UNAUTHORIZED,
            "device_proof_expired",
            "device proof has expired",
        ),
        ProofBoundRefreshError::ReplayedProof => (
            StatusCode::UNAUTHORIZED,
            "device_proof_replayed",
            "device proof has already been used",
        ),
        ProofBoundRefreshError::DeviceKeyMismatch => (
            StatusCode::UNAUTHORIZED,
            "device_key_mismatch",
            "device key does not match the active key",
        ),
        ProofBoundRefreshError::DeviceMismatch => (
            StatusCode::UNAUTHORIZED,
            "refresh_device_mismatch",
            "device does not match the refresh session",
        ),
        ProofBoundRefreshError::DeviceInactive => (
            StatusCode::FORBIDDEN,
            "device_inactive",
            "device is inactive",
        ),
        ProofBoundRefreshError::BindingInactive => (
            StatusCode::FORBIDDEN,
            "device_binding_inactive",
            "device binding is inactive",
        ),
        ProofBoundRefreshError::Store(_) | ProofBoundRefreshError::Token(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ),
    };
    error_response(status, code, message)
}

fn map_device_security_error(error: DeviceSecurityError) -> Response {
    let (status, code, message) = match error {
        DeviceSecurityError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            "invalid_contract",
            "request contract is invalid",
        ),
        DeviceSecurityError::ClientNotFound => (
            StatusCode::NOT_FOUND,
            "client_not_found",
            "client was not found",
        ),
        DeviceSecurityError::InvalidPurpose => (
            StatusCode::BAD_REQUEST,
            "invalid_device_proof_purpose",
            "device proof purpose is invalid",
        ),
        DeviceSecurityError::InvalidChallenge
        | DeviceSecurityError::InvalidPublicKey
        | DeviceSecurityError::InvalidProof => (
            StatusCode::UNAUTHORIZED,
            "device_proof_invalid",
            "device proof is invalid",
        ),
        DeviceSecurityError::ExpiredChallenge => (
            StatusCode::UNAUTHORIZED,
            "device_proof_expired",
            "device proof has expired",
        ),
        DeviceSecurityError::ReplayedChallenge => (
            StatusCode::UNAUTHORIZED,
            "device_proof_replayed",
            "device proof has already been used",
        ),
        DeviceSecurityError::DeviceInactive => (
            StatusCode::FORBIDDEN,
            "device_inactive",
            "device is inactive",
        ),
        DeviceSecurityError::BindingInactive => (
            StatusCode::FORBIDDEN,
            "device_binding_inactive",
            "device binding is inactive",
        ),
        DeviceSecurityError::KeyMismatch => (
            StatusCode::UNAUTHORIZED,
            "device_key_mismatch",
            "device key does not match the active key",
        ),
        DeviceSecurityError::KeyVersionOverflow
        | DeviceSecurityError::Store(_)
        | DeviceSecurityError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ),
    };
    error_response(status, code, message)
}

fn deserialize_json_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|error| {
        let status = match error.classify() {
            serde_json::error::Category::Data => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::BAD_REQUEST,
        };
        error_response(
            status,
            "invalid_json",
            "request body is not valid for this endpoint",
        )
    })
}

fn internal_error_response() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "the request could not be completed",
    )
}

fn error_response(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(ErrorHttpResponse {
            code,
            message: message.to_string(),
        }),
    )
        .into_response()
}

async fn logout(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<LogoutHttpRequest>,
) -> Response {
    let auth_service = state.auth_service.clone();
    match run_service_call(move || {
        auth_service.logout(LogoutSessionCommand {
            refresh_token: request.refresh_token,
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(AuthHttpResponse {
                account_id: result.session.account_id,
                session_id: result.session.id,
                device_id: result.session.device_id,
                access_token: String::new(),
                refresh_token: String::new(),
                refresh_token_version: result.session.refresh_token_version,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn provision_device(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<ProvisionDeviceHttpRequest>,
) -> Response {
    match state.device_security {
        DeviceHttpSecurity::LegacyDevelopmentOnly => {
            let device_service = state.device_service;
            let requested_at = state.clock.now();
            match run_service_call(move || {
                device_service.provision_device(embedded_idp_core::ProvisionDeviceCommand {
                    client_id: request.client_id,
                    device_name: request.device_name,
                    requested_at,
                })
            })
            .await
            {
                Ok(result) => (
                    StatusCode::CREATED,
                    Json(ProvisionDeviceHttpResponse {
                        device: device_response(result.device),
                        challenge: result.nonce.challenge,
                        expires_at_unix_secs: unix_time_secs(result.nonce.expires_at),
                    }),
                )
                    .into_response(),
                Err(error) => map_service_error(error),
            }
        }
        DeviceHttpSecurity::ProofBound(service) => {
            let command = ProvisionPendingDeviceCommand {
                client_id: request.client_id,
                device_name: request.device_name,
            };
            match tokio::task::spawn_blocking(move || service.provision_pending_device(command))
                .await
            {
                Ok(Ok(result)) => (
                    StatusCode::CREATED,
                    Json(SecureProvisionDeviceHttpResponse {
                        device: device_response(result.device),
                    }),
                )
                    .into_response(),
                Ok(Err(error)) => map_device_security_error(error),
                Err(_) => internal_error_response(),
            }
        }
    }
}

async fn complete_device_registration(
    State(state): State<EmbeddedIdpHttpState>,
    request: Request,
) -> Response {
    if !is_json_content_type(request.headers()) {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "request content type must be application/json",
        );
    }
    let body = match to_bytes(request.into_body(), AUTH_DEVICE_BODY_LIMIT_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                "request body exceeds the configured limit",
            )
        }
    };

    match state.device_security {
        DeviceHttpSecurity::LegacyDevelopmentOnly => {
            let request: LegacyCompleteDeviceRegistrationHttpRequest =
                match deserialize_json_body(&body) {
                    Ok(request) => request,
                    Err(response) => return response,
                };
            complete_legacy_device_registration(state.device_service, request).await
        }
        DeviceHttpSecurity::ProofBound(service) => {
            let request: CompleteDeviceKeyRegistrationHttpRequest =
                match deserialize_json_body(&body) {
                    Ok(request) => request,
                    Err(response) => return response,
                };
            let command = CompleteDeviceKeyRegistrationCommand {
                device_id: request.device_id,
                public_jwk: request.public_jwk.get().to_string(),
                challenge: SecretString::new(request.challenge),
                signature: SecretString::new(request.signature),
            };
            match tokio::task::spawn_blocking(move || {
                service.complete_device_key_registration(command)
            })
            .await
            {
                Ok(Ok(result)) => (
                    StatusCode::OK,
                    Json(DeviceKeyHttpResponse {
                        device_id: result.device.id,
                        key_id: result.key.key_id,
                        key_version: result.key.version,
                        key_status: "active",
                    }),
                )
                    .into_response(),
                Ok(Err(error)) => map_device_security_error(error),
                Err(_) => internal_error_response(),
            }
        }
    }
}

async fn complete_legacy_device_registration(
    device_service: Arc<dyn DeviceService>,
    request: LegacyCompleteDeviceRegistrationHttpRequest,
) -> Response {
    match run_service_call(move || {
        device_service.complete_device_registration(CompleteDeviceRegistrationCommand {
            device_id: request.device_id,
            proof: DeviceProof {
                key_id: request.proof_key_id,
                challenge: request.proof_challenge,
                signature: request.proof_signature,
                signed_at: unix_time(request.proof_signed_at_unix_secs),
            },
            completed_at: unix_time(request.completed_at_unix_secs),
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(device_response(result.device))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn issue_device_proof_challenge(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<IssueDeviceProofChallengeHttpRequest>,
) -> Response {
    let DeviceHttpSecurity::ProofBound(service) = state.device_security else {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "device_security_unavailable",
            "device proof security is not configured",
        );
    };
    let purpose = match DeviceProofPurpose::new(request.purpose) {
        Ok(purpose) => purpose,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_device_proof_purpose",
                "device proof purpose is invalid",
            )
        }
    };
    let command = IssueDeviceProofChallengeCommand {
        device_id: request.device_id,
        purpose,
    };
    match tokio::task::spawn_blocking(move || service.issue_device_proof_challenge(command)).await {
        Ok(Ok(result)) => (
            StatusCode::OK,
            Json(DeviceProofChallengeHttpResponse {
                challenge: result.challenge.into_exposed(),
                expires_at_unix_secs: unix_time_secs(result.expires_at),
            }),
        )
            .into_response(),
        Ok(Err(error)) => map_device_security_error(error),
        Err(_) => internal_error_response(),
    }
}

async fn rotate_device_proof_key(
    State(state): State<EmbeddedIdpHttpState>,
    subject: Option<Extension<AuthenticatedSubject>>,
    Json(request): Json<RotateDeviceProofKeyHttpRequest>,
) -> Response {
    let account_id = match subject_account_id(subject) {
        Ok(account_id) => account_id,
        Err(response) => return response,
    };
    let DeviceHttpSecurity::ProofBound(service) = state.device_security else {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "device_security_unavailable",
            "device proof security is not configured",
        );
    };
    let command = RotateDeviceProofKeyCommand {
        account_id,
        device_id: request.device_id,
        proposed_public_jwk: request.new_public_jwk.get().to_string(),
        challenge: SecretString::new(request.challenge),
        current_key_signature: SecretString::new(request.current_key_signature),
        proposed_key_signature: SecretString::new(request.new_key_signature),
    };
    match tokio::task::spawn_blocking(move || service.rotate_device_proof_key(command)).await {
        Ok(Ok(result)) => (
            StatusCode::OK,
            Json(DeviceKeyHttpResponse {
                device_id: result.device.id,
                key_id: result.active_key.key_id,
                key_version: result.active_key.version,
                key_status: "active",
            }),
        )
            .into_response(),
        Ok(Err(error)) => map_device_security_error(error),
        Err(_) => internal_error_response(),
    }
}

async fn bind_device_to_account(
    State(state): State<EmbeddedIdpHttpState>,
    subject: Option<Extension<AuthenticatedSubject>>,
    Json(request): Json<BindDeviceHttpRequest>,
) -> Response {
    let account_id = match subject_account_id(subject) {
        Ok(account_id) => account_id,
        Err(response) => return response,
    };

    let device_service = state.device_service.clone();
    let bound_at = state.clock.now();
    match run_service_call(move || {
        device_service.bind_device_to_account(BindDeviceToAccountCommand {
            account_id,
            device_id: request.device_id,
            bound_at,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(binding_response(result.binding))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn list_devices(
    State(state): State<EmbeddedIdpHttpState>,
    subject: Option<Extension<AuthenticatedSubject>>,
) -> Response {
    let account_id = match subject_account_id(subject) {
        Ok(account_id) => account_id,
        Err(response) => return response,
    };

    let device_service = state.device_service.clone();
    match run_service_call(move || {
        device_service.list_devices(ListDevicesCommand {
            account_id: Some(account_id),
            ..Default::default()
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(DeviceListHttpResponse {
                devices: result.devices.into_iter().map(device_response).collect(),
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn get_device(
    State(state): State<EmbeddedIdpHttpState>,
    subject: Option<Extension<AuthenticatedSubject>>,
    Path(device_id): Path<String>,
) -> Response {
    let account_id = match subject_account_id(subject) {
        Ok(account_id) => account_id,
        Err(response) => return response,
    };

    let device_service = state.device_service.clone();
    match run_service_call(move || device_service.get_device(GetDeviceCommand { device_id })).await
    {
        Ok(result) => match subject_scoped_bindings(result.bindings, &account_id) {
            Some(bindings) => (
                StatusCode::OK,
                Json(DeviceDetailHttpResponse {
                    device: device_response(result.device),
                    bindings: bindings.into_iter().map(binding_response).collect(),
                }),
            )
                .into_response(),
            None => map_service_error(embedded_idp_core::ServiceError::DeviceNotFound),
        },
        Err(error) => map_service_error(error),
    }
}

async fn unbind_device_from_account(
    State(state): State<EmbeddedIdpHttpState>,
    subject: Option<Extension<AuthenticatedSubject>>,
    Json(request): Json<UnbindDeviceHttpRequest>,
) -> Response {
    let account_id = match subject_account_id(subject) {
        Ok(account_id) => account_id,
        Err(response) => return response,
    };

    let device_service = state.device_service.clone();
    let unbound_at = state.clock.now();
    match run_service_call(move || {
        device_service.unbind_device_from_account(UnbindDeviceFromAccountCommand {
            account_id,
            device_id: request.device_id,
            unbound_at,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(binding_response(result.binding))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn device_heartbeat(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<DeviceHeartbeatHttpRequest>,
) -> Response {
    let device_service = state.device_service.clone();
    let observed_at = state.clock.now();
    match run_service_call(move || {
        device_service.heartbeat(DeviceHeartbeatCommand {
            device_id: request.device_id,
            observed_at,
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(device_response(result.device))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn authorize(
    State(state): State<EmbeddedIdpHttpState>,
    subject: Option<Extension<AuthenticatedSubject>>,
    Query(request): Query<AuthorizeHttpRequest>,
) -> Response {
    let account_id = match subject_account_id(subject) {
        Ok(account_id) => account_id,
        Err(response) => return response,
    };

    let oidc_authorization_service = state.oidc_authorization_service.clone();
    match run_service_call(move || {
        oidc_authorization_service.start_authorization(StartAuthorizationCommand {
            subject_account_id: account_id,
            response_type: request.response_type,
            client_id: request.client_id,
            redirect_uri: request.redirect_uri,
            scope: request.scope,
            state: request.state,
            code_challenge: request.code_challenge,
            code_challenge_method: request.code_challenge_method,
            nonce: request.nonce,
        })
    })
    .await
    {
        Ok(result) => Redirect::temporary(&authorization_redirect_location(
            &result.redirect_uri,
            &result.authorization_code,
            result.state.as_deref(),
        ))
        .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn exchange_token(
    State(state): State<EmbeddedIdpHttpState>,
    Form(request): Form<TokenHttpRequest>,
) -> Response {
    let oidc_authorization_service = state.oidc_authorization_service.clone();
    match run_service_call(move || {
        oidc_authorization_service.exchange_authorization_code(ExchangeAuthorizationCodeCommand {
            grant_type: request.grant_type,
            code: request.code,
            redirect_uri: request.redirect_uri,
            client_id: request.client_id,
            client_secret: request.client_secret,
            code_verifier: request.code_verifier,
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(OidcTokenHttpResponse {
                access_token: result.tokens.access_token.into_exposed(),
                refresh_token: result.tokens.refresh_token.into_exposed(),
                refresh_token_version: result.tokens.refresh_token_version,
                token_type: result.token_type,
                id_token: result.id_token.map(SecretString::into_exposed),
                scope: result.scope,
                subject_account_id: result.subject_account_id,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn jwks(State(state): State<EmbeddedIdpHttpState>) -> Response {
    let etag = state.oidc_metadata_service.jwks_etag();
    match state.oidc_metadata_service.jwks_document() {
        Ok(document) => {
            let mut response = (StatusCode::OK, Json(jwks_response(document))).into_response();
            if let Some(value) = etag.and_then(|value| value.parse().ok()) {
                response.headers_mut().insert(header::ETAG, value);
            }
            response
        }
        Err(error) => map_service_error(error),
    }
}

async fn revoke_token(
    State(state): State<EmbeddedIdpHttpState>,
    Form(request): Form<RevokeTokenHttpRequest>,
) -> Response {
    let token_management_service = state.token_management_service.clone();
    let revoked_at = state.clock.now();
    match run_service_call(move || {
        token_management_service.revoke_token(RevokeTokenCommand {
            token: request.token,
            token_type_hint: request.token_type_hint,
            client_id: request.client_id,
            client_secret: request.client_secret,
            revoked_at,
        })
    })
    .await
    {
        Ok(_result) => StatusCode::OK.into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn user_info(State(state): State<EmbeddedIdpHttpState>, headers: HeaderMap) -> Response {
    let Some(access_token) = bearer_token(&headers) else {
        return missing_bearer_token_response();
    };

    let user_info_service = state.user_info_service.clone();
    let access_token = access_token.to_string();
    match run_service_call(move || {
        user_info_service.get_user_info(GetUserInfoCommand {
            access_token,
            observed_at: SystemTime::now(),
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(UserInfoHttpResponse {
                sub: result.subject_account_id,
                email: result.email,
                name: result.display_name,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn introspect_token(
    State(state): State<EmbeddedIdpHttpState>,
    Form(request): Form<IntrospectTokenHttpRequest>,
) -> Response {
    let token_introspection_service = state.token_introspection_service.clone();
    match run_service_call(move || {
        token_introspection_service.introspect_token(IntrospectTokenCommand {
            token: request.token,
            token_type_hint: request.token_type_hint,
            client_id: request.client_id,
            client_secret: request.client_secret,
            observed_at: SystemTime::now(),
        })
    })
    .await
    {
        Ok(result) => (StatusCode::OK, Json(introspection_response(result))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn discovery(State(state): State<EmbeddedIdpHttpState>) -> Json<DiscoveryHttpResponse> {
    let route_mount_plan = &state.route_mount_plan;
    Json(DiscoveryHttpResponse {
        issuer: state.issuer,
        authorization_endpoint: route_mount_plan.external_oidc_authorize_path(),
        jwks_uri: route_mount_plan.external_oidc_jwks_path(),
        revocation_endpoint: route_mount_plan.external_oidc_revoke_path(),
        userinfo_endpoint: route_mount_plan.external_oidc_userinfo_path(),
        introspection_endpoint: route_mount_plan.external_oidc_introspect_path(),
        registration_endpoint: route_mount_plan.external_auth_register_path(),
        email_verification_endpoint: route_mount_plan.external_auth_verify_email_path(),
        resend_verification_endpoint: route_mount_plan.external_auth_resend_verification_path(),
        login_endpoint: route_mount_plan.external_auth_login_path(),
        token_endpoint: route_mount_plan.external_oidc_token_path(),
        device_provision_endpoint: route_mount_plan.external_device_provision_path(),
        device_completion_endpoint: route_mount_plan.external_device_complete_path(),
        device_binding_endpoint: route_mount_plan.external_device_bind_path(),
        devices_endpoint: route_mount_plan.external_devices_path(),
        device_detail_path_template: route_mount_plan.external_device_detail_path_template(),
        device_unbind_endpoint: route_mount_plan.external_device_unbind_path(),
        device_heartbeat_endpoint: route_mount_plan.external_device_heartbeat_path(),
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["plain", "S256"],
    })
}

async fn send_verification_email(
    verification_email_service: Arc<dyn VerificationEmailService>,
    verification: &embedded_idp_core::PendingEmailVerification,
) -> Result<(), String> {
    let request = VerificationEmailRequest {
        email: verification.email.clone(),
        code: verification.code.clone(),
        expires_at: verification.expires_at,
    };
    tokio::task::spawn_blocking(move || verification_email_service.send_verification_email(request))
        .await
        .map_err(|error| format!("verification delivery task failed: {error}"))?
        .map_err(|error| error.message)
}

fn delivery_status(result: Result<(), String>) -> &'static str {
    match result {
        Ok(()) => "sent",
        Err(_) => "failed",
    }
}

fn device_response(device: DeviceRecord) -> DeviceHttpResponse {
    DeviceHttpResponse {
        device_id: device.id,
        client_id: device.client_id,
        proof_key_id: device.proof_key_id,
        status: device_status(&device.status),
    }
}

fn binding_response(binding: AccountDeviceBinding) -> DeviceBindingHttpResponse {
    DeviceBindingHttpResponse {
        binding_id: binding.id,
        account_id: binding.account_id,
        device_id: binding.device_id,
        status: binding_status(&binding.status),
    }
}

fn subject_account_id(
    subject: Option<Extension<AuthenticatedSubject>>,
) -> Result<String, Response> {
    let Some(Extension(subject)) = subject else {
        return Err(missing_authenticated_subject_response());
    };
    if subject.tenant_id != "0" {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unsupported_tenant",
            "these single-domain handlers only support tenant 0",
        ));
    }
    Ok(subject.account_id)
}

fn subject_scoped_bindings(
    bindings: Vec<AccountDeviceBinding>,
    account_id: &str,
) -> Option<Vec<AccountDeviceBinding>> {
    let bindings: Vec<_> = bindings
        .into_iter()
        .filter(|binding| {
            binding.account_id == account_id && binding.status == AccountDeviceBindingStatus::Active
        })
        .collect();

    if bindings.is_empty() {
        None
    } else {
        Some(bindings)
    }
}

fn device_status(status: &DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Disabled => "disabled",
        DeviceStatus::Revoked => "revoked",
    }
}

fn binding_status(status: &embedded_idp_core::AccountDeviceBindingStatus) -> &'static str {
    match status {
        embedded_idp_core::AccountDeviceBindingStatus::Active => "active",
        embedded_idp_core::AccountDeviceBindingStatus::Unbound => "unbound",
        embedded_idp_core::AccountDeviceBindingStatus::Suspended => "suspended",
    }
}

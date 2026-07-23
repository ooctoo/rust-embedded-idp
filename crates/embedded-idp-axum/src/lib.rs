mod admin_api;
mod admin_dto;
mod admin_paging;
mod dto;
mod http_paths;
mod http_support;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dto::{
    AuthHttpResponse, AuthorizeHttpRequest, BindDeviceHttpRequest,
    CompleteDeviceRegistrationHttpRequest, DeviceBindingHttpResponse, DeviceDetailHttpResponse,
    DeviceHeartbeatHttpRequest, DeviceHttpResponse, DeviceListHttpResponse, DiscoveryHttpResponse,
    IntrospectTokenHttpRequest, LoginHttpRequest, LogoutHttpRequest, OidcTokenHttpResponse,
    PendingVerificationHttpResponse, ProvisionDeviceHttpRequest, ProvisionDeviceHttpResponse,
    RefreshHttpRequest, RegisterAccountHttpRequest, ResendVerificationCodeHttpRequest,
    RevokeTokenHttpRequest, TokenHttpRequest, UnbindDeviceHttpRequest, UserInfoHttpResponse,
    VerifyEmailHttpRequest,
};
use embedded_idp_core::{
    AccountDeviceBinding, AccountDeviceBindingStatus, AdminService, AuthService,
    BindDeviceToAccountCommand, CompleteDeviceRegistrationCommand, DeviceHeartbeatCommand,
    DeviceProof, DeviceRecord, DeviceService, DeviceStatus, ExchangeAuthorizationCodeCommand,
    GetDeviceCommand, GetUserInfoCommand, IntrospectTokenCommand, ListDevicesCommand,
    LogoutSessionCommand, OidcAuthorizationService, OidcMetadataService, RegisterAccountCommand,
    ResendVerificationCodeCommand, RevokeTokenCommand, RotateRefreshTokenCommand,
    StartAuthorizationCommand, TokenIntrospectionService, TokenManagementService,
    UnbindDeviceFromAccountCommand, UserInfoService, VerifyEmailCommand, OIDC_AUTHORIZE_PATH,
    OIDC_INTROSPECT_PATH, OIDC_JWKS_PATH, OIDC_REVOKE_PATH, OIDC_TOKEN_PATH, OIDC_USERINFO_PATH,
};
use embedded_idp_email::{VerificationEmailRequest, VerificationEmailService};
pub use http_paths::{RouteMountPlan, ADMIN_API_PREFIX, AUTH_API_PREFIX, DEVICE_API_PREFIX};
use http_paths::{
    AUTH_LOGIN_PATH, AUTH_LOGOUT_PATH, AUTH_REFRESH_PATH, AUTH_REGISTER_PATH,
    AUTH_RESEND_VERIFICATION_PATH, AUTH_VERIFY_EMAIL_PATH, DEVICE_BIND_PATH, DEVICE_COMPLETE_PATH,
    DEVICE_DETAIL_PATH_TEMPLATE, DEVICE_HEARTBEAT_PATH, DEVICE_PROVISION_PATH, DEVICE_UNBIND_PATH,
};
use http_support::{
    authorization_redirect_location, bearer_token, introspection_response, jwks_response,
    map_service_error, missing_authenticated_subject_response, missing_bearer_token_response,
    run_service_call, unix_time, unix_time_secs,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSubject {
    pub account_id: String,
}

impl AuthenticatedSubject {
    pub fn new(account_id: impl Into<String>) -> Self {
        Self {
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
        .route(DEVICE_COMPLETE_PATH, post(complete_device_registration))
        .route(DEVICE_HEARTBEAT_PATH, post(device_heartbeat))
        .route(OIDC_TOKEN_PATH, post(exchange_token))
        .route(OIDC_JWKS_PATH, get(jwks))
        .route(embedded_idp_core::OIDC_DISCOVERY_PATH, get(discovery))
}

fn subject_routes() -> Router<EmbeddedIdpHttpState> {
    Router::new()
        .route(DEVICE_API_PREFIX, get(list_devices))
        .route(DEVICE_DETAIL_PATH_TEMPLATE, get(get_device))
        .route(DEVICE_BIND_PATH, post(bind_device_to_account))
        .route(DEVICE_UNBIND_PATH, post(unbind_device_from_account))
        .route(OIDC_AUTHORIZE_PATH, get(authorize))
}

fn token_routes() -> Router<EmbeddedIdpHttpState> {
    Router::new()
        .route(AUTH_REFRESH_PATH, post(rotate_refresh_token))
        .route(AUTH_LOGOUT_PATH, post(logout))
        .route(OIDC_USERINFO_PATH, get(user_info).post(user_info))
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
                access_token: result.tokens.access_token,
                refresh_token: result.tokens.refresh_token,
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
                access_token: result.tokens.access_token,
                refresh_token: result.tokens.refresh_token,
                refresh_token_version: result.tokens.refresh_token_version,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn rotate_refresh_token(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<RefreshHttpRequest>,
) -> Response {
    let auth_service = state.auth_service.clone();
    match run_service_call(move || {
        auth_service.rotate_refresh_token(RotateRefreshTokenCommand {
            refresh_token: request.refresh_token,
            rotated_at: unix_time(request.rotated_at_unix_secs),
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
                access_token: result.tokens.access_token,
                refresh_token: result.tokens.refresh_token,
                refresh_token_version: result.tokens.refresh_token_version,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn logout(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<LogoutHttpRequest>,
) -> Response {
    let auth_service = state.auth_service.clone();
    match run_service_call(move || {
        auth_service.logout(LogoutSessionCommand {
            refresh_token: request.refresh_token,
            logged_out_at: unix_time(request.logged_out_at_unix_secs),
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
    let device_service = state.device_service.clone();
    match run_service_call(move || {
        device_service.provision_device(embedded_idp_core::ProvisionDeviceCommand {
            client_id: request.client_id,
            device_name: request.device_name,
            requested_at: unix_time(request.requested_at_unix_secs),
        })
    })
    .await
    {
        Ok(result) => (
            StatusCode::CREATED,
            Json(ProvisionDeviceHttpResponse {
                device: device_response(result.device),
                challenge: result.nonce.challenge,
                expires_at_unix_secs: result
                    .nonce
                    .expires_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|value| value.as_secs())
                    .unwrap_or_default(),
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn complete_device_registration(
    State(state): State<EmbeddedIdpHttpState>,
    Json(request): Json<CompleteDeviceRegistrationHttpRequest>,
) -> Response {
    let device_service = state.device_service.clone();
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

async fn bind_device_to_account(
    State(state): State<EmbeddedIdpHttpState>,
    subject: Option<Extension<AuthenticatedSubject>>,
    Json(request): Json<BindDeviceHttpRequest>,
) -> Response {
    let Ok(account_id) = subject_account_id(subject) else {
        return missing_authenticated_subject_response();
    };

    let device_service = state.device_service.clone();
    match run_service_call(move || {
        device_service.bind_device_to_account(BindDeviceToAccountCommand {
            account_id,
            device_id: request.device_id,
            bound_at: unix_time(request.bound_at_unix_secs),
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
    let Ok(account_id) = subject_account_id(subject) else {
        return missing_authenticated_subject_response();
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
    let Ok(account_id) = subject_account_id(subject) else {
        return missing_authenticated_subject_response();
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
    let Ok(account_id) = subject_account_id(subject) else {
        return missing_authenticated_subject_response();
    };

    let device_service = state.device_service.clone();
    match run_service_call(move || {
        device_service.unbind_device_from_account(UnbindDeviceFromAccountCommand {
            account_id,
            device_id: request.device_id,
            unbound_at: unix_time(request.unbound_at_unix_secs),
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
    match run_service_call(move || {
        device_service.heartbeat(DeviceHeartbeatCommand {
            device_id: request.device_id,
            observed_at: unix_time(request.observed_at_unix_secs),
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
    let Some(Extension(subject)) = subject else {
        return missing_authenticated_subject_response();
    };

    let oidc_authorization_service = state.oidc_authorization_service.clone();
    match run_service_call(move || {
        oidc_authorization_service.start_authorization(StartAuthorizationCommand {
            subject_account_id: subject.account_id,
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
                access_token: result.tokens.access_token,
                refresh_token: result.tokens.refresh_token,
                refresh_token_version: result.tokens.refresh_token_version,
                token_type: result.token_type,
                id_token: result.id_token,
                scope: result.scope,
                subject_account_id: result.subject_account_id,
            }),
        )
            .into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn jwks(State(state): State<EmbeddedIdpHttpState>) -> Response {
    match state.oidc_metadata_service.jwks_document() {
        Ok(document) => (StatusCode::OK, Json(jwks_response(document))).into_response(),
        Err(error) => map_service_error(error),
    }
}

async fn revoke_token(
    State(state): State<EmbeddedIdpHttpState>,
    Form(request): Form<RevokeTokenHttpRequest>,
) -> Response {
    let token_management_service = state.token_management_service.clone();
    match run_service_call(move || {
        token_management_service.revoke_token(RevokeTokenCommand {
            token: request.token,
            token_type_hint: request.token_type_hint,
            client_id: request.client_id,
            client_secret: request.client_secret,
            revoked_at: unix_time(request.revoked_at_unix_secs),
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
        device_disable_endpoint: route_mount_plan.external_device_disable_path(),
        device_revoke_endpoint: route_mount_plan.external_device_revoke_path(),
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
    subject
        .map(|Extension(subject)| subject.account_id)
        .ok_or_else(missing_authenticated_subject_response)
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

use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use embedded_idp_axum::{
    router, AuthenticatedSubject, DeviceHttpSecurity, EmbeddedIdpHttpState, RefreshHttpSecurity,
    RouteMountPlan,
};
use embedded_idp_core::{
    ActivateAccountCommand, ActivateAccountResult, AdminService, AuthService,
    BindDeviceToAccountCommand, BindDeviceToAccountResult, CompleteDeviceRegistrationCommand,
    CompleteDeviceRegistrationResult, CreateAccountCommand, CreateAccountResult,
    DeviceHeartbeatCommand, DeviceHeartbeatResult, DeviceService, DisableAccountCommand,
    DisableAccountResult, DisableDeviceCommand, DisableDeviceResult,
    ExchangeAuthorizationCodeCommand, ExchangeAuthorizationCodeResult, GetAccountCommand,
    GetAccountResult, GetClientCommand, GetClientResult, GetDeviceCommand, GetDeviceResult,
    GetSessionCommand, GetSessionResult, GetUserInfoCommand, GetUserInfoResult,
    IntrospectTokenCommand, IntrospectTokenResult, IssuedTokenBundle, JsonWebKey, JwksDocument,
    ListAccountsCommand, ListAccountsResult, ListClientsCommand, ListClientsResult,
    ListDevicesCommand, ListDevicesResult, ListSessionsCommand, ListSessionsResult, LoginCommand,
    LoginResult, LogoutSessionCommand, LogoutSessionResult, OidcAuthorizationService,
    ProvisionDeviceCommand, ProvisionDeviceResult, RegisterAccountCommand, RegisterAccountResult,
    ResendVerificationCodeCommand, ResendVerificationCodeResult, RevokeAccountSessionsCommand,
    RevokeAccountSessionsResult, RevokeDeviceCommand, RevokeDeviceResult, RevokeSessionCommand,
    RevokeSessionResult, RevokeTokenCommand, RevokeTokenResult, RotateRefreshTokenCommand,
    RotateRefreshTokenResult, SecretString, ServiceError, SetAccountPasswordCommand,
    SetAccountPasswordResult, StartAuthorizationCommand, StartAuthorizationResult,
    StaticOidcMetadataService, SystemClock, TokenIntrospectionService, TokenManagementService,
    UnbindDeviceFromAccountCommand, UnbindDeviceFromAccountResult, UpsertClientCommand,
    UpsertClientResult, UserInfoService, VerifyEmailCommand, VerifyEmailResult,
};
use embedded_idp_email::{EmailSendError, VerificationEmailRequest, VerificationEmailService};

fn main() {
    let state = EmbeddedIdpHttpState {
        issuer: "http://127.0.0.1:8080".to_string(),
        route_mount_plan: RouteMountPlan::new("/idp"),
        admin_service: Arc::new(StubAdminService),
        auth_service: Arc::new(StubAuthService),
        verification_email_service: Arc::new(StubVerificationEmailService),
        device_service: Arc::new(StubDeviceService),
        oidc_authorization_service: Arc::new(StubOidcAuthorizationService),
        oidc_metadata_service: Arc::new(StaticOidcMetadataService::new(JwksDocument {
            keys: vec![JsonWebKey {
                key_id: "kid-1".to_string(),
                key_type: "EC".to_string(),
                algorithm: "ES256".to_string(),
                public_key_use: "sig".to_string(),
                curve: Some("P-256".to_string()),
                modulus: None,
                exponent: None,
                x: Some("x-value".to_string()),
                y: Some("y-value".to_string()),
            }],
        })),
        token_management_service: Arc::new(StubTokenManagementService),
        user_info_service: Arc::new(StubUserInfoService),
        token_introspection_service: Arc::new(StubTokenIntrospectionService),
        refresh_security: RefreshHttpSecurity::LegacyDevelopmentOnly,
        device_security: DeviceHttpSecurity::LegacyDevelopmentOnly,
        clock: Arc::new(SystemClock),
    };

    let _host_router = Router::new()
        .route_layer(middleware::from_fn(inject_authenticated_subject))
        .nest("/idp", router(state));

    println!("host router composed with embedded idp module");
}

struct StubAdminService;

impl AdminService for StubAdminService {
    fn create_account(
        &self,
        _command: CreateAccountCommand,
    ) -> Result<CreateAccountResult, ServiceError> {
        Err(ServiceError::AccountNotFound)
    }

    fn list_accounts(
        &self,
        _command: ListAccountsCommand,
    ) -> Result<ListAccountsResult, ServiceError> {
        Err(ServiceError::AccountNotFound)
    }

    fn get_account(&self, _command: GetAccountCommand) -> Result<GetAccountResult, ServiceError> {
        Err(ServiceError::AccountNotFound)
    }

    fn activate_account(
        &self,
        _command: ActivateAccountCommand,
    ) -> Result<ActivateAccountResult, ServiceError> {
        Err(ServiceError::AccountNotFound)
    }

    fn disable_account(
        &self,
        _command: DisableAccountCommand,
    ) -> Result<DisableAccountResult, ServiceError> {
        Err(ServiceError::AccountNotFound)
    }

    fn set_account_password(
        &self,
        _command: SetAccountPasswordCommand,
    ) -> Result<SetAccountPasswordResult, ServiceError> {
        Err(ServiceError::AccountNotFound)
    }

    fn revoke_account_sessions(
        &self,
        _command: RevokeAccountSessionsCommand,
    ) -> Result<RevokeAccountSessionsResult, ServiceError> {
        Err(ServiceError::AccountNotFound)
    }

    fn list_sessions(
        &self,
        _command: ListSessionsCommand,
    ) -> Result<ListSessionsResult, ServiceError> {
        Err(ServiceError::SessionNotFound)
    }

    fn get_session(&self, _command: GetSessionCommand) -> Result<GetSessionResult, ServiceError> {
        Err(ServiceError::SessionNotFound)
    }

    fn revoke_session(
        &self,
        _command: RevokeSessionCommand,
    ) -> Result<RevokeSessionResult, ServiceError> {
        Err(ServiceError::SessionNotFound)
    }

    fn list_clients(
        &self,
        _command: ListClientsCommand,
    ) -> Result<ListClientsResult, ServiceError> {
        Err(ServiceError::ClientNotFound)
    }

    fn get_client(&self, _command: GetClientCommand) -> Result<GetClientResult, ServiceError> {
        Err(ServiceError::ClientNotFound)
    }

    fn upsert_client(
        &self,
        _command: UpsertClientCommand,
    ) -> Result<UpsertClientResult, ServiceError> {
        Err(ServiceError::ClientNotFound)
    }
}

async fn inject_authenticated_subject(mut request: Request, next: Next) -> Response {
    request
        .extensions_mut()
        .insert(AuthenticatedSubject::new("acct-host-user-1"));
    next.run(request).await
}

struct StubAuthService;

struct StubVerificationEmailService;

impl VerificationEmailService for StubVerificationEmailService {
    fn send_verification_email(
        &self,
        _request: VerificationEmailRequest,
    ) -> Result<(), EmailSendError> {
        Ok(())
    }
}

impl AuthService for StubAuthService {
    fn register_account(
        &self,
        _command: RegisterAccountCommand,
    ) -> Result<RegisterAccountResult, ServiceError> {
        Err(ServiceError::RegistrationDisabled)
    }

    fn login(&self, _command: LoginCommand) -> Result<LoginResult, ServiceError> {
        Err(ServiceError::InvalidCredentials)
    }

    fn verify_email(
        &self,
        _command: VerifyEmailCommand,
    ) -> Result<VerifyEmailResult, ServiceError> {
        Err(ServiceError::InvalidVerificationCode)
    }

    fn resend_verification_code(
        &self,
        _command: ResendVerificationCodeCommand,
    ) -> Result<ResendVerificationCodeResult, ServiceError> {
        Err(ServiceError::AccountPendingVerification)
    }

    fn rotate_refresh_token(
        &self,
        _command: RotateRefreshTokenCommand,
    ) -> Result<RotateRefreshTokenResult, ServiceError> {
        Err(ServiceError::SessionExpired)
    }

    fn logout(&self, _command: LogoutSessionCommand) -> Result<LogoutSessionResult, ServiceError> {
        Err(ServiceError::SessionExpired)
    }
}

struct StubDeviceService;

impl DeviceService for StubDeviceService {
    fn provision_device(
        &self,
        _command: ProvisionDeviceCommand,
    ) -> Result<ProvisionDeviceResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }

    fn complete_device_registration(
        &self,
        _command: CompleteDeviceRegistrationCommand,
    ) -> Result<CompleteDeviceRegistrationResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }

    fn bind_device_to_account(
        &self,
        _command: BindDeviceToAccountCommand,
    ) -> Result<BindDeviceToAccountResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }

    fn get_device(&self, _command: GetDeviceCommand) -> Result<GetDeviceResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }

    fn list_devices(
        &self,
        _command: ListDevicesCommand,
    ) -> Result<ListDevicesResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }

    fn unbind_device_from_account(
        &self,
        _command: UnbindDeviceFromAccountCommand,
    ) -> Result<UnbindDeviceFromAccountResult, ServiceError> {
        Err(ServiceError::DeviceBindingNotFound)
    }

    fn disable_device(
        &self,
        _command: DisableDeviceCommand,
    ) -> Result<DisableDeviceResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }

    fn revoke_device(
        &self,
        _command: RevokeDeviceCommand,
    ) -> Result<RevokeDeviceResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }

    fn heartbeat(
        &self,
        _command: DeviceHeartbeatCommand,
    ) -> Result<DeviceHeartbeatResult, ServiceError> {
        Err(ServiceError::DeviceNotFound)
    }
}

struct StubOidcAuthorizationService;

impl OidcAuthorizationService for StubOidcAuthorizationService {
    fn start_authorization(
        &self,
        command: StartAuthorizationCommand,
    ) -> Result<StartAuthorizationResult, ServiceError> {
        Ok(StartAuthorizationResult {
            authorization_code: format!("auth-code-for-{}", command.subject_account_id),
            redirect_uri: command.redirect_uri,
            state: command.state,
        })
    }

    fn exchange_authorization_code(
        &self,
        _command: ExchangeAuthorizationCodeCommand,
    ) -> Result<ExchangeAuthorizationCodeResult, ServiceError> {
        Ok(ExchangeAuthorizationCodeResult {
            subject_account_id: "acct-host-user-1".to_string(),
            tokens: IssuedTokenBundle {
                access_token: SecretString::new("access-token"),
                refresh_token: SecretString::new("refresh-token"),
                access_expires_at: SystemTime::UNIX_EPOCH,
                refresh_expires_at: SystemTime::UNIX_EPOCH,
                refresh_token_version: 0,
            },
            id_token: Some(SecretString::new("id-token")),
            scope: Some("openid profile".to_string()),
            token_type: "Bearer",
        })
    }
}

struct StubTokenManagementService;

impl TokenManagementService for StubTokenManagementService {
    fn revoke_token(
        &self,
        _command: RevokeTokenCommand,
    ) -> Result<RevokeTokenResult, ServiceError> {
        Ok(RevokeTokenResult {
            revoked: true,
            revoked_session_id: Some("sess-1".to_string()),
            revoked_token_version: Some(0),
        })
    }
}

struct StubUserInfoService;

impl UserInfoService for StubUserInfoService {
    fn get_user_info(
        &self,
        command: GetUserInfoCommand,
    ) -> Result<GetUserInfoResult, ServiceError> {
        if command.access_token.trim().is_empty() {
            return Err(ServiceError::InvalidToken);
        }

        Ok(GetUserInfoResult {
            subject_account_id: "acct-host-user-1".to_string(),
            email: "user@example.com".to_string(),
            display_name: Some("Host User".to_string()),
            client_id: "desktop-app".to_string(),
            scope: Some("openid profile".to_string()),
        })
    }
}

struct StubTokenIntrospectionService;

impl TokenIntrospectionService for StubTokenIntrospectionService {
    fn introspect_token(
        &self,
        command: IntrospectTokenCommand,
    ) -> Result<IntrospectTokenResult, ServiceError> {
        if command.token.trim().is_empty() {
            return Err(ServiceError::InvalidToken);
        }

        Ok(IntrospectTokenResult {
            active: true,
            subject_account_id: Some("acct-host-user-1".to_string()),
            client_id: Some(command.client_id),
            scope: Some("openid profile".to_string()),
            token_type: Some("access_token"),
            session_id: Some("sess-1".to_string()),
            expires_at: Some(SystemTime::UNIX_EPOCH),
            issued_at: Some(SystemTime::UNIX_EPOCH),
        })
    }
}

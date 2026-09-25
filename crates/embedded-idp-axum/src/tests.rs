use std::sync::Arc;
use std::time::SystemTime;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    Account, AccountDeviceBinding, AccountDeviceBindingStatus, AccountStatus,
    ActivateAccountCommand, ActivateAccountResult, AdminClientRecord, AdminService, AuthService,
    AuthSession, BindDeviceToAccountCommand, BindDeviceToAccountResult, CanonicalHttpMethod,
    CompleteDeviceKeyRegistrationCommand, CompleteDeviceKeyRegistrationResult,
    CompleteDeviceRegistrationCommand, CompleteDeviceRegistrationResult, CreateAccountCommand,
    CreateAccountResult, DeviceHeartbeatCommand, DeviceHeartbeatResult, DeviceNonceRecord,
    DeviceProofAlgorithm, DeviceProofKeyRecord, DeviceProofKeyStatus, DeviceProofProfile,
    DeviceRecord, DeviceSecurityError, DeviceSecurityService, DeviceService, DeviceStatus,
    DisableAccountCommand, DisableAccountResult, DisableDeviceCommand, DisableDeviceResult,
    ExchangeAuthorizationCodeCommand, ExchangeAuthorizationCodeResult, GetAccountCommand,
    GetAccountResult, GetClientCommand, GetClientResult, GetDeviceCommand, GetDeviceResult,
    GetSessionCommand, GetSessionResult, GetUserInfoCommand, GetUserInfoResult,
    IntrospectTokenCommand, IntrospectTokenResult, IssueDeviceProofChallengeCommand,
    IssueDeviceProofChallengeResult, IssuedTokenBundle, JsonWebKey, JwksDocument,
    ListAccountsCommand, ListAccountsResult, ListClientsCommand, ListClientsResult,
    ListDevicesCommand, ListDevicesResult, ListSessionsCommand, ListSessionsResult, LoginCommand,
    LoginResult, LogoutSessionCommand, LogoutSessionResult, OidcAuthorizationService,
    OidcClientType, OidcMetadataService, PageMetadata, PendingEmailVerification,
    ProofBoundRefreshError, ProofBoundRefreshService, ProvisionDeviceCommand,
    ProvisionDeviceResult, ProvisionPendingDeviceCommand, ProvisionPendingDeviceResult,
    RegisterAccountCommand, RegisterAccountResult, ResendVerificationCodeCommand,
    ResendVerificationCodeResult, RevokeAccountSessionsCommand, RevokeAccountSessionsResult,
    RevokeDeviceCommand, RevokeDeviceResult, RevokeSessionCommand, RevokeSessionResult,
    RevokeTokenCommand, RevokeTokenResult, RotateDeviceProofKeyCommand, RotateDeviceProofKeyResult,
    RotateProofBoundRefreshCommand, RotateProofBoundRefreshOutcome, RotateRefreshTokenCommand,
    RotateRefreshTokenResult, SecretString, ServiceError, SessionStatus, SetAccountPasswordCommand,
    SetAccountPasswordResult, StartAuthorizationCommand, StartAuthorizationResult, SystemClock,
    TokenIntrospectionService, TokenManagementService, UnbindDeviceFromAccountCommand,
    UnbindDeviceFromAccountResult, UpsertClientCommand, UpsertClientResult, UserInfoService,
    VerifyEmailCommand, VerifyEmailResult,
};
use embedded_idp_email::{
    EmailSendError, OutboundEmail, VerificationEmailRequest, VerificationEmailService,
};
use tower::ServiceExt;

use super::{
    admin_router, client_authenticated_router, public_router, router, subject_router, token_router,
    AuthenticatedSubject, DeviceHttpSecurity, EmbeddedIdpHttpState, ProofBoundRefreshHttpConfig,
    ProtectedRouteConfig, RefreshHttpSecurity, RouteMountPlan,
};

struct ReuseProofBoundRefreshService;

impl ProofBoundRefreshService for ReuseProofBoundRefreshService {
    fn rotate_proof_bound_refresh(
        &self,
        command: RotateProofBoundRefreshCommand,
    ) -> Result<RotateProofBoundRefreshOutcome, ProofBoundRefreshError> {
        assert_eq!(command.refresh_token.expose_secret(), "refresh-token");
        assert_eq!(command.binding.external_path, "/auth/refresh");
        assert_eq!(command.proof.device_id, "device-1");
        Ok(RotateProofBoundRefreshOutcome::ReuseDetected {
            session_id: "session-1".to_string(),
        })
    }
}

struct HappyDeviceSecurityService;

impl DeviceSecurityService for HappyDeviceSecurityService {
    fn provision_pending_device(
        &self,
        command: ProvisionPendingDeviceCommand,
    ) -> Result<ProvisionPendingDeviceResult, DeviceSecurityError> {
        assert_eq!(command.client_id, "desktop-app");
        assert_eq!(command.device_name, "Laptop");
        Ok(ProvisionPendingDeviceResult {
            device: DeviceRecord {
                status: DeviceStatus::Pending,
                proof_key_id: None,
                ..test_device()
            },
        })
    }

    fn issue_device_proof_challenge(
        &self,
        command: IssueDeviceProofChallengeCommand,
    ) -> Result<IssueDeviceProofChallengeResult, DeviceSecurityError> {
        assert_eq!(command.device_id, "device-1");
        Ok(IssueDeviceProofChallengeResult {
            challenge: SecretString::new(Base64UrlUnpadded::encode_string(&[2_u8; 32])),
            expires_at: SystemTime::UNIX_EPOCH,
        })
    }

    fn complete_device_key_registration(
        &self,
        command: CompleteDeviceKeyRegistrationCommand,
    ) -> Result<CompleteDeviceKeyRegistrationResult, DeviceSecurityError> {
        assert_eq!(command.device_id, "device-1");
        assert!(command.public_jwk.contains("Ed25519"));
        Ok(CompleteDeviceKeyRegistrationResult {
            device: test_device(),
            key: test_device_key(1, DeviceProofKeyStatus::Active),
        })
    }

    fn rotate_device_proof_key(
        &self,
        command: RotateDeviceProofKeyCommand,
    ) -> Result<RotateDeviceProofKeyResult, DeviceSecurityError> {
        assert_eq!(command.account_id, "acct-1");
        assert_eq!(command.device_id, "device-1");
        let mut device = test_device();
        let active_key = test_device_key(2, DeviceProofKeyStatus::Active);
        device.proof_key_id = Some(active_key.key_id.clone());
        Ok(RotateDeviceProofKeyResult {
            device,
            retired_key: test_device_key(1, DeviceProofKeyStatus::Retired),
            active_key,
        })
    }
}

fn test_device_key(version: u64, status: DeviceProofKeyStatus) -> DeviceProofKeyRecord {
    let byte = version as u8;
    DeviceProofKeyRecord {
        key_id: Base64UrlUnpadded::encode_string(&[byte; 32]),
        device_id: "device-1".to_string(),
        algorithm: DeviceProofAlgorithm::Ed25519,
        public_jwk: "{}".to_string(),
        version,
        status,
        registered_at: SystemTime::UNIX_EPOCH,
        retired_at: (status == DeviceProofKeyStatus::Retired).then_some(SystemTime::UNIX_EPOCH),
    }
}

struct HappyAuthService;

impl AuthService for HappyAuthService {
    fn register_account(
        &self,
        _command: RegisterAccountCommand,
    ) -> Result<RegisterAccountResult, ServiceError> {
        Ok(RegisterAccountResult {
            account: test_account(),
            verification: test_pending_verification(),
        })
    }

    fn login(&self, _command: LoginCommand) -> Result<LoginResult, ServiceError> {
        Ok(LoginResult {
            account: test_account(),
            session: test_session(),
            tokens: test_tokens(),
        })
    }

    fn verify_email(
        &self,
        _command: VerifyEmailCommand,
    ) -> Result<VerifyEmailResult, ServiceError> {
        Ok(VerifyEmailResult {
            account: test_account(),
            session: test_session(),
            tokens: test_tokens(),
        })
    }

    fn resend_verification_code(
        &self,
        _command: ResendVerificationCodeCommand,
    ) -> Result<ResendVerificationCodeResult, ServiceError> {
        Ok(ResendVerificationCodeResult {
            account: test_account(),
            verification: test_pending_verification(),
        })
    }

    fn rotate_refresh_token(
        &self,
        _command: RotateRefreshTokenCommand,
    ) -> Result<RotateRefreshTokenResult, ServiceError> {
        Ok(RotateRefreshTokenResult {
            session: test_session(),
            tokens: test_tokens(),
        })
    }

    fn logout(&self, _command: LogoutSessionCommand) -> Result<LogoutSessionResult, ServiceError> {
        Ok(LogoutSessionResult {
            session: test_session(),
        })
    }
}

struct HappyDeviceService;

struct HappyVerificationEmailService;

impl VerificationEmailService for HappyVerificationEmailService {
    fn send_verification_email(
        &self,
        request: VerificationEmailRequest,
    ) -> Result<(), EmailSendError> {
        let _ = OutboundEmail {
            to: vec![],
            subject: request.code,
            text_body: String::new(),
        };
        Ok(())
    }
}

impl DeviceService for HappyDeviceService {
    fn provision_device(
        &self,
        _command: ProvisionDeviceCommand,
    ) -> Result<ProvisionDeviceResult, ServiceError> {
        Ok(ProvisionDeviceResult {
            device: DeviceRecord {
                status: DeviceStatus::Pending,
                proof_key_id: None,
                ..test_device()
            },
            nonce: DeviceNonceRecord {
                id: "dnonce-1".to_string(),
                device_id: "dev-1".to_string(),
                challenge: "challenge-1".to_string(),
                issued_at: SystemTime::UNIX_EPOCH,
                expires_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(300),
                consumed_at: None,
            },
        })
    }

    fn complete_device_registration(
        &self,
        _command: CompleteDeviceRegistrationCommand,
    ) -> Result<CompleteDeviceRegistrationResult, ServiceError> {
        Ok(CompleteDeviceRegistrationResult {
            device: test_device(),
        })
    }

    fn bind_device_to_account(
        &self,
        _command: BindDeviceToAccountCommand,
    ) -> Result<BindDeviceToAccountResult, ServiceError> {
        Ok(BindDeviceToAccountResult {
            binding: test_binding(),
        })
    }

    fn get_device(&self, _command: GetDeviceCommand) -> Result<GetDeviceResult, ServiceError> {
        Ok(GetDeviceResult {
            device: test_device(),
            bindings: vec![test_binding()],
        })
    }

    fn list_devices(&self, command: ListDevicesCommand) -> Result<ListDevicesResult, ServiceError> {
        Ok(ListDevicesResult {
            devices: vec![test_device()],
            page: test_page(command.page.limit, command.page.offset),
        })
    }

    fn unbind_device_from_account(
        &self,
        _command: UnbindDeviceFromAccountCommand,
    ) -> Result<UnbindDeviceFromAccountResult, ServiceError> {
        Ok(UnbindDeviceFromAccountResult {
            binding: AccountDeviceBinding {
                status: AccountDeviceBindingStatus::Unbound,
                unbound_at: Some(SystemTime::UNIX_EPOCH),
                ..test_binding()
            },
        })
    }

    fn disable_device(
        &self,
        _command: DisableDeviceCommand,
    ) -> Result<DisableDeviceResult, ServiceError> {
        Ok(DisableDeviceResult {
            device: DeviceRecord {
                status: DeviceStatus::Disabled,
                ..test_device()
            },
        })
    }

    fn revoke_device(
        &self,
        _command: RevokeDeviceCommand,
    ) -> Result<RevokeDeviceResult, ServiceError> {
        Ok(RevokeDeviceResult {
            device: DeviceRecord {
                status: DeviceStatus::Revoked,
                ..test_device()
            },
        })
    }

    fn heartbeat(
        &self,
        _command: DeviceHeartbeatCommand,
    ) -> Result<DeviceHeartbeatResult, ServiceError> {
        Ok(DeviceHeartbeatResult {
            device: test_device(),
        })
    }
}

struct HappyAdminService;

impl AdminService for HappyAdminService {
    fn create_account(
        &self,
        command: CreateAccountCommand,
    ) -> Result<CreateAccountResult, ServiceError> {
        Ok(CreateAccountResult {
            account: Account {
                email: command.email,
                display_name: command.display_name,
                ..test_account()
            },
        })
    }

    fn list_accounts(
        &self,
        command: ListAccountsCommand,
    ) -> Result<ListAccountsResult, ServiceError> {
        Ok(ListAccountsResult {
            accounts: vec![test_account()],
            page: test_page(command.page.limit, command.page.offset),
        })
    }

    fn get_account(&self, _command: GetAccountCommand) -> Result<GetAccountResult, ServiceError> {
        Ok(GetAccountResult {
            account: test_account(),
        })
    }

    fn activate_account(
        &self,
        _command: ActivateAccountCommand,
    ) -> Result<ActivateAccountResult, ServiceError> {
        Ok(ActivateAccountResult {
            account: test_account(),
        })
    }

    fn disable_account(
        &self,
        _command: DisableAccountCommand,
    ) -> Result<DisableAccountResult, ServiceError> {
        Ok(DisableAccountResult {
            account: Account {
                status: AccountStatus::Disabled,
                ..test_account()
            },
        })
    }

    fn set_account_password(
        &self,
        _command: SetAccountPasswordCommand,
    ) -> Result<SetAccountPasswordResult, ServiceError> {
        Ok(SetAccountPasswordResult {
            account: test_account(),
        })
    }

    fn revoke_account_sessions(
        &self,
        _command: RevokeAccountSessionsCommand,
    ) -> Result<RevokeAccountSessionsResult, ServiceError> {
        Ok(RevokeAccountSessionsResult {
            sessions: vec![AuthSession {
                status: SessionStatus::Revoked,
                ..test_session()
            }],
        })
    }

    fn list_sessions(
        &self,
        command: ListSessionsCommand,
    ) -> Result<ListSessionsResult, ServiceError> {
        Ok(ListSessionsResult {
            sessions: vec![test_session()],
            page: test_page(command.page.limit, command.page.offset),
        })
    }

    fn get_session(&self, _command: GetSessionCommand) -> Result<GetSessionResult, ServiceError> {
        Ok(GetSessionResult {
            session: test_session(),
        })
    }

    fn revoke_session(
        &self,
        _command: RevokeSessionCommand,
    ) -> Result<RevokeSessionResult, ServiceError> {
        Ok(RevokeSessionResult {
            session: AuthSession {
                status: SessionStatus::Revoked,
                ..test_session()
            },
        })
    }

    fn list_clients(&self, command: ListClientsCommand) -> Result<ListClientsResult, ServiceError> {
        Ok(ListClientsResult {
            clients: vec![test_admin_client()],
            page: test_page(command.page.limit, command.page.offset),
        })
    }

    fn get_client(&self, _command: GetClientCommand) -> Result<GetClientResult, ServiceError> {
        Ok(GetClientResult {
            client: test_admin_client(),
        })
    }

    fn upsert_client(
        &self,
        command: UpsertClientCommand,
    ) -> Result<UpsertClientResult, ServiceError> {
        Ok(UpsertClientResult {
            client: AdminClientRecord {
                client_id: command.client_id,
                client_name: command.client_name,
                redirect_uris: command.redirect_uris,
                client_type: command.client_type,
                pkce_required: command.pkce_required,
                client_secret_configured: command.client_secret.is_some(),
            },
        })
    }
}

struct CursorAdminService;

impl AdminService for CursorAdminService {
    fn create_account(
        &self,
        command: CreateAccountCommand,
    ) -> Result<CreateAccountResult, ServiceError> {
        HappyAdminService.create_account(command)
    }

    fn list_accounts(
        &self,
        command: ListAccountsCommand,
    ) -> Result<ListAccountsResult, ServiceError> {
        let first = Account {
            id: "acct-1".to_string(),
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10),
            ..test_account()
        };
        let second = Account {
            id: "acct-2".to_string(),
            created_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9),
            ..test_account()
        };

        if command.cursor.is_none() {
            return Ok(ListAccountsResult {
                accounts: vec![first],
                page: PageMetadata {
                    limit: command.page.limit,
                    offset: command.page.offset,
                    returned: 1,
                    total: 2,
                    has_more: true,
                },
            });
        }

        Ok(ListAccountsResult {
            accounts: vec![second],
            page: PageMetadata {
                limit: command.page.limit,
                offset: command.page.offset,
                returned: 1,
                total: 2,
                has_more: false,
            },
        })
    }

    fn get_account(&self, command: GetAccountCommand) -> Result<GetAccountResult, ServiceError> {
        HappyAdminService.get_account(command)
    }

    fn activate_account(
        &self,
        command: ActivateAccountCommand,
    ) -> Result<ActivateAccountResult, ServiceError> {
        HappyAdminService.activate_account(command)
    }

    fn disable_account(
        &self,
        command: DisableAccountCommand,
    ) -> Result<DisableAccountResult, ServiceError> {
        HappyAdminService.disable_account(command)
    }

    fn set_account_password(
        &self,
        command: SetAccountPasswordCommand,
    ) -> Result<SetAccountPasswordResult, ServiceError> {
        HappyAdminService.set_account_password(command)
    }

    fn revoke_account_sessions(
        &self,
        command: RevokeAccountSessionsCommand,
    ) -> Result<RevokeAccountSessionsResult, ServiceError> {
        HappyAdminService.revoke_account_sessions(command)
    }

    fn list_sessions(
        &self,
        command: ListSessionsCommand,
    ) -> Result<ListSessionsResult, ServiceError> {
        HappyAdminService.list_sessions(command)
    }

    fn get_session(&self, command: GetSessionCommand) -> Result<GetSessionResult, ServiceError> {
        HappyAdminService.get_session(command)
    }

    fn revoke_session(
        &self,
        command: RevokeSessionCommand,
    ) -> Result<RevokeSessionResult, ServiceError> {
        HappyAdminService.revoke_session(command)
    }

    fn list_clients(&self, command: ListClientsCommand) -> Result<ListClientsResult, ServiceError> {
        HappyAdminService.list_clients(command)
    }

    fn get_client(&self, command: GetClientCommand) -> Result<GetClientResult, ServiceError> {
        HappyAdminService.get_client(command)
    }

    fn upsert_client(
        &self,
        command: UpsertClientCommand,
    ) -> Result<UpsertClientResult, ServiceError> {
        HappyAdminService.upsert_client(command)
    }
}

struct HappyOidcAuthorizationService;

impl OidcAuthorizationService for HappyOidcAuthorizationService {
    fn start_authorization(
        &self,
        command: StartAuthorizationCommand,
    ) -> Result<StartAuthorizationResult, ServiceError> {
        if command.subject_account_id.is_empty() {
            return Err(ServiceError::InvalidContract(
                embedded_idp_core::ContractValidationError::MissingSubjectAccountId,
            ));
        }

        Ok(StartAuthorizationResult {
            authorization_code: "auth-code-1".to_string(),
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            state: Some("state-1".to_string()),
        })
    }

    fn exchange_authorization_code(
        &self,
        _command: ExchangeAuthorizationCodeCommand,
    ) -> Result<ExchangeAuthorizationCodeResult, ServiceError> {
        Ok(ExchangeAuthorizationCodeResult {
            subject_account_id: "acct-1".to_string(),
            tokens: test_tokens(),
            id_token: Some(SecretString::new("id-token-1")),
            scope: Some("openid profile".to_string()),
            token_type: "Bearer",
        })
    }
}

struct HappyOidcMetadataService;

impl OidcMetadataService for HappyOidcMetadataService {
    fn jwks_document(&self) -> Result<JwksDocument, ServiceError> {
        Ok(JwksDocument {
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
        })
    }

    fn jwks_etag(&self) -> Option<String> {
        Some("\"jwks-v1\"".to_string())
    }
}

struct HappyTokenManagementService;

impl TokenManagementService for HappyTokenManagementService {
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

struct HappyUserInfoService;

impl UserInfoService for HappyUserInfoService {
    fn get_user_info(
        &self,
        command: GetUserInfoCommand,
    ) -> Result<GetUserInfoResult, ServiceError> {
        if command.access_token.is_empty() {
            return Err(ServiceError::InvalidToken);
        }

        Ok(GetUserInfoResult {
            subject_account_id: "acct-1".to_string(),
            email: "user@example.com".to_string(),
            display_name: Some("User".to_string()),
            client_id: "desktop-app".to_string(),
            scope: Some("openid profile".to_string()),
        })
    }
}

struct HappyTokenIntrospectionService;

impl TokenIntrospectionService for HappyTokenIntrospectionService {
    fn introspect_token(
        &self,
        command: IntrospectTokenCommand,
    ) -> Result<IntrospectTokenResult, ServiceError> {
        if command.token.is_empty() {
            return Err(ServiceError::InvalidToken);
        }

        Ok(IntrospectTokenResult {
            active: true,
            subject_account_id: Some("acct-1".to_string()),
            client_id: Some(command.client_id),
            scope: Some("openid profile".to_string()),
            token_type: Some("access_token"),
            session_id: Some("sess-1".to_string()),
            expires_at: Some(SystemTime::UNIX_EPOCH),
            issued_at: Some(SystemTime::UNIX_EPOCH),
        })
    }
}

struct RejectingAuthService;

impl AuthService for RejectingAuthService {
    fn register_account(
        &self,
        _command: RegisterAccountCommand,
    ) -> Result<RegisterAccountResult, ServiceError> {
        Err(ServiceError::EmailAlreadyExists)
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

fn test_state(auth_service: Arc<dyn AuthService>) -> EmbeddedIdpHttpState {
    test_state_with_admin_service(Arc::new(HappyAdminService), auth_service)
}

fn proof_bound_refresh_state() -> EmbeddedIdpHttpState {
    let mut state = test_state(Arc::new(HappyAuthService));
    state.refresh_security = RefreshHttpSecurity::ProofBound(ProofBoundRefreshHttpConfig::new(
        Arc::new(ReuseProofBoundRefreshService),
        ProtectedRouteConfig::new(
            DeviceProofProfile::new("SUT-DEVICE-PROOF-V2").unwrap(),
            "sut-api",
            CanonicalHttpMethod::Post,
            "/auth/refresh",
        )
        .unwrap(),
    ));
    state
}

fn proof_bound_device_state() -> EmbeddedIdpHttpState {
    let mut state = test_state(Arc::new(HappyAuthService));
    state.device_security = DeviceHttpSecurity::ProofBound(Arc::new(HappyDeviceSecurityService));
    state
}

fn test_state_with_route_mount_plan(
    route_mount_plan: RouteMountPlan,
    auth_service: Arc<dyn AuthService>,
) -> EmbeddedIdpHttpState {
    test_state_with_admin_service_and_route_mount_plan(
        Arc::new(HappyAdminService),
        auth_service,
        route_mount_plan,
    )
}

fn test_state_with_admin_service(
    admin_service: Arc<dyn AdminService>,
    auth_service: Arc<dyn AuthService>,
) -> EmbeddedIdpHttpState {
    test_state_with_admin_service_and_route_mount_plan(
        admin_service,
        auth_service,
        RouteMountPlan::default_mounts(),
    )
}

fn test_state_with_admin_service_and_route_mount_plan(
    admin_service: Arc<dyn AdminService>,
    auth_service: Arc<dyn AuthService>,
    route_mount_plan: RouteMountPlan,
) -> EmbeddedIdpHttpState {
    EmbeddedIdpHttpState {
        issuer: "http://127.0.0.1:8080".to_string(),
        route_mount_plan,
        admin_service,
        auth_service,
        verification_email_service: Arc::new(HappyVerificationEmailService),
        device_service: Arc::new(HappyDeviceService),
        oidc_authorization_service: Arc::new(HappyOidcAuthorizationService),
        oidc_metadata_service: Arc::new(HappyOidcMetadataService),
        token_management_service: Arc::new(HappyTokenManagementService),
        user_info_service: Arc::new(HappyUserInfoService),
        token_introspection_service: Arc::new(HappyTokenIntrospectionService),
        refresh_security: RefreshHttpSecurity::LegacyDevelopmentOnly,
        device_security: DeviceHttpSecurity::LegacyDevelopmentOnly,
        clock: Arc::new(SystemClock),
    }
}

fn test_account() -> Account {
    Account {
        id: "acct-1".to_string(),
        email: "user@example.com".to_string(),
        password_hash: "$argon2id$demo".to_string(),
        display_name: Some("User".to_string()),
        status: AccountStatus::Active,
        created_at: SystemTime::UNIX_EPOCH,
    }
}

fn test_session() -> AuthSession {
    AuthSession {
        id: "sess-1".to_string(),
        account_id: "acct-1".to_string(),
        client_id: "desktop-app".to_string(),
        device_id: Some("dev-1".to_string()),
        status: SessionStatus::Active,
        created_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH,
        refresh_token_version: 0,
    }
}

fn test_device() -> DeviceRecord {
    DeviceRecord {
        id: "dev-1".to_string(),
        client_id: "desktop-app".to_string(),
        device_name: "MacBook".to_string(),
        proof_key_id: Some("proof-key-1".to_string()),
        status: DeviceStatus::Active,
        registered_at: SystemTime::UNIX_EPOCH,
        last_seen_at: Some(SystemTime::UNIX_EPOCH),
    }
}

fn test_binding() -> AccountDeviceBinding {
    AccountDeviceBinding {
        id: "dbind-1".to_string(),
        account_id: "acct-1".to_string(),
        device_id: "dev-1".to_string(),
        status: AccountDeviceBindingStatus::Active,
        bound_at: SystemTime::UNIX_EPOCH,
        unbound_at: None,
        last_authenticated_at: Some(SystemTime::UNIX_EPOCH),
    }
}

fn test_pending_verification() -> PendingEmailVerification {
    PendingEmailVerification {
        account_id: "acct-1".to_string(),
        email: "user@example.com".to_string(),
        code: "123456".to_string(),
        expires_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(900),
    }
}

fn test_admin_client() -> AdminClientRecord {
    AdminClientRecord {
        client_id: "desktop-app".to_string(),
        client_name: "Desktop App".to_string(),
        redirect_uris: vec!["http://127.0.0.1:43821/callback".to_string()],
        client_type: OidcClientType::PublicDesktop,
        pkce_required: true,
        client_secret_configured: false,
    }
}

fn test_page(limit: u32, offset: u64) -> PageMetadata {
    PageMetadata {
        limit,
        offset,
        returned: 1,
        total: 1,
        has_more: false,
    }
}

fn test_tokens() -> IssuedTokenBundle {
    IssuedTokenBundle {
        access_token: SecretString::new("access-token"),
        refresh_token: SecretString::new("refresh-token"),
        access_expires_at: SystemTime::UNIX_EPOCH,
        refresh_expires_at: SystemTime::UNIX_EPOCH,
        refresh_token_version: 0,
    }
}

#[tokio::test]
async fn route_mounts_follow_fixed_module_prefixes() {
    let plan = RouteMountPlan::default_mounts();

    assert_eq!(plan.external_base_path, "");
    assert_eq!(plan.auth_prefix, "/auth");
    assert_eq!(plan.device_prefix, "/devices");
    assert_eq!(plan.admin_prefix, "/admin");
    assert_eq!(plan.oidc_prefix, "/oidc");
    assert_eq!(plan.discovery_path, "/.well-known/openid-configuration");
    assert_eq!(plan.external_auth_prefix(), "/auth");
    assert_eq!(plan.external_oidc_authorize_path(), "/oidc/authorize");
}

#[tokio::test]
async fn route_mount_plan_applies_external_base_path() {
    let plan = RouteMountPlan::new("/api/v1/");

    assert_eq!(plan.external_base_path, "/api/v1");
    assert_eq!(plan.external_auth_prefix(), "/api/v1/auth");
    assert_eq!(
        plan.external_oidc_authorize_path(),
        "/api/v1/oidc/authorize"
    );
    assert_eq!(
        plan.external_discovery_path(),
        "/api/v1/.well-known/openid-configuration"
    );
}

#[tokio::test]
async fn register_handler_uses_fixed_auth_path() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/auth/register")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"user@example.com","password":"hash","display_name":"User","client_id":"desktop-app"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["account_status"], "pending_verification");
    assert_eq!(json["delivery_status"], "sent");
}

#[tokio::test]
async fn handler_maps_service_errors_to_http_status() {
    let app = router(test_state(Arc::new(RejectingAuthService)));

    let request = Request::builder()
        .uri("/auth/register")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"user@example.com","password":"hash","display_name":"User","client_id":"desktop-app"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn device_provision_handler_returns_pending_device_and_challenge() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/devices/provision")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"client_id":"desktop-app","device_name":"Shared Kiosk"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["device"]["status"], "pending");
    assert_eq!(json["challenge"], "challenge-1");
}

#[tokio::test]
async fn device_complete_and_bind_handlers_use_fixed_paths() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let complete_request = Request::builder()
        .uri("/devices/complete")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"device_id":"dev-1","proof_key_id":"proof-key-1","proof_challenge":"challenge-1","proof_signature":"sig","proof_signed_at_unix_secs":0,"completed_at_unix_secs":0}"#,
        ))
        .unwrap();

    let complete_response = app.clone().oneshot(complete_request).await.unwrap();
    assert_eq!(complete_response.status(), StatusCode::OK);

    let bind_request = Request::builder()
        .uri("/devices/bind")
        .method("POST")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"device_id":"dev-1"}"#))
        .unwrap();

    let bind_response = app.oneshot(bind_request).await.unwrap();

    assert_eq!(bind_response.status(), StatusCode::OK);
    let body = to_bytes(bind_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["binding_id"], "dbind-1");
}

#[tokio::test]
async fn device_query_and_management_handlers_use_fixed_paths() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let list_request = Request::builder()
        .uri("/devices")
        .method("GET")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .body(Body::empty())
        .unwrap();
    let list_response = app.clone().oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_json: serde_json::Value = serde_json::from_slice(&list_body).unwrap();
    assert_eq!(list_json["devices"][0]["device_id"], "dev-1");

    let get_request = Request::builder()
        .uri("/devices/dev-1")
        .method("GET")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .body(Body::empty())
        .unwrap();
    let get_response = app.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let get_body = to_bytes(get_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let get_json: serde_json::Value = serde_json::from_slice(&get_body).unwrap();
    assert_eq!(get_json["bindings"][0]["device_id"], "dev-1");

    let unbind_request = Request::builder()
        .uri("/devices/unbind")
        .method("POST")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"device_id":"dev-1"}"#))
        .unwrap();
    let unbind_response = app.clone().oneshot(unbind_request).await.unwrap();
    assert_eq!(unbind_response.status(), StatusCode::OK);
    let unbind_body = to_bytes(unbind_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let unbind_json: serde_json::Value = serde_json::from_slice(&unbind_body).unwrap();
    assert_eq!(unbind_json["status"], "unbound");

    let disable_request = Request::builder()
        .uri("/admin/devices/disable")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"device_id":"dev-1"}"#))
        .unwrap();
    let disable_response = app.clone().oneshot(disable_request).await.unwrap();
    assert_eq!(disable_response.status(), StatusCode::OK);
    let disable_body = to_bytes(disable_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let disable_json: serde_json::Value = serde_json::from_slice(&disable_body).unwrap();
    assert_eq!(disable_json["status"], "disabled");

    let revoke_request = Request::builder()
        .uri("/admin/devices/revoke")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"device_id":"dev-1"}"#))
        .unwrap();
    let revoke_response = app.oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);
    let revoke_body = to_bytes(revoke_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let revoke_json: serde_json::Value = serde_json::from_slice(&revoke_body).unwrap();
    assert_eq!(revoke_json["status"], "revoked");
}

#[tokio::test]
async fn authorize_handler_uses_fixed_oidc_path() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/authorize?response_type=code&client_id=desktop-app&redirect_uri=http://127.0.0.1:49152/callback&state=state-1")
        .method("GET")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response.headers()["location"],
        "http://127.0.0.1:49152/callback?code=auth-code-1&state=state-1"
    );
}

#[tokio::test]
async fn token_handler_accepts_form_payload() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/token")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=authorization_code&code=auth-code-1&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback&client_id=desktop-app&code_verifier=verifier-1",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["subject_account_id"], "acct-1");
}

#[tokio::test]
async fn logout_handler_uses_fixed_auth_path() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/auth/logout")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"refresh_token":"refresh-token"}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn refresh_rejects_legacy_time_fields_and_oversized_bodies() {
    let app = token_router(test_state(Arc::new(HappyAuthService)));
    let legacy_request = Request::builder()
        .uri("/auth/refresh")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"refresh_token":"refresh-token","rotated_at_unix_secs":0}"#,
        ))
        .unwrap();
    let legacy_response = app.clone().oneshot(legacy_request).await.unwrap();
    assert_eq!(legacy_response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let oversized = format!(r#"{{"refresh_token":"{}"}}"#, "x".repeat(17 * 1024));
    let oversized_request = Request::builder()
        .uri("/auth/refresh")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(oversized))
        .unwrap();
    let oversized_response = app.oneshot(oversized_request).await.unwrap();
    assert_eq!(oversized_response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn production_refresh_requires_the_exact_device_proof_headers() {
    let app = token_router(proof_bound_refresh_state());
    let missing_proof = Request::builder()
        .uri("/auth/refresh")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"refresh_token":"refresh-token"}"#))
        .unwrap();

    let response = app.oneshot(missing_proof).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "device_proof_required");
}

#[tokio::test]
async fn production_refresh_maps_committed_reuse_to_the_stable_public_code() {
    let app = token_router(proof_bound_refresh_state());
    let request = Request::builder()
        .uri("/auth/refresh")
        .method("POST")
        .header("content-type", "application/json")
        .header("x-device-id", "device-1")
        .header(
            "x-device-key-id",
            Base64UrlUnpadded::encode_string(&[1_u8; 32]),
        )
        .header(
            "x-device-challenge",
            Base64UrlUnpadded::encode_string(&[2_u8; 32]),
        )
        .header(
            "x-device-signature",
            Base64UrlUnpadded::encode_string(&[3_u8; 64]),
        )
        .header("x-device-signed-at", "1700000000")
        .body(Body::from(r#"{"refresh_token":"refresh-token"}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "refresh_token_reuse_detected");
}

#[tokio::test]
async fn device_challenge_endpoint_returns_the_nondisclosing_success_shape() {
    let app = public_router(proof_bound_device_state());
    let request = Request::builder()
        .uri("/device-proof/challenges")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"device_id":"device-1","purpose":"device_registration"}"#,
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["challenge"].as_str().unwrap().len(), 43);
    assert_eq!(json["expires_at_unix_secs"], 0);
}

#[tokio::test]
async fn production_provision_uses_server_time_and_returns_no_legacy_challenge() {
    let app = public_router(proof_bound_device_state());
    let request = Request::builder()
        .uri("/devices/provision")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"client_id":"desktop-app","device_name":"Laptop"}"#,
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.get("challenge").is_none());

    let caller_time = Request::builder()
        .uri("/devices/provision")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"client_id":"desktop-app","device_name":"Laptop","requested_at_unix_secs":0}"#,
        ))
        .unwrap();
    assert_eq!(
        app.oneshot(caller_time).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn production_device_registration_uses_public_jwk_without_caller_time() {
    let app = public_router(proof_bound_device_state());
    let request = Request::builder()
        .uri("/devices/complete")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"device_id":"device-1","public_jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{}"}},"challenge":"{}","signature":"{}"}}"#,
            Base64UrlUnpadded::encode_string(&[7_u8; 32]),
            Base64UrlUnpadded::encode_string(&[8_u8; 32]),
            Base64UrlUnpadded::encode_string(&[2_u8; 32]),
            Base64UrlUnpadded::encode_string(&[3_u8; 64]),
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["key_version"], 1);
    assert_eq!(json["key_status"], "active");
}

#[tokio::test]
async fn device_key_rotation_requires_authenticated_account_context() {
    let app = subject_router(proof_bound_device_state());
    let body = format!(
        r#"{{"device_id":"device-1","new_public_jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{}"}},"challenge":"{}","current_key_signature":"{}","new_key_signature":"{}"}}"#,
        Base64UrlUnpadded::encode_string(&[9_u8; 32]),
        Base64UrlUnpadded::encode_string(&[10_u8; 32]),
        Base64UrlUnpadded::encode_string(&[2_u8; 32]),
        Base64UrlUnpadded::encode_string(&[3_u8; 64]),
        Base64UrlUnpadded::encode_string(&[4_u8; 64]),
    );
    let missing_subject = Request::builder()
        .uri("/devices/rotate-key")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body.clone()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(missing_subject).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let authenticated = Request::builder()
        .uri("/devices/rotate-key")
        .method("POST")
        .header("content-type", "application/json")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .body(Body::from(body))
        .unwrap();
    let response = app.oneshot(authenticated).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["key_version"], 2);
}

#[tokio::test]
async fn jwks_handler_returns_json_keyset() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/jwks.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["etag"], "\"jwks-v1\"");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["keys"][0]["kid"], "kid-1");
    assert_eq!(json["keys"][0]["use"], "sig");
}

#[tokio::test]
async fn revoke_handler_accepts_form_payload() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/revoke")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "token=refresh-token&token_type_hint=refresh_token&client_id=desktop-app",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn user_info_handler_reads_bearer_token() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/userinfo")
        .method("GET")
        .header("authorization", "Bearer access-token")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sub"], "acct-1");
    assert_eq!(json["email"], "user@example.com");
}

#[tokio::test]
async fn introspection_handler_accepts_form_payload() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/introspect")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "token=access-token&token_type_hint=access_token&client_id=desktop-app",
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], true);
    assert_eq!(json["client_id"], "desktop-app");
    assert_eq!(json["sid"], "sess-1");
}

#[tokio::test]
async fn discovery_includes_resource_endpoints() {
    let app = router(test_state_with_route_mount_plan(
        RouteMountPlan::new("/api/v1"),
        Arc::new(HappyAuthService),
    ));

    let request = Request::builder()
        .uri("/.well-known/openid-configuration")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["authorization_endpoint"], "/api/v1/oidc/authorize");
    assert_eq!(json["token_endpoint"], "/api/v1/oidc/token");
    assert_eq!(json["userinfo_endpoint"], "/api/v1/oidc/userinfo");
    assert_eq!(json["introspection_endpoint"], "/api/v1/oidc/introspect");
    assert_eq!(json["registration_endpoint"], "/api/v1/auth/register");
    assert_eq!(
        json["device_provision_endpoint"],
        "/api/v1/devices/provision"
    );
    assert_eq!(json["devices_endpoint"], "/api/v1/devices");
    assert_eq!(json["device_unbind_endpoint"], "/api/v1/devices/unbind");
    assert!(json.get("device_disable_endpoint").is_none());
    assert!(json.get("device_revoke_endpoint").is_none());
}

#[tokio::test]
async fn authorize_handler_rejects_missing_authenticated_subject() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/authorize?response_type=code&client_id=desktop-app&redirect_uri=http://127.0.0.1:49152/callback")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "missing_authenticated_subject");
}

#[tokio::test]
async fn public_router_exposes_only_public_endpoints() {
    let app = public_router(test_state(Arc::new(HappyAuthService)));

    let register_request = Request::builder()
        .uri("/auth/register")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"user@example.com","password":"hash","display_name":"User","client_id":"desktop-app"}"#,
        ))
        .unwrap();
    let register_response = app.clone().oneshot(register_request).await.unwrap();
    assert_eq!(register_response.status(), StatusCode::ACCEPTED);

    let authorize_request = Request::builder()
        .uri("/oidc/authorize?response_type=code&client_id=desktop-app&redirect_uri=http://127.0.0.1:49152/callback")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let authorize_response = app.clone().oneshot(authorize_request).await.unwrap();
    assert_eq!(authorize_response.status(), StatusCode::NOT_FOUND);

    let disable_request = Request::builder()
        .uri("/devices/disable")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"device_id":"dev-1"}"#))
        .unwrap();
    let disable_response = app.oneshot(disable_request).await.unwrap();
    assert_eq!(disable_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn subject_router_exposes_subject_bound_endpoints() {
    let app = subject_router(test_state(Arc::new(HappyAuthService)));

    let list_request = Request::builder()
        .uri("/devices")
        .method("GET")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .body(Body::empty())
        .unwrap();
    let list_response = app.clone().oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);

    let authorize_request = Request::builder()
        .uri("/oidc/authorize?response_type=code&client_id=desktop-app&redirect_uri=http://127.0.0.1:49152/callback&state=state-1")
        .method("GET")
        .extension(AuthenticatedSubject::new("0", "acct-1"))
        .body(Body::empty())
        .unwrap();
    let authorize_response = app.clone().oneshot(authorize_request).await.unwrap();
    assert_eq!(authorize_response.status(), StatusCode::TEMPORARY_REDIRECT);

    let token_request = Request::builder()
        .uri("/oidc/token")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=authorization_code&code=auth-code-1&redirect_uri=http%3A%2F%2F127.0.0.1%3A49152%2Fcallback&client_id=desktop-app&code_verifier=verifier-1",
        ))
        .unwrap();
    let token_response = app.oneshot(token_request).await.unwrap();
    assert_eq!(token_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn subject_router_rejects_nonzero_legacy_tenant_context() {
    let app = subject_router(test_state(Arc::new(HappyAuthService)));
    let request = Request::builder()
        .uri("/devices")
        .method("GET")
        .extension(AuthenticatedSubject::new("tenant-a", "acct-1"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "unsupported_tenant");

    let app = subject_router(test_state(Arc::new(HappyAuthService)));
    let authorize = Request::builder()
        .uri("/oidc/authorize?response_type=code&client_id=desktop-app&redirect_uri=http://127.0.0.1:49152/callback")
        .method("GET")
        .extension(AuthenticatedSubject::new("tenant-a", "acct-1"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(authorize).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn token_and_client_routers_are_split_from_public_routes() {
    let token_app = token_router(test_state(Arc::new(HappyAuthService)));
    let refresh_request = Request::builder()
        .uri("/auth/refresh")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"refresh_token":"refresh-token"}"#))
        .unwrap();
    let refresh_response = token_app.clone().oneshot(refresh_request).await.unwrap();
    assert_eq!(refresh_response.status(), StatusCode::OK);

    let userinfo_request = Request::builder()
        .uri("/oidc/userinfo")
        .method("GET")
        .header("authorization", "Bearer access-token")
        .body(Body::empty())
        .unwrap();
    let userinfo_response = token_app.clone().oneshot(userinfo_request).await.unwrap();
    assert_eq!(userinfo_response.status(), StatusCode::OK);

    let public_request = Request::builder()
        .uri("/auth/register")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"user@example.com","password":"hash","display_name":"User","client_id":"desktop-app"}"#,
        ))
        .unwrap();
    let public_response = token_app.oneshot(public_request).await.unwrap();
    assert_eq!(public_response.status(), StatusCode::NOT_FOUND);

    let client_app = client_authenticated_router(test_state(Arc::new(HappyAuthService)));
    let introspect_request = Request::builder()
        .uri("/oidc/introspect")
        .method("POST")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "token=access-token&token_type_hint=access_token&client_id=desktop-app",
        ))
        .unwrap();
    let introspect_response = client_app
        .clone()
        .oneshot(introspect_request)
        .await
        .unwrap();
    assert_eq!(introspect_response.status(), StatusCode::OK);

    let list_request = Request::builder()
        .uri("/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let list_response = client_app.oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_router_exposes_only_management_endpoints() {
    let app = admin_router(test_state(Arc::new(HappyAuthService)));

    let list_accounts_request = Request::builder()
        .uri("/admin/accounts?status=active&limit=10&offset=0")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let list_accounts_response = app.clone().oneshot(list_accounts_request).await.unwrap();
    assert_eq!(list_accounts_response.status(), StatusCode::OK);
    let list_accounts_body = to_bytes(list_accounts_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_accounts_json: serde_json::Value =
        serde_json::from_slice(&list_accounts_body).unwrap();
    assert_eq!(list_accounts_json["page"]["limit"], 10);
    assert_eq!(list_accounts_json["page"]["returned"], 1);
    assert_eq!(list_accounts_json["page"]["total"], 1);
    assert_eq!(list_accounts_json["page"]["has_more"], false);

    let get_session_request = Request::builder()
        .uri("/admin/sessions/sess-1")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let get_session_response = app.clone().oneshot(get_session_request).await.unwrap();
    assert_eq!(get_session_response.status(), StatusCode::OK);

    let list_clients_request = Request::builder()
        .uri("/admin/clients?client_type=public_desktop&pkce_required=true")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let list_clients_response = app.clone().oneshot(list_clients_request).await.unwrap();
    assert_eq!(list_clients_response.status(), StatusCode::OK);

    let disable_request = Request::builder()
        .uri("/admin/devices/disable")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"device_id":"dev-1"}"#))
        .unwrap();
    let disable_response = app.clone().oneshot(disable_request).await.unwrap();
    assert_eq!(disable_response.status(), StatusCode::OK);

    let unbind_request = Request::builder()
        .uri("/admin/devices/unbind")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"account_id":"acct-1","device_id":"dev-1"}"#))
        .unwrap();
    let unbind_response = app.clone().oneshot(unbind_request).await.unwrap();
    assert_eq!(unbind_response.status(), StatusCode::OK);

    let register_request = Request::builder()
        .uri("/auth/register")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"user@example.com","password":"hash","display_name":"User","client_id":"desktop-app"}"#,
        ))
        .unwrap();
    let register_response = app.oneshot(register_request).await.unwrap();
    assert_eq!(register_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_router_rejects_unknown_filter_values() {
    let app = admin_router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/admin/accounts?status=unknown")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_router_rejects_invalid_cursor_values() {
    let app = admin_router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/admin/accounts?cursor=bad-cursor")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn admin_router_returns_next_cursor_for_account_lists() {
    let app = admin_router(test_state_with_admin_service(
        Arc::new(CursorAdminService),
        Arc::new(HappyAuthService),
    ));

    let first_request = Request::builder()
        .uri("/admin/accounts?limit=1")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let first_response = app.clone().oneshot(first_request).await.unwrap();
    assert_eq!(first_response.status(), StatusCode::OK);
    let first_body = to_bytes(first_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let first_json: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
    assert_eq!(first_json["page"]["next_cursor"], "10:acct-1");
    assert_eq!(first_json["page"]["has_more"], true);

    let second_request = Request::builder()
        .uri("/admin/accounts?limit=1&cursor=10:acct-1")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let second_response = app.oneshot(second_request).await.unwrap();
    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = to_bytes(second_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let second_json: serde_json::Value = serde_json::from_slice(&second_body).unwrap();
    assert_eq!(second_json["accounts"][0]["account_id"], "acct-2");
    assert_eq!(second_json["page"]["has_more"], false);
    assert!(second_json["page"]["next_cursor"].is_null());
}

#[tokio::test]
async fn device_subject_routes_reject_missing_authenticated_subject() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let list_request = Request::builder()
        .uri("/devices")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let list_response = app.oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_info_handler_rejects_missing_bearer_token() {
    let app = router(test_state(Arc::new(HappyAuthService)));

    let request = Request::builder()
        .uri("/oidc/userinfo")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "invalid_token");
}

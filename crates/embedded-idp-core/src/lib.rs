mod client_secret;
mod config;
mod device_proof;
mod domain;
mod module;
mod paging;
mod paths;
mod service;
mod store;
mod support;
mod token;

pub use client_secret::{
    ClientSecretError, ClientSecretHasher, ClientSecretVerifier, PhcClientSecretCodec,
};
pub use config::{AuthConfig, ConfigValidationError, DeviceConfig, EmbeddedIdpConfig, OidcConfig};
pub use device_proof::{
    validate_proof_freshness, DeviceProof, DeviceProofError, DeviceProofVerifier,
};
pub use domain::{
    Account, AccountDeviceBinding, AccountDeviceBindingStatus, AccountStatus, AuthSession,
    AuthorizationCodeRecord, ClientValidationError, DeviceNonceRecord, DeviceRecord, DeviceStatus,
    EmailVerificationCode, OidcClient, OidcClientType, PkceChallengeMethod, RefreshTokenRecord,
    SessionStatus,
};
pub use module::{DomainScope, ModuleDescriptor};
pub(crate) use paging::finalize_page;
pub use paging::{PageMetadata, PageRequest, TimePageCursor, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
pub use paths::{
    OIDC_API_PREFIX, OIDC_AUTHORIZE_PATH, OIDC_DISCOVERY_PATH, OIDC_INTROSPECT_PATH,
    OIDC_JWKS_PATH, OIDC_REVOKE_PATH, OIDC_TOKEN_PATH, OIDC_USERINFO_PATH,
};
pub use service::{
    ActivateAccountCommand, ActivateAccountResult, AdminClientRecord, AdminService, AuthService,
    BindDeviceToAccountCommand, BindDeviceToAccountResult, CompleteDeviceRegistrationCommand,
    CompleteDeviceRegistrationResult, ContractValidationError, CoreAdminService, CoreAuthService,
    CoreDeviceService, CoreOidcResourceService, CoreOidcService, CreateAccountCommand,
    CreateAccountResult, DeviceHeartbeatCommand, DeviceHeartbeatResult, DeviceService,
    DisableAccountCommand, DisableAccountResult, DisableDeviceCommand, DisableDeviceResult,
    ExchangeAuthorizationCodeCommand, ExchangeAuthorizationCodeResult, GetAccountCommand,
    GetAccountResult, GetClientCommand, GetClientResult, GetDeviceCommand, GetDeviceResult,
    GetSessionCommand, GetSessionResult, GetUserInfoCommand, GetUserInfoResult,
    IntrospectTokenCommand, IntrospectTokenResult, JsonWebKey, JwksDocument, ListAccountsCommand,
    ListAccountsResult, ListClientsCommand, ListClientsResult, ListDevicesCommand,
    ListDevicesResult, ListSessionsCommand, ListSessionsResult, LoginCommand, LoginResult,
    LogoutSessionCommand, LogoutSessionResult, OidcAuthorizationService, OidcMetadataService,
    PendingEmailVerification, ProvisionDeviceCommand, ProvisionDeviceResult,
    RegisterAccountCommand, RegisterAccountResult, ResendVerificationCodeCommand,
    ResendVerificationCodeResult, RevokeAccountSessionsCommand, RevokeAccountSessionsResult,
    RevokeDeviceCommand, RevokeDeviceResult, RevokeSessionCommand, RevokeSessionResult,
    RevokeTokenCommand, RevokeTokenResult, RotateRefreshTokenCommand, RotateRefreshTokenResult,
    ServiceError, SetAccountPasswordCommand, SetAccountPasswordResult, StartAuthorizationCommand,
    StartAuthorizationResult, StaticOidcMetadataService, TokenIntrospectionService,
    TokenManagementService, UnbindDeviceFromAccountCommand, UnbindDeviceFromAccountResult,
    UpsertClientCommand, UpsertClientResult, UserInfoService, VerifyEmailCommand,
    VerifyEmailResult,
};
pub use store::{
    AccountDeviceBindingStore, AccountListQuery, AccountStore, AuthorizationCodeStore,
    ClientListQuery, ClientStore, DeviceListQuery, DeviceNonceStore, DeviceStore,
    EmailVerificationStore, RefreshTokenStore, SessionListQuery, SessionStore, StoreError,
    StoreTransaction, StoreTransactionRunner,
};
pub use support::{
    Clock, IdGenerator, NumericVerificationCodeGenerator, SystemClock, UuidV7IdGenerator,
    VerificationCodeGenerator,
};
pub use token::{
    next_refresh_token_version, AccessTokenValidator, IdTokenClaims, IdTokenIssuer,
    IssuedTokenBundle, TokenError, TokenIssuer, ValidatedAccessToken,
};

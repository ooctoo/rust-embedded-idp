pub mod access;
mod client_secret;
mod config;
mod device_proof;
mod domain;
mod module;
mod paging;
mod paths;
mod secret;
mod security;
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
    Account, AccountDeviceBinding, AccountDeviceBindingId, AccountDeviceBindingStatus, AccountId,
    AccountStatus, AuthSession, AuthorizationCodeId, AuthorizationCodeRecord, ClientId,
    ClientValidationError, DeviceId, DeviceNonceId, DeviceNonceRecord, DeviceProofAlgorithm,
    DeviceProofChallengeRecord, DeviceProofKeyRecord, DeviceProofKeyStatus,
    DeviceProofKeyValidationError, DeviceRecord, DeviceStatus, EmailVerificationCode,
    EmailVerificationId, OidcClient, OidcClientType, PkceChallengeMethod, RefreshTokenId,
    RefreshTokenRecord, RefreshTokenRevocationReason, SessionId, SessionStatus,
};
pub use module::{DomainScope, ModuleDescriptor};
pub(crate) use paging::finalize_page;
pub use paging::{PageMetadata, PageRequest, TimePageCursor, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
pub use paths::{
    OIDC_API_PREFIX, OIDC_AUTHORIZE_PATH, OIDC_DISCOVERY_PATH, OIDC_INTROSPECT_PATH,
    OIDC_JWKS_PATH, OIDC_REVOKE_PATH, OIDC_TOKEN_PATH, OIDC_USERINFO_PATH,
};
pub use secret::SecretString;
pub use security::{
    build_device_key_rotation_proof_bytes, build_device_registration_proof_bytes,
    build_request_proof_bytes, decode_device_signature, digest_device_challenge,
    validate_external_path, CanonicalHttpMethod, DeviceChallengeGenerator, DeviceProofPresentation,
    DeviceProofProfile, DeviceProofPurpose, DevicePublicJwkParser, DevicePublicJwkValidator,
    DeviceRequestBinding, DeviceSignatureVerifier, RefreshTokenDigester, RefreshTokenGenerator,
    SecurityContractError, ValidatedDevicePublicJwk, VerifiedDeviceRequest,
    DEVICE_KEY_ROTATION_PURPOSE, DEVICE_REGISTRATION_PURPOSE, REFRESH_PURPOSE,
};
pub use service::{
    ActivateAccountCommand, ActivateAccountResult, AdminClientRecord, AdminService, AuthService,
    BindDeviceToAccountCommand, BindDeviceToAccountResult, CompleteDeviceKeyRegistrationCommand,
    CompleteDeviceKeyRegistrationResult, CompleteDeviceRegistrationCommand,
    CompleteDeviceRegistrationResult, ContractValidationError, CoreAdminService, CoreAuthService,
    CoreDeviceRequestVerificationService, CoreDeviceSecurityService, CoreDeviceService,
    CoreOidcResourceService, CoreOidcService, CoreProofBoundRefreshService, CreateAccountCommand,
    CreateAccountResult, DeviceHeartbeatCommand, DeviceHeartbeatResult,
    DeviceRequestVerificationError, DeviceRequestVerificationService,
    DeviceRequestVerificationTransaction, DeviceRequestVerificationTransactionRunner,
    DeviceSecurityError, DeviceSecurityService, DeviceSecurityTransaction,
    DeviceSecurityTransactionRunner, DeviceService, DisableAccountCommand, DisableAccountResult,
    DisableDeviceCommand, DisableDeviceResult, ExchangeAuthorizationCodeCommand,
    ExchangeAuthorizationCodeResult, GetAccountCommand, GetAccountResult, GetClientCommand,
    GetClientResult, GetDeviceCommand, GetDeviceResult, GetSessionCommand, GetSessionResult,
    GetUserInfoCommand, GetUserInfoResult, IntrospectTokenCommand, IntrospectTokenResult,
    IssueDeviceProofChallengeCommand, IssueDeviceProofChallengeResult, JsonWebKey, JwksDocument,
    ListAccountsCommand, ListAccountsResult, ListClientsCommand, ListClientsResult,
    ListDevicesCommand, ListDevicesResult, ListSessionsCommand, ListSessionsResult, LoginCommand,
    LoginResult, LogoutSessionCommand, LogoutSessionResult, OidcAuthorizationService,
    OidcMetadataService, PendingEmailVerification, ProofBoundRefreshError,
    ProofBoundRefreshService, ProofBoundRefreshTransaction, ProofBoundRefreshTransactionRunner,
    ProofBoundTokenResult, ProvisionDeviceCommand, ProvisionDeviceResult,
    ProvisionPendingDeviceCommand, ProvisionPendingDeviceResult, RegisterAccountCommand,
    RegisterAccountResult, ResendVerificationCodeCommand, ResendVerificationCodeResult,
    RevokeAccountSessionsCommand, RevokeAccountSessionsResult, RevokeDeviceCommand,
    RevokeDeviceResult, RevokeSessionCommand, RevokeSessionResult, RevokeTokenCommand,
    RevokeTokenResult, RotateDeviceProofKeyCommand, RotateDeviceProofKeyResult,
    RotateProofBoundRefreshCommand, RotateProofBoundRefreshOutcome, RotateRefreshTokenCommand,
    RotateRefreshTokenResult, ServiceError, SetAccountPasswordCommand, SetAccountPasswordResult,
    StartAuthorizationCommand, StartAuthorizationResult, StaticOidcMetadataService,
    TokenIntrospectionService, TokenManagementService, UnbindDeviceFromAccountCommand,
    UnbindDeviceFromAccountResult, UpsertClientCommand, UpsertClientResult, UserInfoService,
    VerifyDeviceRequestCommand, VerifyEmailCommand, VerifyEmailResult,
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
    digest_refresh_token, next_refresh_token_version, normalize_oauth_scope, AccessTokenIssuer,
    AccessTokenPurpose, AccessTokenValidator, IdTokenClaims, IdTokenIssuer, IssuedAccessToken,
    IssuedTokenBundle, ScopedAccessTokenIssuer, TokenError, TokenIssuer, ValidatedAccessToken,
};

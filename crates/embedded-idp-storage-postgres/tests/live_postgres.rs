use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use embedded_idp_core::{
    AccountStatus, AdminService, AuthConfig, AuthService, ClientSecretError, ClientSecretVerifier,
    Clock, CoreAdminService, CoreAuthService, CoreDeviceService, CoreOidcService, DeviceConfig,
    DeviceHeartbeatCommand, DeviceProof, DeviceProofError, DeviceProofVerifier, DeviceService,
    DeviceStatus, ExchangeAuthorizationCodeCommand, IdGenerator, IdTokenClaims, IdTokenIssuer,
    IssuedTokenBundle, ListAccountsCommand, ListClientsCommand, ListDevicesCommand,
    ListSessionsCommand, LoginCommand, LogoutSessionCommand, OidcAuthorizationService,
    OidcClientType, OidcConfig, PageRequest, PhcClientSecretCodec, RegisterAccountCommand,
    RevokeTokenCommand, RotateRefreshTokenCommand, SessionStatus, StartAuthorizationCommand,
    TimePageCursor, TokenError, TokenIssuer, TokenManagementService, UuidV7IdGenerator,
    VerificationCodeGenerator, VerifyEmailCommand,
};
use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresStorageAdapter,
};
use postgres::{Client, NoTls};
use uuid::Uuid;

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
}

struct AtomicIds;

impl AtomicIds {
    fn new() -> Self {
        Self
    }

    fn starting_from(_start: u64) -> Self {
        Self
    }
}

impl IdGenerator for AtomicIds {
    fn next_id(&self, prefix: &str) -> String {
        UuidV7IdGenerator.next_id(prefix)
    }
}

struct FixedVerificationCodes;

impl VerificationCodeGenerator for FixedVerificationCodes {
    fn generate_code(&self) -> String {
        "123456".to_string()
    }
}

struct TestTokenIssuer;

impl TokenIssuer for TestTokenIssuer {
    fn issue_session_tokens(
        &self,
        session_id: &str,
        account_id: &str,
        client_id: &str,
        refresh_token_version: u64,
        issued_at: SystemTime,
    ) -> Result<IssuedTokenBundle, TokenError> {
        Ok(IssuedTokenBundle {
            access_token: format!("access:{session_id}:{account_id}:{client_id}"),
            refresh_token: format!("refresh:{session_id}:{refresh_token_version}"),
            access_expires_at: issued_at + Duration::from_secs(900),
            refresh_expires_at: issued_at + Duration::from_secs(86_400),
            refresh_token_version,
        })
    }
}

struct TestDeviceProofVerifier;

impl DeviceProofVerifier for TestDeviceProofVerifier {
    fn verify(
        &self,
        proof: &DeviceProof,
        _observed_at: SystemTime,
        _allowed_skew_secs: u64,
    ) -> Result<(), DeviceProofError> {
        if proof.signature == "reject" {
            return Err(DeviceProofError::VerifierRejected);
        }
        Ok(())
    }
}

struct TestIdTokenIssuer;

impl IdTokenIssuer for TestIdTokenIssuer {
    fn issue_id_token(&self, claims: &IdTokenClaims) -> Result<String, TokenError> {
        Ok(format!(
            "id:{}:{}:{}",
            claims.subject_account_id, claims.audience, claims.issuer
        ))
    }
}

struct TestClientSecretVerifier;

impl ClientSecretVerifier for TestClientSecretVerifier {
    fn verify_client_secret(
        &self,
        provided_secret: &str,
        stored_secret_hash: &str,
    ) -> Result<bool, ClientSecretError> {
        Ok(stored_secret_hash == format!("hash:{provided_secret}"))
    }
}

struct LiveHarness {
    connection_uri: String,
    schema_name: String,
    adapter: PostgresStorageAdapter,
}

impl LiveHarness {
    fn new() -> Self {
        let connection_uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
            .expect("set EMBEDDED_IDP_TEST_PG_CONNECTION_URI");
        let schema_name = format!("embedded_idp_it_{}", unique_suffix());
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: connection_uri.clone(),
                schema_name: schema_name.clone(),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "embedded-idp-live-tests".to_string(),
                max_connections: 4,
                connect_timeout_secs: 5,
            },
        })
        .expect("valid test postgres config");

        adapter.apply_migrations().expect("apply test migrations");
        let harness = Self {
            connection_uri,
            schema_name,
            adapter,
        };
        harness.seed_default_client();
        harness
    }

    fn adapter(&self) -> PostgresStorageAdapter {
        self.adapter.clone()
    }

    fn seed_default_client(&self) {
        let mut client = Client::connect(&self.connection_uri, NoTls).expect("connect seed client");
        let sql = format!(
            "insert into {}.oidc_clients \
             (client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash, created_at_epoch) \
             values ($1, $2, $3, $4, $5, $6, $7)",
            self.schema_name
        );
        client
            .execute(
                &sql,
                &[
                    &"desktop-app",
                    &"Desktop App",
                    &serde_json::to_string(&vec!["http://127.0.0.1:49152/callback"])
                        .expect("serialize redirect uris"),
                    &"public_desktop",
                    &true,
                    &Option::<String>::None,
                    &1_700_000_000_i64,
                ],
            )
            .expect("seed oidc client");
    }

    fn seed_confidential_client(&self) {
        let mut client = Client::connect(&self.connection_uri, NoTls).expect("connect seed client");
        let sql = format!(
            "insert into {}.oidc_clients \
             (client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash, created_at_epoch) \
             values ($1, $2, $3, $4, $5, $6, $7)",
            self.schema_name
        );
        client
            .execute(
                &sql,
                &[
                    &"web-app",
                    &"Web App",
                    &serde_json::to_string(&vec!["https://example.com/callback"])
                        .expect("serialize confidential redirect uris"),
                    &"confidential_web",
                    &false,
                    &Some("hash:top-secret".to_string()),
                    &1_700_000_000_i64,
                ],
            )
            .expect("seed confidential oidc client");
    }
}

impl Drop for LiveHarness {
    fn drop(&mut self) {
        if let Ok(mut client) = Client::connect(&self.connection_uri, NoTls) {
            let drop_sql = format!("drop schema if exists {} cascade", self.schema_name);
            let _ = client.batch_execute(&drop_sql);
        }
    }
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos()
}

#[test]
#[ignore = "requires a live local postgres instance"]
fn runs_auth_and_device_flow_against_live_postgres() {
    let harness = LiveHarness::new();
    let auth_service = CoreAuthService::new(
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86_400,
            session_ttl_secs: 604_800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        },
        harness.adapter(),
        TestTokenIssuer,
        FixedClock,
        AtomicIds::new(),
        FixedVerificationCodes,
    );
    let device_service = CoreDeviceService::new(
        DeviceConfig {
            nonce_ttl_secs: 300,
            proof_clock_skew_secs: 30,
            heartbeat_grace_period_secs: 60,
        },
        harness.adapter(),
        TestDeviceProofVerifier,
        AtomicIds::new(),
    );
    let oidc_service = CoreOidcService::new(
        "http://127.0.0.1:8080".to_string(),
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86_400,
            session_ttl_secs: 604_800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        },
        OidcConfig {
            authorization_code_ttl_secs: 300,
            require_pkce_for_public_clients: true,
        },
        harness.adapter(),
        TestTokenIssuer,
        TestIdTokenIssuer,
        TestClientSecretVerifier,
        FixedClock,
        AtomicIds::starting_from(10_000),
    );

    let registered = auth_service
        .register_account(RegisterAccountCommand {
            email: "user@example.com".to_string(),
            password: "demo-password".to_string(),
            display_name: Some("Demo User".to_string()),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("register account");
    assert_eq!(registered.account.email, "user@example.com");
    let verified = auth_service
        .verify_email(VerifyEmailCommand {
            email: "user@example.com".to_string(),
            verification_code: registered.verification.code.clone(),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("verify email");
    assert_eq!(verified.session.refresh_token_version, 0);

    let provisioned_login_device = device_service
        .provision_device(embedded_idp_core::ProvisionDeviceCommand {
            client_id: "desktop-app".to_string(),
            device_name: "Integration Laptop".to_string(),
            requested_at: FixedClock.now(),
        })
        .expect("provision login device");
    assert_eq!(
        provisioned_login_device.device.status,
        embedded_idp_core::DeviceStatus::Pending
    );

    let login_device = device_service
        .complete_device_registration(embedded_idp_core::CompleteDeviceRegistrationCommand {
            device_id: provisioned_login_device.device.id.clone(),
            proof: DeviceProof {
                key_id: "proof-key-1".to_string(),
                challenge: provisioned_login_device.nonce.challenge.clone(),
                signature: "ok".to_string(),
                signed_at: FixedClock.now(),
            },
            completed_at: FixedClock.now(),
        })
        .expect("complete login device");
    assert_eq!(
        login_device.device.status,
        embedded_idp_core::DeviceStatus::Active
    );

    let logged_in = auth_service
        .login(LoginCommand {
            email: "user@example.com".to_string(),
            password: "demo-password".to_string(),
            client_id: "desktop-app".to_string(),
            device_id: Some(login_device.device.id.clone()),
        })
        .expect("login");
    assert_eq!(logged_in.account.id, registered.account.id);
    assert_eq!(
        logged_in.session.device_id,
        Some(login_device.device.id.clone())
    );

    let rotated = auth_service
        .rotate_refresh_token(RotateRefreshTokenCommand {
            refresh_token: logged_in.tokens.refresh_token.clone(),
            rotated_at: FixedClock.now(),
        })
        .expect("rotate refresh token");
    assert_eq!(rotated.session.refresh_token_version, 1);
    assert_eq!(
        rotated.session.device_id,
        Some(login_device.device.id.clone())
    );

    let heartbeat = device_service
        .heartbeat(DeviceHeartbeatCommand {
            device_id: login_device.device.id.clone(),
            observed_at: FixedClock.now(),
        })
        .expect("device heartbeat");
    assert_eq!(
        heartbeat.device.last_seen_at,
        Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
    );

    let provisioned = device_service
        .provision_device(embedded_idp_core::ProvisionDeviceCommand {
            client_id: "desktop-app".to_string(),
            device_name: "Shared Terminal".to_string(),
            requested_at: FixedClock.now(),
        })
        .expect("provision device");
    assert_eq!(
        provisioned.device.status,
        embedded_idp_core::DeviceStatus::Pending
    );

    let completed = device_service
        .complete_device_registration(embedded_idp_core::CompleteDeviceRegistrationCommand {
            device_id: provisioned.device.id.clone(),
            proof: DeviceProof {
                key_id: "proof-key-2".to_string(),
                challenge: provisioned.nonce.challenge.clone(),
                signature: "ok".to_string(),
                signed_at: FixedClock.now(),
            },
            completed_at: FixedClock.now(),
        })
        .expect("complete provisioned device");
    assert_eq!(
        completed.device.status,
        embedded_idp_core::DeviceStatus::Active
    );
    let provisioned_device_id = provisioned.device.id.clone();

    let bound = device_service
        .bind_device_to_account(embedded_idp_core::BindDeviceToAccountCommand {
            account_id: registered.account.id.clone(),
            device_id: provisioned_device_id.clone(),
            bound_at: FixedClock.now(),
        })
        .expect("bind device to account");
    assert_eq!(bound.binding.account_id, registered.account.id);

    let listed = device_service
        .list_devices(embedded_idp_core::ListDevicesCommand {
            account_id: Some(registered.account.id.clone()),
            ..Default::default()
        })
        .expect("list devices for account");
    assert_eq!(listed.devices.len(), 2);

    let fetched = device_service
        .get_device(embedded_idp_core::GetDeviceCommand {
            device_id: login_device.device.id.clone(),
        })
        .expect("get device");
    assert_eq!(fetched.device.id, login_device.device.id);
    assert_eq!(fetched.bindings.len(), 1);

    let unbound = device_service
        .unbind_device_from_account(embedded_idp_core::UnbindDeviceFromAccountCommand {
            account_id: registered.account.id.clone(),
            device_id: login_device.device.id.clone(),
            unbound_at: FixedClock.now(),
        })
        .expect("unbind device");
    assert_eq!(
        unbound.binding.status,
        embedded_idp_core::AccountDeviceBindingStatus::Unbound
    );

    let disabled = device_service
        .disable_device(embedded_idp_core::DisableDeviceCommand {
            device_id: login_device.device.id,
        })
        .expect("disable device");
    assert_eq!(
        disabled.device.status,
        embedded_idp_core::DeviceStatus::Disabled
    );

    let revoked = device_service
        .revoke_device(embedded_idp_core::RevokeDeviceCommand {
            device_id: provisioned_device_id,
        })
        .expect("revoke device");
    assert_eq!(
        revoked.device.status,
        embedded_idp_core::DeviceStatus::Revoked
    );

    let authorization = oidc_service
        .start_authorization(StartAuthorizationCommand {
            subject_account_id: registered.account.id.clone(),
            response_type: "code".to_string(),
            client_id: "desktop-app".to_string(),
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            scope: Some("openid profile".to_string()),
            state: Some("state-1".to_string()),
            code_challenge: Some("verifier-1".to_string()),
            code_challenge_method: Some("plain".to_string()),
            nonce: Some("nonce-1".to_string()),
        })
        .expect("start authorization");
    let authorization_code_uuid = Uuid::parse_str(&authorization.authorization_code)
        .expect("authorization code should be uuid");
    assert_eq!(authorization_code_uuid.get_version_num(), 7);

    let exchanged = oidc_service
        .exchange_authorization_code(ExchangeAuthorizationCodeCommand {
            grant_type: "authorization_code".to_string(),
            code: authorization.authorization_code,
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            client_id: "desktop-app".to_string(),
            client_secret: None,
            code_verifier: Some("verifier-1".to_string()),
        })
        .expect("exchange authorization code");
    assert_eq!(exchanged.subject_account_id, registered.account.id);
    assert_eq!(
        exchanged.id_token,
        Some(format!(
            "id:{}:desktop-app:http://127.0.0.1:8080",
            registered.account.id
        ))
    );

    let revoked = oidc_service
        .revoke_token(RevokeTokenCommand {
            token: exchanged.tokens.refresh_token,
            token_type_hint: Some("refresh_token".to_string()),
            client_id: "desktop-app".to_string(),
            client_secret: None,
            revoked_at: FixedClock.now(),
        })
        .expect("revoke token");
    assert!(revoked.revoked);

    let logged_out = auth_service
        .logout(LogoutSessionCommand {
            refresh_token: rotated.tokens.refresh_token,
            logged_out_at: FixedClock.now(),
        })
        .expect("logout");
    assert_eq!(
        logged_out.session.status,
        embedded_idp_core::SessionStatus::Revoked
    );
}

#[test]
#[ignore = "requires a live local postgres instance"]
fn confidential_client_flow_requires_secret_against_live_postgres() {
    let harness = LiveHarness::new();
    harness.seed_confidential_client();
    let oidc_service = CoreOidcService::new(
        "http://127.0.0.1:8080".to_string(),
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86_400,
            session_ttl_secs: 604_800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        },
        OidcConfig {
            authorization_code_ttl_secs: 300,
            require_pkce_for_public_clients: true,
        },
        harness.adapter(),
        TestTokenIssuer,
        TestIdTokenIssuer,
        TestClientSecretVerifier,
        FixedClock,
        AtomicIds::starting_from(20_000),
    );
    let auth_service = CoreAuthService::new(
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86_400,
            session_ttl_secs: 604_800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        },
        harness.adapter(),
        TestTokenIssuer,
        FixedClock,
        AtomicIds::starting_from(30_000),
        FixedVerificationCodes,
    );
    let registered = auth_service
        .register_account(RegisterAccountCommand {
            email: "confidential@example.com".to_string(),
            password: "demo-password".to_string(),
            display_name: Some("Confidential User".to_string()),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("register account");
    auth_service
        .verify_email(VerifyEmailCommand {
            email: "confidential@example.com".to_string(),
            verification_code: registered.verification.code.clone(),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("verify confidential account email");

    let authorization = oidc_service
        .start_authorization(StartAuthorizationCommand {
            subject_account_id: registered.account.id.clone(),
            response_type: "code".to_string(),
            client_id: "web-app".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid profile".to_string()),
            state: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: Some("nonce-1".to_string()),
        })
        .expect("start authorization");

    let missing_secret =
        oidc_service.exchange_authorization_code(ExchangeAuthorizationCodeCommand {
            grant_type: "authorization_code".to_string(),
            code: authorization.authorization_code.clone(),
            redirect_uri: "https://example.com/callback".to_string(),
            client_id: "web-app".to_string(),
            client_secret: None,
            code_verifier: None,
        });
    assert_eq!(
        missing_secret,
        Err(embedded_idp_core::ServiceError::ClientAuthenticationRequired)
    );

    let exchanged = oidc_service
        .exchange_authorization_code(ExchangeAuthorizationCodeCommand {
            grant_type: "authorization_code".to_string(),
            code: authorization.authorization_code,
            redirect_uri: "https://example.com/callback".to_string(),
            client_id: "web-app".to_string(),
            client_secret: Some("top-secret".to_string()),
            code_verifier: None,
        })
        .expect("confidential token exchange should succeed");

    assert_eq!(
        exchanged.id_token,
        Some(format!(
            "id:{}:web-app:http://127.0.0.1:8080",
            registered.account.id
        ))
    );
}

#[test]
#[ignore = "requires a live local postgres instance"]
fn duplicate_email_hits_real_storage_constraint_path() {
    let harness = LiveHarness::new();
    let auth_service = CoreAuthService::new(
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86_400,
            session_ttl_secs: 604_800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        },
        harness.adapter(),
        TestTokenIssuer,
        FixedClock,
        AtomicIds::new(),
        FixedVerificationCodes,
    );

    auth_service
        .register_account(RegisterAccountCommand {
            email: "duplicate@example.com".to_string(),
            password: "demo-password".to_string(),
            display_name: None,
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("first registration should succeed");

    let duplicate = auth_service.register_account(RegisterAccountCommand {
        email: "duplicate@example.com".to_string(),
        password: "demo-password".to_string(),
        display_name: None,
        client_id: "desktop-app".to_string(),
        device_id: None,
    });

    assert_eq!(
        duplicate,
        Err(embedded_idp_core::ServiceError::EmailAlreadyExists)
    );
}

#[test]
#[ignore = "requires a live local postgres instance"]
fn admin_list_queries_support_filters_and_paging_against_live_postgres() {
    let harness = LiveHarness::new();
    harness.seed_confidential_client();

    let auth_config = AuthConfig {
        allow_local_registration: true,
        access_token_ttl_secs: 900,
        refresh_token_ttl_secs: 86_400,
        session_ttl_secs: 604_800,
        verification_code_ttl_secs: 900,
        password_min_length: 8,
        password_max_length: 128,
    };
    let auth_service = CoreAuthService::new(
        auth_config.clone(),
        harness.adapter(),
        TestTokenIssuer,
        FixedClock,
        AtomicIds::starting_from(40_000),
        FixedVerificationCodes,
    );
    let admin_service = CoreAdminService::new(auth_config, harness.adapter(), PhcClientSecretCodec);
    let device_service = CoreDeviceService::new(
        DeviceConfig {
            nonce_ttl_secs: 300,
            proof_clock_skew_secs: 30,
            heartbeat_grace_period_secs: 60,
        },
        harness.adapter(),
        TestDeviceProofVerifier,
        AtomicIds::starting_from(50_000),
    );

    let first = auth_service
        .register_account(RegisterAccountCommand {
            email: "alpha@example.com".to_string(),
            password: "demo-password".to_string(),
            display_name: Some("Alpha".to_string()),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("register first account");
    auth_service
        .verify_email(VerifyEmailCommand {
            email: "alpha@example.com".to_string(),
            verification_code: first.verification.code.clone(),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("verify first account");
    let second = auth_service
        .register_account(RegisterAccountCommand {
            email: "beta@example.com".to_string(),
            password: "demo-password".to_string(),
            display_name: Some("Beta".to_string()),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("register second account");
    auth_service
        .verify_email(VerifyEmailCommand {
            email: "beta@example.com".to_string(),
            verification_code: second.verification.code.clone(),
            client_id: "desktop-app".to_string(),
            device_id: None,
        })
        .expect("verify second account");
    assert_ne!(first.account.id, second.account.id);

    let provisioned = device_service
        .provision_device(embedded_idp_core::ProvisionDeviceCommand {
            client_id: "desktop-app".to_string(),
            device_name: "Admin Query Device".to_string(),
            requested_at: FixedClock.now(),
        })
        .expect("provision device");
    let completed = device_service
        .complete_device_registration(embedded_idp_core::CompleteDeviceRegistrationCommand {
            device_id: provisioned.device.id.clone(),
            proof: DeviceProof {
                key_id: "admin-query-key".to_string(),
                challenge: provisioned.nonce.challenge.clone(),
                signature: "ok".to_string(),
                signed_at: FixedClock.now(),
            },
            completed_at: FixedClock.now(),
        })
        .expect("complete device");
    device_service
        .bind_device_to_account(embedded_idp_core::BindDeviceToAccountCommand {
            account_id: first.account.id.clone(),
            device_id: completed.device.id.clone(),
            bound_at: FixedClock.now(),
        })
        .expect("bind device");

    let accounts = admin_service
        .list_accounts(ListAccountsCommand {
            status: Some(AccountStatus::Active),
            email: Some("alpha@".to_string()),
            page: PageRequest {
                limit: 10,
                offset: 0,
            },
            ..Default::default()
        })
        .expect("list filtered accounts");
    assert_eq!(accounts.accounts.len(), 1);
    assert_eq!(accounts.accounts[0].email, "alpha@example.com");
    assert_eq!(accounts.page.returned, 1);
    assert_eq!(accounts.page.total, 1);

    let first_account_page = admin_service
        .list_accounts(ListAccountsCommand {
            page: PageRequest {
                limit: 1,
                offset: 0,
            },
            ..Default::default()
        })
        .expect("list first account page");
    assert_eq!(first_account_page.accounts.len(), 1);
    assert_eq!(first_account_page.page.total, 2);
    assert!(first_account_page.page.has_more);

    let second_account_page = admin_service
        .list_accounts(ListAccountsCommand {
            cursor: Some(TimePageCursor {
                sort_time: first_account_page.accounts[0].created_at,
                entity_id: first_account_page.accounts[0].id.clone(),
            }),
            page: PageRequest {
                limit: 1,
                offset: 0,
            },
            ..Default::default()
        })
        .expect("list second account page");
    assert_eq!(second_account_page.accounts.len(), 1);
    assert_eq!(second_account_page.page.total, 2);
    assert!(!second_account_page.page.has_more);
    assert_ne!(
        second_account_page.accounts[0].id,
        first_account_page.accounts[0].id
    );

    let sessions = admin_service
        .list_sessions(ListSessionsCommand {
            account_id: Some(first.account.id.clone()),
            status: Some(SessionStatus::Active),
            client_id: Some("desktop-app".to_string()),
            page: PageRequest {
                limit: 10,
                offset: 0,
            },
            ..Default::default()
        })
        .expect("list filtered sessions");
    assert_eq!(sessions.sessions.len(), 1);
    assert_eq!(sessions.sessions[0].account_id, first.account.id);
    assert_eq!(sessions.page.total, 1);

    let clients = admin_service
        .list_clients(ListClientsCommand {
            client_type: Some(OidcClientType::ConfidentialWeb),
            pkce_required: Some(false),
            page: PageRequest {
                limit: 1,
                offset: 0,
            },
        })
        .expect("list filtered clients");
    assert_eq!(clients.clients.len(), 1);
    assert_eq!(clients.clients[0].client_id, "web-app");
    assert_eq!(clients.page.total, 1);
    assert!(!clients.page.has_more);

    let first_client_page = admin_service
        .list_clients(ListClientsCommand {
            page: PageRequest {
                limit: 1,
                offset: 0,
            },
            ..Default::default()
        })
        .expect("list paged clients");
    assert_eq!(first_client_page.clients.len(), 1);
    assert_eq!(first_client_page.page.total, 2);
    assert!(first_client_page.page.has_more);

    let devices = device_service
        .list_devices(ListDevicesCommand {
            account_id: Some(first.account.id.clone()),
            client_id: Some("desktop-app".to_string()),
            status: Some(DeviceStatus::Active),
            page: PageRequest {
                limit: 10,
                offset: 0,
            },
            ..Default::default()
        })
        .expect("list filtered devices");
    assert_eq!(devices.devices.len(), 1);
    assert_eq!(devices.devices[0].id, completed.device.id);
    assert_eq!(devices.page.total, 1);
}

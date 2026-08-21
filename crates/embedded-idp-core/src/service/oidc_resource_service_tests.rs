use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use crate::{
    AccessTokenValidator, Account, AccountDeviceBinding, AccountDeviceBindingStore, AccountStatus,
    AccountStore, AuthSession, AuthorizationCodeRecord, AuthorizationCodeStore, ClientSecretError,
    ClientSecretVerifier, ClientStore, CoreOidcResourceService, DeviceNonceRecord,
    DeviceNonceStore, DeviceRecord, DeviceStore, EmailVerificationCode, EmailVerificationStore,
    GetUserInfoCommand, IntrospectTokenCommand, OidcClient, OidcClientType, RefreshTokenRecord,
    RefreshTokenStore, ServiceError, SessionStatus, SessionStore, StoreError,
    StoreTransactionRunner, TokenError, TokenIntrospectionService, UserInfoService,
    ValidatedAccessToken,
};

#[derive(Default)]
struct TestStoreState {
    accounts: HashMap<String, Account>,
    sessions: HashMap<String, AuthSession>,
    refresh_tokens: HashMap<[u8; 32], RefreshTokenRecord>,
}

#[derive(Default)]
struct TestStoreRunner {
    state: Mutex<TestStoreState>,
}

struct TestStoreTx<'a> {
    state: MutexGuard<'a, TestStoreState>,
}

impl StoreTransactionRunner for TestStoreRunner {
    type Transaction<'a>
        = TestStoreTx<'a>
    where
        Self: 'a;

    fn transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut tx = TestStoreTx {
            state: self.state.lock().unwrap(),
        };
        run(&mut tx)
    }
}

impl AccountStore for TestStoreTx<'_> {
    fn find_account(&mut self, account_id: &str) -> Result<Option<Account>, StoreError> {
        Ok(self.state.accounts.get(account_id).cloned())
    }

    fn list_accounts(&mut self) -> Result<Vec<Account>, StoreError> {
        Ok(self.state.accounts.values().cloned().collect())
    }

    fn list_accounts_by_query(
        &mut self,
        _query: &crate::AccountListQuery,
    ) -> Result<Vec<Account>, StoreError> {
        self.list_accounts()
    }

    fn count_accounts_by_query(
        &mut self,
        _query: &crate::AccountListQuery,
    ) -> Result<u64, StoreError> {
        Ok(self.state.accounts.len() as u64)
    }

    fn find_by_email(&mut self, _email: &str) -> Result<Option<Account>, StoreError> {
        Ok(None)
    }

    fn insert_account(&mut self, _account: Account) -> Result<Account, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn update_account(&mut self, _account: Account) -> Result<Account, StoreError> {
        unreachable!("not needed in resource service tests")
    }
}

impl SessionStore for TestStoreTx<'_> {
    fn find_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError> {
        Ok(self.state.sessions.get(session_id).cloned())
    }

    fn list_sessions(&mut self, account_id: Option<&str>) -> Result<Vec<AuthSession>, StoreError> {
        Ok(self
            .state
            .sessions
            .values()
            .filter(|session| account_id.is_none_or(|account_id| session.account_id == account_id))
            .cloned()
            .collect())
    }

    fn list_sessions_by_query(
        &mut self,
        query: &crate::SessionListQuery,
    ) -> Result<Vec<AuthSession>, StoreError> {
        self.list_sessions(query.account_id.as_deref())
    }

    fn count_sessions_by_query(
        &mut self,
        query: &crate::SessionListQuery,
    ) -> Result<u64, StoreError> {
        Ok(self
            .state
            .sessions
            .values()
            .filter(|session| {
                query
                    .account_id
                    .as_deref()
                    .is_none_or(|account_id| session.account_id == account_id)
            })
            .count() as u64)
    }

    fn insert_session(&mut self, _session: AuthSession) -> Result<AuthSession, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn update_session(&mut self, _session: AuthSession) -> Result<AuthSession, StoreError> {
        unreachable!("not needed in resource service tests")
    }
}

impl DeviceStore for TestStoreTx<'_> {
    fn find_device(&mut self, _device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
        Ok(None)
    }

    fn list_devices(&mut self) -> Result<Vec<DeviceRecord>, StoreError> {
        Ok(Vec::new())
    }

    fn list_devices_by_query(
        &mut self,
        _query: &crate::DeviceListQuery,
    ) -> Result<Vec<DeviceRecord>, StoreError> {
        Ok(Vec::new())
    }

    fn count_devices_by_query(
        &mut self,
        _query: &crate::DeviceListQuery,
    ) -> Result<u64, StoreError> {
        Ok(0)
    }

    fn find_device_by_proof_key_id(
        &mut self,
        _proof_key_id: &str,
    ) -> Result<Option<DeviceRecord>, StoreError> {
        Ok(None)
    }

    fn insert_device(&mut self, _device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn update_device(&mut self, _device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
        unreachable!("not needed in resource service tests")
    }
}

impl AccountDeviceBindingStore for TestStoreTx<'_> {
    fn find_active_account_device_binding(
        &mut self,
        _account_id: &str,
        _device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError> {
        Ok(None)
    }

    fn list_account_device_bindings_by_device(
        &mut self,
        _device_id: &str,
    ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
        Ok(Vec::new())
    }

    fn list_active_account_device_bindings_by_account(
        &mut self,
        _account_id: &str,
    ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
        Ok(Vec::new())
    }

    fn insert_account_device_binding(
        &mut self,
        _binding: AccountDeviceBinding,
    ) -> Result<AccountDeviceBinding, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn update_account_device_binding(
        &mut self,
        _binding: AccountDeviceBinding,
    ) -> Result<AccountDeviceBinding, StoreError> {
        unreachable!("not needed in resource service tests")
    }
}

impl DeviceNonceStore for TestStoreTx<'_> {
    fn find_device_nonce(
        &mut self,
        _challenge: &str,
    ) -> Result<Option<DeviceNonceRecord>, StoreError> {
        Ok(None)
    }

    fn insert_device_nonce(
        &mut self,
        _nonce: DeviceNonceRecord,
    ) -> Result<DeviceNonceRecord, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn consume_device_nonce(
        &mut self,
        _challenge: &str,
        _consumed_at: SystemTime,
    ) -> Result<Option<DeviceNonceRecord>, StoreError> {
        unreachable!("not needed in resource service tests")
    }
}

impl ClientStore for TestStoreTx<'_> {
    fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
        let client = match client_id {
            "web-app" => OidcClient {
                client_id: client_id.to_string(),
                client_name: "Web App".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                client_type: OidcClientType::ConfidentialWeb,
                pkce_required: false,
                client_secret_hash: Some("hash:top-secret".to_string()),
            },
            _ => OidcClient {
                client_id: client_id.to_string(),
                client_name: "Desktop App".to_string(),
                redirect_uris: vec!["http://127.0.0.1:49152/callback".to_string()],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret_hash: None,
            },
        };
        Ok(Some(client))
    }

    fn list_clients(&mut self) -> Result<Vec<OidcClient>, StoreError> {
        Ok(vec![
            OidcClient {
                client_id: "desktop-app".to_string(),
                client_name: "Desktop App".to_string(),
                redirect_uris: vec!["http://127.0.0.1:49152/callback".to_string()],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret_hash: None,
            },
            OidcClient {
                client_id: "web-app".to_string(),
                client_name: "Web App".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                client_type: OidcClientType::ConfidentialWeb,
                pkce_required: false,
                client_secret_hash: Some("hash:top-secret".to_string()),
            },
        ])
    }

    fn list_clients_by_query(
        &mut self,
        _query: &crate::ClientListQuery,
    ) -> Result<Vec<OidcClient>, StoreError> {
        self.list_clients()
    }

    fn count_clients_by_query(
        &mut self,
        _query: &crate::ClientListQuery,
    ) -> Result<u64, StoreError> {
        Ok(2)
    }

    fn upsert_client(&mut self, client: OidcClient) -> Result<OidcClient, StoreError> {
        Ok(client)
    }
}

impl AuthorizationCodeStore for TestStoreTx<'_> {
    fn find_authorization_code(
        &mut self,
        _code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
        Ok(None)
    }

    fn insert_authorization_code(
        &mut self,
        _code: AuthorizationCodeRecord,
    ) -> Result<AuthorizationCodeRecord, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn consume_authorization_code(
        &mut self,
        _code: &str,
        _consumed_at: SystemTime,
    ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
        unreachable!("not needed in resource service tests")
    }
}

impl EmailVerificationStore for TestStoreTx<'_> {
    fn find_email_verification_code(
        &mut self,
        _email: &str,
        _code: &str,
    ) -> Result<Option<EmailVerificationCode>, StoreError> {
        Ok(None)
    }

    fn insert_email_verification_code(
        &mut self,
        verification: EmailVerificationCode,
    ) -> Result<EmailVerificationCode, StoreError> {
        Ok(verification)
    }

    fn consume_email_verification_code(
        &mut self,
        _verification_id: &str,
        _consumed_at: SystemTime,
    ) -> Result<Option<EmailVerificationCode>, StoreError> {
        Ok(None)
    }

    fn consume_email_verification_codes_for_account(
        &mut self,
        _account_id: &str,
        _consumed_at: SystemTime,
    ) -> Result<Vec<EmailVerificationCode>, StoreError> {
        Ok(Vec::new())
    }
}

impl RefreshTokenStore for TestStoreTx<'_> {
    fn find_refresh_token(
        &mut self,
        token_digest: &[u8; 32],
    ) -> Result<Option<RefreshTokenRecord>, StoreError> {
        Ok(self.state.refresh_tokens.get(token_digest).cloned())
    }

    fn insert_refresh_token(
        &mut self,
        _token: RefreshTokenRecord,
    ) -> Result<RefreshTokenRecord, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn revoke_refresh_token(
        &mut self,
        _token_digest: &[u8; 32],
        _reason: crate::RefreshTokenRevocationReason,
        _revoked_at: SystemTime,
    ) -> Result<Option<RefreshTokenRecord>, StoreError> {
        unreachable!("not needed in resource service tests")
    }

    fn revoke_refresh_tokens_for_session(
        &mut self,
        _session_id: &str,
        _reason: crate::RefreshTokenRevocationReason,
        _revoked_at: SystemTime,
    ) -> Result<Vec<RefreshTokenRecord>, StoreError> {
        unreachable!("not needed in resource service tests")
    }
}

struct TestAccessTokenValidator {
    result: Result<Option<ValidatedAccessToken>, TokenError>,
}

impl AccessTokenValidator for TestAccessTokenValidator {
    fn validate_access_token(
        &self,
        _token: &str,
        _observed_at: SystemTime,
    ) -> Result<Option<ValidatedAccessToken>, TokenError> {
        self.result.clone()
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

#[test]
fn user_info_returns_account_claims_for_active_access_token() {
    let observed_at = SystemTime::UNIX_EPOCH;
    let service = CoreOidcResourceService::new(
        test_store_runner(observed_at),
        TestAccessTokenValidator {
            result: Ok(Some(test_access_token(
                observed_at + Duration::from_secs(60),
            ))),
        },
        TestClientSecretVerifier,
    );

    let result = service
        .get_user_info(GetUserInfoCommand {
            access_token: "access-token".to_string(),
            observed_at,
        })
        .expect("userinfo should succeed");

    assert_eq!(result.subject_account_id, "acct-1");
    assert_eq!(result.email, "user@example.com");
    assert_eq!(result.client_id, "desktop-app");
}

#[test]
fn user_info_rejects_invalid_access_token() {
    let service = CoreOidcResourceService::new(
        test_store_runner(SystemTime::UNIX_EPOCH),
        TestAccessTokenValidator { result: Ok(None) },
        TestClientSecretVerifier,
    );

    let error = service
        .get_user_info(GetUserInfoCommand {
            access_token: "bad-token".to_string(),
            observed_at: SystemTime::UNIX_EPOCH,
        })
        .expect_err("userinfo should reject missing token");

    assert_eq!(error, ServiceError::InvalidToken);
}

#[test]
fn introspection_returns_active_refresh_token() {
    let observed_at = SystemTime::UNIX_EPOCH;
    let service = CoreOidcResourceService::new(
        test_store_runner(observed_at),
        TestAccessTokenValidator { result: Ok(None) },
        TestClientSecretVerifier,
    );

    let result = service
        .introspect_token(IntrospectTokenCommand {
            token: "refresh-token".to_string(),
            token_type_hint: Some("refresh_token".to_string()),
            client_id: "desktop-app".to_string(),
            client_secret: None,
            observed_at,
        })
        .expect("refresh token should introspect");

    assert!(result.active);
    assert_eq!(result.token_type, Some("refresh_token"));
    assert_eq!(result.session_id.as_deref(), Some("sess-1"));
}

#[test]
fn introspection_without_hint_falls_back_to_access_token_validation() {
    let observed_at = SystemTime::UNIX_EPOCH;
    let service = CoreOidcResourceService::new(
        test_store_runner(observed_at),
        TestAccessTokenValidator {
            result: Ok(Some(test_access_token(
                observed_at + Duration::from_secs(60),
            ))),
        },
        TestClientSecretVerifier,
    );

    let result = service
        .introspect_token(IntrospectTokenCommand {
            token: "access-token".to_string(),
            token_type_hint: None,
            client_id: "desktop-app".to_string(),
            client_secret: None,
            observed_at,
        })
        .expect("access token should introspect");

    assert!(result.active);
    assert_eq!(result.token_type, Some("access_token"));
    assert_eq!(result.subject_account_id.as_deref(), Some("acct-1"));
}

#[test]
fn introspection_rejects_access_token_client_mismatch() {
    let observed_at = SystemTime::UNIX_EPOCH;
    let service = CoreOidcResourceService::new(
        test_store_runner(observed_at),
        TestAccessTokenValidator {
            result: Ok(Some(test_access_token(
                observed_at + Duration::from_secs(60),
            ))),
        },
        TestClientSecretVerifier,
    );

    let error = service
        .introspect_token(IntrospectTokenCommand {
            token: "access-token".to_string(),
            token_type_hint: Some("access_token".to_string()),
            client_id: "other-client".to_string(),
            client_secret: None,
            observed_at,
        })
        .expect_err("mismatched client should fail");

    assert_eq!(error, ServiceError::InvalidClientAuthentication);
}

#[test]
fn confidential_introspection_requires_valid_client_secret() {
    let observed_at = SystemTime::UNIX_EPOCH;
    let service = CoreOidcResourceService::new(
        test_store_runner(observed_at),
        TestAccessTokenValidator {
            result: Ok(Some(ValidatedAccessToken {
                token: crate::SecretString::new("web-access-token"),
                subject_account_id: "acct-1".to_string(),
                session_id: "sess-web-1".to_string(),
                client_id: "web-app".to_string(),
                scope: Some("openid profile".to_string()),
                issued_at: SystemTime::UNIX_EPOCH,
                expires_at: observed_at + Duration::from_secs(60),
            })),
        },
        TestClientSecretVerifier,
    );

    let result = service.introspect_token(IntrospectTokenCommand {
        token: "web-access-token".to_string(),
        token_type_hint: Some("access_token".to_string()),
        client_id: "web-app".to_string(),
        client_secret: None,
        observed_at,
    });

    assert_eq!(result, Err(ServiceError::ClientAuthenticationRequired));
}

fn test_store_runner(observed_at: SystemTime) -> TestStoreRunner {
    let mut state = TestStoreState::default();
    state.accounts.insert(
        "acct-1".to_string(),
        Account {
            id: "acct-1".to_string(),
            email: "user@example.com".to_string(),
            password_hash: "$argon2id$demo".to_string(),
            display_name: Some("User".to_string()),
            status: AccountStatus::Active,
            created_at: observed_at,
        },
    );
    state.sessions.insert(
        "sess-1".to_string(),
        AuthSession {
            id: "sess-1".to_string(),
            account_id: "acct-1".to_string(),
            client_id: "desktop-app".to_string(),
            device_id: None,
            status: SessionStatus::Active,
            created_at: observed_at,
            expires_at: observed_at + Duration::from_secs(120),
            refresh_token_version: 0,
        },
    );
    state.sessions.insert(
        "sess-web-1".to_string(),
        AuthSession {
            id: "sess-web-1".to_string(),
            account_id: "acct-1".to_string(),
            client_id: "web-app".to_string(),
            device_id: None,
            status: SessionStatus::Active,
            created_at: observed_at,
            expires_at: observed_at + Duration::from_secs(120),
            refresh_token_version: 0,
        },
    );
    state.refresh_tokens.insert(
        crate::digest_refresh_token("refresh-token"),
        RefreshTokenRecord {
            id: "rtok-1".to_string(),
            session_id: "sess-1".to_string(),
            token_digest: crate::digest_refresh_token("refresh-token"),
            token_version: 0,
            issued_at: observed_at,
            expires_at: observed_at + Duration::from_secs(120),
            revoked_at: None,
            revocation_reason: None,
        },
    );
    state.refresh_tokens.insert(
        crate::digest_refresh_token("web-refresh-token"),
        RefreshTokenRecord {
            id: "rtok-web-1".to_string(),
            session_id: "sess-web-1".to_string(),
            token_digest: crate::digest_refresh_token("web-refresh-token"),
            token_version: 0,
            issued_at: observed_at,
            expires_at: observed_at + Duration::from_secs(120),
            revoked_at: None,
            revocation_reason: None,
        },
    );

    TestStoreRunner {
        state: Mutex::new(state),
    }
}

fn test_access_token(expires_at: SystemTime) -> ValidatedAccessToken {
    ValidatedAccessToken {
        token: crate::SecretString::new("access-token"),
        subject_account_id: "acct-1".to_string(),
        session_id: "sess-1".to_string(),
        client_id: "desktop-app".to_string(),
        scope: Some("openid profile".to_string()),
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at,
    }
}

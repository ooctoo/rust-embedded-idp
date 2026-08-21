use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use crate::{
    AccountStatus, AccountStore, AuthConfig, AuthSession, AuthorizationCodeRecord,
    AuthorizationCodeStore, ClientSecretVerifier, Clock, ExchangeAuthorizationCodeCommand,
    ExchangeAuthorizationCodeResult, IdGenerator, IdTokenClaims, IdTokenIssuer,
    OidcAuthorizationService, OidcClient, OidcConfig, PkceChallengeMethod, RefreshTokenRecord,
    RefreshTokenStore, RevokeTokenCommand, RevokeTokenResult, SessionStatus, SessionStore,
    StartAuthorizationCommand, StartAuthorizationResult, StoreError, StoreTransactionRunner,
    TokenError, TokenIssuer, TokenManagementService,
};

use super::auth_support::{map_account_status_conflict, require_active_account_status};
use super::{auth, client_auth, ServiceError};

pub struct CoreOidcService<S, T, J, C, K, I> {
    issuer: String,
    auth_config: AuthConfig,
    oidc_config: OidcConfig,
    store_runner: S,
    token_issuer: T,
    id_token_issuer: J,
    client_secret_verifier: C,
    clock: K,
    id_generator: I,
}

impl<S, T, J, C, K, I> CoreOidcService<S, T, J, C, K, I> {
    pub fn new(
        issuer: String,
        auth_config: AuthConfig,
        oidc_config: OidcConfig,
        store_runner: S,
        token_issuer: T,
        id_token_issuer: J,
        client_secret_verifier: C,
        clock: K,
        id_generator: I,
    ) -> Self {
        Self {
            issuer,
            auth_config,
            oidc_config,
            store_runner,
            token_issuer,
            id_token_issuer,
            client_secret_verifier,
            clock,
            id_generator,
        }
    }
}

impl<S, T, J, C, K, I> OidcAuthorizationService for CoreOidcService<S, T, J, C, K, I>
where
    S: StoreTransactionRunner + Send + Sync,
    T: TokenIssuer + Send + Sync,
    J: IdTokenIssuer + Send + Sync,
    C: ClientSecretVerifier + Send + Sync,
    K: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn start_authorization(
        &self,
        command: StartAuthorizationCommand,
    ) -> Result<StartAuthorizationResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        if command.response_type != "code" {
            return Err(ServiceError::UnsupportedResponseType);
        }

        let now = self.clock.now();
        let id_generator = &self.id_generator;
        let ttl_secs = self.oidc_config.authorization_code_ttl_secs;

        self.store_runner
            .transaction(|tx| {
                let account = tx
                    .find_account(&command.subject_account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                require_active_account_status(&account.status)?;

                let client = auth::resolve_client(tx, &command.client_id)?;
                ensure_redirect_uri(&client, &command.redirect_uri)?;
                let method = validate_pkce_on_authorize(&client, &command)?;

                let stored = tx.insert_authorization_code(AuthorizationCodeRecord {
                    code: id_generator.next_id("authcode"),
                    account_id: account.id,
                    client_id: client.client_id,
                    redirect_uri: command.redirect_uri,
                    scope: command.scope,
                    nonce: command.nonce,
                    code_challenge: command.code_challenge,
                    code_challenge_method: method,
                    created_at: now,
                    expires_at: now + Duration::from_secs(ttl_secs),
                    consumed_at: None,
                })?;

                Ok(StartAuthorizationResult {
                    authorization_code: stored.code,
                    redirect_uri: stored.redirect_uri,
                    state: command.state,
                })
            })
            .map_err(map_store_error)
    }

    fn exchange_authorization_code(
        &self,
        command: ExchangeAuthorizationCodeCommand,
    ) -> Result<ExchangeAuthorizationCodeResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        if command.grant_type != "authorization_code" {
            return Err(ServiceError::UnsupportedGrantType);
        }

        let now = self.clock.now();
        let issuer = &self.issuer;
        let session_ttl_secs = self.auth_config.session_ttl_secs;
        let id_generator = &self.id_generator;
        let token_issuer = &self.token_issuer;
        let id_token_issuer = &self.id_token_issuer;
        let client_secret_verifier = &self.client_secret_verifier;

        self.store_runner
            .transaction(|tx| {
                let code = tx
                    .find_authorization_code(&command.code)?
                    .ok_or(StoreError::NotFound("authorization_code.code"))?;
                if code.consumed_at.is_some() {
                    return Err(StoreError::Conflict("authorization_code.consumed"));
                }
                if code.expires_at <= now {
                    return Err(StoreError::Conflict("authorization_code.expired"));
                }

                let client = auth::resolve_client(tx, &code.client_id)?;
                if command.client_id != client.client_id {
                    return Err(StoreError::Conflict("oidc_client.authentication"));
                }
                if command.redirect_uri != code.redirect_uri {
                    return Err(StoreError::Conflict("authorization_code.redirect_uri"));
                }
                client_auth::authenticate_client(
                    &client,
                    command.client_secret.as_deref(),
                    client_secret_verifier,
                )?;

                validate_pkce_on_exchange(&code, &client, command.code_verifier.as_deref())?;

                let account = tx
                    .find_account(&code.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                if account.status != AccountStatus::Active {
                    return Err(StoreError::Conflict("account.status"));
                }

                let consumed = tx
                    .consume_authorization_code(&code.code, now)?
                    .ok_or(StoreError::Conflict("authorization_code.consumed"))?;
                let session = tx.insert_session(new_session(
                    id_generator,
                    session_ttl_secs,
                    &account.id,
                    &client.client_id,
                    now,
                ))?;
                let tokens = token_issuer
                    .issue_session_tokens(
                        &session.id,
                        &account.id,
                        &client.client_id,
                        session.refresh_token_version,
                        now,
                    )
                    .map_err(store_error_from_token)?;
                insert_refresh_token_record(tx, id_generator, &tokens, &session.id, now)?;
                let id_token = if scope_requests_openid(consumed.scope.as_deref()) {
                    Some(
                        id_token_issuer
                            .issue_id_token(&IdTokenClaims {
                                issuer: issuer.clone(),
                                subject_account_id: account.id.clone(),
                                audience: client.client_id.clone(),
                                nonce: consumed.nonce.clone(),
                                issued_at: now,
                                expires_at: tokens.access_expires_at,
                                auth_time: now,
                            })
                            .map_err(store_error_from_token)?,
                    )
                } else {
                    None
                };

                Ok(ExchangeAuthorizationCodeResult {
                    subject_account_id: account.id,
                    tokens,
                    id_token,
                    scope: consumed.scope,
                    token_type: "Bearer",
                })
            })
            .map_err(map_store_error)
    }
}

impl<S, T, J, C, K, I> TokenManagementService for CoreOidcService<S, T, J, C, K, I>
where
    S: StoreTransactionRunner + Send + Sync,
    T: TokenIssuer + Send + Sync,
    J: IdTokenIssuer + Send + Sync,
    C: ClientSecretVerifier + Send + Sync,
    K: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn revoke_token(&self, command: RevokeTokenCommand) -> Result<RevokeTokenResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let client = auth::resolve_client(tx, &command.client_id)?;
                client_auth::authenticate_client(
                    &client,
                    command.client_secret.as_deref(),
                    &self.client_secret_verifier,
                )?;
                let token_digest = crate::digest_refresh_token(&command.token);
                let refresh_token = match tx.find_refresh_token(&token_digest)? {
                    Some(token) => token,
                    None => {
                        return Ok(RevokeTokenResult {
                            revoked: false,
                            revoked_session_id: None,
                            revoked_token_version: None,
                        });
                    }
                };

                let mut session = tx
                    .find_session(&refresh_token.session_id)?
                    .ok_or(StoreError::NotFound("auth_session.id"))?;
                if session.client_id != client.client_id {
                    return Err(StoreError::Conflict("oidc_client.authentication"));
                }

                if refresh_token.revoked_at.is_some() {
                    return Ok(RevokeTokenResult {
                        revoked: false,
                        revoked_session_id: Some(session.id),
                        revoked_token_version: Some(refresh_token.token_version),
                    });
                }

                let revoked = tx
                    .revoke_refresh_token(
                        &token_digest,
                        crate::RefreshTokenRevocationReason::ClientRevocation,
                        command.revoked_at,
                    )?
                    .ok_or(StoreError::NotFound("refresh_token.value"))?;

                if session.status == SessionStatus::Active {
                    session.status = SessionStatus::Revoked;
                    session = tx.update_session(session)?;
                }

                Ok(RevokeTokenResult {
                    revoked: true,
                    revoked_session_id: Some(session.id),
                    revoked_token_version: Some(revoked.token_version),
                })
            })
            .map_err(map_store_error)
    }
}

fn ensure_redirect_uri(client: &OidcClient, redirect_uri: &str) -> Result<(), StoreError> {
    if client
        .redirect_uris
        .iter()
        .any(|value| value == redirect_uri)
    {
        return Ok(());
    }

    Err(StoreError::Conflict("authorization_code.redirect_uri"))
}

fn validate_pkce_on_authorize(
    client: &OidcClient,
    command: &StartAuthorizationCommand,
) -> Result<Option<PkceChallengeMethod>, StoreError> {
    match command.code_challenge.as_deref().map(str::trim) {
        Some("") | None if client.pkce_required => {
            Err(StoreError::Conflict("authorization_code.pkce_required"))
        }
        Some(challenge) => {
            if challenge.is_empty() {
                return Err(StoreError::Conflict("authorization_code.pkce_required"));
            }
            Ok(Some(parse_code_challenge_method(
                command.code_challenge_method.as_deref(),
            )?))
        }
        None => Ok(None),
    }
}

fn validate_pkce_on_exchange(
    code: &AuthorizationCodeRecord,
    client: &OidcClient,
    code_verifier: Option<&str>,
) -> Result<(), StoreError> {
    match code.code_challenge.as_deref() {
        Some(code_challenge) => {
            let code_verifier = code_verifier
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or(StoreError::Conflict("authorization_code.code_verifier"))?;
            let method = code
                .code_challenge_method
                .unwrap_or(PkceChallengeMethod::Plain);
            let matches = match method {
                PkceChallengeMethod::Plain => code_verifier == code_challenge,
                PkceChallengeMethod::S256 => {
                    Base64UrlUnpadded::encode_string(&Sha256::digest(code_verifier.as_bytes()))
                        == code_challenge
                }
            };
            if matches {
                Ok(())
            } else {
                Err(StoreError::Conflict("authorization_code.pkce_failed"))
            }
        }
        None if client.pkce_required => {
            Err(StoreError::Conflict("authorization_code.pkce_required"))
        }
        None => Ok(()),
    }
}

fn parse_code_challenge_method(value: Option<&str>) -> Result<PkceChallengeMethod, StoreError> {
    match value.unwrap_or("plain") {
        "plain" => Ok(PkceChallengeMethod::Plain),
        "S256" => Ok(PkceChallengeMethod::S256),
        _ => Err(StoreError::Conflict("authorization_code.challenge_method")),
    }
}

fn scope_requests_openid(scope: Option<&str>) -> bool {
    scope
        .unwrap_or("")
        .split_whitespace()
        .any(|entry| entry == "openid")
}

fn new_session(
    id_generator: &impl IdGenerator,
    session_ttl_secs: u64,
    account_id: &str,
    client_id: &str,
    now: std::time::SystemTime,
) -> AuthSession {
    AuthSession {
        id: id_generator.next_id("sess"),
        account_id: account_id.to_string(),
        client_id: client_id.to_string(),
        device_id: None,
        status: SessionStatus::Active,
        created_at: now,
        expires_at: now + Duration::from_secs(session_ttl_secs),
        refresh_token_version: 0,
    }
}

fn insert_refresh_token_record(
    store: &mut impl RefreshTokenStore,
    id_generator: &impl IdGenerator,
    tokens: &crate::IssuedTokenBundle,
    session_id: &str,
    issued_at: std::time::SystemTime,
) -> Result<RefreshTokenRecord, StoreError> {
    store.insert_refresh_token(RefreshTokenRecord {
        id: id_generator.next_id("rtok"),
        session_id: session_id.to_string(),
        token_digest: crate::digest_refresh_token(tokens.refresh_token.expose_secret()),
        token_version: tokens.refresh_token_version,
        issued_at,
        expires_at: tokens.refresh_expires_at,
        revoked_at: None,
        revocation_reason: None,
    })
}

fn store_error_from_token(error: TokenError) -> StoreError {
    StoreError::Backend(format!("token:{error:?}"))
}

fn map_store_error(error: StoreError) -> ServiceError {
    if let Some(error) = map_account_status_conflict(&error) {
        return error;
    }

    match error {
        StoreError::NotFound("account.id") => ServiceError::AccountNotFound,
        StoreError::NotFound("oidc_client.id") => ServiceError::ClientNotFound,
        StoreError::NotFound("authorization_code.code") => ServiceError::AuthorizationCodeNotFound,
        StoreError::Conflict("authorization_code.redirect_uri") => {
            ServiceError::RedirectUriMismatch
        }
        StoreError::Conflict("authorization_code.expired") => {
            ServiceError::AuthorizationCodeExpired
        }
        StoreError::Conflict("authorization_code.consumed") => {
            ServiceError::AuthorizationCodeConsumed
        }
        StoreError::Conflict("authorization_code.pkce_required") => ServiceError::PkceRequired,
        StoreError::Conflict("authorization_code.code_verifier")
        | StoreError::Conflict("authorization_code.pkce_failed") => {
            ServiceError::InvalidCodeVerifier
        }
        StoreError::Conflict("authorization_code.challenge_method") => {
            ServiceError::UnsupportedCodeChallengeMethod
        }
        StoreError::Conflict("oidc_client.client_secret") => {
            ServiceError::ClientAuthenticationRequired
        }
        StoreError::Conflict("oidc_client.authentication") => {
            ServiceError::InvalidClientAuthentication
        }
        StoreError::NotFound("refresh_token.value") => ServiceError::InvalidToken,
        StoreError::Backend(message) if message.starts_with("invalid client config:") => {
            ServiceError::InvalidClientConfig(auth::parse_client_error(&message))
        }
        StoreError::Backend(message) if message.starts_with("token:") => {
            ServiceError::Token(auth::parse_token_error(&message))
        }
        other => ServiceError::Store(other),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use std::time::SystemTime;

    use super::*;
    use crate::{
        Account, AccountDeviceBinding, AccountDeviceBindingStore, AccountStore,
        AuthorizationCodeStore, ClientSecretError, ClientSecretVerifier, ClientStore,
        DeviceNonceRecord, DeviceNonceStore, DeviceRecord, DeviceStore, EmailVerificationCode,
        EmailVerificationStore, IssuedTokenBundle, OidcClientType, RefreshTokenRecord,
        RefreshTokenStore, SessionStore,
    };

    struct TestClock;
    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH
        }
    }

    struct TestIds;
    impl IdGenerator for TestIds {
        fn next_id(&self, prefix: &str) -> String {
            format!("{prefix}-1")
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
                access_token: crate::SecretString::new(format!(
                    "access:{session_id}:{account_id}:{client_id}"
                )),
                refresh_token: crate::SecretString::new(format!(
                    "refresh:{session_id}:{refresh_token_version}"
                )),
                access_expires_at: issued_at,
                refresh_expires_at: issued_at,
                refresh_token_version,
            })
        }
    }

    struct TestIdTokenIssuer;
    impl IdTokenIssuer for TestIdTokenIssuer {
        fn issue_id_token(
            &self,
            claims: &IdTokenClaims,
        ) -> Result<crate::SecretString, TokenError> {
            Ok(crate::SecretString::new(format!(
                "id:{}:{}:{}",
                claims.subject_account_id, claims.audience, claims.issuer
            )))
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

    #[derive(Default)]
    struct TestStoreState {
        accounts: HashMap<String, Account>,
        sessions: HashMap<String, AuthSession>,
        authorization_codes: HashMap<String, AuthorizationCodeRecord>,
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

        fn find_by_email(&mut self, email: &str) -> Result<Option<Account>, StoreError> {
            Ok(self
                .state
                .accounts
                .values()
                .find(|account| account.email == email)
                .cloned())
        }

        fn insert_account(&mut self, account: Account) -> Result<Account, StoreError> {
            self.state
                .accounts
                .insert(account.id.clone(), account.clone());
            Ok(account)
        }

        fn update_account(&mut self, account: Account) -> Result<Account, StoreError> {
            self.state
                .accounts
                .insert(account.id.clone(), account.clone());
            Ok(account)
        }
    }

    impl SessionStore for TestStoreTx<'_> {
        fn find_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError> {
            Ok(self.state.sessions.get(session_id).cloned())
        }

        fn list_sessions(
            &mut self,
            account_id: Option<&str>,
        ) -> Result<Vec<AuthSession>, StoreError> {
            Ok(self
                .state
                .sessions
                .values()
                .filter(|session| {
                    account_id.is_none_or(|account_id| session.account_id == account_id)
                })
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

        fn insert_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
            self.state
                .sessions
                .insert(session.id.clone(), session.clone());
            Ok(session)
        }

        fn update_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
            self.state
                .sessions
                .insert(session.id.clone(), session.clone());
            Ok(session)
        }
    }

    impl AuthorizationCodeStore for TestStoreTx<'_> {
        fn find_authorization_code(
            &mut self,
            code: &str,
        ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
            Ok(self.state.authorization_codes.get(code).cloned())
        }

        fn insert_authorization_code(
            &mut self,
            code: AuthorizationCodeRecord,
        ) -> Result<AuthorizationCodeRecord, StoreError> {
            self.state
                .authorization_codes
                .insert(code.code.clone(), code.clone());
            Ok(code)
        }

        fn consume_authorization_code(
            &mut self,
            code: &str,
            consumed_at: SystemTime,
        ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
            let Some(stored) = self.state.authorization_codes.get_mut(code) else {
                return Ok(None);
            };
            if stored.consumed_at.is_some() {
                return Ok(None);
            }
            stored.consumed_at = Some(consumed_at);
            Ok(Some(stored.clone()))
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

    impl ClientStore for TestStoreTx<'_> {
        fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
            let client = match client_id {
                "web-app" => OidcClient {
                    client_id: client_id.to_string(),
                    client_name: "Web".to_string(),
                    redirect_uris: vec!["https://example.com/callback".to_string()],
                    client_type: OidcClientType::ConfidentialWeb,
                    pkce_required: false,
                    client_secret_hash: Some("hash:top-secret".to_string()),
                },
                _ => OidcClient {
                    client_id: client_id.to_string(),
                    client_name: "Desktop".to_string(),
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
                    client_name: "Desktop".to_string(),
                    redirect_uris: vec!["http://127.0.0.1:49152/callback".to_string()],
                    client_type: OidcClientType::PublicDesktop,
                    pkce_required: true,
                    client_secret_hash: None,
                },
                OidcClient {
                    client_id: "web-app".to_string(),
                    client_name: "Web".to_string(),
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

    impl RefreshTokenStore for TestStoreTx<'_> {
        fn find_refresh_token(
            &mut self,
            token_digest: &[u8; 32],
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(self.state.refresh_tokens.get(token_digest).cloned())
        }

        fn insert_refresh_token(
            &mut self,
            token: RefreshTokenRecord,
        ) -> Result<RefreshTokenRecord, StoreError> {
            self.state
                .refresh_tokens
                .insert(token.token_digest, token.clone());
            Ok(token)
        }

        fn revoke_refresh_token(
            &mut self,
            token_digest: &[u8; 32],
            reason: crate::RefreshTokenRevocationReason,
            revoked_at: SystemTime,
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            let Some(token) = self.state.refresh_tokens.get_mut(token_digest) else {
                return Ok(None);
            };
            token.revoked_at = Some(revoked_at);
            token.revocation_reason = Some(reason);
            Ok(Some(token.clone()))
        }

        fn revoke_refresh_tokens_for_session(
            &mut self,
            session_id: &str,
            reason: crate::RefreshTokenRevocationReason,
            revoked_at: SystemTime,
        ) -> Result<Vec<RefreshTokenRecord>, StoreError> {
            let mut revoked = Vec::new();
            for token in self.state.refresh_tokens.values_mut() {
                if token.session_id == session_id && token.revoked_at.is_none() {
                    token.revoked_at = Some(revoked_at);
                    token.revocation_reason = Some(reason);
                    revoked.push(token.clone());
                }
            }
            Ok(revoked)
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

        fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            Ok(device)
        }

        fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            Ok(device)
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
            binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            Ok(binding)
        }

        fn update_account_device_binding(
            &mut self,
            binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            Ok(binding)
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
            nonce: DeviceNonceRecord,
        ) -> Result<DeviceNonceRecord, StoreError> {
            Ok(nonce)
        }

        fn consume_device_nonce(
            &mut self,
            _challenge: &str,
            _consumed_at: SystemTime,
        ) -> Result<Option<DeviceNonceRecord>, StoreError> {
            Ok(None)
        }
    }

    fn service() -> CoreOidcService<
        TestStoreRunner,
        TestTokenIssuer,
        TestIdTokenIssuer,
        TestClientSecretVerifier,
        TestClock,
        TestIds,
    > {
        let runner = TestStoreRunner::default();
        runner.state.lock().unwrap().accounts.insert(
            "acct-1".to_string(),
            Account {
                id: "acct-1".to_string(),
                email: "user@example.com".to_string(),
                password_hash: "$argon2id$demo".to_string(),
                display_name: Some("User".to_string()),
                status: AccountStatus::Active,
                created_at: SystemTime::UNIX_EPOCH,
            },
        );

        CoreOidcService::new(
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
            runner,
            TestTokenIssuer,
            TestIdTokenIssuer,
            TestClientSecretVerifier,
            TestClock,
            TestIds,
        )
    }

    #[test]
    fn start_authorization_persists_pkce_code() {
        let service = service();

        let result = service
            .start_authorization(StartAuthorizationCommand {
                subject_account_id: "acct-1".to_string(),
                response_type: "code".to_string(),
                client_id: "desktop-app".to_string(),
                redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
                scope: Some("openid profile".to_string()),
                state: Some("state-1".to_string()),
                code_challenge: Some("verifier-1".to_string()),
                code_challenge_method: Some("plain".to_string()),
                nonce: Some("nonce-1".to_string()),
            })
            .expect("authorization should succeed");

        assert_eq!(result.authorization_code, "authcode-1");
        assert_eq!(result.redirect_uri, "http://127.0.0.1:49152/callback");
    }

    #[test]
    fn exchange_authorization_code_issues_tokens_and_id_token() {
        let service = service();
        let started = service
            .start_authorization(StartAuthorizationCommand {
                subject_account_id: "acct-1".to_string(),
                response_type: "code".to_string(),
                client_id: "desktop-app".to_string(),
                redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
                scope: Some("openid profile".to_string()),
                state: Some("state-1".to_string()),
                code_challenge: Some("verifier-1".to_string()),
                code_challenge_method: Some("plain".to_string()),
                nonce: Some("nonce-1".to_string()),
            })
            .expect("authorization should succeed");

        let exchanged = service
            .exchange_authorization_code(ExchangeAuthorizationCodeCommand {
                grant_type: "authorization_code".to_string(),
                code: started.authorization_code,
                redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
                client_id: "desktop-app".to_string(),
                client_secret: None,
                code_verifier: Some("verifier-1".to_string()),
            })
            .expect("token exchange should succeed");

        assert_eq!(exchanged.subject_account_id, "acct-1");
        assert_eq!(exchanged.tokens.refresh_token_version, 0);
        assert_eq!(
            exchanged
                .id_token
                .as_ref()
                .map(crate::SecretString::expose_secret),
            Some("id:acct-1:desktop-app:http://127.0.0.1:8080")
        );
    }

    #[test]
    fn exchange_authorization_code_rejects_invalid_verifier() {
        let service = service();
        let started = service
            .start_authorization(StartAuthorizationCommand {
                subject_account_id: "acct-1".to_string(),
                response_type: "code".to_string(),
                client_id: "desktop-app".to_string(),
                redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
                scope: Some("openid".to_string()),
                state: None,
                code_challenge: Some("expected-verifier".to_string()),
                code_challenge_method: Some("plain".to_string()),
                nonce: None,
            })
            .expect("authorization should succeed");

        let result = service.exchange_authorization_code(ExchangeAuthorizationCodeCommand {
            grant_type: "authorization_code".to_string(),
            code: started.authorization_code,
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            client_id: "desktop-app".to_string(),
            client_secret: None,
            code_verifier: Some("wrong-verifier".to_string()),
        });

        assert_eq!(result, Err(ServiceError::InvalidCodeVerifier));
    }

    #[test]
    fn confidential_client_exchange_requires_valid_secret() {
        let service = service();
        let started = service
            .start_authorization(StartAuthorizationCommand {
                subject_account_id: "acct-1".to_string(),
                response_type: "code".to_string(),
                client_id: "web-app".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
                scope: Some("openid".to_string()),
                state: None,
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
            })
            .expect("authorization should succeed");

        let missing_secret =
            service.exchange_authorization_code(ExchangeAuthorizationCodeCommand {
                grant_type: "authorization_code".to_string(),
                code: started.authorization_code.clone(),
                redirect_uri: "https://example.com/callback".to_string(),
                client_id: "web-app".to_string(),
                client_secret: None,
                code_verifier: None,
            });
        assert_eq!(
            missing_secret,
            Err(ServiceError::ClientAuthenticationRequired)
        );

        let invalid_secret =
            service.exchange_authorization_code(ExchangeAuthorizationCodeCommand {
                grant_type: "authorization_code".to_string(),
                code: started.authorization_code,
                redirect_uri: "https://example.com/callback".to_string(),
                client_id: "web-app".to_string(),
                client_secret: Some("wrong-secret".to_string()),
                code_verifier: None,
            });
        assert_eq!(
            invalid_secret,
            Err(ServiceError::InvalidClientAuthentication)
        );
    }

    #[test]
    fn revoke_token_revokes_session_and_refresh_token() {
        let service = service();
        let started = service
            .start_authorization(StartAuthorizationCommand {
                subject_account_id: "acct-1".to_string(),
                response_type: "code".to_string(),
                client_id: "desktop-app".to_string(),
                redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
                scope: Some("openid".to_string()),
                state: None,
                code_challenge: Some("verifier-1".to_string()),
                code_challenge_method: Some("plain".to_string()),
                nonce: None,
            })
            .expect("authorization should succeed");

        let exchanged = service
            .exchange_authorization_code(ExchangeAuthorizationCodeCommand {
                grant_type: "authorization_code".to_string(),
                code: started.authorization_code,
                redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
                client_id: "desktop-app".to_string(),
                client_secret: None,
                code_verifier: Some("verifier-1".to_string()),
            })
            .expect("token exchange should succeed");

        let revoked = service
            .revoke_token(RevokeTokenCommand {
                token: exchanged.tokens.refresh_token.into_exposed(),
                token_type_hint: Some("refresh_token".to_string()),
                client_id: "desktop-app".to_string(),
                client_secret: None,
                revoked_at: SystemTime::UNIX_EPOCH,
            })
            .expect("revoke should succeed");

        assert!(revoked.revoked);
        assert_eq!(revoked.revoked_token_version, Some(0));
    }

    #[test]
    fn confidential_client_revoke_requires_valid_secret() {
        let service = service();
        let started = service
            .start_authorization(StartAuthorizationCommand {
                subject_account_id: "acct-1".to_string(),
                response_type: "code".to_string(),
                client_id: "web-app".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
                scope: Some("openid".to_string()),
                state: None,
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
            })
            .expect("authorization should succeed");

        let exchanged = service
            .exchange_authorization_code(ExchangeAuthorizationCodeCommand {
                grant_type: "authorization_code".to_string(),
                code: started.authorization_code,
                redirect_uri: "https://example.com/callback".to_string(),
                client_id: "web-app".to_string(),
                client_secret: Some("top-secret".to_string()),
                code_verifier: None,
            })
            .expect("token exchange should succeed");

        let result = service.revoke_token(RevokeTokenCommand {
            token: exchanged.tokens.refresh_token.into_exposed(),
            token_type_hint: Some("refresh_token".to_string()),
            client_id: "web-app".to_string(),
            client_secret: Some("wrong-secret".to_string()),
            revoked_at: SystemTime::UNIX_EPOCH,
        });

        assert_eq!(result, Err(ServiceError::InvalidClientAuthentication));
    }
}

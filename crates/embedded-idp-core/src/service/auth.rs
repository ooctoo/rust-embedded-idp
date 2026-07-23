use std::time::{Duration, SystemTime};

use crate::{
    next_refresh_token_version, Account, AccountDeviceBinding, AccountDeviceBindingStatus,
    AccountDeviceBindingStore, AccountStatus, AccountStore, AuthConfig, AuthService, AuthSession,
    ClientStore, Clock, DeviceRecord, DeviceStatus, DeviceStore, EmailVerificationStore,
    IdGenerator, LoginCommand, LoginResult, LogoutSessionCommand, LogoutSessionResult, OidcClient,
    PendingEmailVerification, RefreshTokenRecord, RefreshTokenStore, RegisterAccountCommand,
    RegisterAccountResult, ResendVerificationCodeCommand, ResendVerificationCodeResult,
    RotateRefreshTokenCommand, RotateRefreshTokenResult, SessionStatus, SessionStore, StoreError,
    StoreTransactionRunner, TokenError, TokenIssuer, VerificationCodeGenerator, VerifyEmailCommand,
    VerifyEmailResult,
};

use super::{
    auth_support::{
        build_email_verification_code, map_account_status_conflict, require_active_account_status,
    },
    password::{hash_password, validate_registration_password, verify_password},
    ServiceError,
};

pub struct CoreAuthService<S, T, K, I, V> {
    config: AuthConfig,
    store_runner: S,
    token_issuer: T,
    clock: K,
    id_generator: I,
    verification_code_generator: V,
}

impl<S, T, K, I, V> CoreAuthService<S, T, K, I, V> {
    pub fn new(
        config: AuthConfig,
        store_runner: S,
        token_issuer: T,
        clock: K,
        id_generator: I,
        verification_code_generator: V,
    ) -> Self {
        Self {
            config,
            store_runner,
            token_issuer,
            clock,
            id_generator,
            verification_code_generator,
        }
    }
}

impl<S, T, K, I, V> AuthService for CoreAuthService<S, T, K, I, V>
where
    S: StoreTransactionRunner + Send + Sync,
    T: TokenIssuer + Send + Sync,
    K: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    V: VerificationCodeGenerator + Send + Sync,
{
    fn register_account(
        &self,
        command: RegisterAccountCommand,
    ) -> Result<RegisterAccountResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        if !self.config.allow_local_registration {
            return Err(ServiceError::RegistrationDisabled);
        }

        validate_registration_password(&self.config, &command.password)
            .map_err(ServiceError::InvalidContract)?;

        let now = self.clock.now();
        let id_generator = &self.id_generator;
        let verification_code_generator = &self.verification_code_generator;
        let password_hash = hash_password(&command.password).map_err(ServiceError::Store)?;

        self.store_runner
            .transaction(|tx| {
                resolve_client(tx, &command.client_id)?;
                if tx.find_by_email(&command.email)?.is_some() {
                    return Err(StoreError::Conflict("account.email"));
                }

                let account = tx.insert_account(Account {
                    id: id_generator.next_id("acct"),
                    email: command.email,
                    password_hash,
                    display_name: command.display_name,
                    status: AccountStatus::PendingVerification,
                    created_at: now,
                })?;
                let verification =
                    tx.insert_email_verification_code(build_email_verification_code(
                        &self.config,
                        verification_code_generator,
                        id_generator,
                        &account.id,
                        &account.email,
                        now,
                    ))?;

                Ok(RegisterAccountResult {
                    account,
                    verification: pending_email_verification(&verification),
                })
            })
            .map_err(map_store_error)
    }

    fn login(&self, command: LoginCommand) -> Result<LoginResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        let now = self.clock.now();
        let id_generator = &self.id_generator;
        let token_issuer = &self.token_issuer;
        let session_ttl_secs = self.config.session_ttl_secs;

        self.store_runner
            .transaction(|tx| {
                let client = resolve_client(tx, &command.client_id)?;
                let account = tx
                    .find_by_email(&command.email)?
                    .ok_or(StoreError::NotFound("account.credentials"))?;
                if !verify_password(&account.password_hash, &command.password)? {
                    return Err(StoreError::NotFound("account.credentials"));
                }
                require_active_account_status(&account.status)?;
                let session_device_id = maybe_attach_device_to_account(
                    tx,
                    &self.id_generator,
                    &account.id,
                    &client.client_id,
                    command.device_id.as_deref(),
                    now,
                )?;

                let session = tx.insert_session(new_session(
                    id_generator,
                    session_ttl_secs,
                    &account.id,
                    &client.client_id,
                    session_device_id,
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
                    .map_err(StoreError::from_token)?;
                insert_refresh_token_record(tx, id_generator, &tokens, &session.id, now)?;

                Ok(LoginResult {
                    account,
                    session,
                    tokens,
                })
            })
            .map_err(map_store_error)
    }

    fn verify_email(&self, command: VerifyEmailCommand) -> Result<VerifyEmailResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        let now = self.clock.now();
        let id_generator = &self.id_generator;
        let token_issuer = &self.token_issuer;
        let session_ttl_secs = self.config.session_ttl_secs;

        self.store_runner
            .transaction(|tx| {
                let client = resolve_client(tx, &command.client_id)?;
                let verification = tx
                    .find_email_verification_code(&command.email, &command.verification_code)?
                    .ok_or(StoreError::NotFound("email_verification.code"))?;
                if verification.consumed_at.is_some() {
                    return Err(StoreError::Conflict("email_verification.code"));
                }
                if verification.expires_at <= now {
                    return Err(StoreError::Conflict("email_verification.expired"));
                }

                let mut account = tx
                    .find_account(&verification.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                match account.status {
                    AccountStatus::PendingVerification => {
                        account.status = AccountStatus::Active;
                        account = tx.update_account(account)?;
                    }
                    AccountStatus::Active => return Err(StoreError::Conflict("account.active")),
                    AccountStatus::Disabled => {
                        return Err(StoreError::Conflict("account.disabled"))
                    }
                }

                tx.consume_email_verification_code(&verification.id, now)?;
                tx.consume_email_verification_codes_for_account(&account.id, now)?;

                let session_device_id = maybe_attach_device_to_account(
                    tx,
                    id_generator,
                    &account.id,
                    &client.client_id,
                    command.device_id.as_deref(),
                    now,
                )?;
                let session = tx.insert_session(new_session(
                    id_generator,
                    session_ttl_secs,
                    &account.id,
                    &client.client_id,
                    session_device_id,
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
                    .map_err(StoreError::from_token)?;
                insert_refresh_token_record(tx, id_generator, &tokens, &session.id, now)?;

                Ok(VerifyEmailResult {
                    account,
                    session,
                    tokens,
                })
            })
            .map_err(map_store_error)
    }

    fn resend_verification_code(
        &self,
        command: ResendVerificationCodeCommand,
    ) -> Result<ResendVerificationCodeResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        let now = self.clock.now();
        let id_generator = &self.id_generator;
        let verification_code_generator = &self.verification_code_generator;

        self.store_runner
            .transaction(|tx| {
                let account = tx
                    .find_by_email(&command.email)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                match account.status {
                    AccountStatus::PendingVerification => {}
                    AccountStatus::Active => return Err(StoreError::Conflict("account.active")),
                    AccountStatus::Disabled => {
                        return Err(StoreError::Conflict("account.disabled"))
                    }
                }

                tx.consume_email_verification_codes_for_account(&account.id, now)?;
                let verification =
                    tx.insert_email_verification_code(build_email_verification_code(
                        &self.config,
                        verification_code_generator,
                        id_generator,
                        &account.id,
                        &account.email,
                        now,
                    ))?;

                Ok(ResendVerificationCodeResult {
                    account,
                    verification: pending_email_verification(&verification),
                })
            })
            .map_err(map_store_error)
    }

    fn rotate_refresh_token(
        &self,
        command: RotateRefreshTokenCommand,
    ) -> Result<RotateRefreshTokenResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        let token_issuer = &self.token_issuer;

        self.store_runner
            .transaction(|tx| {
                let refresh_token = tx
                    .find_refresh_token(&command.refresh_token)?
                    .ok_or(StoreError::NotFound("refresh_token.value"))?;
                if refresh_token.revoked_at.is_some()
                    || refresh_token.expires_at <= command.rotated_at
                {
                    return Err(StoreError::Conflict("refresh_token.inactive"));
                }
                let mut session = tx
                    .find_session(&refresh_token.session_id)?
                    .ok_or(StoreError::NotFound("auth_session.id"))?;
                if session.status != SessionStatus::Active {
                    return Err(StoreError::Conflict("auth_session.status"));
                }
                if session.expires_at <= command.rotated_at {
                    return Err(StoreError::Conflict("auth_session.expired"));
                }

                session.refresh_token_version = next_refresh_token_version(
                    session.refresh_token_version,
                    refresh_token.token_version,
                )
                .map_err(StoreError::from_token)?;
                session = tx.update_session(session)?;
                tx.revoke_refresh_token(&command.refresh_token, command.rotated_at)?;
                let tokens = token_issuer
                    .issue_session_tokens(
                        &session.id,
                        &session.account_id,
                        &session.client_id,
                        session.refresh_token_version,
                        command.rotated_at,
                    )
                    .map_err(StoreError::from_token)?;
                insert_refresh_token_record(
                    tx,
                    &self.id_generator,
                    &tokens,
                    &session.id,
                    command.rotated_at,
                )?;

                Ok(RotateRefreshTokenResult { session, tokens })
            })
            .map_err(map_store_error)
    }

    fn logout(&self, command: LogoutSessionCommand) -> Result<LogoutSessionResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let refresh_token = tx
                    .find_refresh_token(&command.refresh_token)?
                    .ok_or(StoreError::NotFound("refresh_token.value"))?;
                if refresh_token.revoked_at.is_some()
                    || refresh_token.expires_at <= command.logged_out_at
                {
                    return Err(StoreError::Conflict("refresh_token.inactive"));
                }
                let mut session = tx
                    .find_session(&refresh_token.session_id)?
                    .ok_or(StoreError::NotFound("auth_session.id"))?;

                if session.status == SessionStatus::Expired {
                    return Err(StoreError::Conflict("auth_session.expired"));
                }

                if session.status != SessionStatus::Revoked {
                    session.status = SessionStatus::Revoked;
                    session = tx.update_session(session)?;
                }

                tx.revoke_refresh_tokens_for_session(&session.id, command.logged_out_at)?;

                Ok(LogoutSessionResult { session })
            })
            .map_err(map_store_error)
    }
}

pub(super) fn resolve_client(
    store: &mut impl ClientStore,
    client_id: &str,
) -> Result<OidcClient, StoreError> {
    let client = store
        .find_client(client_id)?
        .ok_or(StoreError::NotFound("oidc_client.id"))?;
    client
        .validate()
        .map_err(|error| StoreError::Backend(format!("invalid client config: {error:?}")))?;
    Ok(client)
}

pub(super) fn new_session(
    id_generator: &impl IdGenerator,
    session_ttl_secs: u64,
    account_id: &str,
    client_id: &str,
    device_id: Option<String>,
    now: SystemTime,
) -> AuthSession {
    AuthSession {
        id: id_generator.next_id("sess"),
        account_id: account_id.to_string(),
        client_id: client_id.to_string(),
        device_id,
        status: SessionStatus::Active,
        created_at: now,
        expires_at: now + Duration::from_secs(session_ttl_secs),
        refresh_token_version: 0,
    }
}

fn maybe_attach_device_to_account(
    store: &mut impl AuthStoreDeviceBinding,
    id_generator: &impl IdGenerator,
    account_id: &str,
    client_id: &str,
    device_id: Option<&str>,
    now: SystemTime,
) -> Result<Option<String>, StoreError> {
    let Some(device_id) = device_id.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };

    let mut device = store
        .find_device(device_id)?
        .ok_or(StoreError::NotFound("device.id"))?;
    ensure_device_is_active_for_auth(&device)?;
    if device.client_id != client_id {
        return Err(StoreError::Conflict("device.client_id"));
    }

    device.last_seen_at = Some(now);
    store.update_device(device)?;

    match store.find_active_account_device_binding(account_id, device_id)? {
        Some(mut binding) => {
            binding.last_authenticated_at = Some(now);
            store.update_account_device_binding(binding)?;
        }
        None => {
            store.insert_account_device_binding(AccountDeviceBinding {
                id: id_generator.next_id("dbind"),
                account_id: account_id.to_string(),
                device_id: device_id.to_string(),
                status: AccountDeviceBindingStatus::Active,
                bound_at: now,
                unbound_at: None,
                last_authenticated_at: Some(now),
            })?;
        }
    }

    Ok(Some(device_id.to_string()))
}

fn ensure_device_is_active_for_auth(device: &DeviceRecord) -> Result<(), StoreError> {
    match device.status {
        DeviceStatus::Active => Ok(()),
        DeviceStatus::Disabled | DeviceStatus::Revoked => {
            Err(StoreError::Conflict("device.status"))
        }
        DeviceStatus::Pending => Err(StoreError::Conflict("device.registration_state")),
    }
}

fn insert_refresh_token_record(
    store: &mut impl RefreshTokenStore,
    id_generator: &impl IdGenerator,
    tokens: &crate::IssuedTokenBundle,
    session_id: &str,
    issued_at: SystemTime,
) -> Result<RefreshTokenRecord, StoreError> {
    store.insert_refresh_token(RefreshTokenRecord {
        id: id_generator.next_id("rtok"),
        session_id: session_id.to_string(),
        token_value: tokens.refresh_token.clone(),
        token_version: tokens.refresh_token_version,
        issued_at,
        expires_at: tokens.refresh_expires_at,
        revoked_at: None,
    })
}

fn map_store_error(error: StoreError) -> ServiceError {
    if let Some(error) = map_account_status_conflict(&error) {
        return error;
    }

    match error {
        StoreError::Conflict("account.email") => ServiceError::EmailAlreadyExists,
        StoreError::Conflict("account.active") => ServiceError::InvalidVerificationCode,
        StoreError::Conflict("email_verification.code")
        | StoreError::NotFound("email_verification.code") => ServiceError::InvalidVerificationCode,
        StoreError::Conflict("email_verification.expired") => ServiceError::VerificationCodeExpired,
        StoreError::Conflict("auth_session.status")
        | StoreError::Conflict("auth_session.expired") => ServiceError::SessionExpired,
        StoreError::Conflict("auth_session.revoked") => ServiceError::SessionRevoked,
        StoreError::Conflict("device.client_id") => ServiceError::DeviceClientMismatch,
        StoreError::Conflict("device.status") => ServiceError::DeviceDisabled,
        StoreError::Conflict("device.registration_state") => {
            ServiceError::DeviceRegistrationStateInvalid
        }
        StoreError::Conflict("refresh_token.inactive")
        | StoreError::NotFound("refresh_token.value") => ServiceError::InvalidToken,
        StoreError::NotFound("device.id") => ServiceError::DeviceNotFound,
        StoreError::NotFound("oidc_client.id") => ServiceError::ClientNotFound,
        StoreError::NotFound("account.credentials") => ServiceError::InvalidCredentials,
        StoreError::NotFound("account.id") => ServiceError::AccountNotFound,
        StoreError::NotFound("auth_session.id") => ServiceError::SessionNotFound,
        StoreError::Backend(message) if message.starts_with("invalid client config:") => {
            ServiceError::InvalidClientConfig(parse_client_error(&message))
        }
        StoreError::Backend(message) if message.starts_with("token:") => {
            ServiceError::Token(parse_token_error(&message))
        }
        other => ServiceError::Store(other),
    }
}

pub(super) fn parse_client_error(message: &str) -> crate::ClientValidationError {
    if message.contains("PublicClientMustRequirePkce") {
        return crate::ClientValidationError::PublicClientMustRequirePkce;
    }
    if message.contains("PublicClientCannotHaveClientSecret") {
        return crate::ClientValidationError::PublicClientCannotHaveClientSecret;
    }
    if message.contains("ConfidentialClientRequiresSecret") {
        return crate::ClientValidationError::ConfidentialClientRequiresSecret;
    }
    if message.contains("MissingClientId") {
        return crate::ClientValidationError::MissingClientId;
    }
    if message.contains("MissingRedirectUri") {
        return crate::ClientValidationError::MissingRedirectUri;
    }
    crate::ClientValidationError::InvalidRedirectUri(message.to_string())
}

pub(super) fn parse_token_error(message: &str) -> TokenError {
    if message.contains("InvalidRefreshRotation") {
        return TokenError::InvalidRefreshRotation;
    }
    if message.contains("RefreshTokenVersionOverflow") {
        return TokenError::RefreshTokenVersionOverflow;
    }
    TokenError::IssuerRejected(message.to_string())
}

impl StoreError {
    fn from_token(error: TokenError) -> Self {
        StoreError::Backend(format!("token:{error:?}"))
    }
}

trait AuthStoreDeviceBinding:
    DeviceStore
    + AccountDeviceBindingStore
    + SessionStore
    + AccountStore
    + ClientStore
    + EmailVerificationStore
    + RefreshTokenStore
{
}

impl<T> AuthStoreDeviceBinding for T where
    T: DeviceStore
        + AccountDeviceBindingStore
        + SessionStore
        + AccountStore
        + ClientStore
        + EmailVerificationStore
        + RefreshTokenStore
{
}

fn pending_email_verification(
    verification: &crate::EmailVerificationCode,
) -> PendingEmailVerification {
    PendingEmailVerification {
        account_id: verification.account_id.clone(),
        email: verification.email.clone(),
        code: verification.code.clone(),
        expires_at: verification.expires_at,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    use super::*;
    use crate::{
        AccountDeviceBinding, AccountDeviceBindingStore, AccountStore, AuthorizationCodeRecord,
        AuthorizationCodeStore, DeviceNonceRecord, DeviceNonceStore, DeviceRecord, DeviceStore,
        EmailVerificationCode, EmailVerificationStore, IssuedTokenBundle, OidcClientType,
        RefreshTokenRecord, RefreshTokenStore, SessionStore, VerificationCodeGenerator,
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
            _account_id: &str,
            _client_id: &str,
            refresh_token_version: u64,
            issued_at: SystemTime,
        ) -> Result<IssuedTokenBundle, TokenError> {
            Ok(IssuedTokenBundle {
                access_token: format!("access-{session_id}"),
                refresh_token: format!("refresh-{session_id}-{refresh_token_version}"),
                access_expires_at: issued_at + Duration::from_secs(900),
                refresh_expires_at: issued_at + Duration::from_secs(86_400),
                refresh_token_version,
            })
        }
    }

    struct TestVerificationCodeGenerator;
    impl VerificationCodeGenerator for TestVerificationCodeGenerator {
        fn generate_code(&self) -> String {
            "123456".to_string()
        }
    }

    #[derive(Default)]
    struct TestStoreState {
        accounts: HashMap<String, Account>,
        sessions: HashMap<String, AuthSession>,
        devices: HashMap<String, DeviceRecord>,
        bindings: Vec<AccountDeviceBinding>,
        email_verifications: HashMap<String, EmailVerificationCode>,
        refresh_tokens: HashMap<String, RefreshTokenRecord>,
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
            _code: &str,
        ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
            Ok(None)
        }

        fn insert_authorization_code(
            &mut self,
            code: AuthorizationCodeRecord,
        ) -> Result<AuthorizationCodeRecord, StoreError> {
            Ok(code)
        }

        fn consume_authorization_code(
            &mut self,
            _code: &str,
            _consumed_at: SystemTime,
        ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
            Ok(None)
        }
    }

    impl RefreshTokenStore for TestStoreTx<'_> {
        fn find_refresh_token(
            &mut self,
            token_value: &str,
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(self.state.refresh_tokens.get(token_value).cloned())
        }

        fn insert_refresh_token(
            &mut self,
            token: RefreshTokenRecord,
        ) -> Result<RefreshTokenRecord, StoreError> {
            self.state
                .refresh_tokens
                .insert(token.token_value.clone(), token.clone());
            Ok(token)
        }

        fn revoke_refresh_token(
            &mut self,
            token_value: &str,
            revoked_at: SystemTime,
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            let Some(token) = self.state.refresh_tokens.get_mut(token_value) else {
                return Ok(None);
            };
            token.revoked_at = Some(revoked_at);
            Ok(Some(token.clone()))
        }

        fn revoke_refresh_tokens_for_session(
            &mut self,
            session_id: &str,
            revoked_at: SystemTime,
        ) -> Result<Vec<RefreshTokenRecord>, StoreError> {
            let mut revoked = Vec::new();
            for token in self.state.refresh_tokens.values_mut() {
                if token.session_id == session_id && token.revoked_at.is_none() {
                    token.revoked_at = Some(revoked_at);
                    revoked.push(token.clone());
                }
            }
            Ok(revoked)
        }
    }

    impl EmailVerificationStore for TestStoreTx<'_> {
        fn find_email_verification_code(
            &mut self,
            email: &str,
            code: &str,
        ) -> Result<Option<EmailVerificationCode>, StoreError> {
            Ok(self
                .state
                .email_verifications
                .values()
                .filter(|verification| verification.email == email && verification.code == code)
                .max_by_key(|verification| verification.issued_at)
                .cloned())
        }

        fn insert_email_verification_code(
            &mut self,
            verification: EmailVerificationCode,
        ) -> Result<EmailVerificationCode, StoreError> {
            self.state
                .email_verifications
                .insert(verification.id.clone(), verification.clone());
            Ok(verification)
        }

        fn consume_email_verification_code(
            &mut self,
            verification_id: &str,
            consumed_at: SystemTime,
        ) -> Result<Option<EmailVerificationCode>, StoreError> {
            let Some(verification) = self.state.email_verifications.get_mut(verification_id) else {
                return Ok(None);
            };
            verification.consumed_at = Some(consumed_at);
            Ok(Some(verification.clone()))
        }

        fn consume_email_verification_codes_for_account(
            &mut self,
            account_id: &str,
            consumed_at: SystemTime,
        ) -> Result<Vec<EmailVerificationCode>, StoreError> {
            let mut consumed = Vec::new();
            for verification in self.state.email_verifications.values_mut() {
                if verification.account_id == account_id && verification.consumed_at.is_none() {
                    verification.consumed_at = Some(consumed_at);
                    consumed.push(verification.clone());
                }
            }
            Ok(consumed)
        }
    }

    impl ClientStore for TestStoreTx<'_> {
        fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
            Ok(Some(OidcClient {
                client_id: client_id.to_string(),
                client_name: "Desktop".to_string(),
                redirect_uris: vec!["http://127.0.0.1:8080/callback".to_string()],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret_hash: None,
            }))
        }

        fn list_clients(&mut self) -> Result<Vec<OidcClient>, StoreError> {
            Ok(vec![OidcClient {
                client_id: "desktop-app".to_string(),
                client_name: "Desktop".to_string(),
                redirect_uris: vec!["http://127.0.0.1:8080/callback".to_string()],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret_hash: None,
            }])
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
            Ok(1)
        }

        fn upsert_client(&mut self, client: OidcClient) -> Result<OidcClient, StoreError> {
            Ok(client)
        }
    }

    impl DeviceStore for TestStoreTx<'_> {
        fn find_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(self.state.devices.get(device_id).cloned())
        }

        fn list_devices(&mut self) -> Result<Vec<DeviceRecord>, StoreError> {
            Ok(self.state.devices.values().cloned().collect())
        }

        fn list_devices_by_query(
            &mut self,
            _query: &crate::DeviceListQuery,
        ) -> Result<Vec<DeviceRecord>, StoreError> {
            self.list_devices()
        }

        fn count_devices_by_query(
            &mut self,
            _query: &crate::DeviceListQuery,
        ) -> Result<u64, StoreError> {
            Ok(self.state.devices.len() as u64)
        }

        fn find_device_by_proof_key_id(
            &mut self,
            _proof_key_id: &str,
        ) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(None)
        }

        fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            self.state.devices.insert(device.id.clone(), device.clone());
            Ok(device)
        }

        fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            self.state.devices.insert(device.id.clone(), device.clone());
            Ok(device)
        }
    }

    impl AccountDeviceBindingStore for TestStoreTx<'_> {
        fn find_active_account_device_binding(
            &mut self,
            account_id: &str,
            device_id: &str,
        ) -> Result<Option<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .iter()
                .find(|binding| {
                    binding.account_id == account_id
                        && binding.device_id == device_id
                        && binding.status == AccountDeviceBindingStatus::Active
                })
                .cloned())
        }

        fn list_account_device_bindings_by_device(
            &mut self,
            device_id: &str,
        ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .iter()
                .filter(|binding| binding.device_id == device_id)
                .cloned()
                .collect())
        }

        fn list_active_account_device_bindings_by_account(
            &mut self,
            account_id: &str,
        ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .iter()
                .filter(|binding| {
                    binding.account_id == account_id
                        && binding.status == AccountDeviceBindingStatus::Active
                })
                .cloned()
                .collect())
        }

        fn insert_account_device_binding(
            &mut self,
            binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            self.state.bindings.push(binding.clone());
            Ok(binding)
        }

        fn update_account_device_binding(
            &mut self,
            binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            if let Some(existing) = self
                .state
                .bindings
                .iter_mut()
                .find(|existing| existing.id == binding.id)
            {
                *existing = binding.clone();
            } else {
                self.state.bindings.push(binding.clone());
            }
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

    fn service_with_account(
        account: Option<Account>,
    ) -> CoreAuthService<
        TestStoreRunner,
        TestTokenIssuer,
        TestClock,
        TestIds,
        TestVerificationCodeGenerator,
    > {
        service_with_state(account, None)
    }

    fn service_with_state(
        account: Option<Account>,
        device: Option<DeviceRecord>,
    ) -> CoreAuthService<
        TestStoreRunner,
        TestTokenIssuer,
        TestClock,
        TestIds,
        TestVerificationCodeGenerator,
    > {
        let runner = TestStoreRunner::default();
        {
            let mut state = runner.state.lock().unwrap();
            if let Some(account) = account {
                state.accounts.insert(account.id.clone(), account);
            }
            if let Some(device) = device {
                state.devices.insert(device.id.clone(), device);
            }
        }

        CoreAuthService::new(
            AuthConfig {
                allow_local_registration: true,
                access_token_ttl_secs: 900,
                refresh_token_ttl_secs: 86_400,
                session_ttl_secs: 604_800,
                verification_code_ttl_secs: 900,
                password_min_length: 8,
                password_max_length: 128,
            },
            runner,
            TestTokenIssuer,
            TestClock,
            TestIds,
            TestVerificationCodeGenerator,
        )
    }

    #[test]
    fn register_account_returns_pending_verification() {
        let service = service_with_account(None);

        let result = service.register_account(RegisterAccountCommand {
            email: "user@example.com".to_string(),
            password: "password-1".to_string(),
            display_name: Some("User".to_string()),
            client_id: "desktop-app".to_string(),
            device_id: None,
        });

        let result = result.expect("register account should succeed");
        assert_eq!(result.account.id, "acct-1");
        assert_eq!(result.account.status, AccountStatus::PendingVerification);
        assert_eq!(result.verification.code, "123456");
        assert_eq!(result.verification.account_id, "acct-1");
        assert_ne!(result.account.password_hash, "hash");
    }

    #[test]
    fn login_rejects_wrong_password() {
        let service = service_with_account(Some(Account {
            id: "acct-1".to_string(),
            email: "user@example.com".to_string(),
            password_hash: hash_password("correct").expect("hash password"),
            display_name: None,
            status: AccountStatus::Active,
            created_at: SystemTime::UNIX_EPOCH,
        }));

        let result = service.login(LoginCommand {
            email: "user@example.com".to_string(),
            password: "wrong".to_string(),
            client_id: "desktop-app".to_string(),
            device_id: None,
        });

        assert_eq!(result, Err(ServiceError::InvalidCredentials));
    }

    #[test]
    fn register_account_rejects_short_password() {
        let service = service_with_account(None);

        let result = service.register_account(RegisterAccountCommand {
            email: "user@example.com".to_string(),
            password: "short".to_string(),
            display_name: None,
            client_id: "desktop-app".to_string(),
            device_id: None,
        });

        assert_eq!(
            result,
            Err(ServiceError::InvalidContract(
                crate::ContractValidationError::PasswordTooShort { min_length: 8 }
            ))
        );
    }

    #[test]
    fn rotate_refresh_token_increments_version() {
        let service = service_with_account(None);
        let registered = service
            .register_account(RegisterAccountCommand {
                email: "user@example.com".to_string(),
                password: "password-1".to_string(),
                display_name: None,
                client_id: "desktop-app".to_string(),
                device_id: None,
            })
            .expect("register account should succeed");
        let verified = service
            .verify_email(VerifyEmailCommand {
                email: "user@example.com".to_string(),
                verification_code: registered.verification.code,
                client_id: "desktop-app".to_string(),
                device_id: None,
            })
            .expect("verify email should succeed");

        let rotated = service
            .rotate_refresh_token(RotateRefreshTokenCommand {
                refresh_token: verified.tokens.refresh_token,
                rotated_at: SystemTime::UNIX_EPOCH,
            })
            .expect("rotation should succeed");

        assert_eq!(rotated.session.refresh_token_version, 1);
        assert_eq!(rotated.tokens.refresh_token, "refresh-sess-1-1");
    }

    #[test]
    fn logout_revokes_session_and_refresh_tokens() {
        let service = service_with_account(None);
        let registered = service
            .register_account(RegisterAccountCommand {
                email: "user@example.com".to_string(),
                password: "password-1".to_string(),
                display_name: None,
                client_id: "desktop-app".to_string(),
                device_id: None,
            })
            .expect("register account should succeed");
        let verified = service
            .verify_email(VerifyEmailCommand {
                email: "user@example.com".to_string(),
                verification_code: registered.verification.code,
                client_id: "desktop-app".to_string(),
                device_id: None,
            })
            .expect("verify email should succeed");

        let logged_out = service
            .logout(LogoutSessionCommand {
                refresh_token: verified.tokens.refresh_token,
                logged_out_at: SystemTime::UNIX_EPOCH,
            })
            .expect("logout should succeed");

        assert_eq!(logged_out.session.status, SessionStatus::Revoked);
    }

    #[test]
    fn login_with_active_device_sets_session_device_and_binding() {
        let service = service_with_state(
            Some(Account {
                id: "acct-1".to_string(),
                email: "user@example.com".to_string(),
                password_hash: hash_password("correct").expect("hash password"),
                display_name: None,
                status: AccountStatus::Active,
                created_at: SystemTime::UNIX_EPOCH,
            }),
            Some(DeviceRecord {
                id: "dev-1".to_string(),
                client_id: "desktop-app".to_string(),
                device_name: "Demo Device".to_string(),
                proof_key_id: Some("proof-1".to_string()),
                status: DeviceStatus::Active,
                registered_at: SystemTime::UNIX_EPOCH,
                last_seen_at: None,
            }),
        );

        let result = service
            .login(LoginCommand {
                email: "user@example.com".to_string(),
                password: "correct".to_string(),
                client_id: "desktop-app".to_string(),
                device_id: Some("dev-1".to_string()),
            })
            .expect("login should succeed");

        assert_eq!(result.session.device_id.as_deref(), Some("dev-1"));
    }

    #[test]
    fn login_rejects_pending_device_context() {
        let service = service_with_state(
            Some(Account {
                id: "acct-1".to_string(),
                email: "user@example.com".to_string(),
                password_hash: hash_password("correct").expect("hash password"),
                display_name: None,
                status: AccountStatus::Active,
                created_at: SystemTime::UNIX_EPOCH,
            }),
            Some(DeviceRecord {
                id: "dev-1".to_string(),
                client_id: "desktop-app".to_string(),
                device_name: "Demo Device".to_string(),
                proof_key_id: None,
                status: DeviceStatus::Pending,
                registered_at: SystemTime::UNIX_EPOCH,
                last_seen_at: None,
            }),
        );

        let result = service.login(LoginCommand {
            email: "user@example.com".to_string(),
            password: "correct".to_string(),
            client_id: "desktop-app".to_string(),
            device_id: Some("dev-1".to_string()),
        });

        assert_eq!(result, Err(ServiceError::DeviceRegistrationStateInvalid));
    }

    #[test]
    fn login_rejects_pending_verification_account() {
        let service = service_with_account(Some(Account {
            id: "acct-1".to_string(),
            email: "user@example.com".to_string(),
            password_hash: hash_password("correct").expect("hash password"),
            display_name: None,
            status: AccountStatus::PendingVerification,
            created_at: SystemTime::UNIX_EPOCH,
        }));

        let result = service.login(LoginCommand {
            email: "user@example.com".to_string(),
            password: "correct".to_string(),
            client_id: "desktop-app".to_string(),
            device_id: None,
        });

        assert_eq!(result, Err(ServiceError::AccountPendingVerification));
    }

    #[test]
    fn verify_email_activates_account_and_returns_tokens() {
        let service = service_with_account(None);
        let registered = service
            .register_account(RegisterAccountCommand {
                email: "user@example.com".to_string(),
                password: "password-1".to_string(),
                display_name: Some("User".to_string()),
                client_id: "desktop-app".to_string(),
                device_id: None,
            })
            .expect("register account should succeed");

        let result = service
            .verify_email(VerifyEmailCommand {
                email: "user@example.com".to_string(),
                verification_code: registered.verification.code,
                client_id: "desktop-app".to_string(),
                device_id: None,
            })
            .expect("verify email should succeed");

        assert_eq!(result.account.status, AccountStatus::Active);
        assert_eq!(result.session.id, "sess-1");
        assert_eq!(result.tokens.access_token, "access-sess-1");
    }

    #[test]
    fn resend_verification_code_reissues_code_for_pending_account() {
        let service = service_with_account(None);
        service
            .register_account(RegisterAccountCommand {
                email: "user@example.com".to_string(),
                password: "password-1".to_string(),
                display_name: None,
                client_id: "desktop-app".to_string(),
                device_id: None,
            })
            .expect("register account should succeed");

        let result = service
            .resend_verification_code(ResendVerificationCodeCommand {
                email: "user@example.com".to_string(),
            })
            .expect("resend should succeed");

        assert_eq!(result.account.status, AccountStatus::PendingVerification);
        assert_eq!(result.verification.code, "123456");
    }
}

use super::*;
use crate::{RefreshTokenRevocationReason, ScopedAccessTokenIssuer, TokenError};

/// A browser's expected current session. This assertion prevents a stale tab
/// from silently accepting a different account or tenant after Cookie rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionIdentity {
    pub tenant_id: String,
    pub account_id: String,
    pub session_id: String,
    pub client_id: String,
}

/// A currently valid business browser session, constructed only after the
/// refresh credential and its owning session have both been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedBrowserSession {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String,
    authenticated_at: SystemTime,
    expires_at: SystemTime,
}

impl AuthenticatedBrowserSession {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn authenticated_at(&self) -> SystemTime {
        self.authenticated_at
    }

    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

/// Reads the authenticated identity behind a browser refresh Cookie without
/// rotating, issuing, or revoking credentials. This is limited to business
/// browser workflows that need to bind an action to the current person.
pub trait BrowserSessionIdentityService: Send + Sync {
    /// Configured upper bound for restricted, non-renewable browser sessions.
    fn browser_session_lifetime_secs(&self) -> Option<u64> {
        None
    }
    fn authenticate_browser(
        &self,
        cookie: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<AuthenticatedBrowserSession, TenantAuthError>;
}

/// Cookie adapters use this dedicated contract instead of exposing refresh
/// credentials to browser scripts. Implementations remain purpose-specific.
pub trait BrowserSessionService: Send + Sync {
    /// Configured upper bound for restricted, non-renewable browser sessions.
    fn browser_session_lifetime_secs(&self) -> Option<u64> {
        None
    }
    fn browser_purpose(&self) -> AccessTokenPurpose;
    fn browser_login(
        &self,
        command: TenantPasswordLogin,
    ) -> Result<TenantLoginOutcome, TenantAuthError>;
    fn browser_select(
        &self,
        ticket: SecretString,
        tenant: String,
    ) -> Result<TenantLoginSession, TenantAuthError>;
    fn browser_refresh(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError>;
    fn browser_logout(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<(), TenantAuthError>;
}

impl<S, T, G, D, C, I> CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
{
    fn browser_refresh_impl(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        self.rotate_with_device_step(token, expected.as_ref(), |_, session| {
            if self.entry.require_device_proof || session.device_id.is_some() {
                return Err(TenantAuthError::DeviceProofRequired);
            }
            Ok(())
        })
    }

    fn browser_logout_impl(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<(), TenantAuthError> {
        let digest = match self.digester.digest_refresh_token(token.expose_secret()) {
            Ok(digest) => digest,
            Err(TokenError::InvalidRefreshTokenEncoding) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        self.store.auth_transaction(self.mode, |tx| {
            let Some(hint) = tx.find_refresh(&digest)? else {
                return Ok(());
            };
            if self.validate_login_tenant(&hint.tenant_id).is_err() {
                return Ok(());
            }
            tx.lock_tenants(&[hint.tenant_id.clone()])?;
            let Some(session_hint) = tx.session(&hint.tenant_id, &hint.session_id)? else {
                return Ok(());
            };
            let Some(account) = tx.lock_account(&session_hint.account_id)? else {
                return Ok(());
            };
            let Some(session) = tx.lock_refresh_session(&hint.tenant_id, &hint.session_id)? else {
                return Ok(());
            };
            let Some(refresh) = tx.lock_refresh_record(&hint.tenant_id, &digest)? else {
                return Ok(());
            };
            if account.id != session.account_id
                || session.account_id != session_hint.account_id
                || session.tenant_id != hint.tenant_id
                || session.id != hint.session_id
                || refresh.tenant_id != session.tenant_id
                || refresh.session_id != session.id
                || refresh.id != hint.id
                || refresh.token_digest != digest
                || session.client_id != self.entry.client_id
                || !tx.client_exists(&self.entry.client_id)?
            {
                return Ok(());
            }
            let now = self.clock.now();
            let identity_valid = match self.require_session_identity(
                tx,
                &session,
                &session.tenant_id,
                &session.id,
                &account.id,
                now,
            ) {
                Ok(()) => true,
                Err(
                    error @ (TenantAuthError::Store(_)
                    | TenantAuthError::Access(AccessError::Store(_))),
                ) => return Err(error),
                Err(_) => false,
            };
            if !account.active
                || !identity_valid
                || refresh.issued_at < session.created_at
                || refresh.issued_at > now
                || refresh.expires_at <= now
                || refresh.expires_at > session.expires_at
                || refresh.revoked_at.is_some()
                || refresh.token_version != session.refresh_token_version
            {
                return Ok(());
            }
            if expected.is_some_and(|expected| {
                expected.tenant_id != session.tenant_id
                    || expected.account_id != session.account_id
                    || expected.session_id != session.id
                    || expected.client_id != session.client_id
            }) {
                return Err(AccessError::InvalidInput("browser_session_changed").into());
            }
            if self.entry.require_device_proof || session.device_id.is_some() {
                return Err(TenantAuthError::DeviceProofRequired);
            }
            tx.revoke_refresh_family(&session, RefreshTokenRevocationReason::Logout, now)?;
            Ok(())
        })
    }

    fn authenticate_browser_impl(
        &self,
        cookie: SecretString,
        expected: Option<BrowserSessionIdentity>,
        lifetime_secs: Option<u64>,
    ) -> Result<AuthenticatedBrowserSession, TenantAuthError> {
        if self.purpose != AccessTokenPurpose::Business || self.entry.require_device_proof {
            return Err(TenantAuthError::InvalidSession);
        }
        let digest = self
            .digester
            .digest_refresh_token(cookie.expose_secret())
            .map_err(|_| TenantAuthError::InvalidRefresh)?;
        self.store.auth_transaction(self.mode, |tx| {
            let hint = tx
                .find_refresh(&digest)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            self.validate_login_tenant(&hint.tenant_id)
                .map_err(|_| TenantAuthError::InvalidRefresh)?;
            // Use the same tenant -> account -> session -> refresh ordering as
            // rotation. A stale refresh is rejected below without reuse-family
            // revocation because this operation has no state-changing purpose.
            tx.lock_tenants(&[hint.tenant_id.clone()])?;
            let session_hint = tx
                .session(&hint.tenant_id, &hint.session_id)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            let account = tx
                .lock_account(&session_hint.account_id)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            let session = tx
                .lock_refresh_session(&hint.tenant_id, &hint.session_id)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            let refresh = tx
                .lock_refresh_record(&hint.tenant_id, &digest)?
                .ok_or(TenantAuthError::InvalidRefresh)?;
            if !account.active
                || account.id != session.account_id
                || session.account_id != session_hint.account_id
                || session.tenant_id != hint.tenant_id
                || session.id != hint.session_id
                || refresh.tenant_id != session.tenant_id
                || refresh.session_id != session.id
                || refresh.id != hint.id
                || refresh.token_digest != digest
                || session.client_id != self.entry.client_id
                || !tx.client_exists(&self.entry.client_id)?
            {
                return Err(TenantAuthError::InvalidRefresh);
            }
            let now = self.clock.now();
            self.require_session_identity(
                tx,
                &session,
                &session.tenant_id,
                &session.id,
                &account.id,
                now,
            )?;
            if lifetime_secs.is_some_and(|lifetime| {
                session
                    .created_at
                    .checked_add(Duration::from_secs(lifetime))
                    .is_none_or(|bound| session.expires_at > bound)
            }) {
                return Err(TenantAuthError::InvalidSession);
            }
            if session.device_id.is_some() {
                return Err(TenantAuthError::DeviceProofRequired);
            }
            if expected.is_some_and(|expected| {
                expected.tenant_id != session.tenant_id
                    || expected.account_id != session.account_id
                    || expected.session_id != session.id
                    || expected.client_id != session.client_id
            }) {
                return Err(AccessError::InvalidInput("browser_session_changed").into());
            }
            if refresh.issued_at < session.created_at
                || refresh.issued_at > now
                || refresh.expires_at <= now
                || refresh.expires_at > session.expires_at
                || refresh.token_version == 0
                || refresh.token_version != session.refresh_token_version
                || refresh.revoked_at.is_some()
                || refresh.revocation_reason.is_some()
            {
                return Err(TenantAuthError::InvalidRefresh);
            }
            Ok(AuthenticatedBrowserSession {
                tenant_id: session.tenant_id,
                account_id: session.account_id,
                session_id: session.id,
                client_id: session.client_id,
                authenticated_at: session.authenticated_at,
                expires_at: session.expires_at.min(refresh.expires_at),
            })
        })
    }
}

impl<S, T, G, D, C, I> BrowserSessionIdentityService
    for CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore + Send + Sync,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn authenticate_browser(
        &self,
        cookie: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<AuthenticatedBrowserSession, TenantAuthError> {
        self.authenticate_browser_impl(cookie, expected, None)
    }
}

impl<S, T, G, D, C, I> BrowserSessionService for CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore + Send + Sync,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn browser_purpose(&self) -> AccessTokenPurpose {
        self.purpose
    }

    fn browser_login(
        &self,
        command: TenantPasswordLogin,
    ) -> Result<TenantLoginOutcome, TenantAuthError> {
        if self.entry.require_device_proof {
            return Err(TenantAuthError::DeviceProofRequired);
        }
        self.login(command)
    }

    fn browser_select(
        &self,
        ticket: SecretString,
        tenant: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        if self.entry.require_device_proof {
            return Err(TenantAuthError::DeviceProofRequired);
        }
        self.select_tenant(ticket, tenant)
    }

    fn browser_refresh(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        self.browser_refresh_impl(token, expected)
    }

    fn browser_logout(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<(), TenantAuthError> {
        self.browser_logout_impl(token, expected)
    }
}

impl<S, T, G, D, C, I> BrowserSessionService
    for CoreManagementAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore + Send + Sync,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn browser_purpose(&self) -> AccessTokenPurpose {
        AccessTokenPurpose::Management
    }

    fn browser_login(
        &self,
        command: TenantPasswordLogin,
    ) -> Result<TenantLoginOutcome, TenantAuthError> {
        self.auth.login(command)
    }

    fn browser_select(
        &self,
        ticket: SecretString,
        tenant: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.auth.select_tenant(ticket, tenant)
    }

    fn browser_refresh(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        self.auth.browser_refresh_impl(token, expected)
    }

    fn browser_logout(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<(), TenantAuthError> {
        self.auth.browser_logout_impl(token, expected)
    }
}

/// A purpose-specific browser-only service with bounded issuance and no refresh.
/// Construct a separate service and compatible token issuer for this mode;
/// consuming the service does not modify other browser or device services.
pub struct RestrictedBrowserSessionService<S, T, G, D, C, I> {
    auth: CoreTenantAuthenticationService<S, T, G, D, C, I>,
    lifetime_secs: u64,
}

impl<S, T, G, D, C, I> CoreTenantAuthenticationService<S, T, G, D, C, I> {
    pub fn into_restricted_browser(
        mut self,
        lifetime_secs: u64,
    ) -> Result<RestrictedBrowserSessionService<S, T, G, D, C, I>, TenantAuthError> {
        if !(60..=3600).contains(&lifetime_secs) {
            return Err(AccessError::InvalidInput("browser_session_lifetime").into());
        }
        if self.entry.require_device_proof {
            return Err(TenantAuthError::DeviceProofRequired);
        }
        self.config.session_ttl_secs = self.config.session_ttl_secs.min(lifetime_secs);
        self.config.refresh_token_ttl_secs = self.config.refresh_token_ttl_secs.min(lifetime_secs);
        self.config.access_token_ttl_secs = self
            .config
            .access_token_ttl_secs
            .min(self.config.refresh_token_ttl_secs - 1);
        self.config
            .validate()
            .map_err(TenantAuthError::Configuration)?;
        Ok(RestrictedBrowserSessionService {
            auth: self,
            lifetime_secs,
        })
    }
}
impl<S, T, G, D, C, I> CoreManagementAuthenticationService<S, T, G, D, C, I> {
    pub fn into_restricted_browser(
        self,
        lifetime_secs: u64,
    ) -> Result<RestrictedBrowserSessionService<S, T, G, D, C, I>, TenantAuthError> {
        self.auth.into_restricted_browser(lifetime_secs)
    }
}
impl<S, T, G, D, C, I> BrowserSessionService for RestrictedBrowserSessionService<S, T, G, D, C, I>
where
    S: TenantAuthStore + Send + Sync,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn browser_session_lifetime_secs(&self) -> Option<u64> {
        Some(self.lifetime_secs)
    }
    fn browser_purpose(&self) -> AccessTokenPurpose {
        self.auth.purpose
    }
    fn browser_login(
        &self,
        command: TenantPasswordLogin,
    ) -> Result<TenantLoginOutcome, TenantAuthError> {
        self.auth.browser_login(command)
    }
    fn browser_select(
        &self,
        ticket: SecretString,
        tenant: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.auth.browser_select(ticket, tenant)
    }
    fn browser_refresh(
        &self,
        _: SecretString,
        _: Option<BrowserSessionIdentity>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        Err(AccessError::InvalidInput("browser_refresh_disabled").into())
    }
    fn browser_logout(
        &self,
        token: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<(), TenantAuthError> {
        let expected = expected.ok_or(AccessError::InvalidInput(
            "browser_expected_session_required",
        ))?;
        self.auth.browser_logout(token, Some(expected))
    }
}
impl<S, T, G, D, C, I> BrowserSessionIdentityService
    for RestrictedBrowserSessionService<S, T, G, D, C, I>
where
    S: TenantAuthStore + Send + Sync,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn browser_session_lifetime_secs(&self) -> Option<u64> {
        Some(self.lifetime_secs)
    }
    fn authenticate_browser(
        &self,
        cookie: SecretString,
        expected: Option<BrowserSessionIdentity>,
    ) -> Result<AuthenticatedBrowserSession, TenantAuthError> {
        let expected = expected.ok_or(AccessError::InvalidInput(
            "browser_expected_session_required",
        ))?;
        self.auth
            .authenticate_browser_impl(cookie, Some(expected), Some(self.lifetime_secs))
    }
}

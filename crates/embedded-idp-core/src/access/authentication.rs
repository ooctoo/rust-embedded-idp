mod device_transport;
pub use device_transport::*;
mod oidc;
pub use oidc::*;
mod browser;
mod device_login;
mod management;
mod refresh;
pub use browser::*;
pub use device_login::*;
pub use management::*;
pub use refresh::*;

use super::{query::validate_id, service::finish_page, *};
use crate::service::password::verify_password;
use crate::{
    AccessTokenPurpose, AccessTokenValidator, AuthConfig, Clock, ConfigValidationError,
    IdGenerator, IssuedTokenBundle, RefreshTokenDigester, RefreshTokenGenerator, SecretString,
    SessionStatus, StoreError, TokenError, TokenIssuer, ValidatedAccessToken,
};
use std::time::{Duration, SystemTime};

const SELECTION_PURPOSE: &str = "tenant_selection";
const SELECTION_TTL_SECS: u64 = 300;

/// Trusted host configuration, never deserialized from a login request.
#[derive(Debug, Clone)]
pub struct TenantLoginEntry {
    pub client_id: String,
    pub login_entry: String,
    pub policy: LoginTenantPolicy,
    /// Missing proof must never issue a device-less business session.
    pub require_device_proof: bool,
}
#[derive(Debug, Clone)]
pub struct TenantPasswordLogin {
    pub email: String,
    pub password: SecretString,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSession {
    pub purpose: AccessTokenPurpose,
    pub tenant_id: String,
    pub id: String,
    pub account_id: String,
    pub client_id: String,
    pub device_id: Option<String>,
    /// None uses the host default; Some is the exact delegated OAuth scope.
    pub scope: Option<String>,
    pub authenticated_at: SystemTime,
    pub status: SessionStatus,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub refresh_token_version: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantLoginSession {
    pub session: TenantSession,
    pub tokens: IssuedTokenBundle,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSelectionTicket {
    pub ticket: SecretString,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantLoginOutcome {
    Authenticated(TenantLoginSession),
    SelectionRequired(TenantSelectionTicket),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionSource {
    pub tenant_id: String,
    pub session_id: String,
}
/// Persistence projection: never includes the raw selection credential.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantSelectionRecord {
    pub id: String,
    pub ticket_digest: [u8; 32],
    pub account_id: String,
    pub client_id: String,
    pub login_entry: String,
    pub purpose: String,
    pub authenticated_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
    pub revoked_at: Option<SystemTime>,
    pub source: Option<SelectionSource>,
}
#[derive(Clone)]
pub struct TenantLoginIdentity {
    pub id: String,
    pub password_hash: SecretString,
    pub active: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantAuthError {
    Access(AccessError),
    Configuration(ConfigValidationError),
    Store(StoreError),
    Token(TokenError),
    InvalidCredentials,
    InvalidSelection,
    InvalidSession,
    InvalidRefresh,
    InvalidAuthorization,
    InvalidGrant,
    InvalidClient,
    DeviceProofRequired,
    DeviceProof(crate::DeviceRequestVerificationError),
    Security(crate::SecurityContractError),
}
impl From<AccessError> for TenantAuthError {
    fn from(e: AccessError) -> Self {
        Self::Access(e)
    }
}
impl From<StoreError> for TenantAuthError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<TokenError> for TenantAuthError {
    fn from(e: TokenError) -> Self {
        Self::Token(e)
    }
}

pub trait TenantAuthTransaction {
    /// Sorted, deduplicated shared tenant locks; call before any account/ticket locks.
    fn lock_tenants(&mut self, tenant_ids: &[String]) -> Result<(), StoreError>;
    fn lock_account_by_email(
        &mut self,
        email: &str,
    ) -> Result<Option<TenantLoginIdentity>, StoreError>;
    fn lock_account(&mut self, account_id: &str)
        -> Result<Option<TenantLoginIdentity>, StoreError>;
    fn client_exists(&mut self, client_id: &str) -> Result<bool, StoreError>;
    fn tenant(&mut self, tenant_id: &str) -> Result<Option<Tenant>, StoreError>;
    fn membership(
        &mut self,
        tenant_id: &str,
        account_id: &str,
    ) -> Result<Option<TenantMembership>, StoreError>;
    /// Non-locking hint ONLY, re-read with lock_selection after account lock.
    fn find_selection(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantSelectionRecord>, StoreError>;
    fn lock_selection(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantSelectionRecord>, StoreError>;
    fn insert_selection(&mut self, record: &TenantSelectionRecord) -> Result<(), StoreError>;
    fn consume_selection(&mut self, id: &str, now: SystemTime) -> Result<(), StoreError>;
    fn list_tenants(
        &mut self,
        account_id: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<SubjectTenant>, StoreError>;
    /// Current device/key/binding snapshot for a session. Called after the domain
    /// and account locks. Revocation writes must follow the same lock protocol.
    fn session_device(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<TenantSessionDevice>, StoreError>;
    fn session(
        &mut self,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<Option<TenantSession>, StoreError>;
    /// Insert session and initial refresh digest atomically; no plaintext credential.
    fn insert_session(
        &mut self,
        session: &TenantSession,
        refresh_id: &str,
        digest: &[u8; 32],
        refresh_expires_at: SystemTime,
    ) -> Result<(), StoreError>;
}
pub trait TenantAuthStore: Send + Sync {
    type Transaction<'a>: TenantAuthTransaction
    where
        Self: 'a;
    /// Read Committed, shared access_state lock and mode/bootstrap check before
    /// callback. Core then locks domains -> account -> ticket. Commit only on Ok.
    fn auth_transaction<R>(
        &self,
        mode: TenancyMode,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, TenantAuthError>,
    ) -> Result<R, TenantAuthError>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantLoginCapabilities {
    pub mode: TenancyMode,
    pub policy: LoginTenantPolicy,
}

/// HTTP adapters depend on this object-safe service; no database rules in handlers.
pub trait TenantAuthenticationService: Send + Sync {
    fn login_capabilities(&self) -> TenantLoginCapabilities;
    fn login(&self, command: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError>;
    fn list_tenants(
        &self,
        ticket: SecretString,
        page: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError>;
    fn select_tenant(
        &self,
        ticket: SecretString,
        tenant_id: String,
    ) -> Result<TenantLoginSession, TenantAuthError>;
    fn authenticate(&self, access_token: SecretString) -> Result<AccessActor, TenantAuthError>;
    fn begin_switch(
        &self,
        access_token: SecretString,
    ) -> Result<TenantSelectionTicket, TenantAuthError>;
}

pub struct CoreTenantAuthenticationService<S, T, G, D, C, I> {
    mode: TenancyMode,
    purpose: AccessTokenPurpose,
    config: AuthConfig,
    entry: TenantLoginEntry,
    store: S,
    tokens: T,
    generator: G,
    digester: D,
    clock: C,
    ids: I,
}
impl<S, T, G, D, C, I> CoreTenantAuthenticationService<S, T, G, D, C, I> {
    fn validate_login_tenant(&self, tenant: &str) -> Result<(), AccessError> {
        if self.purpose == AccessTokenPurpose::Management
            && self.entry.policy
                == (LoginTenantPolicy::Fixed {
                    tenant_id: SYSTEM_TENANT_ID.into(),
                })
            && tenant == SYSTEM_TENANT_ID
        {
            return Ok(());
        }
        self.entry.policy.validate_selection(self.mode, tenant)
    }
    fn selection_purpose(&self) -> &'static str {
        match self.purpose {
            AccessTokenPurpose::Business => SELECTION_PURPOSE,
            AccessTokenPurpose::Management => "management_tenant_selection",
        }
    }
    pub fn new(
        mode: TenancyMode,
        config: AuthConfig,
        entry: TenantLoginEntry,
        store: S,
        tokens: T,
        generator: G,
        digester: D,
        clock: C,
        ids: I,
    ) -> Result<Self, TenantAuthError> {
        Self::new_with_purpose(
            mode,
            config,
            entry,
            store,
            tokens,
            generator,
            digester,
            clock,
            ids,
            AccessTokenPurpose::Business,
        )
    }
    fn new_with_purpose(
        mode: TenancyMode,
        config: AuthConfig,
        entry: TenantLoginEntry,
        store: S,
        tokens: T,
        generator: G,
        digester: D,
        clock: C,
        ids: I,
        purpose: AccessTokenPurpose,
    ) -> Result<Self, TenantAuthError> {
        config.validate().map_err(TenantAuthError::Configuration)?;
        if purpose != AccessTokenPurpose::Management
            || entry.policy
                != (LoginTenantPolicy::Fixed {
                    tenant_id: SYSTEM_TENANT_ID.into(),
                })
        {
            entry.policy.validate(mode)?;
        }
        validate_id(&entry.client_id, 128, "client_id")?;
        validate_id(&entry.login_entry, 128, "login_entry")?;
        Ok(Self {
            mode,
            purpose,
            config,
            entry,
            store,
            tokens,
            generator,
            digester,
            clock,
            ids,
        })
    }
}
impl<S, T, G, D, C, I> CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore,
    T: TokenIssuer + AccessTokenValidator + crate::ScopedAccessTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
{
    fn login_with_device_step(
        &self,
        command: TenantPasswordLogin,
        attach: impl FnOnce(
            &mut S::Transaction<'_>,
            &str,
            &str,
        ) -> Result<Option<String>, TenantAuthError>,
    ) -> Result<TenantLoginOutcome, TenantAuthError> {
        if command.email.trim().is_empty()
            || command.password.expose_secret().is_empty()
            || command.password.expose_secret().chars().count() > self.config.password_max_length
        {
            return Err(TenantAuthError::InvalidCredentials);
        }
        self.store.auth_transaction(self.mode, |tx| {
            if let LoginTenantPolicy::Fixed { tenant_id } = &self.entry.policy {
                tx.lock_tenants(&[tenant_id.clone()])?;
            }
            let account = tx
                .lock_account_by_email(&command.email)?
                .ok_or(TenantAuthError::InvalidCredentials)?;
            if !account.active
                || !verify_password(
                    account.password_hash.expose_secret(),
                    command.password.expose_secret(),
                )?
                || !tx.client_exists(&self.entry.client_id)?
            {
                return Err(TenantAuthError::InvalidCredentials);
            }
            match &self.entry.policy {
                LoginTenantPolicy::Fixed { tenant_id } => {
                    if !self.require_member(tx, tenant_id, &account.id)? {
                        return Err(TenantAuthError::InvalidCredentials);
                    }
                    let device = attach(tx, tenant_id, &account.id)?;
                    self.issue_session(tx, tenant_id, &account.id, self.clock.now(), device)
                        .map(TenantLoginOutcome::Authenticated)
                }
                LoginTenantPolicy::ChooseAfterAuthentication => self
                    .issue_selection(tx, &account.id, None, self.clock.now())
                    .map(TenantLoginOutcome::SelectionRequired),
            }
        })
    }
    fn select_with_device_step(
        &self,
        ticket: SecretString,
        tenant_id: String,
        attach: impl FnOnce(
            &mut S::Transaction<'_>,
            &str,
            &str,
        ) -> Result<Option<String>, TenantAuthError>,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.require_choose()?;
        self.validate_login_tenant(&tenant_id)
            .map_err(|_| TenantAuthError::InvalidSelection)?;
        let digest = self
            .digester
            .digest_refresh_token(ticket.expose_secret())
            .map_err(|_| TenantAuthError::InvalidSelection)?;
        self.store.auth_transaction(self.mode, |tx| {
            let record = self.selection(tx, &digest, Some(&tenant_id))?;
            if !self.require_member(tx, &tenant_id, &record.account_id)? {
                return Err(TenantAuthError::InvalidSelection);
            }
            let device = attach(tx, &tenant_id, &record.account_id)?;
            let now = self.clock.now();
            if record.expires_at <= now {
                return Err(TenantAuthError::InvalidSelection);
            }
            let source = record
                .source
                .as_ref()
                .map(|source| {
                    self.active_session(
                        tx,
                        &source.tenant_id,
                        &source.session_id,
                        &record.account_id,
                        now,
                    )
                })
                .transpose()?;
            let scope = source.as_ref().and_then(|s| s.scope.clone());
            let authenticated_at = source
                .as_ref()
                .map(|s| s.authenticated_at)
                .unwrap_or(record.authenticated_at);
            tx.consume_selection(&record.id, now)?;
            self.issue_session_using(
                tx,
                &tenant_id,
                &record.account_id,
                now,
                device,
                scope.clone(),
                authenticated_at,
                |session| {
                    if let Some(scope) = scope {
                        let access = self.tokens.issue_scoped_access_token(
                            &tenant_id,
                            &session.id,
                            &record.account_id,
                            &session.client_id,
                            now,
                            &scope,
                        )?;
                        Ok(IssuedTokenBundle {
                            access_token: access.token,
                            access_expires_at: access.expires_at,
                            refresh_token: self.generator.generate_refresh_token()?,
                            refresh_expires_at: now
                                .checked_add(Duration::from_secs(
                                    self.config.refresh_token_ttl_secs,
                                ))
                                .ok_or_else(|| {
                                    TokenError::IssuerRejected("refresh expiry overflow".into())
                                })?,
                            refresh_token_version: 1,
                        })
                    } else {
                        self.tokens.issue_session_tokens(
                            &tenant_id,
                            &session.id,
                            &record.account_id,
                            &session.client_id,
                            1,
                            now,
                        )
                    }
                },
            )
        })
    }
    fn require_member(
        &self,
        tx: &mut impl TenantAuthTransaction,
        tenant: &str,
        account: &str,
    ) -> Result<bool, TenantAuthError> {
        self.validate_login_tenant(tenant)?;
        Ok(tx
            .tenant(tenant)?
            .is_some_and(|t| t.id == tenant && t.status == TenantStatus::Active)
            && tx.membership(tenant, account)?.is_some_and(|m| {
                m.tenant_id == tenant
                    && m.subject_id == account
                    && m.status == MembershipStatus::Active
            }))
    }
    fn issue_session(
        &self,
        tx: &mut impl TenantAuthTransaction,
        tenant: &str,
        account: &str,
        now: SystemTime,
        device_id: Option<String>,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.issue_session_using(tx, tenant, account, now, device_id, None, now, |session| {
            self.tokens.issue_session_tokens(
                tenant,
                &session.id,
                account,
                &session.client_id,
                1,
                now,
            )
        })
    }
    fn issue_session_using(
        &self,
        tx: &mut impl TenantAuthTransaction,
        tenant: &str,
        account: &str,
        now: SystemTime,
        device_id: Option<String>,
        scope: Option<String>,
        authenticated_at: SystemTime,
        issue: impl FnOnce(&TenantSession) -> Result<IssuedTokenBundle, TokenError>,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        if self.entry.require_device_proof && device_id.is_none() {
            return Err(TenantAuthError::DeviceProofRequired);
        }
        let session = TenantSession {
            purpose: self.purpose,
            tenant_id: tenant.into(),
            id: self.ids.next_id("sess"),
            account_id: account.into(),
            client_id: self.entry.client_id.clone(),
            device_id,
            scope,
            authenticated_at,
            status: SessionStatus::Active,
            created_at: now,
            expires_at: now
                .checked_add(Duration::from_secs(self.config.session_ttl_secs))
                .ok_or(AccessError::InvalidInput("session_expiry"))?,
            refresh_token_version: 1,
        };
        let tokens = issue(&session)?;
        self.validate_issued_access(&tokens.access_token, &session)?;
        if tokens.refresh_token_version != 1
            || tokens.access_token.expose_secret().is_empty()
            || tokens.access_expires_at <= now
            || tokens.refresh_expires_at <= tokens.access_expires_at
            || tokens.refresh_expires_at > session.expires_at
        {
            return Err(TenantAuthError::Token(TokenError::IssuerRejected(
                "invalid tenant session token bundle".into(),
            )));
        }
        let digest = self
            .digester
            .digest_refresh_token(tokens.refresh_token.expose_secret())?;
        tx.insert_session(
            &session,
            &self.ids.next_id("rtok"),
            &digest,
            tokens.refresh_expires_at,
        )?;
        Ok(TenantLoginSession { session, tokens })
    }
    fn issue_selection(
        &self,
        tx: &mut impl TenantAuthTransaction,
        account: &str,
        source: Option<SelectionSource>,
        now: SystemTime,
    ) -> Result<TenantSelectionTicket, TenantAuthError> {
        let ticket = self.generator.generate_refresh_token()?;
        let digest = self.digester.digest_refresh_token(ticket.expose_secret())?;
        let expires_at = now
            .checked_add(Duration::from_secs(SELECTION_TTL_SECS))
            .ok_or(AccessError::InvalidInput("selection_expiry"))?;
        tx.insert_selection(&TenantSelectionRecord {
            id: self.ids.next_id("selection"),
            ticket_digest: digest,
            account_id: account.into(),
            client_id: self.entry.client_id.clone(),
            login_entry: self.entry.login_entry.clone(),
            purpose: self.selection_purpose().into(),
            authenticated_at: now,
            expires_at,
            consumed_at: None,
            revoked_at: None,
            source,
        })?;
        Ok(TenantSelectionTicket {
            ticket,
            issued_at: now,
            expires_at,
        })
    }
    fn require_choose(&self) -> Result<(), TenantAuthError> {
        if self.entry.policy != LoginTenantPolicy::ChooseAfterAuthentication {
            return Err(TenantAuthError::InvalidSelection);
        }
        Ok(())
    }
    fn require_session_identity(
        &self,
        tx: &mut impl TenantAuthTransaction,
        session: &TenantSession,
        tenant: &str,
        session_id: &str,
        account: &str,
        now: SystemTime,
    ) -> Result<(), TenantAuthError> {
        if !self.require_member(tx, tenant, account)? {
            return Err(TenantAuthError::InvalidSession);
        }
        if session.purpose != self.purpose
            || (self.purpose == AccessTokenPurpose::Management && session.device_id.is_some())
            || session.tenant_id != tenant
            || session.id != session_id
            || session.account_id != account
            || session.client_id != self.entry.client_id
            || session.status != SessionStatus::Active
            || session.authenticated_at > session.created_at
            || session.created_at > now
            || session.expires_at <= now
        {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(())
    }
    fn active_session(
        &self,
        tx: &mut impl TenantAuthTransaction,
        tenant: &str,
        session_id: &str,
        account: &str,
        now: SystemTime,
    ) -> Result<TenantSession, TenantAuthError> {
        let session = tx
            .session(tenant, session_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        self.require_session_identity(tx, &session, tenant, session_id, account, now)?;
        if let Some(device) = &session.device_id {
            let authority = tx
                .session_device(tenant, account, device)?
                .ok_or(TenantAuthError::InvalidSession)?;
            authority.validate(tenant, account, device, &self.entry.client_id)?;
        } else if self.entry.require_device_proof {
            return Err(TenantAuthError::DeviceProofRequired);
        }
        let checked_at = self.clock.now();
        if session.created_at > checked_at || session.expires_at <= checked_at {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(session)
    }
    fn selection(
        &self,
        tx: &mut impl TenantAuthTransaction,
        digest: &[u8; 32],
        target: Option<&str>,
    ) -> Result<TenantSelectionRecord, TenantAuthError> {
        let hint = tx
            .find_selection(digest)?
            .ok_or(TenantAuthError::InvalidSelection)?;
        let mut domains: Vec<String> = target.map(str::to_owned).into_iter().collect();
        if let Some(source) = &hint.source {
            self.validate_login_tenant(&source.tenant_id)?;
            domains.push(source.tenant_id.clone());
        }
        tx.lock_tenants(&domains)?;
        let account = tx
            .lock_account(&hint.account_id)?
            .ok_or(TenantAuthError::InvalidSelection)?;
        let record = tx
            .lock_selection(digest)?
            .ok_or(TenantAuthError::InvalidSelection)?;
        let now = self.clock.now();
        if !account.active
            || account.id != record.account_id
            || record.account_id != hint.account_id
            || record.source != hint.source
            || record.ticket_digest != *digest
            || record.client_id != self.entry.client_id
            || record.login_entry != self.entry.login_entry
            || record.purpose != self.selection_purpose()
            || record.authenticated_at > now
            || record.expires_at <= now
            || record.consumed_at.is_some()
            || record.revoked_at.is_some()
            || !tx.client_exists(&self.entry.client_id)?
        {
            return Err(TenantAuthError::InvalidSelection);
        }
        if let Some(source) = &record.source {
            let session = self
                .active_session(tx, &source.tenant_id, &source.session_id, &account.id, now)
                .map_err(|e| match e {
                    TenantAuthError::InvalidSession => TenantAuthError::InvalidSelection,
                    other => other,
                })?;
            if session.created_at > record.authenticated_at {
                return Err(TenantAuthError::InvalidSelection);
            }
        }
        Ok(record)
    }
    fn validate_token(&self, raw: &SecretString) -> Result<ValidatedAccessToken, TenantAuthError> {
        let now = self.clock.now();
        let token = self
            .tokens
            .validate_access_token(raw.expose_secret(), now)?
            .ok_or(TenantAuthError::InvalidSession)?;
        if self.validate_login_tenant(&token.tenant_id).is_err()
            || token.purpose != self.purpose
            || token.client_id != self.entry.client_id
            || token.issued_at > now
            || token.expires_at <= now
        {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(token)
    }
    fn validate_issued_access(
        &self,
        raw: &SecretString,
        session: &TenantSession,
    ) -> Result<(), TenantAuthError> {
        let token = self.validate_token(raw)?;
        if token.tenant_id != session.tenant_id
            || token.session_id != session.id
            || token.subject_account_id != session.account_id
            || token.expires_at > session.expires_at
        {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(())
    }
    fn locked_token(
        &self,
        tx: &mut impl TenantAuthTransaction,
        token: &ValidatedAccessToken,
    ) -> Result<AccessActor, TenantAuthError> {
        tx.lock_tenants(&[token.tenant_id.clone()])?;
        let account = tx
            .lock_account(&token.subject_account_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        let now = self.clock.now();
        if !account.active
            || account.id != token.subject_account_id
            || token.expires_at <= now
            || !tx.client_exists(&self.entry.client_id)?
        {
            return Err(TenantAuthError::InvalidSession);
        }
        let session =
            self.active_session(tx, &token.tenant_id, &token.session_id, &account.id, now)?;
        if token.issued_at < session.created_at
            || token.expires_at > session.expires_at
            || session
                .scope
                .as_ref()
                .is_some_and(|scope| token.scope.as_ref() != Some(scope))
        {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(AccessActor {
            tenant_id: token.tenant_id.clone(),
            subject_id: account.id,
            session_id: session.id,
        })
    }
}
impl<S, T, G, D, C, I> TenantAuthenticationService
    for CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore,
    T: TokenIssuer + AccessTokenValidator + crate::ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        TenantLoginCapabilities {
            mode: self.mode,
            policy: self.entry.policy.clone(),
        }
    }
    fn login(&self, command: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        self.login_with_device_step(command, |_, _, _| Ok(None))
    }
    fn list_tenants(
        &self,
        ticket: SecretString,
        page: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        self.require_choose()?;
        let digest = self
            .digester
            .digest_refresh_token(ticket.expose_secret())
            .map_err(|_| TenantAuthError::InvalidSelection)?;
        self.store.auth_transaction(self.mode, |tx| {
            let record = self.selection(tx, &digest, None)?;
            let scope = AccessListScope::SubjectTenants {
                subject_id: record.account_id.clone(),
            };
            page.validate(&scope)?;
            let rows = tx.list_tenants(&record.account_id, &page)?;
            if rows.iter().any(|r| {
                r.tenant.id == SYSTEM_TENANT_ID
                    || r.membership.subject_id != record.account_id
                    || r.membership.tenant_id != r.tenant.id
                    || r.membership.status == MembershipStatus::Removed
            }) {
                return Err(AccessError::InvalidStoreResponse.into());
            }
            Ok(finish_page(rows, page, scope, |r| {
                vec![r.tenant.id.clone()]
            })?)
        })
    }
    fn select_tenant(
        &self,
        ticket: SecretString,
        tenant_id: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.select_with_device_step(ticket, tenant_id, |_, _, _| Ok(None))
    }
    fn authenticate(&self, access_token: SecretString) -> Result<AccessActor, TenantAuthError> {
        let token = self.validate_token(&access_token)?;
        self.store
            .auth_transaction(self.mode, |tx| self.locked_token(tx, &token))
    }
    fn begin_switch(
        &self,
        access_token: SecretString,
    ) -> Result<TenantSelectionTicket, TenantAuthError> {
        self.require_choose()?;
        let token = self.validate_token(&access_token)?;
        self.store.auth_transaction(self.mode, |tx| {
            let actor = self.locked_token(tx, &token)?;
            self.issue_selection(
                tx,
                &actor.subject_id,
                Some(SelectionSource {
                    tenant_id: actor.tenant_id,
                    session_id: actor.session_id,
                }),
                self.clock.now(),
            )
        })
    }
}

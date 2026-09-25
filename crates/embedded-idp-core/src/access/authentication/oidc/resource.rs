use super::*;
use crate::RefreshTokenRevocationReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantTokenType {
    Access,
    Refresh,
}
#[derive(Debug, Clone)]
pub struct TenantTokenRequest {
    pub client_id: String,
    pub client_secret: Option<SecretString>,
    pub token: SecretString,
    /// A lookup preference, not an assertion of the token's actual type.
    pub token_type_hint: Option<TenantTokenType>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantTokenInfo {
    pub tenant_id: String,
    pub subject_account_id: String,
    pub session_id: String,
    pub client_id: String,
    pub scope: Option<String>,
    pub token_type: TenantTokenType,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantUserInfo {
    pub tenant_id: String,
    pub subject_account_id: String,
    pub client_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}
/// Current profile read under the account lock; no passwords or credential data.
pub struct TenantUserProfile {
    pub subject_account_id: String,
    pub email: String,
    pub display_name: Option<String>,
}
pub trait TenantOidcResourceTransaction: TenantOidcTransaction + TenantRefreshTransaction {
    fn user_profile(
        &mut self,
        tenant: &str,
        account: &str,
    ) -> Result<Option<TenantUserProfile>, StoreError>;
}
pub trait TenantOidcResourceService: Send + Sync {
    fn user_info(&self, access_token: SecretString) -> Result<TenantUserInfo, TenantAuthError>;
    /// Only authenticated confidential clients may introspect. None means inactive
    /// and carries no identity metadata. Store/validator failures remain errors.
    fn introspect_token(
        &self,
        command: TenantTokenRequest,
    ) -> Result<Option<TenantTokenInfo>, TenantAuthError>;
    /// Idempotent: invalid/expired/revoked/wrong-tenant tokens are a no-op.
    /// A current token revokes only its exact session and refresh family.
    fn revoke_token(&self, command: TenantTokenRequest) -> Result<(), TenantAuthError>;
    /// The same family operation, accepting only a current refresh credential.
    fn logout(&self, command: TenantTokenRequest) -> Result<(), TenantAuthError>;
}
impl<S, T, G, D, C, I, V> TenantOidcResourceService for CoreTenantOidcService<S, T, G, D, C, I, V>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantOidcResourceTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + IdTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    V: ClientSecretVerifier + Send + Sync,
{
    fn user_info(&self, raw: SecretString) -> Result<TenantUserInfo, TenantAuthError> {
        let token = self.auth.validate_token(&raw)?;
        self.auth.store.auth_transaction(self.auth.mode, |tx| {
            let actor = self.auth.locked_token(tx, &token)?;
            let scope = token.scope.as_deref().unwrap_or("");
            if !scope.split_whitespace().any(|s| s == "openid") {
                return Err(AccessError::Forbidden.into());
            }
            let profile = tx
                .user_profile(&actor.tenant_id, &actor.subject_id)?
                .ok_or(TenantAuthError::InvalidSession)?;
            if token.expires_at <= self.auth.clock.now() {
                return Err(TenantAuthError::InvalidSession);
            }
            if profile.subject_account_id != actor.subject_id {
                return Err(AccessError::InvalidStoreResponse.into());
            }
            Ok(TenantUserInfo {
                tenant_id: actor.tenant_id,
                subject_account_id: actor.subject_id,
                client_id: token.client_id,
                email: scope
                    .split_whitespace()
                    .any(|s| s == "email")
                    .then_some(profile.email),
                display_name: scope
                    .split_whitespace()
                    .any(|s| s == "profile")
                    .then_some(profile.display_name)
                    .flatten(),
            })
        })
    }
    fn introspect_token(
        &self,
        command: TenantTokenRequest,
    ) -> Result<Option<TenantTokenInfo>, TenantAuthError> {
        self.validate_resource_command(&command)?;
        self.auth.store.auth_transaction(self.auth.mode, |tx| {
            let resolved = self.resolve_resource_token(tx, &command)?;
            self.authenticate_resource_client(tx, &command, true)?;
            Ok(resolved
                .map(|(_, info)| info)
                .filter(|info| info.expires_at > self.auth.clock.now()))
        })
    }
    fn revoke_token(&self, command: TenantTokenRequest) -> Result<(), TenantAuthError> {
        self.revoke_resource_session(
            command,
            RefreshTokenRevocationReason::ClientRevocation,
            false,
        )
    }
    fn logout(&self, command: TenantTokenRequest) -> Result<(), TenantAuthError> {
        self.revoke_resource_session(command, RefreshTokenRevocationReason::Logout, true)
    }
}
impl<S, T, G, D, C, I, V> CoreTenantOidcService<S, T, G, D, C, I, V>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantOidcResourceTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + IdTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
    V: ClientSecretVerifier,
{
    fn validate_resource_command(
        &self,
        command: &TenantTokenRequest,
    ) -> Result<(), TenantAuthError> {
        if command.client_id != self.auth.entry.client_id {
            return Err(TenantAuthError::InvalidClient);
        }
        if command.token.expose_secret().is_empty() || command.token.expose_secret().len() > 16_384
        {
            return Err(AccessError::InvalidInput("token").into());
        }
        if command.client_secret.as_ref().is_some_and(|s| {
            s.expose_secret().len() > 4096 || s.expose_secret().trim() != s.expose_secret()
        }) {
            return Err(TenantAuthError::InvalidClient);
        }
        Ok(())
    }
    fn authenticate_resource_client(
        &self,
        tx: &mut impl TenantOidcTransaction,
        command: &TenantTokenRequest,
        confidential: bool,
    ) -> Result<(), TenantAuthError> {
        // Acquire this shared client lock AFTER tenant/account/session locks, as
        // authorization and management do. Even inactive tokens reach this check.
        let client = self.client(tx)?;
        if confidential && client.client_type != OidcClientType::ConfidentialWeb {
            return Err(TenantAuthError::InvalidClient);
        }
        crate::service::authenticate_client(
            &client,
            command
                .client_secret
                .as_ref()
                .map(SecretString::expose_secret),
            &self.client_secrets,
        )
        .map_err(|e| match e {
            StoreError::Conflict(_) => TenantAuthError::InvalidClient,
            other => other.into(),
        })
    }
    fn revoke_resource_session(
        &self,
        command: TenantTokenRequest,
        reason: RefreshTokenRevocationReason,
        refresh_only: bool,
    ) -> Result<(), TenantAuthError> {
        self.validate_resource_command(&command)?;
        self.auth.store.auth_transaction(self.auth.mode, |tx| {
            let resolved = if refresh_only {
                self.resolve_resource_refresh(tx, &command.token)?
            } else {
                self.resolve_resource_token(tx, &command)?
            };
            self.authenticate_resource_client(tx, &command, false)?;
            if let Some((session, info)) = resolved {
                let now = self.auth.clock.now();
                if info.expires_at > now && session.expires_at > now {
                    tx.revoke_refresh_family(&session, reason, now)?;
                }
            }
            Ok(())
        })
    }
    fn resolve_resource_token(
        &self,
        tx: &mut S::Transaction<'_>,
        command: &TenantTokenRequest,
    ) -> Result<Option<(TenantSession, TenantTokenInfo)>, TenantAuthError> {
        if command.token_type_hint == Some(TenantTokenType::Refresh) {
            match self.resolve_resource_refresh(tx, &command.token)? {
                Some(found) => Ok(Some(found)),
                None => self.resolve_resource_access(tx, &command.token),
            }
        } else {
            match self.resolve_resource_access(tx, &command.token)? {
                Some(found) => Ok(Some(found)),
                None => self.resolve_resource_refresh(tx, &command.token),
            }
        }
    }
    fn resolve_resource_access(
        &self,
        tx: &mut S::Transaction<'_>,
        raw: &SecretString,
    ) -> Result<Option<(TenantSession, TenantTokenInfo)>, TenantAuthError> {
        let Some(token) = inactive_identity(self.auth.validate_token(raw))? else {
            return Ok(None);
        };
        if inactive_identity(self.auth.locked_token(tx, &token))?.is_none() {
            return Ok(None);
        }
        let session = tx
            .session(&token.tenant_id, &token.session_id)?
            .ok_or(AccessError::InvalidStoreResponse)?;
        let info = TenantTokenInfo {
            tenant_id: token.tenant_id,
            subject_account_id: token.subject_account_id,
            session_id: token.session_id,
            client_id: token.client_id,
            scope: token.scope,
            token_type: TenantTokenType::Access,
            issued_at: token.issued_at,
            expires_at: token.expires_at,
        };
        Ok(Some((session, info)))
    }
    fn resolve_resource_refresh(
        &self,
        tx: &mut S::Transaction<'_>,
        raw: &SecretString,
    ) -> Result<Option<(TenantSession, TenantTokenInfo)>, TenantAuthError> {
        let digest = match self.auth.digester.digest_refresh_token(raw.expose_secret()) {
            Ok(digest) => digest,
            Err(TokenError::InvalidRefreshTokenEncoding) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(hint) = tx.find_refresh(&digest)? else {
            return Ok(None);
        };
        if self
            .auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &hint.tenant_id)
            .is_err()
        {
            return Ok(None);
        }
        tx.lock_tenants(&[hint.tenant_id.clone()])?;
        let Some(session_hint) = tx.session(&hint.tenant_id, &hint.session_id)? else {
            return Ok(None);
        };
        let Some(account) = tx.lock_account(&session_hint.account_id)? else {
            return Ok(None);
        };
        let Some(session) = tx.lock_refresh_session(&hint.tenant_id, &hint.session_id)? else {
            return Ok(None);
        };
        let Some(refresh) = tx.lock_refresh_record(&hint.tenant_id, &digest)? else {
            return Ok(None);
        };
        if !account.active
            || account.id != session.account_id
            || session.account_id != session_hint.account_id
            || session.tenant_id != hint.tenant_id
            || session.id != hint.session_id
            || session.client_id != self.auth.entry.client_id
            || refresh.tenant_id != session.tenant_id
            || refresh.session_id != session.id
            || refresh.id != hint.id
            || refresh.token_digest != digest
        {
            return Ok(None);
        }
        if inactive_identity(self.auth.active_session(
            tx,
            &session.tenant_id,
            &session.id,
            &account.id,
            self.auth.clock.now(),
        ))?
        .is_none()
        {
            return Ok(None);
        }
        let now = self.auth.clock.now();
        if refresh.revoked_at.is_some()
            || refresh.revocation_reason.is_some()
            || refresh.token_version == 0
            || refresh.token_version != session.refresh_token_version
            || refresh.issued_at < session.created_at
            || refresh.issued_at > now
            || refresh.expires_at <= now
            || refresh.expires_at > session.expires_at
            || session.expires_at <= now
        {
            return Ok(None);
        }
        let info = TenantTokenInfo {
            tenant_id: session.tenant_id.clone(),
            subject_account_id: session.account_id.clone(),
            session_id: session.id.clone(),
            client_id: session.client_id.clone(),
            scope: session.scope.clone(),
            token_type: TenantTokenType::Refresh,
            issued_at: refresh.issued_at,
            expires_at: refresh.expires_at,
        };
        Ok(Some((session, info)))
    }
}
fn inactive_identity<T>(result: Result<T, TenantAuthError>) -> Result<Option<T>, TenantAuthError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(TenantAuthError::InvalidSession | TenantAuthError::DeviceProofRequired) => Ok(None),
        Err(error) => Err(error),
    }
}

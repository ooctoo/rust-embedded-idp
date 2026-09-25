mod resource;
pub use resource::*;
mod transport;
pub use transport::*;

use super::*;
use crate::{
    normalize_oauth_scope, ClientSecretVerifier, DeviceChallengeGenerator, DeviceProofPurpose,
    DevicePublicJwkValidator, DeviceRequestVerificationError, DeviceSignatureVerifier,
    IdTokenClaims, IdTokenIssuer, OidcClient, OidcClientType, OidcConfig, PkceChallengeMethod,
    ScopedAccessTokenIssuer,
};
use base64ct::{Base64UrlUnpadded, Encoding};

pub const TENANT_OIDC_EXCHANGE_PURPOSE: &str = "authorization_code";
#[derive(Debug, Clone)]
pub struct TenantAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<PkceChallengeMethod>,
}
#[derive(Debug, Clone)]
pub struct TenantCodeExchange {
    pub grant_type: String,
    pub client_id: String,
    pub code: SecretString,
    pub redirect_uri: String,
    pub client_secret: Option<SecretString>,
    pub code_verifier: Option<SecretString>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TenantAuthorizationCode {
    pub tenant_id: String,
    pub code_digest: [u8; 32],
    pub account_id: String,
    pub source_session_id: String,
    pub client_id: String,
    pub login_entry: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<PkceChallengeMethod>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantAuthorizationResult {
    pub code: SecretString,
    pub tenant_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub expires_at: SystemTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantCodeExchangeResult {
    pub login: TenantLoginSession,
    pub id_token: Option<SecretString>,
    pub scope: String,
}
pub trait TenantOidcTransaction: TenantAuthTransaction {
    fn oidc_client(&mut self, client: &str) -> Result<Option<OidcClient>, StoreError>;
    fn insert_authorization(&mut self, code: &TenantAuthorizationCode) -> Result<(), StoreError>;
    /// Non-locking routing hint only; lock domains/account before re-reading it.
    fn find_authorization(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantAuthorizationCode>, StoreError>;
    fn lock_authorization(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantAuthorizationCode>, StoreError>;
    fn consume_authorization(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), StoreError>;
}
/// A client-specific OIDC module composed from the existing authentication entry.
/// Issuer, allowed scopes and client verification are trusted host configuration.
pub struct CoreTenantOidcService<S, T, G, D, C, I, V> {
    auth: CoreTenantAuthenticationService<S, T, G, D, C, I>,
    issuer: String,
    config: OidcConfig,
    allowed_scopes: String,
    client_secrets: V,
}
impl<S, T, G, D, C, I, V> CoreTenantOidcService<S, T, G, D, C, I, V> {
    pub fn new(
        auth: CoreTenantAuthenticationService<S, T, G, D, C, I>,
        issuer: String,
        config: OidcConfig,
        allowed_scopes: String,
        client_secrets: V,
    ) -> Result<Self, TenantAuthError> {
        config.validate().map_err(TenantAuthError::Configuration)?;
        if !crate::config::is_supported_issuer(&issuer) {
            return Err(TenantAuthError::Configuration(
                ConfigValidationError::InvalidIssuer,
            ));
        }
        let allowed_scopes = normalize_oauth_scope(&allowed_scopes)?;
        Ok(Self {
            auth,
            issuer,
            config,
            allowed_scopes,
            client_secrets,
        })
    }
}
impl<S, T, G, D, C, I, V> CoreTenantOidcService<S, T, G, D, C, I, V>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantOidcTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + IdTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
    V: ClientSecretVerifier,
{
    /// actor must come from trusted authentication, never from caller JSON.
    pub fn authorize(
        &self,
        actor: AccessActor,
        request: TenantAuthorizationRequest,
    ) -> Result<TenantAuthorizationResult, TenantAuthError> {
        if request.response_type != "code"
            || request.client_id != self.auth.entry.client_id
            || request.redirect_uri.len() > 2048
            || request.redirect_uri.contains('#')
            || request
                .state
                .as_ref()
                .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
            || request
                .nonce
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
        {
            return Err(TenantAuthError::InvalidAuthorization);
        }
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &actor.tenant_id)?;
        let scope = normalize_oauth_scope(&request.scope)
            .map_err(|_| TenantAuthError::InvalidAuthorization)?;
        if !scope_subset(&scope, &self.allowed_scopes) {
            return Err(TenantAuthError::InvalidAuthorization);
        }
        self.auth.store.auth_transaction(self.auth.mode, |tx| {
            tx.lock_tenants(&[actor.tenant_id.clone()])?;
            let account = tx
                .lock_account(&actor.subject_id)?
                .ok_or(TenantAuthError::InvalidSession)?;
            if !account.active || account.id != actor.subject_id {
                return Err(TenantAuthError::InvalidSession);
            }
            let client = self.client(tx)?;
            if !client.redirect_uris.contains(&request.redirect_uri) {
                return Err(TenantAuthError::InvalidAuthorization);
            }
            let method = authorize_pkce(&client, &self.config, &request)?;
            let source = self.auth.active_session(
                tx,
                &actor.tenant_id,
                &actor.session_id,
                &actor.subject_id,
                self.auth.clock.now(),
            )?;
            if source
                .scope
                .as_ref()
                .is_some_and(|s| !scope_subset(&scope, s))
            {
                return Err(TenantAuthError::InvalidAuthorization);
            }
            let now = self.auth.clock.now();
            let expires_at = now
                .checked_add(Duration::from_secs(self.config.authorization_code_ttl_secs))
                .ok_or(AccessError::InvalidInput("authorization_expiry"))?
                .min(source.expires_at);
            if expires_at <= now {
                return Err(TenantAuthError::InvalidSession);
            }
            let code = self.auth.generator.generate_refresh_token()?;
            let digest = self
                .auth
                .digester
                .digest_refresh_token(code.expose_secret())?;
            tx.insert_authorization(&TenantAuthorizationCode {
                tenant_id: actor.tenant_id.clone(),
                code_digest: digest,
                account_id: account.id,
                source_session_id: source.id,
                client_id: client.client_id,
                login_entry: self.auth.entry.login_entry.clone(),
                redirect_uri: request.redirect_uri.clone(),
                scope,
                nonce: request.nonce,
                code_challenge: request.code_challenge,
                code_challenge_method: method,
                created_at: now,
                expires_at,
                consumed_at: None,
            })?;
            Ok(TenantAuthorizationResult {
                code,
                tenant_id: actor.tenant_id,
                redirect_uri: request.redirect_uri,
                state: request.state,
                expires_at,
            })
        })
    }
    pub fn exchange(
        &self,
        command: TenantCodeExchange,
    ) -> Result<TenantCodeExchangeResult, TenantAuthError> {
        self.exchange_with_device_step(command, |_, source| {
            if self.auth.entry.require_device_proof || source.device_id.is_some() {
                return Err(TenantAuthError::DeviceProofRequired);
            }
            Ok(())
        })
    }
    fn client(&self, tx: &mut impl TenantOidcTransaction) -> Result<OidcClient, TenantAuthError> {
        let client = tx
            .oidc_client(&self.auth.entry.client_id)?
            .ok_or(TenantAuthError::InvalidClient)?;
        if client.client_id != self.auth.entry.client_id || client.validate().is_err() {
            return Err(TenantAuthError::InvalidClient);
        }
        Ok(client)
    }
    fn exchange_with_device_step(
        &self,
        command: TenantCodeExchange,
        verify: impl FnOnce(&mut S::Transaction<'_>, &TenantSession) -> Result<(), TenantAuthError>,
    ) -> Result<TenantCodeExchangeResult, TenantAuthError> {
        if command.grant_type != "authorization_code" || command.redirect_uri.len() > 2048 {
            return Err(TenantAuthError::InvalidGrant);
        }
        if command.client_id != self.auth.entry.client_id {
            return Err(TenantAuthError::InvalidClient);
        }
        let digest = self
            .auth
            .digester
            .digest_refresh_token(command.code.expose_secret())
            .map_err(|_| TenantAuthError::InvalidGrant)?;
        self.auth.store.auth_transaction(self.auth.mode, |tx| {
            let hint = tx
                .find_authorization(&digest)?
                .ok_or(TenantAuthError::InvalidGrant)?;
            self.auth
                .entry
                .policy
                .validate_selection(self.auth.mode, &hint.tenant_id)
                .map_err(|_| TenantAuthError::InvalidGrant)?;
            tx.lock_tenants(&[hint.tenant_id.clone()])?;
            let account = tx
                .lock_account(&hint.account_id)?
                .ok_or(TenantAuthError::InvalidGrant)?;
            let code = tx
                .lock_authorization(&hint.tenant_id, &digest)?
                .ok_or(TenantAuthError::InvalidGrant)?;
            if !account.active
                || account.id != code.account_id
                || code.account_id != hint.account_id
                || code.tenant_id != hint.tenant_id
                || code.code_digest != digest
                || code.source_session_id != hint.source_session_id
                || code.client_id != self.auth.entry.client_id
                || code.login_entry != self.auth.entry.login_entry
                || code.redirect_uri != command.redirect_uri
                || code.consumed_at.is_some()
            {
                return Err(TenantAuthError::InvalidGrant);
            }
            let client = self.client(tx)?;
            if !client.redirect_uris.contains(&code.redirect_uri)
                || !scope_subset(&code.scope, &self.allowed_scopes)
            {
                return Err(TenantAuthError::InvalidGrant);
            }
            let secret = command
                .client_secret
                .as_ref()
                .map(SecretString::expose_secret);
            if secret.is_some_and(|s| s.len() > 4096 || s.trim() != s) {
                return Err(TenantAuthError::InvalidClient);
            }
            crate::service::authenticate_client(&client, secret, &self.client_secrets).map_err(
                |e| match e {
                    StoreError::Conflict(_) => TenantAuthError::InvalidClient,
                    other => TenantAuthError::Store(other),
                },
            )?;
            exchange_pkce(
                &code,
                &client,
                &self.config,
                command
                    .code_verifier
                    .as_ref()
                    .map(SecretString::expose_secret),
            )?;
            let source = tx
                .session(&code.tenant_id, &code.source_session_id)?
                .ok_or(TenantAuthError::InvalidGrant)?;
            self.auth.require_session_identity(
                tx,
                &source,
                &code.tenant_id,
                &code.source_session_id,
                &account.id,
                self.auth.clock.now(),
            )?;
            if source.created_at > code.created_at
                || source
                    .scope
                    .as_ref()
                    .is_some_and(|s| !scope_subset(&code.scope, s))
            {
                return Err(TenantAuthError::InvalidGrant);
            }
            verify(tx, &source)?;
            let now = self.auth.clock.now();
            if code.created_at > now || code.expires_at <= now || source.expires_at <= now {
                return Err(TenantAuthError::InvalidGrant);
            }
            tx.consume_authorization(&code.tenant_id, &digest, now)?;
            let login = self.auth.issue_session_using(
                tx,
                &code.tenant_id,
                &account.id,
                now,
                source.device_id.clone(),
                Some(code.scope.clone()),
                source.authenticated_at,
                |session| {
                    let access = self.auth.tokens.issue_scoped_access_token(
                        &code.tenant_id,
                        &session.id,
                        &account.id,
                        &client.client_id,
                        now,
                        &code.scope,
                    )?;
                    Ok(IssuedTokenBundle {
                        access_token: access.token,
                        access_expires_at: access.expires_at,
                        refresh_token: self.auth.generator.generate_refresh_token()?,
                        refresh_expires_at: now
                            .checked_add(Duration::from_secs(
                                self.auth.config.refresh_token_ttl_secs,
                            ))
                            .ok_or_else(|| {
                                TokenError::IssuerRejected("OIDC refresh expiry overflow".into())
                            })?,
                        refresh_token_version: 1,
                    })
                },
            )?;
            let id_token = if code.scope.split_whitespace().any(|s| s == "openid") {
                Some(self.auth.tokens.issue_id_token(&IdTokenClaims {
                    tenant_id: code.tenant_id,
                    issuer: self.issuer.clone(),
                    subject_account_id: account.id,
                    audience: client.client_id,
                    nonce: code.nonce,
                    issued_at: now,
                    expires_at: login.tokens.access_expires_at,
                    auth_time: source.authenticated_at,
                })?)
            } else {
                None
            };
            Ok(TenantCodeExchangeResult {
                login,
                id_token,
                scope: code.scope,
            })
        })
    }
}
impl<S, T, G, D, C, I, V> CoreTenantOidcService<S, T, G, D, C, I, V>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantOidcTransaction + TenantDeviceProofTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + IdTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
    V: ClientSecretVerifier,
{
    pub fn exchange_with_proof<J, W, N, K, Z>(
        &self,
        command: TenantCodeExchange,
        proof: TenantAuthenticationProof,
        devices: &CoreTenantDeviceProofService<S, J, W, N, K, Z>,
    ) -> Result<TenantCodeExchangeResult, TenantAuthError>
    where
        J: DevicePublicJwkValidator,
        W: DeviceSignatureVerifier,
        N: DeviceChallengeGenerator,
        K: Clock,
        Z: IdGenerator,
    {
        if !devices.matches_login_entry(self.auth.mode, &self.auth.entry.client_id) {
            return Err(AccessError::InvalidInput("device_oidc_configuration").into());
        }
        let context = tenant_code_proof_context(&self.auth.entry.login_entry, &command);
        self.exchange_with_device_step(command, |tx, source| {
            if source.device_id.as_deref() != Some(proof.proof.device_id.as_str()) {
                return Err(TenantAuthError::DeviceProof(
                    DeviceRequestVerificationError::InvalidProof,
                ));
            }
            devices.verify_in_transaction(
                tx,
                &source.tenant_id,
                &source.account_id,
                &DeviceProofPurpose::new(TENANT_OIDC_EXCHANGE_PURPOSE)
                    .map_err(TenantAuthError::Security)?,
                &proof.proof,
                &proof.binding,
                Some(&context),
                false,
            )?;
            Ok(())
        })
    }
}
pub fn tenant_code_proof_context(entry: &str, command: &TenantCodeExchange) -> [u8; 32] {
    super::device_login::credential_context(&[
        TENANT_OIDC_EXCHANGE_PURPOSE,
        &command.client_id,
        entry,
        &command.grant_type,
        command.code.expose_secret(),
        &command.redirect_uri,
        command
            .code_verifier
            .as_ref()
            .map(SecretString::expose_secret)
            .unwrap_or(""),
        command
            .client_secret
            .as_ref()
            .map(SecretString::expose_secret)
            .unwrap_or(""),
    ])
}
fn scope_subset(requested: &str, allowed: &str) -> bool {
    requested
        .split_whitespace()
        .all(|s| allowed.split_whitespace().any(|a| a == s))
}
fn verifier_syntax(s: &str) -> bool {
    (43..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}
fn authorize_pkce(
    client: &OidcClient,
    config: &OidcConfig,
    request: &TenantAuthorizationRequest,
) -> Result<Option<PkceChallengeMethod>, TenantAuthError> {
    match request.code_challenge.as_deref() {
        None if request.code_challenge_method.is_some()
            || client.pkce_required
            || (config.require_pkce_for_public_clients
                && client.client_type == OidcClientType::PublicDesktop) =>
        {
            Err(TenantAuthError::InvalidAuthorization)
        }
        None => Ok(None),
        Some(challenge) => {
            let method = request
                .code_challenge_method
                .unwrap_or(PkceChallengeMethod::Plain);
            let valid = match method {
                PkceChallengeMethod::Plain => verifier_syntax(challenge),
                PkceChallengeMethod::S256 => {
                    Base64UrlUnpadded::decode_vec(challenge).is_ok_and(|b| {
                        b.len() == 32 && Base64UrlUnpadded::encode_string(&b) == challenge
                    })
                }
            };
            if !valid {
                return Err(TenantAuthError::InvalidAuthorization);
            }
            Ok(Some(method))
        }
    }
}
fn exchange_pkce(
    code: &TenantAuthorizationCode,
    client: &OidcClient,
    config: &OidcConfig,
    verifier: Option<&str>,
) -> Result<(), TenantAuthError> {
    match (code.code_challenge.as_deref(), code.code_challenge_method) {
        (Some(challenge), Some(method))
            if verifier.is_some_and(|v| {
                verifier_syntax(v) && crate::service::pkce_matches(method, challenge, v)
            }) =>
        {
            Ok(())
        }
        (None, None)
            if !client.pkce_required
                && !(config.require_pkce_for_public_clients
                    && client.client_type == OidcClientType::PublicDesktop) =>
        {
            Ok(())
        }
        _ => Err(TenantAuthError::InvalidGrant),
    }
}

use super::*;

/// Independently mounted management entry. Hosts supply a dedicated token
/// issuer/validator with management purpose and audience, plus a trusted client
/// and login policy. This service is deliberately not a TenantAuthenticationService.
pub trait ManagementAuthenticationService: Send + Sync {
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
        tenant: String,
    ) -> Result<TenantLoginSession, TenantAuthError>;
    fn authenticate(
        &self,
        token: SecretString,
        request_id: String,
    ) -> Result<AccessAdminContext, TenantAuthError>;
    fn begin_switch(&self, token: SecretString) -> Result<TenantSelectionTicket, TenantAuthError>;
    fn rotate_refresh(&self, token: SecretString) -> Result<TenantRefreshOutcome, TenantAuthError>;
    fn logout(&self, token: SecretString) -> Result<(), TenantAuthError>;
}

pub struct CoreManagementAuthenticationService<S, T, G, D, C, I> {
    pub(crate) auth: CoreTenantAuthenticationService<S, T, G, D, C, I>,
}

impl<S, T, G, D, C, I> CoreManagementAuthenticationService<S, T, G, D, C, I> {
    /// Fixed `0` explicitly selects platform management in either mode. Other
    /// policies follow ordinary tenant rules; selection never includes `0`.
    /// The initial management entry supports bearer sessions only. Reject a
    /// proof-required configuration rather than silently weakening it.
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
        if entry.require_device_proof {
            return Err(AccessError::InvalidInput("management_device_proof_unsupported").into());
        }
        Ok(Self {
            auth: CoreTenantAuthenticationService::new_with_purpose(
                mode,
                config,
                entry,
                store,
                tokens,
                generator,
                digester,
                clock,
                ids,
                AccessTokenPurpose::Management,
            )?,
        })
    }
}

impl<S, T, G, D, C, I> ManagementAuthenticationService
    for CoreManagementAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + crate::ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        self.auth.login_capabilities()
    }
    fn login(&self, command: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        self.auth.login(command)
    }
    fn list_tenants(
        &self,
        ticket: SecretString,
        page: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        self.auth.list_tenants(ticket, page)
    }
    fn select_tenant(
        &self,
        ticket: SecretString,
        tenant: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.auth.select_tenant(ticket, tenant)
    }
    fn authenticate(
        &self,
        token: SecretString,
        request_id: String,
    ) -> Result<AccessAdminContext, TenantAuthError> {
        validate_id(&request_id, 128, "request_id")?;
        Ok(AccessAdminContext {
            actor: self.auth.authenticate(token)?,
            authentication_source: "management_access".into(),
            request_id,
        })
    }
    fn begin_switch(&self, token: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        self.auth.begin_switch(token)
    }
    fn rotate_refresh(&self, token: SecretString) -> Result<TenantRefreshOutcome, TenantAuthError> {
        self.auth.rotate_refresh(token)
    }
    fn logout(&self, token: SecretString) -> Result<(), TenantAuthError> {
        let token = self.auth.validate_token(&token)?;
        self.auth.store.auth_transaction(self.auth.mode, |tx| {
            let actor = self.auth.locked_token(tx, &token)?;
            let session = tx
                .lock_refresh_session(&actor.tenant_id, &actor.session_id)?
                .ok_or(TenantAuthError::InvalidSession)?;
            let now = self.auth.clock.now();
            self.auth.require_session_identity(
                tx,
                &session,
                &actor.tenant_id,
                &actor.session_id,
                &actor.subject_id,
                now,
            )?;
            if token.expires_at <= now || session.device_id.is_some() {
                return Err(TenantAuthError::InvalidSession);
            }
            tx.revoke_refresh_family(&session, crate::RefreshTokenRevocationReason::Logout, now)?;
            Ok(())
        })
    }
}

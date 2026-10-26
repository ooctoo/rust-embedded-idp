//! Frozen host registry. Routing hints never replace the selected service's
//! client authentication, live session checks, or authorization-code binding.
use embedded_idp_core::{access::*, AccessTokenPurpose, AccessTokenValidator, SecretString};
use embedded_idp_security::Rs256JwtService;
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

pub(crate) struct OidcEntry {
    pub authorization: Arc<dyn TenantOidcAuthorizationService>,
    pub resource: Arc<dyn TenantOidcResourceService>,
}
pub(crate) struct OidcDispatch {
    pub entries: BTreeMap<String, OidcEntry>,
    pub tokens: Rs256JwtService,
}
impl OidcDispatch {
    fn entry(&self, client: &str) -> Result<&OidcEntry, TenantAuthError> {
        self.entries
            .get(client)
            .ok_or(TenantAuthError::InvalidClient)
    }
    fn validated_entry(&self, raw: &SecretString) -> Result<&OidcEntry, TenantAuthError> {
        let token = self
            .tokens
            .validate_access_token(raw.expose_secret(), SystemTime::now())?
            .ok_or(TenantAuthError::InvalidSession)?;
        if token.purpose != AccessTokenPurpose::Business {
            return Err(TenantAuthError::InvalidSession);
        }
        self.entries
            .get(&token.client_id)
            .ok_or(TenantAuthError::InvalidSession)
    }
}
impl TenantOidcAuthorizationService for OidcDispatch {
    fn authenticate(&self, access: SecretString) -> Result<AccessActor, TenantAuthError> {
        self.validated_entry(&access)?
            .authorization
            .authenticate(access)
    }
    fn authorize(
        &self,
        actor: AccessActor,
        request: TenantAuthorizationRequest,
    ) -> Result<TenantAuthorizationResult, TenantAuthError> {
        self.entry(&request.client_id)?
            .authorization
            .authorize(actor, request)
    }
    fn exchange(
        &self,
        command: TenantCodeExchange,
        proof: Option<TenantAuthenticationProof>,
    ) -> Result<TenantCodeExchangeResult, TenantAuthError> {
        self.entry(&command.client_id)?
            .authorization
            .exchange(command, proof)
    }
}
impl TenantOidcResourceService for OidcDispatch {
    fn user_info(&self, access: SecretString) -> Result<TenantUserInfo, TenantAuthError> {
        self.validated_entry(&access)?.resource.user_info(access)
    }
    fn introspect_token(
        &self,
        command: TenantTokenRequest,
    ) -> Result<Option<TenantTokenInfo>, TenantAuthError> {
        self.entry(&command.client_id)?
            .resource
            .introspect_token(command)
    }
    fn revoke_token(&self, command: TenantTokenRequest) -> Result<(), TenantAuthError> {
        self.entry(&command.client_id)?
            .resource
            .revoke_token(command)
    }
    fn logout(&self, _: TenantTokenRequest) -> Result<(), TenantAuthError> {
        Err(TenantAuthError::InvalidClient)
    }
}

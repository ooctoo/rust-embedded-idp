use super::*;

/// Object-safe access to the existing OIDC transactions. The host authenticates
/// the bearer before authorize; authorize rechecks the actor's live session.
pub trait TenantOidcAuthorizationService: Send + Sync {
    fn authenticate(&self, access: SecretString) -> Result<AccessActor, TenantAuthError>;
    fn authorize(
        &self,
        actor: AccessActor,
        request: TenantAuthorizationRequest,
    ) -> Result<TenantAuthorizationResult, TenantAuthError>;
    fn exchange(
        &self,
        command: TenantCodeExchange,
        proof: Option<TenantAuthenticationProof>,
    ) -> Result<TenantCodeExchangeResult, TenantAuthError>;
}

pub struct CoreTenantOidcAuthorizationService<O, P> {
    oidc: O,
    devices: P,
}
impl<O, P> CoreTenantOidcAuthorizationService<O, P> {
    pub fn new(oidc: O, devices: P) -> Self {
        Self { oidc, devices }
    }
}
impl<S, T, G, D, C, I, V, J, W, N, K, Z> TenantOidcAuthorizationService
    for CoreTenantOidcAuthorizationService<
        CoreTenantOidcService<S, T, G, D, C, I, V>,
        CoreTenantDeviceProofService<S, J, W, N, K, Z>,
    >
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantOidcTransaction + TenantDeviceProofTransaction,
    T: TokenIssuer + AccessTokenValidator + ScopedAccessTokenIssuer + IdTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    V: ClientSecretVerifier + Send + Sync,
    J: DevicePublicJwkValidator + Send + Sync,
    W: DeviceSignatureVerifier + Send + Sync,
    N: DeviceChallengeGenerator + Send + Sync,
    K: Clock + Send + Sync,
    Z: IdGenerator + Send + Sync,
{
    fn authenticate(&self, access: SecretString) -> Result<AccessActor, TenantAuthError> {
        self.oidc.auth.authenticate(access)
    }
    fn authorize(
        &self,
        actor: AccessActor,
        request: TenantAuthorizationRequest,
    ) -> Result<TenantAuthorizationResult, TenantAuthError> {
        self.oidc.authorize(actor, request)
    }
    fn exchange(
        &self,
        command: TenantCodeExchange,
        proof: Option<TenantAuthenticationProof>,
    ) -> Result<TenantCodeExchangeResult, TenantAuthError> {
        match proof {
            Some(proof) => self.oidc.exchange_with_proof(command, proof, &self.devices),
            None => self.oidc.exchange(command),
        }
    }
}

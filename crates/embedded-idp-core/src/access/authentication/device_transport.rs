use super::*;
use crate::{
    DeviceChallengeGenerator, DeviceProofPurpose, DevicePublicJwkValidator,
    DeviceSignatureVerifier, IssueDeviceProofChallengeResult, RotateProofBoundRefreshCommand,
};

/// Object-safe composition of the existing login and proof services for hosts.
/// Request bindings are reconstructed by the host; their tenant is an assertion
/// that the underlying transaction checks against the selected/session tenant.
pub trait TenantDeviceAuthenticationService: TenantAuthenticationService {
    /// Authenticate one business request and require its current session to be device-bound.
    /// The device ID comes only from the validated session, never from caller input.
    fn authenticate_device(
        &self,
        access_token: SecretString,
    ) -> Result<AuthenticatedDeviceSession, TenantAuthError>;
    fn login_proven(
        &self,
        command: TenantPasswordLogin,
        proof: TenantAuthenticationProof,
    ) -> Result<TenantLoginOutcome, TenantAuthError>;
    fn select_proven(
        &self,
        ticket: SecretString,
        tenant: String,
        proof: TenantAuthenticationProof,
    ) -> Result<TenantLoginSession, TenantAuthError>;
    fn refresh(
        &self,
        token: SecretString,
        proof: Option<TenantAuthenticationProof>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError>;
    fn authentication_challenge(
        &self,
        tenant: String,
        device: String,
        purpose: DeviceProofPurpose,
    ) -> Result<IssueDeviceProofChallengeResult, TenantAuthError>;
}
pub struct CoreTenantDeviceAuthenticationService<A, P> {
    auth: A,
    devices: P,
}
impl<A, P> CoreTenantDeviceAuthenticationService<A, P> {
    pub fn new(auth: A, devices: P) -> Self {
        Self { auth, devices }
    }
}
impl<A: TenantAuthenticationService, P: Send + Sync> TenantAuthenticationService
    for CoreTenantDeviceAuthenticationService<A, P>
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
    fn authenticate(&self, token: SecretString) -> Result<AccessActor, TenantAuthError> {
        self.auth.authenticate(token)
    }
    fn begin_switch(&self, token: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        self.auth.begin_switch(token)
    }
}
impl<S, T, G, D, C, I, J, V, N, K, Z> TenantDeviceAuthenticationService
    for CoreTenantDeviceAuthenticationService<
        CoreTenantAuthenticationService<S, T, G, D, C, I>,
        CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    >
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantDeviceLoginTransaction + TenantRefreshTransaction,
    T: TokenIssuer + AccessTokenValidator + crate::ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    J: DevicePublicJwkValidator + Send + Sync,
    V: DeviceSignatureVerifier + Send + Sync,
    N: DeviceChallengeGenerator + Send + Sync,
    K: Clock + Send + Sync,
    Z: IdGenerator + Send + Sync,
{
    fn authenticate_device(
        &self,
        access_token: SecretString,
    ) -> Result<AuthenticatedDeviceSession, TenantAuthError> {
        self.auth.authenticate_device(access_token)
    }
    fn login_proven(
        &self,
        command: TenantPasswordLogin,
        proof: TenantAuthenticationProof,
    ) -> Result<TenantLoginOutcome, TenantAuthError> {
        self.auth.login_with_proof(command, proof, &self.devices)
    }
    fn select_proven(
        &self,
        ticket: SecretString,
        tenant: String,
        proof: TenantAuthenticationProof,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        self.auth
            .select_tenant_with_proof(ticket, tenant, proof, &self.devices)
    }
    fn refresh(
        &self,
        token: SecretString,
        proof: Option<TenantAuthenticationProof>,
    ) -> Result<TenantRefreshOutcome, TenantAuthError> {
        match proof {
            Some(p) => self.auth.rotate_refresh_with_proof(
                RotateProofBoundRefreshCommand {
                    refresh_token: token,
                    proof: p.proof,
                    binding: p.binding,
                },
                &self.devices,
            ),
            None => self.auth.rotate_refresh(token),
        }
    }
    fn authentication_challenge(
        &self,
        tenant: String,
        device: String,
        purpose: DeviceProofPurpose,
    ) -> Result<IssueDeviceProofChallengeResult, TenantAuthError> {
        if !self
            .devices
            .matches_login_entry(self.auth.mode, &self.auth.entry.client_id)
        {
            return Err(AccessError::InvalidInput("device_login_configuration").into());
        }
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &tenant)?;
        if ![
            TENANT_DEVICE_LOGIN_PURPOSE,
            TENANT_DEVICE_SELECTION_PURPOSE,
            crate::REFRESH_PURPOSE,
            TENANT_OIDC_EXCHANGE_PURPOSE,
            crate::DEVICE_REGISTRATION_PURPOSE,
            crate::DEVICE_KEY_ROTATION_PURPOSE,
            TENANT_DEVICE_HEARTBEAT_PURPOSE,
            "scan_login_create",
            "scan_login_claim",
            "scan_login_status",
            "scan_login_lookup",
            "scan_login_cancel",
            "scan_login_exchange",
            "scan_login_recover",
            "scan_login_ack",
            "scan_login_abort",
            "scan_login_close_origin",
        ]
        .contains(&purpose.as_str())
        {
            return Err(AccessError::InvalidInput("purpose").into());
        }
        self.devices.issue_challenge(&tenant, &device, purpose)
    }
}

/// Self-service devices only; administrative cross-user actions use a separate
/// management boundary. First binding still happens exclusively during login.
pub trait TenantDeviceService: TenantDeviceAuthenticationService {
    fn provision(
        &self,
        command: ProvisionTenantDevice,
        trusted: &TrustedDeviceAdmission,
        admission: &dyn TenantDeviceAdmission,
    ) -> Result<DeviceRegistrationResult, TenantAuthError>;
    fn registration_result(
        &self,
        lookup: DeviceRegistrationLookup,
        trusted: &TrustedDeviceAdmission,
        admission: &dyn TenantDeviceAdmission,
    ) -> Result<DeviceRegistrationResult, TenantAuthError>;
    fn complete(
        &self,
        command: CompleteTenantDeviceRegistration,
    ) -> Result<TenantProofKey, TenantAuthError>;
    fn rotate(&self, command: RotateTenantDeviceKey) -> Result<TenantProofKey, TenantAuthError>;
    fn devices(
        &self,
        actor: AccessActor,
        page: AccessPageRequest,
    ) -> Result<AccessPage<TenantSubjectDevice>, TenantAuthError>;
    fn device(
        &self,
        actor: AccessActor,
        device: String,
    ) -> Result<TenantSubjectDevice, TenantAuthError>;
    fn key_metadata(
        &self,
        actor: AccessActor,
        device: String,
        key: String,
    ) -> Result<DeviceKeyMetadata, TenantAuthError>;
    fn unbind(
        &self,
        actor: AccessActor,
        device: String,
        binding_id: String,
        expected_version: u64,
        operation_id: String,
    ) -> Result<DeviceOperationReceipt, TenantAuthError>;
    fn operation_result(
        &self,
        actor: AccessActor,
        operation_id: String,
    ) -> Result<DeviceOperationReceipt, TenantAuthError>;
    fn heartbeat(
        &self,
        command: VerifyTenantDeviceRequest,
    ) -> Result<crate::VerifiedDeviceRequest, TenantAuthError>;
}
impl<S, T, G, D, C, I, J, V, N, K, Z> TenantDeviceService
    for CoreTenantDeviceAuthenticationService<
        CoreTenantAuthenticationService<S, T, G, D, C, I>,
        CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    >
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>:
        TenantDeviceLoginTransaction + TenantRefreshTransaction + TenantDeviceManagementTransaction,
    T: TokenIssuer + AccessTokenValidator + crate::ScopedAccessTokenIssuer + Send + Sync,
    G: RefreshTokenGenerator + Send + Sync,
    D: RefreshTokenDigester + Send + Sync,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
    J: DevicePublicJwkValidator + Send + Sync,
    V: DeviceSignatureVerifier + Send + Sync,
    N: DeviceChallengeGenerator + Send + Sync,
    K: Clock + Send + Sync,
    Z: IdGenerator + Send + Sync,
{
    fn provision(
        &self,
        command: ProvisionTenantDevice,
        trusted: &TrustedDeviceAdmission,
        admission: &dyn TenantDeviceAdmission,
    ) -> Result<DeviceRegistrationResult, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &command.tenant_id)?;
        if !self
            .devices
            .matches_login_entry(self.auth.mode, &self.auth.entry.client_id)
        {
            return Err(AccessError::InvalidInput("device_configuration").into());
        }
        self.devices.provision_device(command, trusted, admission)
    }
    fn registration_result(
        &self,
        lookup: DeviceRegistrationLookup,
        trusted: &TrustedDeviceAdmission,
        admission: &dyn TenantDeviceAdmission,
    ) -> Result<DeviceRegistrationResult, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &lookup.tenant_id)?;
        if !self
            .devices
            .matches_login_entry(self.auth.mode, &self.auth.entry.client_id)
        {
            return Err(AccessError::InvalidInput("device_configuration").into());
        }
        self.devices.registration_result(lookup, trusted, admission)
    }
    fn complete(
        &self,
        command: CompleteTenantDeviceRegistration,
    ) -> Result<TenantProofKey, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &command.tenant_id)?;
        if !self
            .devices
            .matches_login_entry(self.auth.mode, &self.auth.entry.client_id)
        {
            return Err(AccessError::InvalidInput("device_configuration").into());
        }
        self.devices.complete_registration(command)
    }
    fn rotate(&self, command: RotateTenantDeviceKey) -> Result<TenantProofKey, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &command.actor.tenant_id)?;
        self.devices.rotate_key(command)
    }
    fn devices(
        &self,
        actor: AccessActor,
        page: AccessPageRequest,
    ) -> Result<AccessPage<TenantSubjectDevice>, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &actor.tenant_id)?;
        self.devices.list_subject_devices(actor, page)
    }
    fn device(
        &self,
        actor: AccessActor,
        device: String,
    ) -> Result<TenantSubjectDevice, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &actor.tenant_id)?;
        self.devices.get_subject_device(actor, &device)
    }
    fn key_metadata(
        &self,
        actor: AccessActor,
        device: String,
        key: String,
    ) -> Result<DeviceKeyMetadata, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &actor.tenant_id)?;
        self.devices
            .subject_device_key_metadata(actor, &device, &key)
    }
    fn unbind(
        &self,
        actor: AccessActor,
        device: String,
        binding_id: String,
        expected_version: u64,
        operation_id: String,
    ) -> Result<DeviceOperationReceipt, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &actor.tenant_id)?;
        self.devices.unbind_subject_device(
            actor,
            &device,
            &binding_id,
            expected_version,
            &operation_id,
        )
    }
    fn operation_result(
        &self,
        actor: AccessActor,
        operation_id: String,
    ) -> Result<DeviceOperationReceipt, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &actor.tenant_id)?;
        self.devices
            .self_device_operation_result(actor, &operation_id)
    }
    fn heartbeat(
        &self,
        command: VerifyTenantDeviceRequest,
    ) -> Result<crate::VerifiedDeviceRequest, TenantAuthError> {
        self.auth
            .entry
            .policy
            .validate_selection(self.auth.mode, &command.actor.tenant_id)?;
        self.devices.heartbeat(command)
    }
}

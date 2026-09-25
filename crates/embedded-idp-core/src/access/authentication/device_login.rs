use super::*;
use crate::{
    build_request_proof_bytes, AccountDeviceBindingStatus, DeviceChallengeGenerator,
    DeviceProofKeyStatus, DeviceProofPresentation, DeviceProofPurpose, DevicePublicJwkValidator,
    DeviceRequestBinding, DeviceSignatureVerifier, DeviceStatus, SecurityContractError,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

pub const TENANT_DEVICE_LOGIN_PURPOSE: &str = "tenant_login";
pub const TENANT_DEVICE_SELECTION_PURPOSE: &str = "tenant_selection";
pub const TENANT_DEVICE_AUTH_PROFILE: &str = "EMBEDDED-IDP-DEVICE-AUTH-V2";

/// Host-reconstructed route/body metadata. The binding tenant is an assertion:
/// authentication must check it against its selected/session tenant in the
/// transaction before consuming a nonce. It never selects the refresh tenant.
#[derive(Debug, Clone)]
pub struct TenantAuthenticationProof {
    pub proof: DeviceProofPresentation,
    pub binding: DeviceRequestBinding,
}

/// Prevent transplanting a device proof to another password login or login entry.
pub fn tenant_password_proof_context(
    client: &str,
    entry: &str,
    command: &TenantPasswordLogin,
) -> [u8; 32] {
    credential_context(&[
        TENANT_DEVICE_LOGIN_PURPOSE,
        client,
        entry,
        &command.email,
        command.password.expose_secret(),
    ])
}
pub fn tenant_selection_proof_context(
    client: &str,
    entry: &str,
    ticket: &SecretString,
) -> [u8; 32] {
    credential_context(&[
        TENANT_DEVICE_SELECTION_PURPOSE,
        client,
        entry,
        ticket.expose_secret(),
    ])
}
/// Refresh proof binds the exact bearer credential, including when the host
/// carries it outside the signed body. The Core refresh service recomputes this.
pub fn tenant_refresh_proof_context(client: &str, entry: &str, refresh: &SecretString) -> [u8; 32] {
    credential_context(&[
        crate::REFRESH_PURPOSE,
        client,
        entry,
        refresh.expose_secret(),
    ])
}
pub(super) fn credential_context(parts: &[&str]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"EMBEDDED-IDP-LOGIN-CREDENTIAL-V2\n");
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.finalize().into()
}
/// Authentication proofs preserve the raw-body hash and additionally sign the
/// credential context. A selection ticket in an Authorization header must be
/// covered too; raw-body binding alone would allow swapping that ticket.
pub fn build_tenant_authentication_proof_bytes(
    binding: &DeviceRequestBinding,
    proof: &DeviceProofPresentation,
    credential_context: &[u8; 32],
) -> Result<Vec<u8>, SecurityContractError> {
    let mut bytes = build_request_proof_bytes(binding, proof)?;
    if binding.profile.as_str() != TENANT_DEVICE_AUTH_PROFILE {
        return Err(SecurityContractError::InvalidProfile);
    }
    bytes.extend_from_slice(
        format!(
            "credential-sha256:{}\n",
            Base64UrlUnpadded::encode_string(credential_context)
        )
        .as_bytes(),
    );
    Ok(bytes)
}

/// A single statement's current authority, read after domain/account locks.
#[derive(Debug, Clone)]
pub struct TenantSessionDevice {
    pub device: TenantProofDevice,
    pub key: TenantProofKey,
    pub binding: TenantProofBinding,
}
impl TenantSessionDevice {
    pub(in crate::access) fn validate(
        &self,
        tenant: &str,
        account: &str,
        device: &str,
        client: &str,
    ) -> Result<(), TenantAuthError> {
        if self.device.tenant_id != tenant
            || self.device.id != device
            || self.device.client_id != client
            || self.device.status != DeviceStatus::Active
            || self.key.tenant_id != tenant
            || self.key.device_id != device
            || self.device.proof_key_id.as_deref() != Some(self.key.key_id.as_str())
            || self.key.status != DeviceProofKeyStatus::Active
            || self.key.version == 0
            || self.binding.tenant_id != tenant
            || self.binding.account_id != account
            || self.binding.device_id != device
            || self.binding.status != AccountDeviceBindingStatus::Active
        {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(())
    }
}
pub trait TenantDeviceLoginTransaction: TenantDeviceProofTransaction {
    /// Called with domain/account/device locks, only after password/ticket and
    /// fresh device proof checks. Never reactivate a suspended binding.
    fn insert_login_binding(
        &mut self,
        binding: &TenantProofBinding,
        id: &str,
        now: SystemTime,
    ) -> Result<(), StoreError>;
}

impl<S, T, G, D, C, I> CoreTenantAuthenticationService<S, T, G, D, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantDeviceLoginTransaction,
    T: TokenIssuer + AccessTokenValidator + crate::ScopedAccessTokenIssuer,
    G: RefreshTokenGenerator,
    D: RefreshTokenDigester,
    C: Clock,
    I: IdGenerator,
{
    /// Fixed-tenant password login with fresh device possession. Choose policy
    /// authenticates the password normally, then verifies proof at selection.
    pub fn login_with_proof<J, V, N, K, Z>(
        &self,
        command: TenantPasswordLogin,
        proof: TenantAuthenticationProof,
        devices: &CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    ) -> Result<TenantLoginOutcome, TenantAuthError>
    where
        J: DevicePublicJwkValidator,
        V: DeviceSignatureVerifier,
        N: DeviceChallengeGenerator,
        K: Clock,
        Z: IdGenerator,
    {
        if !matches!(self.entry.policy, LoginTenantPolicy::Fixed { .. }) {
            return Err(AccessError::InvalidInput("proof_requires_selected_tenant").into());
        }
        let context =
            tenant_password_proof_context(&self.entry.client_id, &self.entry.login_entry, &command);
        self.login_with_device_step(command, |tx, tenant, account| {
            self.attach_proven_device(
                tx,
                tenant,
                account,
                TENANT_DEVICE_LOGIN_PURPOSE,
                &context,
                &proof,
                devices,
            )
            .map(Some)
        })
    }
    pub fn select_tenant_with_proof<J, V, N, K, Z>(
        &self,
        ticket: SecretString,
        tenant: String,
        proof: TenantAuthenticationProof,
        devices: &CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    ) -> Result<TenantLoginSession, TenantAuthError>
    where
        J: DevicePublicJwkValidator,
        V: DeviceSignatureVerifier,
        N: DeviceChallengeGenerator,
        K: Clock,
        Z: IdGenerator,
    {
        let context =
            tenant_selection_proof_context(&self.entry.client_id, &self.entry.login_entry, &ticket);
        self.select_with_device_step(ticket, tenant, |tx, tenant, account| {
            self.attach_proven_device(
                tx,
                tenant,
                account,
                TENANT_DEVICE_SELECTION_PURPOSE,
                &context,
                &proof,
                devices,
            )
            .map(Some)
        })
    }
    fn attach_proven_device<J, V, N, K, Z>(
        &self,
        tx: &mut S::Transaction<'_>,
        tenant: &str,
        account: &str,
        purpose: &str,
        context: &[u8; 32],
        proof: &TenantAuthenticationProof,
        devices: &CoreTenantDeviceProofService<S, J, V, N, K, Z>,
    ) -> Result<String, TenantAuthError>
    where
        J: DevicePublicJwkValidator,
        V: DeviceSignatureVerifier,
        N: DeviceChallengeGenerator,
        K: Clock,
        Z: IdGenerator,
    {
        if !devices.matches_login_entry(self.mode, &self.entry.client_id) {
            return Err(AccessError::InvalidInput("device_login_configuration").into());
        }
        let purpose = DeviceProofPurpose::new(purpose).map_err(TenantAuthError::Security)?;
        // Uses the caller's existing transaction; never starts a second pool checkout.
        let (verified, needs_binding) = devices.verify_in_transaction(
            tx,
            tenant,
            account,
            &purpose,
            &proof.proof,
            &proof.binding,
            Some(context),
            true,
        )?;
        if needs_binding {
            tx.insert_login_binding(
                &TenantProofBinding {
                    tenant_id: tenant.into(),
                    account_id: account.into(),
                    device_id: verified.device_id.clone(),
                    status: AccountDeviceBindingStatus::Active,
                },
                &self.ids.next_id("binding"),
                verified.verified_at,
            )?;
        }
        Ok(verified.device_id)
    }
}

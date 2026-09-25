use super::*;
use crate::{
    build_device_key_rotation_proof_bytes, build_device_registration_proof_bytes,
    decode_device_signature, SecretString, DEVICE_KEY_ROTATION_PURPOSE,
};

/// Required host admission policy, never deserialized from a provisioning body.
/// Host authentication/rate limits and provisioning policy remain host-owned.
pub trait TenantDeviceAdmission: Send + Sync {
    fn authorize_provision(&self, tenant_id: &str, client_id: &str) -> Result<(), AccessError>;
}
pub trait TenantDeviceLifecycleTransaction: TenantDeviceProofTransaction {
    fn insert_pending_device(
        &mut self,
        device: &TenantProofDevice,
        name: &str,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    /// Insert the new key and advance the device pointer; retire the expected old
    /// key for rotation. No tenant changes. Failure rolls back the whole transaction.
    fn activate_device_key(
        &mut self,
        key: &TenantProofKey,
        expected_old_key: Option<&str>,
        now: SystemTime,
    ) -> Result<(), StoreError>;
}
#[derive(Debug, Clone)]
pub struct CompleteTenantDeviceRegistration {
    pub tenant_id: String,
    pub device_id: String,
    pub public_jwk: String,
    pub challenge: SecretString,
    pub signature: SecretString,
}
#[derive(Debug, Clone)]
pub struct RotateTenantDeviceKey {
    pub actor: AccessActor,
    pub device_id: String,
    pub proposed_public_jwk: String,
    pub challenge: SecretString,
    pub current_key_signature: SecretString,
    pub proposed_key_signature: SecretString,
}
impl<S, J, V, G, C, I> CoreTenantDeviceProofService<S, J, V, G, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantDeviceLifecycleTransaction,
    J: DevicePublicJwkValidator,
    V: DeviceSignatureVerifier,
    G: DeviceChallengeGenerator,
    C: Clock,
    I: IdGenerator,
{
    pub fn provision_device(
        &self,
        tenant: &str,
        name: &str,
        admission: &(impl TenantDeviceAdmission + ?Sized),
    ) -> Result<TenantProofDevice, TenantAuthError> {
        self.mode.validate_business_tenant(tenant)?;
        if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(AccessError::InvalidInput("device_name").into());
        }
        admission.authorize_provision(tenant, &self.config.client_id)?;
        self.store.auth_transaction(self.mode, |tx| {
            tx.lock_tenants(&[tenant.into()])?;
            self.require_active_domain(tx, tenant)?;
            let device = TenantProofDevice {
                tenant_id: tenant.into(),
                id: self.ids.next_id("device"),
                client_id: self.config.client_id.clone(),
                proof_key_id: None,
                status: DeviceStatus::Pending,
            };
            tx.insert_pending_device(&device, name, self.clock.now())?;
            Ok(device)
        })
    }
    pub fn complete_registration(
        &self,
        command: CompleteTenantDeviceRegistration,
    ) -> Result<TenantProofKey, TenantAuthError> {
        self.mode.validate_business_tenant(&command.tenant_id)?;
        self.require_purpose(
            &DeviceProofPurpose::new(DEVICE_REGISTRATION_PURPOSE)
                .map_err(TenantAuthError::Security)?,
        )?;
        let proposed = self
            .jwk_parser
            .validate_ed25519_public_jwk(&command.public_jwk)
            .map_err(|_| invalid_proof())?;
        let digest = digest_device_challenge(command.challenge.expose_secret())
            .map_err(|_| invalid_proof())?;
        let signature = decode_device_signature(command.signature.expose_secret())
            .map_err(|_| invalid_proof())?;
        let canonical = build_device_registration_proof_bytes(
            &command.tenant_id,
            &command.device_id,
            &proposed.key_id,
            command.challenge.expose_secret(),
        )
        .map_err(|_| invalid_proof())?;
        self.store.auth_transaction(self.mode, |tx| {
            tx.lock_tenants(&[command.tenant_id.clone()])?;
            self.require_active_domain(tx, &command.tenant_id)?;
            let device = tx
                .lock_proof_device(&command.tenant_id, &command.device_id)?
                .ok_or_else(invalid_proof)?;
            if device.tenant_id != command.tenant_id
                || device.id != command.device_id
                || device.client_id != self.config.client_id
                || device.status != DeviceStatus::Pending
                || device.proof_key_id.is_some()
            {
                return Err(invalid_proof());
            }
            let challenge = tx
                .lock_proof_challenge(&device.tenant_id, &digest)?
                .ok_or_else(invalid_proof)?;
            let now = self.clock.now();
            self.verifier
                .verify_ed25519(&proposed.public_key, &canonical, &signature)
                .map_err(|_| invalid_proof())?;
            require_challenge(
                &challenge,
                &device,
                &digest,
                DEVICE_REGISTRATION_PURPOSE,
                now,
            )?;
            let key = TenantProofKey {
                tenant_id: device.tenant_id,
                device_id: device.id,
                key_id: proposed.key_id,
                public_jwk: proposed.canonical_public_jwk,
                version: 1,
                status: DeviceProofKeyStatus::Active,
            };
            consume(tx, &key.tenant_id, &digest, now)?;
            tx.activate_device_key(&key, None, now)?;
            Ok(key)
        })
    }
    pub fn rotate_key(
        &self,
        command: RotateTenantDeviceKey,
    ) -> Result<TenantProofKey, TenantAuthError> {
        self.mode
            .validate_business_tenant(&command.actor.tenant_id)?;
        self.require_purpose(
            &DeviceProofPurpose::new(DEVICE_KEY_ROTATION_PURPOSE)
                .map_err(TenantAuthError::Security)?,
        )?;
        let proposed = self
            .jwk_parser
            .validate_ed25519_public_jwk(&command.proposed_public_jwk)
            .map_err(|_| invalid_proof())?;
        let digest = digest_device_challenge(command.challenge.expose_secret())
            .map_err(|_| invalid_proof())?;
        let current_signature =
            decode_device_signature(command.current_key_signature.expose_secret())
                .map_err(|_| invalid_proof())?;
        let proposed_signature =
            decode_device_signature(command.proposed_key_signature.expose_secret())
                .map_err(|_| invalid_proof())?;
        self.store.auth_transaction(self.mode, |tx| {
            let session = self.lock_actor(tx, &command.actor)?;
            let device = tx
                .lock_proof_device(&command.actor.tenant_id, &command.device_id)?
                .ok_or_else(invalid_proof)?;
            let key_id = device.proof_key_id.as_deref().ok_or_else(invalid_proof)?;
            let current = tx
                .lock_proof_key(&command.actor.tenant_id, &command.device_id, key_id)?
                .ok_or_else(invalid_proof)?;
            let binding = tx
                .lock_proof_binding(
                    &command.actor.tenant_id,
                    &command.actor.subject_id,
                    &command.device_id,
                )?
                .ok_or_else(invalid_proof)?;
            let challenge = tx
                .lock_proof_challenge(&command.actor.tenant_id, &digest)?
                .ok_or_else(invalid_proof)?;
            let now = self.clock.now();
            if session.created_at > now || session.expires_at <= now {
                return Err(TenantAuthError::InvalidSession);
            }
            if device.tenant_id != command.actor.tenant_id
                || device.id != command.device_id
                || device.client_id != self.config.client_id
                || current.tenant_id != device.tenant_id
                || current.device_id != device.id
                || current.key_id != key_id
                || current.version == 0
            {
                return Err(invalid_proof());
            }
            let version = current
                .version
                .checked_add(1)
                .ok_or(AccessError::InvalidInput("key_version_overflow"))?;
            let canonical = build_device_key_rotation_proof_bytes(
                &device.tenant_id,
                &device.id,
                &current.key_id,
                &proposed.key_id,
                version,
                command.challenge.expose_secret(),
            )
            .map_err(|_| invalid_proof())?;
            let old = self
                .jwk_parser
                .validate_ed25519_public_jwk(&current.public_jwk)
                .map_err(|_| invalid_proof())?;
            if old.key_id != current.key_id {
                return Err(invalid_proof());
            }
            self.verifier
                .verify_ed25519(&old.public_key, &canonical, &current_signature)
                .map_err(|_| invalid_proof())?;
            self.verifier
                .verify_ed25519(&proposed.public_key, &canonical, &proposed_signature)
                .map_err(|_| invalid_proof())?;
            if device.status != DeviceStatus::Active
                || current.status != DeviceProofKeyStatus::Active
                || proposed.key_id == current.key_id
                || binding.tenant_id != device.tenant_id
                || binding.device_id != device.id
                || binding.account_id != command.actor.subject_id
                || binding.status != AccountDeviceBindingStatus::Active
            {
                return Err(invalid_proof());
            }
            require_challenge(
                &challenge,
                &device,
                &digest,
                DEVICE_KEY_ROTATION_PURPOSE,
                now,
            )?;
            let key = TenantProofKey {
                tenant_id: device.tenant_id,
                device_id: device.id,
                key_id: proposed.key_id,
                public_jwk: proposed.canonical_public_jwk,
                version,
                status: DeviceProofKeyStatus::Active,
            };
            consume(tx, &key.tenant_id, &digest, now)?;
            tx.activate_device_key(&key, Some(&current.key_id), now)?;
            Ok(key)
        })
    }
    fn require_active_domain(
        &self,
        tx: &mut impl TenantAuthTransaction,
        tenant: &str,
    ) -> Result<(), TenantAuthError> {
        if !tx
            .tenant(tenant)?
            .is_some_and(|t| t.id == tenant && t.status == TenantStatus::Active)
            || !tx.client_exists(&self.config.client_id)?
        {
            return Err(AccessError::Forbidden.into());
        }
        Ok(())
    }
}
fn require_challenge(
    c: &TenantProofChallenge,
    d: &TenantProofDevice,
    digest: &[u8; 32],
    purpose: &str,
    now: SystemTime,
) -> Result<(), TenantAuthError> {
    if c.tenant_id != d.tenant_id
        || c.device_id != d.id
        || c.challenge_digest != *digest
        || c.purpose.as_str() != purpose
    {
        return Err(invalid_proof());
    }
    if c.issued_at > now || c.expires_at <= now {
        return Err(TenantAuthError::DeviceProof(
            DeviceRequestVerificationError::ExpiredProof,
        ));
    }
    if c.consumed_at.is_some() {
        return Err(TenantAuthError::DeviceProof(
            DeviceRequestVerificationError::ReplayedProof,
        ));
    }
    Ok(())
}
fn consume(
    tx: &mut impl TenantDeviceProofTransaction,
    tenant: &str,
    digest: &[u8; 32],
    now: SystemTime,
) -> Result<(), TenantAuthError> {
    if !tx.consume_proof_challenge(tenant, digest, now)? {
        return Err(TenantAuthError::DeviceProof(
            DeviceRequestVerificationError::ReplayedProof,
        ));
    }
    Ok(())
}

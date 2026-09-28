use super::*;
use crate::{
    build_device_key_rotation_proof_bytes, build_device_registration_proof_bytes,
    decode_device_signature, SecretString, DEVICE_KEY_ROTATION_PURPOSE,
};

/// Constructed by the host from authenticated admission state, never from JSON.
#[derive(Debug, Clone)]
pub struct TrustedDeviceAdmission {
    pub registration_scope: String,
    pub valid_until: SystemTime,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAdmissionAction {
    Provision,
    ReadResult,
}
/// The host checks that the proposed device ID belongs to this admission scope.
pub trait TenantDeviceAdmission: Send + Sync {
    fn authorize(
        &self,
        tenant_id: &str,
        client_id: &str,
        device_id: &str,
        action: DeviceAdmissionAction,
        admission: &TrustedDeviceAdmission,
    ) -> Result<(), AccessError>;
}
#[derive(Debug, Clone)]
pub struct ProvisionTenantDevice {
    pub tenant_id: String,
    pub device_id: String,
    pub registration_request_id: String,
    pub device_name: String,
    pub public_jwk: String,
}
#[derive(Debug, Clone)]
pub struct DeviceRegistrationLookup {
    pub tenant_id: String,
    pub device_id: String,
    pub registration_request_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantDeviceRegistration {
    pub tenant_id: String,
    pub client_id: String,
    pub registration_scope: String,
    pub registration_request_id: String,
    pub device_id: String,
    pub device_name: String,
    pub expected_key_id: String,
    pub public_jwk: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub completed_at: Option<SystemTime>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRegistrationResult {
    pub device: TenantProofDevice,
    pub expected_key_id: String,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub completed_at: Option<SystemTime>,
}
pub trait TenantDeviceLifecycleTransaction: TenantDeviceProofTransaction {
    fn append_rotation_audit(
        &mut self,
        actor: &AccessActor,
        device: &TenantProofDevice,
        before: &TenantProofKey,
        after: &TenantProofKey,
        now: SystemTime,
        audit_id: &str,
        request_id: &str,
    ) -> Result<(), StoreError>;
    fn insert_pending_device(
        &mut self,
        device: &TenantProofDevice,
        name: &str,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    fn registration(
        &mut self,
        tenant: &str,
        client: &str,
        scope: &str,
        request_id: &str,
    ) -> Result<Option<TenantDeviceRegistration>, StoreError>;
    fn insert_registration(&mut self, record: &TenantDeviceRegistration) -> Result<(), StoreError>;
    fn complete_registration_record(
        &mut self,
        tenant: &str,
        device: &str,
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
    pub expected_key_id: String,
    pub expected_key_version: u64,
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
        command: ProvisionTenantDevice,
        trusted: &TrustedDeviceAdmission,
        admission: &(impl TenantDeviceAdmission + ?Sized),
    ) -> Result<DeviceRegistrationResult, TenantAuthError> {
        let tenant = &command.tenant_id;
        self.mode.validate_business_tenant(tenant)?;
        for (value, field) in [
            (&command.device_id, "device_id"),
            (&command.registration_request_id, "registration_request_id"),
        ] {
            if uuid::Uuid::parse_str(value).map_or(true, |id| id.to_string() != *value) {
                return Err(AccessError::InvalidInput(field).into());
            }
        }
        super::super::query::validate_id(&trusted.registration_scope, 128, "registration_scope")?;
        if command.device_name.trim().is_empty()
            || command.device_name.len() > 256
            || command.device_name.chars().any(char::is_control)
        {
            return Err(AccessError::InvalidInput("device_name").into());
        }
        let proposed = self
            .jwk_parser
            .validate_ed25519_public_jwk(&command.public_jwk)
            .map_err(|_| AccessError::InvalidInput("public_jwk"))?;
        admission.authorize(
            tenant,
            &self.config.client_id,
            &command.device_id,
            DeviceAdmissionAction::Provision,
            trusted,
        )?;
        self.store.auth_transaction(self.mode, |tx| {
            tx.lock_tenants(&[tenant.into()])?;
            self.require_active_domain(tx, tenant)?;
            let now = self.clock.now();
            if trusted.valid_until <= now {
                return Err(AccessError::Forbidden.into());
            }
            admission.authorize(
                tenant,
                &self.config.client_id,
                &command.device_id,
                DeviceAdmissionAction::Provision,
                trusted,
            )?;
            if let Some(existing) = tx.registration(
                tenant,
                &self.config.client_id,
                &trusted.registration_scope,
                &command.registration_request_id,
            )? {
                if existing.device_id != command.device_id
                    || existing.device_name != command.device_name
                    || existing.expected_key_id != proposed.key_id
                    || existing.public_jwk != proposed.canonical_public_jwk
                {
                    return Err(AccessError::Conflict("device_registration").into());
                }
                let device = tx
                    .lock_proof_device(tenant, &existing.device_id)?
                    .ok_or(AccessError::InvalidStoreResponse)?;
                if device.client_id != self.config.client_id || device.tenant_id != *tenant {
                    return Err(AccessError::InvalidStoreResponse.into());
                }
                return Ok(DeviceRegistrationResult {
                    device,
                    expected_key_id: existing.expected_key_id,
                    created_at: existing.created_at,
                    expires_at: existing.expires_at,
                    completed_at: existing.completed_at,
                });
            }
            let expires_at = now
                .checked_add(Duration::from_secs(24 * 60 * 60))
                .ok_or(AccessError::InvalidInput("registration_expiry"))?
                .min(trusted.valid_until);
            if expires_at.duration_since(now).unwrap_or_default() < Duration::from_secs(1) {
                return Err(AccessError::Forbidden.into());
            }
            let device = TenantProofDevice {
                tenant_id: tenant.into(),
                id: command.device_id.clone(),
                client_id: self.config.client_id.clone(),
                proof_key_id: None,
                status: DeviceStatus::Pending,
                version: 1,
                key_version: None,
            };
            let record = TenantDeviceRegistration {
                tenant_id: tenant.into(),
                client_id: self.config.client_id.clone(),
                registration_scope: trusted.registration_scope.clone(),
                registration_request_id: command.registration_request_id.clone(),
                device_id: device.id.clone(),
                device_name: command.device_name.clone(),
                expected_key_id: proposed.key_id,
                public_jwk: proposed.canonical_public_jwk,
                created_at: now,
                expires_at,
                completed_at: None,
            };
            tx.insert_pending_device(&device, &command.device_name, now)
                .map_err(AccessError::from)?;
            tx.insert_registration(&record).map_err(AccessError::from)?;
            Ok(DeviceRegistrationResult {
                device,
                expected_key_id: record.expected_key_id,
                created_at: now,
                expires_at,
                completed_at: None,
            })
        })
    }
    pub fn registration_result(
        &self,
        lookup: DeviceRegistrationLookup,
        trusted: &TrustedDeviceAdmission,
        admission: &(impl TenantDeviceAdmission + ?Sized),
    ) -> Result<DeviceRegistrationResult, TenantAuthError> {
        self.mode.validate_business_tenant(&lookup.tenant_id)?;
        for (value, field) in [
            (&lookup.device_id, "device_id"),
            (&lookup.registration_request_id, "registration_request_id"),
        ] {
            if uuid::Uuid::parse_str(value).map_or(true, |id| id.to_string() != *value) {
                return Err(AccessError::InvalidInput(field).into());
            }
        }
        super::super::query::validate_id(&trusted.registration_scope, 128, "registration_scope")?;
        admission.authorize(
            &lookup.tenant_id,
            &self.config.client_id,
            &lookup.device_id,
            DeviceAdmissionAction::ReadResult,
            trusted,
        )?;
        self.store.auth_transaction(self.mode, |tx| {
            tx.lock_tenants(&[lookup.tenant_id.clone()])?;
            self.require_active_domain(tx, &lookup.tenant_id)?;
            if trusted.valid_until <= self.clock.now() {
                return Err(AccessError::Forbidden.into());
            }
            admission.authorize(
                &lookup.tenant_id,
                &self.config.client_id,
                &lookup.device_id,
                DeviceAdmissionAction::ReadResult,
                trusted,
            )?;
            let record = tx
                .registration(
                    &lookup.tenant_id,
                    &self.config.client_id,
                    &trusted.registration_scope,
                    &lookup.registration_request_id,
                )?
                .ok_or(AccessError::NotFound("device_registration"))?;
            if record.device_id != lookup.device_id {
                return Err(AccessError::NotFound("device_registration").into());
            }
            let device = tx
                .lock_proof_device(&lookup.tenant_id, &record.device_id)?
                .ok_or(AccessError::InvalidStoreResponse)?;
            if device.tenant_id != lookup.tenant_id || device.client_id != self.config.client_id {
                return Err(AccessError::InvalidStoreResponse.into());
            }
            Ok(DeviceRegistrationResult {
                device,
                expected_key_id: record.expected_key_id,
                created_at: record.created_at,
                expires_at: record.expires_at,
                completed_at: record.completed_at,
            })
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
            let registration = tx
                .registration_for_device(&command.tenant_id, &command.device_id)?
                .ok_or_else(invalid_proof)?;
            if device.tenant_id != command.tenant_id
                || device.id != command.device_id
                || device.client_id != self.config.client_id
                || device.status != DeviceStatus::Pending
                || device.proof_key_id.is_some()
                || registration.client_id != self.config.client_id
                || registration.expected_key_id != proposed.key_id
                || registration.public_jwk != proposed.canonical_public_jwk
                || registration.completed_at.is_some()
            {
                return Err(invalid_proof());
            }
            let challenge = tx
                .lock_proof_challenge(&device.tenant_id, &digest)?
                .ok_or_else(invalid_proof)?;
            let now = self.clock.now();
            if registration.created_at > now || registration.expires_at <= now {
                return Err(invalid_proof());
            }
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
                tenant_id: device.tenant_id.clone(),
                device_id: device.id.clone(),
                key_id: proposed.key_id,
                public_jwk: proposed.canonical_public_jwk,
                version: 1,
                status: DeviceProofKeyStatus::Active,
            };
            consume(tx, &key.tenant_id, &digest, now)?;
            tx.activate_device_key(&key, None, now)
                .map_err(AccessError::from)?;
            tx.complete_registration_record(&key.tenant_id, &key.device_id, now)
                .map_err(AccessError::from)?;
            Ok(key)
        })
    }
    pub fn rotate_key(
        &self,
        command: RotateTenantDeviceKey,
    ) -> Result<TenantProofKey, TenantAuthError> {
        self.mode
            .validate_business_tenant(&command.actor.tenant_id)?;
        super::super::query::validate_id(&command.expected_key_id, 128, "expected_key_id")?;
        if command.expected_key_version == 0 || i64::try_from(command.expected_key_version).is_err()
        {
            return Err(AccessError::InvalidInput("expected_key_version").into());
        }
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
            if current.key_id != command.expected_key_id
                || current.version != command.expected_key_version
            {
                return Err(AccessError::Conflict("device_key_changed").into());
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
                tenant_id: device.tenant_id.clone(),
                device_id: device.id.clone(),
                key_id: proposed.key_id,
                public_jwk: proposed.canonical_public_jwk,
                version,
                status: DeviceProofKeyStatus::Active,
            };
            consume(tx, &key.tenant_id, &digest, now)?;
            tx.activate_device_key(&key, Some(&current.key_id), now)
                .map_err(AccessError::from)?;
            tx.append_rotation_audit(
                &command.actor,
                &device,
                &current,
                &key,
                now,
                &self.ids.next_id("audit"),
                &self.ids.next_id("request"),
            )?;
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

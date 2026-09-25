//! Tenant-scoped device lifecycle, proof verification and single-use challenges.
mod management;
pub use management::*;
mod lifecycle;
pub use lifecycle::*;

use super::*;
use crate::{
    build_request_proof_bytes, digest_device_challenge, validate_proof_freshness,
    AccountDeviceBindingStatus, Clock, DeviceChallengeGenerator, DeviceProofKeyStatus,
    DeviceProofPresentation, DeviceProofPurpose, DevicePublicJwkValidator, DeviceRequestBinding,
    DeviceRequestVerificationError, DeviceSignatureVerifier, DeviceStatus, IdGenerator,
    IssueDeviceProofChallengeResult, SessionStatus, StoreError, VerifiedDeviceRequest,
    DEVICE_REGISTRATION_PURPOSE,
};
use std::time::{Duration, SystemTime};

// These projections contain exactly the authority read from tenant_v1; they never
// wrap a single-domain store or infer a missing tenant from caller input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantProofDevice {
    pub tenant_id: String,
    pub id: String,
    pub client_id: String,
    pub proof_key_id: Option<String>,
    pub status: DeviceStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantProofKey {
    pub tenant_id: String,
    pub device_id: String,
    pub key_id: String,
    pub public_jwk: String,
    pub version: u64,
    pub status: DeviceProofKeyStatus,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantProofBinding {
    pub tenant_id: String,
    pub account_id: String,
    pub device_id: String,
    pub status: AccountDeviceBindingStatus,
}
#[derive(Clone, PartialEq, Eq)]
pub struct TenantProofChallenge {
    pub tenant_id: String,
    pub id: String,
    pub device_id: String,
    pub purpose: DeviceProofPurpose,
    pub challenge_digest: [u8; 32],
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
}

/// State -> tenant -> account -> device -> key -> binding -> challenge.
/// The surrounding TenantAuthStore transaction commits only on Ok.
pub trait TenantDeviceProofTransaction: TenantAuthTransaction {
    fn lock_proof_device(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<TenantProofDevice>, StoreError>;
    fn lock_proof_key(
        &mut self,
        tenant: &str,
        device: &str,
        key: &str,
    ) -> Result<Option<TenantProofKey>, StoreError>;
    fn lock_proof_binding(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<TenantProofBinding>, StoreError>;
    fn lock_proof_challenge(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantProofChallenge>, StoreError>;
    fn insert_proof_challenge(
        &mut self,
        challenge: &TenantProofChallenge,
    ) -> Result<(), StoreError>;
    fn consume_proof_challenge(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
        now: SystemTime,
    ) -> Result<bool, StoreError>;
}

#[derive(Debug, Clone)]
pub struct TenantDeviceProofConfig {
    pub client_id: String,
    pub allowed_purposes: Vec<DeviceProofPurpose>,
    pub challenge_ttl_secs: u64,
    pub clock_skew_secs: u64,
}
#[derive(Debug, Clone)]
pub struct VerifyTenantDeviceRequest {
    /// Constructed after host authentication, never deserialized from request JSON.
    pub actor: AccessActor,
    /// Fixed by the host route, never chosen by request JSON.
    pub expected_purpose: DeviceProofPurpose,
    pub proof: DeviceProofPresentation,
    /// Reconstructed from the trusted tenant, configured route and raw body hash.
    pub binding: DeviceRequestBinding,
}

pub struct CoreTenantDeviceProofService<S, J, V, G, C, I> {
    mode: TenancyMode,
    config: TenantDeviceProofConfig,
    store: S,
    jwk_parser: J,
    verifier: V,
    challenges: G,
    clock: C,
    ids: I,
}
impl<S, J, V, G, C, I> CoreTenantDeviceProofService<S, J, V, G, C, I> {
    pub fn new(
        mode: TenancyMode,
        config: TenantDeviceProofConfig,
        store: S,
        jwk_parser: J,
        verifier: V,
        challenges: G,
        clock: C,
        ids: I,
    ) -> Result<Self, TenantAuthError> {
        super::query::validate_id(&config.client_id, 128, "client_id")?;
        if config.challenge_ttl_secs == 0 || config.allowed_purposes.is_empty() {
            return Err(AccessError::InvalidInput("device_proof_config").into());
        }
        Ok(Self {
            mode,
            config,
            store,
            jwk_parser,
            verifier,
            challenges,
            clock,
            ids,
        })
    }
}
impl<S, J, V, G, C, I> CoreTenantDeviceProofService<S, J, V, G, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantDeviceProofTransaction,
    J: DevicePublicJwkValidator,
    V: DeviceSignatureVerifier,
    G: DeviceChallengeGenerator,
    C: Clock,
    I: IdGenerator,
{
    /// Unknown/ineligible devices receive the same opaque response but no stored nonce.
    pub fn issue_challenge(
        &self,
        tenant: &str,
        device: &str,
        purpose: DeviceProofPurpose,
    ) -> Result<IssueDeviceProofChallengeResult, TenantAuthError> {
        self.mode.validate_business_tenant(tenant)?;
        super::query::validate_id(device, 128, "device_id")?;
        self.require_purpose(&purpose)?;
        let raw = self
            .challenges
            .generate_device_challenge()
            .map_err(TenantAuthError::Security)?;
        let digest =
            digest_device_challenge(raw.expose_secret()).map_err(TenantAuthError::Security)?;
        self.store.auth_transaction(self.mode, |tx| {
            tx.lock_tenants(&[tenant.into()])?;
            let domain_active = tx
                .tenant(tenant)?
                .is_some_and(|t| t.id == tenant && t.status == TenantStatus::Active);
            let device_record = tx.lock_proof_device(tenant, device)?;
            let now = self.clock.now();
            let expires_at = now
                .checked_add(Duration::from_secs(self.config.challenge_ttl_secs))
                .ok_or(AccessError::InvalidInput("challenge_expiry"))?;
            if domain_active
                && tx.client_exists(&self.config.client_id)?
                && device_record.is_some_and(|d| {
                    d.tenant_id == tenant
                        && d.id == device
                        && d.client_id == self.config.client_id
                        && if purpose.as_str() == DEVICE_REGISTRATION_PURPOSE {
                            d.status == DeviceStatus::Pending
                        } else {
                            d.status == DeviceStatus::Active
                        }
                })
            {
                tx.insert_proof_challenge(&TenantProofChallenge {
                    tenant_id: tenant.into(),
                    id: self.ids.next_id("dnonce"),
                    device_id: device.into(),
                    purpose,
                    challenge_digest: digest,
                    issued_at: now,
                    expires_at,
                    consumed_at: None,
                })?;
            }
            Ok(IssueDeviceProofChallengeResult {
                challenge: raw,
                expires_at,
            })
        })
    }

    pub fn verify_request(
        &self,
        command: VerifyTenantDeviceRequest,
    ) -> Result<VerifiedDeviceRequest, TenantAuthError> {
        self.mode
            .validate_business_tenant(&command.actor.tenant_id)?;
        if command.binding.tenant_id != command.actor.tenant_id {
            return Err(invalid_proof());
        }
        self.require_purpose(&command.expected_purpose)?;
        self.store.auth_transaction(self.mode, |tx| {
            let actor = &command.actor;
            let session = self.lock_actor(tx, actor)?;
            if session
                .device_id
                .as_ref()
                .is_some_and(|id| id != &command.proof.device_id)
            {
                return Err(TenantAuthError::InvalidSession);
            }
            let (verified, _) = self.verify_in_transaction(
                tx,
                &actor.tenant_id,
                &actor.subject_id,
                &command.expected_purpose,
                &command.proof,
                &command.binding,
                None,
                false,
            )?;
            if session.created_at > verified.verified_at
                || session.expires_at <= verified.verified_at
            {
                return Err(TenantAuthError::InvalidSession);
            }
            Ok(verified)
        })
    }
    pub(super) fn verify_in_transaction(
        &self,
        tx: &mut impl TenantDeviceProofTransaction,
        tenant: &str,
        account: &str,
        purpose: &DeviceProofPurpose,
        proof: &DeviceProofPresentation,
        request: &DeviceRequestBinding,
        credential_context: Option<&[u8; 32]>,
        allow_first_binding: bool,
    ) -> Result<(VerifiedDeviceRequest, bool), TenantAuthError> {
        self.mode.validate_business_tenant(tenant)?;
        if request.tenant_id != tenant {
            return Err(invalid_proof());
        }
        self.require_purpose(purpose)?;
        let canonical = match credential_context {
            Some(context) => build_tenant_authentication_proof_bytes(request, proof, context),
            None => build_request_proof_bytes(request, proof),
        }
        .map_err(|_| invalid_proof())?;
        let digest = digest_device_challenge(&proof.challenge).map_err(|_| invalid_proof())?;
        let signature = proof.signature_bytes().map_err(|_| invalid_proof())?;
        let device = tx
            .lock_proof_device(tenant, &proof.device_id)?
            .ok_or_else(invalid_proof)?;
        let key = tx
            .lock_proof_key(tenant, &device.id, &proof.key_id)?
            .ok_or_else(invalid_proof)?;
        let binding = tx.lock_proof_binding(tenant, account, &device.id)?;
        let challenge = tx
            .lock_proof_challenge(tenant, &digest)?
            .ok_or_else(invalid_proof)?;
        // Read server time after all potentially blocking locks.
        let now = self.clock.now();
        if device.tenant_id != tenant
            || device.id != proof.device_id
            || device.client_id != self.config.client_id
            || key.tenant_id != tenant
            || key.device_id != device.id
            || key.key_id != proof.key_id
            || key.version == 0
            || challenge.tenant_id != tenant
            || challenge.device_id != device.id
            || challenge.challenge_digest != digest
            || challenge.purpose != *purpose
        {
            return Err(invalid_proof());
        }
        validate_proof_freshness(proof.signed_at, now, self.config.clock_skew_secs).map_err(
            |_| TenantAuthError::DeviceProof(DeviceRequestVerificationError::ExpiredProof),
        )?;
        let public_key = self
            .jwk_parser
            .validate_ed25519_public_jwk(&key.public_jwk)
            .map_err(|_| invalid_proof())?;
        if public_key.key_id != key.key_id {
            return Err(invalid_proof());
        }
        self.verifier
            .verify_ed25519(&public_key.public_key, &canonical, &signature)
            .map_err(|_| invalid_proof())?;
        // Do not disclose device/binding/replay state until the signature passes.
        if device.status != DeviceStatus::Active
            || key.status != DeviceProofKeyStatus::Active
            || device.proof_key_id.as_deref() != Some(key.key_id.as_str())
        {
            return Err(invalid_proof());
        }
        let needs_binding = binding.is_none();
        if (needs_binding && !allow_first_binding)
            || binding.is_some_and(|b| {
                b.tenant_id != tenant
                    || b.account_id != account
                    || b.device_id != device.id
                    || b.status != AccountDeviceBindingStatus::Active
            })
        {
            return Err(invalid_proof());
        }
        if challenge.issued_at > now || challenge.expires_at <= now {
            return Err(TenantAuthError::DeviceProof(
                DeviceRequestVerificationError::ExpiredProof,
            ));
        }
        if challenge.consumed_at.is_some() || !tx.consume_proof_challenge(tenant, &digest, now)? {
            return Err(TenantAuthError::DeviceProof(
                DeviceRequestVerificationError::ReplayedProof,
            ));
        }
        Ok((
            VerifiedDeviceRequest {
                tenant_id: tenant.into(),
                account_id: account.into(),
                device_id: device.id,
                key_id: key.key_id,
                key_version: key.version,
                purpose: purpose.clone(),
                challenge_id: challenge.id,
                verified_at: now,
            },
            needs_binding,
        ))
    }
    pub(super) fn matches_login_entry(&self, mode: TenancyMode, client: &str) -> bool {
        self.mode == mode && self.config.client_id == client
    }
    fn lock_actor(
        &self,
        tx: &mut impl TenantAuthTransaction,
        actor: &AccessActor,
    ) -> Result<TenantSession, TenantAuthError> {
        tx.lock_tenants(&[actor.tenant_id.clone()])?;
        let account = tx
            .lock_account(&actor.subject_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        let tenant = tx
            .tenant(&actor.tenant_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        let member = tx
            .membership(&actor.tenant_id, &actor.subject_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        let session = tx
            .session(&actor.tenant_id, &actor.session_id)?
            .ok_or(TenantAuthError::InvalidSession)?;
        if !account.active
            || account.id != actor.subject_id
            || tenant.id != actor.tenant_id
            || tenant.status != TenantStatus::Active
            || member.tenant_id != actor.tenant_id
            || member.subject_id != actor.subject_id
            || member.status != MembershipStatus::Active
            || session.tenant_id != actor.tenant_id
            || session.id != actor.session_id
            || session.account_id != actor.subject_id
            || session.client_id != self.config.client_id
            || session.status != SessionStatus::Active
            || !tx.client_exists(&self.config.client_id)?
        {
            return Err(TenantAuthError::InvalidSession);
        }
        if let Some(device) = &session.device_id {
            tx.session_device(&actor.tenant_id, &actor.subject_id, device)?
                .ok_or(TenantAuthError::InvalidSession)?
                .validate(
                    &actor.tenant_id,
                    &actor.subject_id,
                    device,
                    &self.config.client_id,
                )?;
        }
        let now = self.clock.now();
        if session.created_at > now || session.expires_at <= now {
            return Err(TenantAuthError::InvalidSession);
        }
        Ok(session)
    }
    fn require_purpose(&self, purpose: &DeviceProofPurpose) -> Result<(), TenantAuthError> {
        if !self.config.allowed_purposes.contains(purpose) {
            return Err(AccessError::InvalidInput("device_proof_purpose").into());
        }
        Ok(())
    }
}
fn invalid_proof() -> TenantAuthError {
    TenantAuthError::DeviceProof(DeviceRequestVerificationError::InvalidProof)
}

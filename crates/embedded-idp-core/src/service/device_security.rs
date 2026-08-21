use std::time::{Duration, SystemTime};

use crate::{
    build_device_key_rotation_proof_bytes, build_device_registration_proof_bytes,
    decode_device_signature, digest_device_challenge, AccountDeviceBinding,
    AccountDeviceBindingStatus, Clock, DeviceChallengeGenerator, DeviceProofAlgorithm,
    DeviceProofChallengeRecord, DeviceProofKeyRecord, DeviceProofKeyStatus, DeviceProofPurpose,
    DevicePublicJwkParser, DevicePublicJwkValidator, DeviceRecord, DeviceSignatureVerifier,
    DeviceStatus, IdGenerator, OidcClient, SecretString, StoreError, DEVICE_KEY_ROTATION_PURPOSE,
    DEVICE_REGISTRATION_PURPOSE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionPendingDeviceCommand {
    pub client_id: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionPendingDeviceResult {
    pub device: DeviceRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueDeviceProofChallengeCommand {
    pub device_id: String,
    pub purpose: DeviceProofPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueDeviceProofChallengeResult {
    pub challenge: SecretString,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteDeviceKeyRegistrationCommand {
    pub device_id: String,
    pub public_jwk: String,
    pub challenge: SecretString,
    pub signature: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteDeviceKeyRegistrationResult {
    pub device: DeviceRecord,
    pub key: DeviceProofKeyRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateDeviceProofKeyCommand {
    pub account_id: String,
    pub device_id: String,
    pub proposed_public_jwk: String,
    pub challenge: SecretString,
    pub current_key_signature: SecretString,
    pub proposed_key_signature: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateDeviceProofKeyResult {
    pub device: DeviceRecord,
    pub retired_key: DeviceProofKeyRecord,
    pub active_key: DeviceProofKeyRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceSecurityError {
    InvalidRequest,
    ClientNotFound,
    InvalidPurpose,
    InvalidChallenge,
    ExpiredChallenge,
    ReplayedChallenge,
    InvalidPublicKey,
    InvalidProof,
    DeviceInactive,
    BindingInactive,
    KeyMismatch,
    KeyVersionOverflow,
    Store(StoreError),
    Internal,
}

pub trait DeviceSecurityService: Send + Sync {
    fn provision_pending_device(
        &self,
        command: ProvisionPendingDeviceCommand,
    ) -> Result<ProvisionPendingDeviceResult, DeviceSecurityError>;

    fn issue_device_proof_challenge(
        &self,
        command: IssueDeviceProofChallengeCommand,
    ) -> Result<IssueDeviceProofChallengeResult, DeviceSecurityError>;

    fn complete_device_key_registration(
        &self,
        command: CompleteDeviceKeyRegistrationCommand,
    ) -> Result<CompleteDeviceKeyRegistrationResult, DeviceSecurityError>;

    fn rotate_device_proof_key(
        &self,
        command: RotateDeviceProofKeyCommand,
    ) -> Result<RotateDeviceProofKeyResult, DeviceSecurityError>;
}

pub trait DeviceSecurityTransaction {
    fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError>;
    fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError>;
    fn find_device_for_challenge(
        &mut self,
        device_id: &str,
    ) -> Result<Option<DeviceRecord>, StoreError>;
    fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError>;
    fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError>;
    fn lock_active_device_key(
        &mut self,
        device_id: &str,
    ) -> Result<Option<DeviceProofKeyRecord>, StoreError>;
    fn lock_device_key(&mut self, key_id: &str)
        -> Result<Option<DeviceProofKeyRecord>, StoreError>;
    fn insert_device_key(
        &mut self,
        key: DeviceProofKeyRecord,
    ) -> Result<DeviceProofKeyRecord, StoreError>;
    fn update_device_key(
        &mut self,
        key: DeviceProofKeyRecord,
    ) -> Result<DeviceProofKeyRecord, StoreError>;
    fn lock_active_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError>;
    fn insert_challenge(
        &mut self,
        challenge: DeviceProofChallengeRecord,
    ) -> Result<DeviceProofChallengeRecord, StoreError>;
    fn lock_challenge(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<DeviceProofChallengeRecord>, StoreError>;
    fn consume_challenge_if_active(
        &mut self,
        digest: &[u8; 32],
        observed_at: SystemTime,
    ) -> Result<bool, StoreError>;
}

pub trait DeviceSecurityTransactionRunner {
    type Transaction<'a>: DeviceSecurityTransaction
    where
        Self: 'a;

    fn device_security_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, DeviceSecurityError>,
    ) -> Result<R, DeviceSecurityError>;
}

pub struct CoreDeviceSecurityService<S, G, J, V, K, I> {
    store_runner: S,
    challenge_generator: G,
    jwk_validator: J,
    signature_verifier: V,
    clock: K,
    id_generator: I,
    challenge_ttl_secs: u64,
    allowed_purposes: Vec<DeviceProofPurpose>,
}

impl<S, G, J, V, K, I> CoreDeviceSecurityService<S, G, J, V, K, I> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store_runner: S,
        challenge_generator: G,
        jwk_validator: J,
        signature_verifier: V,
        clock: K,
        id_generator: I,
        challenge_ttl_secs: u64,
        allowed_purposes: Vec<DeviceProofPurpose>,
    ) -> Self {
        Self {
            store_runner,
            challenge_generator,
            jwk_validator,
            signature_verifier,
            clock,
            id_generator,
            challenge_ttl_secs,
            allowed_purposes,
        }
    }
}

impl<S, G, J, V, K, I> DeviceSecurityService for CoreDeviceSecurityService<S, G, J, V, K, I>
where
    S: DeviceSecurityTransactionRunner + Send + Sync,
    G: DeviceChallengeGenerator + Send + Sync,
    J: DevicePublicJwkValidator + DevicePublicJwkParser + Send + Sync,
    V: DeviceSignatureVerifier + Send + Sync,
    K: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn provision_pending_device(
        &self,
        command: ProvisionPendingDeviceCommand,
    ) -> Result<ProvisionPendingDeviceResult, DeviceSecurityError> {
        validate_identifier(&command.client_id)?;
        validate_device_name(&command.device_name)?;
        let observed_at = self.clock.now();

        self.store_runner.device_security_transaction(|tx| {
            let client = tx
                .find_client(&command.client_id)
                .map_err(DeviceSecurityError::Store)?
                .ok_or(DeviceSecurityError::ClientNotFound)?;
            let device = tx
                .insert_device(DeviceRecord {
                    id: self.id_generator.next_id("dev"),
                    client_id: client.client_id,
                    device_name: command.device_name,
                    proof_key_id: None,
                    status: DeviceStatus::Pending,
                    registered_at: observed_at,
                    last_seen_at: None,
                })
                .map_err(DeviceSecurityError::Store)?;
            Ok(ProvisionPendingDeviceResult { device })
        })
    }

    fn issue_device_proof_challenge(
        &self,
        command: IssueDeviceProofChallengeCommand,
    ) -> Result<IssueDeviceProofChallengeResult, DeviceSecurityError> {
        validate_identifier(&command.device_id)?;
        if !self.allowed_purposes.contains(&command.purpose) {
            return Err(DeviceSecurityError::InvalidPurpose);
        }
        let observed_at = self.clock.now();
        let expires_at = observed_at
            .checked_add(Duration::from_secs(self.challenge_ttl_secs))
            .ok_or(DeviceSecurityError::Internal)?;
        let raw_challenge = self
            .challenge_generator
            .generate_device_challenge()
            .map_err(|_| DeviceSecurityError::Internal)?;
        let challenge_digest = digest_device_challenge(raw_challenge.expose_secret())
            .map_err(|_| DeviceSecurityError::Internal)?;

        self.store_runner.device_security_transaction(|tx| {
            let eligible = tx
                .find_device_for_challenge(&command.device_id)
                .map_err(DeviceSecurityError::Store)?
                .is_some_and(|device| device_is_eligible(&device, &command.purpose));
            if eligible {
                tx.insert_challenge(DeviceProofChallengeRecord {
                    id: self.id_generator.next_id("dnonce"),
                    device_id: command.device_id,
                    purpose: command.purpose,
                    challenge_digest,
                    issued_at: observed_at,
                    expires_at,
                    consumed_at: None,
                })
                .map_err(DeviceSecurityError::Store)?;
            }
            Ok(IssueDeviceProofChallengeResult {
                challenge: raw_challenge,
                expires_at,
            })
        })
    }

    fn complete_device_key_registration(
        &self,
        command: CompleteDeviceKeyRegistrationCommand,
    ) -> Result<CompleteDeviceKeyRegistrationResult, DeviceSecurityError> {
        validate_identifier(&command.device_id)?;
        let observed_at = self.clock.now();
        let challenge_digest = digest_device_challenge(command.challenge.expose_secret())
            .map_err(|_| DeviceSecurityError::InvalidChallenge)?;
        let proposed = self
            .jwk_validator
            .validate_ed25519_public_jwk(&command.public_jwk)
            .map_err(|_| DeviceSecurityError::InvalidPublicKey)?;
        let signature = decode_device_signature(command.signature.expose_secret())
            .map_err(|_| DeviceSecurityError::InvalidProof)?;
        let canonical = build_device_registration_proof_bytes(
            &command.device_id,
            &proposed.key_id,
            command.challenge.expose_secret(),
        )
        .map_err(|_| DeviceSecurityError::InvalidProof)?;

        self.store_runner.device_security_transaction(|tx| {
            let mut device = tx
                .lock_device(&command.device_id)
                .map_err(DeviceSecurityError::Store)?
                .ok_or(DeviceSecurityError::InvalidChallenge)?;
            let challenge = tx
                .lock_challenge(&challenge_digest)
                .map_err(DeviceSecurityError::Store)?
                .ok_or(DeviceSecurityError::InvalidChallenge)?;
            if device.status != DeviceStatus::Pending
                || challenge.device_id != device.id
                || challenge.purpose.as_str() != DEVICE_REGISTRATION_PURPOSE
            {
                return Err(DeviceSecurityError::InvalidChallenge);
            }
            if tx
                .lock_active_device_key(&device.id)
                .map_err(DeviceSecurityError::Store)?
                .is_some()
            {
                return Err(DeviceSecurityError::InvalidChallenge);
            }
            self.signature_verifier
                .verify_ed25519(&proposed.public_key, &canonical, &signature)
                .map_err(|_| DeviceSecurityError::InvalidProof)?;
            validate_challenge_liveness(&challenge, observed_at)?;

            let key = tx
                .insert_device_key(DeviceProofKeyRecord {
                    key_id: proposed.key_id.clone(),
                    device_id: device.id.clone(),
                    algorithm: DeviceProofAlgorithm::Ed25519,
                    public_jwk: proposed.canonical_public_jwk,
                    version: 1,
                    status: DeviceProofKeyStatus::Active,
                    registered_at: observed_at,
                    retired_at: None,
                })
                .map_err(DeviceSecurityError::Store)?;
            consume_challenge(tx, &challenge_digest, observed_at)?;
            device.proof_key_id = Some(key.key_id.clone());
            device.status = DeviceStatus::Active;
            device.last_seen_at = Some(observed_at);
            let device = tx
                .update_device(device)
                .map_err(DeviceSecurityError::Store)?;
            Ok(CompleteDeviceKeyRegistrationResult { device, key })
        })
    }

    fn rotate_device_proof_key(
        &self,
        command: RotateDeviceProofKeyCommand,
    ) -> Result<RotateDeviceProofKeyResult, DeviceSecurityError> {
        validate_identifier(&command.account_id)?;
        validate_identifier(&command.device_id)?;
        let observed_at = self.clock.now();
        let challenge_digest = digest_device_challenge(command.challenge.expose_secret())
            .map_err(|_| DeviceSecurityError::InvalidChallenge)?;
        let proposed = self
            .jwk_validator
            .validate_ed25519_public_jwk(&command.proposed_public_jwk)
            .map_err(|_| DeviceSecurityError::InvalidPublicKey)?;
        let current_signature =
            decode_device_signature(command.current_key_signature.expose_secret())
                .map_err(|_| DeviceSecurityError::InvalidProof)?;
        let proposed_signature =
            decode_device_signature(command.proposed_key_signature.expose_secret())
                .map_err(|_| DeviceSecurityError::InvalidProof)?;

        self.store_runner.device_security_transaction(|tx| {
            let mut device = tx
                .lock_device(&command.device_id)
                .map_err(DeviceSecurityError::Store)?
                .ok_or(DeviceSecurityError::InvalidProof)?;
            let mut current_key = tx
                .lock_active_device_key(&device.id)
                .map_err(DeviceSecurityError::Store)?
                .ok_or(DeviceSecurityError::InvalidProof)?;
            let binding = tx
                .lock_active_binding(&command.account_id, &device.id)
                .map_err(DeviceSecurityError::Store)?;
            let challenge = tx
                .lock_challenge(&challenge_digest)
                .map_err(DeviceSecurityError::Store)?
                .ok_or(DeviceSecurityError::InvalidProof)?;
            if challenge.device_id != device.id
                || challenge.purpose.as_str() != DEVICE_KEY_ROTATION_PURPOSE
            {
                return Err(DeviceSecurityError::InvalidProof);
            }
            let next_version = current_key
                .version
                .checked_add(1)
                .ok_or(DeviceSecurityError::KeyVersionOverflow)?;
            let canonical = build_device_key_rotation_proof_bytes(
                &device.id,
                &current_key.key_id,
                &proposed.key_id,
                next_version,
                command.challenge.expose_secret(),
            )
            .map_err(|_| DeviceSecurityError::InvalidProof)?;
            let current_public_key = self
                .jwk_validator
                .parse_ed25519_public_key(&current_key.public_jwk)
                .map_err(|_| DeviceSecurityError::Internal)?;
            self.signature_verifier
                .verify_ed25519(&current_public_key, &canonical, &current_signature)
                .map_err(|_| DeviceSecurityError::InvalidProof)?;
            self.signature_verifier
                .verify_ed25519(&proposed.public_key, &canonical, &proposed_signature)
                .map_err(|_| DeviceSecurityError::InvalidProof)?;

            if device.status != DeviceStatus::Active {
                return Err(DeviceSecurityError::DeviceInactive);
            }
            if current_key.status != DeviceProofKeyStatus::Active
                || device.proof_key_id.as_deref() != Some(current_key.key_id.as_str())
                || proposed.key_id == current_key.key_id
            {
                return Err(DeviceSecurityError::KeyMismatch);
            }
            if binding
                .as_ref()
                .is_none_or(|binding| binding.status != AccountDeviceBindingStatus::Active)
            {
                return Err(DeviceSecurityError::BindingInactive);
            }
            validate_challenge_liveness(&challenge, observed_at)?;
            if tx
                .lock_device_key(&proposed.key_id)
                .map_err(DeviceSecurityError::Store)?
                .is_some()
            {
                return Err(DeviceSecurityError::KeyMismatch);
            }

            consume_challenge(tx, &challenge_digest, observed_at)?;
            current_key.status = DeviceProofKeyStatus::Retired;
            current_key.retired_at = Some(observed_at);
            let retired_key = tx
                .update_device_key(current_key)
                .map_err(DeviceSecurityError::Store)?;
            let active_key = tx
                .insert_device_key(DeviceProofKeyRecord {
                    key_id: proposed.key_id.clone(),
                    device_id: device.id.clone(),
                    algorithm: DeviceProofAlgorithm::Ed25519,
                    public_jwk: proposed.canonical_public_jwk,
                    version: next_version,
                    status: DeviceProofKeyStatus::Active,
                    registered_at: observed_at,
                    retired_at: None,
                })
                .map_err(DeviceSecurityError::Store)?;
            device.proof_key_id = Some(active_key.key_id.clone());
            device.last_seen_at = Some(observed_at);
            let device = tx
                .update_device(device)
                .map_err(DeviceSecurityError::Store)?;
            Ok(RotateDeviceProofKeyResult {
                device,
                retired_key,
                active_key,
            })
        })
    }
}

fn validate_identifier(value: &str) -> Result<(), DeviceSecurityError> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(DeviceSecurityError::InvalidRequest);
    }
    Ok(())
}

fn validate_device_name(value: &str) -> Result<(), DeviceSecurityError> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(DeviceSecurityError::InvalidRequest);
    }
    Ok(())
}

fn device_is_eligible(device: &DeviceRecord, purpose: &DeviceProofPurpose) -> bool {
    match purpose.as_str() {
        DEVICE_REGISTRATION_PURPOSE => device.status == DeviceStatus::Pending,
        _ => device.status == DeviceStatus::Active,
    }
}

fn validate_challenge_liveness(
    challenge: &DeviceProofChallengeRecord,
    observed_at: SystemTime,
) -> Result<(), DeviceSecurityError> {
    if challenge.expires_at <= observed_at {
        return Err(DeviceSecurityError::ExpiredChallenge);
    }
    if challenge.consumed_at.is_some() {
        return Err(DeviceSecurityError::ReplayedChallenge);
    }
    Ok(())
}

fn consume_challenge<T: DeviceSecurityTransaction>(
    tx: &mut T,
    digest: &[u8; 32],
    observed_at: SystemTime,
) -> Result<(), DeviceSecurityError> {
    if !tx
        .consume_challenge_if_active(digest, observed_at)
        .map_err(DeviceSecurityError::Store)?
    {
        return Err(DeviceSecurityError::ReplayedChallenge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};

    use base64ct::{Base64UrlUnpadded, Encoding};

    use super::*;
    use crate::{
        AccountDeviceBindingStatus, OidcClientType, SecurityContractError, ValidatedDevicePublicJwk,
    };

    #[derive(Clone, Default)]
    struct TestState {
        clients: HashMap<String, OidcClient>,
        devices: HashMap<String, DeviceRecord>,
        keys: HashMap<String, DeviceProofKeyRecord>,
        bindings: HashMap<(String, String), AccountDeviceBinding>,
        challenges: HashMap<[u8; 32], DeviceProofChallengeRecord>,
    }

    struct TestRunner {
        state: Mutex<TestState>,
    }

    struct TestTx<'a> {
        state: &'a mut TestState,
    }

    impl DeviceSecurityTransactionRunner for TestRunner {
        type Transaction<'a> = TestTx<'a>;

        fn device_security_transaction<R>(
            &self,
            run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, DeviceSecurityError>,
        ) -> Result<R, DeviceSecurityError> {
            let mut state = self.state.lock().unwrap();
            let mut working = state.clone();
            let result = run(&mut TestTx {
                state: &mut working,
            });
            if result.is_ok() {
                *state = working;
            }
            result
        }
    }

    impl DeviceSecurityTransaction for TestTx<'_> {
        fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
            Ok(self.state.clients.get(client_id).cloned())
        }

        fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            self.state.devices.insert(device.id.clone(), device.clone());
            Ok(device)
        }

        fn find_device_for_challenge(
            &mut self,
            device_id: &str,
        ) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(self.state.devices.get(device_id).cloned())
        }

        fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(self.state.devices.get(device_id).cloned())
        }

        fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            self.state.devices.insert(device.id.clone(), device.clone());
            Ok(device)
        }

        fn lock_active_device_key(
            &mut self,
            device_id: &str,
        ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
            Ok(self
                .state
                .keys
                .values()
                .find(|key| {
                    key.device_id == device_id && key.status == DeviceProofKeyStatus::Active
                })
                .cloned())
        }

        fn lock_device_key(
            &mut self,
            key_id: &str,
        ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
            Ok(self.state.keys.get(key_id).cloned())
        }

        fn insert_device_key(
            &mut self,
            key: DeviceProofKeyRecord,
        ) -> Result<DeviceProofKeyRecord, StoreError> {
            if self.state.keys.contains_key(&key.key_id) {
                return Err(StoreError::Conflict("device_proof_key.id"));
            }
            self.state.keys.insert(key.key_id.clone(), key.clone());
            Ok(key)
        }

        fn update_device_key(
            &mut self,
            key: DeviceProofKeyRecord,
        ) -> Result<DeviceProofKeyRecord, StoreError> {
            self.state.keys.insert(key.key_id.clone(), key.clone());
            Ok(key)
        }

        fn lock_active_binding(
            &mut self,
            account_id: &str,
            device_id: &str,
        ) -> Result<Option<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .get(&(account_id.to_string(), device_id.to_string()))
                .filter(|binding| binding.status == AccountDeviceBindingStatus::Active)
                .cloned())
        }

        fn insert_challenge(
            &mut self,
            challenge: DeviceProofChallengeRecord,
        ) -> Result<DeviceProofChallengeRecord, StoreError> {
            self.state
                .challenges
                .insert(challenge.challenge_digest, challenge.clone());
            Ok(challenge)
        }

        fn lock_challenge(
            &mut self,
            digest: &[u8; 32],
        ) -> Result<Option<DeviceProofChallengeRecord>, StoreError> {
            Ok(self.state.challenges.get(digest).cloned())
        }

        fn consume_challenge_if_active(
            &mut self,
            digest: &[u8; 32],
            observed_at: SystemTime,
        ) -> Result<bool, StoreError> {
            let Some(challenge) = self.state.challenges.get_mut(digest) else {
                return Ok(false);
            };
            if challenge.consumed_at.is_some() || challenge.expires_at <= observed_at {
                return Ok(false);
            }
            challenge.consumed_at = Some(observed_at);
            Ok(true)
        }
    }

    struct TestChallengeGenerator;
    impl DeviceChallengeGenerator for TestChallengeGenerator {
        fn generate_device_challenge(&self) -> Result<SecretString, SecurityContractError> {
            Ok(SecretString::new(encoded(2, 32)))
        }
    }

    struct TestJwk;
    impl DevicePublicJwkValidator for TestJwk {
        fn validate_ed25519_public_jwk(
            &self,
            public_jwk: &str,
        ) -> Result<ValidatedDevicePublicJwk, SecurityContractError> {
            let byte = match public_jwk {
                "new-jwk" => 8,
                "next-jwk" => 9,
                _ => return Err(SecurityContractError::InvalidKeyId),
            };
            Ok(ValidatedDevicePublicJwk {
                key_id: encoded(byte, 32),
                public_key: [byte; 32],
                canonical_public_jwk: public_jwk.to_string(),
            })
        }
    }

    impl DevicePublicJwkParser for TestJwk {
        fn parse_ed25519_public_key(
            &self,
            canonical_public_jwk: &str,
        ) -> Result<[u8; 32], SecurityContractError> {
            match canonical_public_jwk {
                "new-jwk" => Ok([8; 32]),
                "next-jwk" => Ok([9; 32]),
                _ => Err(SecurityContractError::InvalidKeyId),
            }
        }
    }

    struct TestVerifier {
        accepts: bool,
    }
    impl DeviceSignatureVerifier for TestVerifier {
        fn verify_ed25519(
            &self,
            _public_key: &[u8; 32],
            _message: &[u8],
            _signature: &[u8; 64],
        ) -> Result<(), SecurityContractError> {
            self.accepts
                .then_some(())
                .ok_or(SecurityContractError::InvalidSignature)
        }
    }

    struct TestClock;
    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            now()
        }
    }

    struct TestIds;
    impl IdGenerator for TestIds {
        fn next_id(&self, prefix: &str) -> String {
            format!("{prefix}-generated")
        }
    }

    type Service = CoreDeviceSecurityService<
        TestRunner,
        TestChallengeGenerator,
        TestJwk,
        TestVerifier,
        TestClock,
        TestIds,
    >;

    fn service(status: DeviceStatus, accepts: bool) -> Service {
        let active = status == DeviceStatus::Active;
        let device = DeviceRecord {
            id: "device-1".to_string(),
            client_id: "desktop-app".to_string(),
            device_name: "Laptop".to_string(),
            proof_key_id: active.then(|| encoded(8, 32)),
            status,
            registered_at: now(),
            last_seen_at: None,
        };
        let mut state = TestState {
            clients: HashMap::from([(
                "desktop-app".to_string(),
                OidcClient {
                    client_id: "desktop-app".to_string(),
                    client_name: "Desktop App".to_string(),
                    redirect_uris: vec![],
                    client_type: OidcClientType::PublicDesktop,
                    pkce_required: true,
                    client_secret_hash: None,
                },
            )]),
            devices: HashMap::from([(device.id.clone(), device)]),
            ..TestState::default()
        };
        if active {
            let key_id = encoded(8, 32);
            state.keys.insert(
                key_id.clone(),
                DeviceProofKeyRecord {
                    key_id,
                    device_id: "device-1".to_string(),
                    algorithm: DeviceProofAlgorithm::Ed25519,
                    public_jwk: "new-jwk".to_string(),
                    version: 1,
                    status: DeviceProofKeyStatus::Active,
                    registered_at: now(),
                    retired_at: None,
                },
            );
            state.bindings.insert(
                ("account-1".to_string(), "device-1".to_string()),
                AccountDeviceBinding {
                    id: "binding-1".to_string(),
                    account_id: "account-1".to_string(),
                    device_id: "device-1".to_string(),
                    status: AccountDeviceBindingStatus::Active,
                    bound_at: now(),
                    unbound_at: None,
                    last_authenticated_at: Some(now()),
                },
            );
        }
        CoreDeviceSecurityService::new(
            TestRunner {
                state: Mutex::new(state),
            },
            TestChallengeGenerator,
            TestJwk,
            TestVerifier { accepts },
            TestClock,
            TestIds,
            60,
            vec![
                DeviceProofPurpose::new(DEVICE_REGISTRATION_PURPOSE).unwrap(),
                DeviceProofPurpose::new(DEVICE_KEY_ROTATION_PURPOSE).unwrap(),
                DeviceProofPurpose::new("refresh").unwrap(),
            ],
        )
    }

    fn issue(service: &Service, purpose: &str) -> SecretString {
        service
            .issue_device_proof_challenge(IssueDeviceProofChallengeCommand {
                device_id: "device-1".to_string(),
                purpose: DeviceProofPurpose::new(purpose).unwrap(),
            })
            .unwrap()
            .challenge
    }

    #[test]
    fn secure_provision_creates_only_a_pending_device() {
        let service = service(DeviceStatus::Pending, true);
        let challenge_count = service.store_runner.state.lock().unwrap().challenges.len();

        let result = service
            .provision_pending_device(ProvisionPendingDeviceCommand {
                client_id: "desktop-app".to_string(),
                device_name: "New Laptop".to_string(),
            })
            .unwrap();

        assert_eq!(result.device.status, DeviceStatus::Pending);
        assert_eq!(result.device.proof_key_id, None);
        assert_eq!(result.device.id, "dev-generated");
        assert_eq!(service.store_runner.state.lock().unwrap().devices.len(), 2);
        assert_eq!(
            service.store_runner.state.lock().unwrap().challenges.len(),
            challenge_count
        );
    }

    #[test]
    fn challenge_issuance_is_same_shape_for_unknown_device_without_authorizing_it() {
        let service = service(DeviceStatus::Pending, true);
        let known = issue(&service, DEVICE_REGISTRATION_PURPOSE);
        let unknown = service
            .issue_device_proof_challenge(IssueDeviceProofChallengeCommand {
                device_id: "00000000-0000-0000-0000-000000000000".to_string(),
                purpose: DeviceProofPurpose::new(DEVICE_REGISTRATION_PURPOSE).unwrap(),
            })
            .unwrap();

        assert_eq!(
            known.expose_secret().len(),
            unknown.challenge.expose_secret().len()
        );
        assert_eq!(
            service.store_runner.state.lock().unwrap().challenges.len(),
            1
        );
    }

    #[test]
    fn registration_activates_device_and_key_version_one_atomically() {
        let service = service(DeviceStatus::Pending, true);
        let challenge = issue(&service, DEVICE_REGISTRATION_PURPOSE);
        let result = service
            .complete_device_key_registration(CompleteDeviceKeyRegistrationCommand {
                device_id: "device-1".to_string(),
                public_jwk: "new-jwk".to_string(),
                challenge,
                signature: SecretString::new(encoded(4, 64)),
            })
            .unwrap();

        assert_eq!(result.device.status, DeviceStatus::Active);
        assert_eq!(result.key.version, 1);
        assert_eq!(result.key.status, DeviceProofKeyStatus::Active);
        assert!(service
            .store_runner
            .state
            .lock()
            .unwrap()
            .challenges
            .values()
            .all(|challenge| challenge.consumed_at.is_some()));
    }

    #[test]
    fn concurrent_registration_consumes_one_challenge_exactly_once() {
        let service = std::sync::Arc::new(service(DeviceStatus::Pending, true));
        let challenge = issue(&service, DEVICE_REGISTRATION_PURPOSE);
        let command = CompleteDeviceKeyRegistrationCommand {
            device_id: "device-1".to_string(),
            public_jwk: "new-jwk".to_string(),
            challenge,
            signature: SecretString::new(encoded(4, 64)),
        };
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let service = service.clone();
                let command = command.clone();
                std::thread::spawn(move || service.complete_device_key_registration(command))
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(service.store_runner.state.lock().unwrap().keys.len(), 1);
    }

    #[test]
    fn rotation_retires_current_key_and_activates_exact_next_version() {
        let service = service(DeviceStatus::Active, true);
        let challenge = issue(&service, DEVICE_KEY_ROTATION_PURPOSE);
        let result = service
            .rotate_device_proof_key(RotateDeviceProofKeyCommand {
                account_id: "account-1".to_string(),
                device_id: "device-1".to_string(),
                proposed_public_jwk: "next-jwk".to_string(),
                challenge,
                current_key_signature: SecretString::new(encoded(4, 64)),
                proposed_key_signature: SecretString::new(encoded(5, 64)),
            })
            .unwrap();

        assert_eq!(result.retired_key.status, DeviceProofKeyStatus::Retired);
        assert_eq!(result.active_key.version, 2);
        assert_eq!(result.device.proof_key_id, Some(result.active_key.key_id));
    }

    #[test]
    fn invalid_current_signature_cannot_disclose_inactive_or_replayed_state() {
        let service = service(DeviceStatus::Active, false);
        let challenge = issue(&service, DEVICE_KEY_ROTATION_PURPOSE);
        {
            let mut state = service.store_runner.state.lock().unwrap();
            state.devices.get_mut("device-1").unwrap().status = DeviceStatus::Disabled;
            state
                .bindings
                .get_mut(&("account-1".to_string(), "device-1".to_string()))
                .unwrap()
                .status = AccountDeviceBindingStatus::Suspended;
            state.challenges.values_mut().next().unwrap().consumed_at = Some(now());
        }

        assert_eq!(
            service.rotate_device_proof_key(RotateDeviceProofKeyCommand {
                account_id: "account-1".to_string(),
                device_id: "device-1".to_string(),
                proposed_public_jwk: "next-jwk".to_string(),
                challenge,
                current_key_signature: SecretString::new(encoded(4, 64)),
                proposed_key_signature: SecretString::new(encoded(5, 64)),
            }),
            Err(DeviceSecurityError::InvalidProof)
        );
        let state = service.store_runner.state.lock().unwrap();
        assert_eq!(state.keys.len(), 1);
        assert_eq!(
            state.keys.values().next().unwrap().status,
            DeviceProofKeyStatus::Active
        );
    }

    fn encoded(byte: u8, len: usize) -> String {
        Base64UrlUnpadded::encode_string(&vec![byte; len])
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
}

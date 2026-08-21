use std::time::SystemTime;

use crate::{
    build_request_proof_bytes, digest_device_challenge, validate_proof_freshness,
    AccountDeviceBinding, AccountDeviceBindingStatus, Clock, DeviceProofChallengeRecord,
    DeviceProofKeyRecord, DeviceProofKeyStatus, DeviceProofPresentation, DeviceProofPurpose,
    DevicePublicJwkParser, DeviceRecord, DeviceRequestBinding, DeviceSignatureVerifier,
    DeviceStatus, SecurityContractError, StoreError, VerifiedDeviceRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyDeviceRequestCommand {
    pub account_id: String,
    pub expected_purpose: DeviceProofPurpose,
    pub proof: DeviceProofPresentation,
    pub binding: DeviceRequestBinding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRequestVerificationError {
    InvalidRequest,
    InvalidProof,
    ExpiredProof,
    ReplayedProof,
    DeviceKeyMismatch,
    DeviceInactive,
    BindingInactive,
    Store(StoreError),
}

pub trait DeviceRequestVerificationService: Send + Sync {
    fn verify_device_request(
        &self,
        command: VerifyDeviceRequestCommand,
    ) -> Result<VerifiedDeviceRequest, DeviceRequestVerificationError>;
}

pub trait DeviceRequestVerificationTransaction {
    fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError>;
    fn lock_device_key(&mut self, key_id: &str)
        -> Result<Option<DeviceProofKeyRecord>, StoreError>;
    fn lock_active_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError>;
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

pub trait DeviceRequestVerificationTransactionRunner {
    type Transaction<'a>: DeviceRequestVerificationTransaction
    where
        Self: 'a;

    fn device_request_verification_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, DeviceRequestVerificationError>,
    ) -> Result<R, DeviceRequestVerificationError>;
}

pub struct CoreDeviceRequestVerificationService<S, J, V, K> {
    store_runner: S,
    jwk_parser: J,
    signature_verifier: V,
    clock: K,
    proof_clock_skew_secs: u64,
}

impl<S, J, V, K> CoreDeviceRequestVerificationService<S, J, V, K> {
    pub fn new(
        store_runner: S,
        jwk_parser: J,
        signature_verifier: V,
        clock: K,
        proof_clock_skew_secs: u64,
    ) -> Self {
        Self {
            store_runner,
            jwk_parser,
            signature_verifier,
            clock,
            proof_clock_skew_secs,
        }
    }
}

impl<S, J, V, K> DeviceRequestVerificationService
    for CoreDeviceRequestVerificationService<S, J, V, K>
where
    S: DeviceRequestVerificationTransactionRunner + Send + Sync,
    J: DevicePublicJwkParser + Send + Sync,
    V: DeviceSignatureVerifier + Send + Sync,
    K: Clock + Send + Sync,
{
    fn verify_device_request(
        &self,
        command: VerifyDeviceRequestCommand,
    ) -> Result<VerifiedDeviceRequest, DeviceRequestVerificationError> {
        validate_identifier(&command.account_id)?;
        command
            .proof
            .validate()
            .map_err(map_security_contract_error)?;
        let observed_at = self.clock.now();
        let challenge_digest = digest_device_challenge(&command.proof.challenge)
            .map_err(map_security_contract_error)?;

        self.store_runner
            .device_request_verification_transaction(|tx| {
                let device = tx
                    .lock_device(&command.proof.device_id)
                    .map_err(DeviceRequestVerificationError::Store)?
                    .ok_or(DeviceRequestVerificationError::InvalidProof)?;
                let key = tx
                    .lock_device_key(&command.proof.key_id)
                    .map_err(DeviceRequestVerificationError::Store)?
                    .ok_or(DeviceRequestVerificationError::InvalidProof)?;
                if key.device_id != device.id {
                    return Err(DeviceRequestVerificationError::InvalidProof);
                }
                let binding = tx
                    .lock_active_binding(&command.account_id, &device.id)
                    .map_err(DeviceRequestVerificationError::Store)?;
                let challenge = tx
                    .lock_challenge(&challenge_digest)
                    .map_err(DeviceRequestVerificationError::Store)?
                    .ok_or(DeviceRequestVerificationError::InvalidProof)?;
                if challenge.device_id != device.id || challenge.purpose != command.expected_purpose
                {
                    return Err(DeviceRequestVerificationError::InvalidProof);
                }

                validate_proof_freshness(
                    command.proof.signed_at,
                    observed_at,
                    self.proof_clock_skew_secs,
                )
                .map_err(|_| DeviceRequestVerificationError::ExpiredProof)?;
                let public_key = self
                    .jwk_parser
                    .parse_ed25519_public_key(&key.public_jwk)
                    .map_err(map_security_contract_error)?;
                let canonical = build_request_proof_bytes(&command.binding, &command.proof)
                    .map_err(map_security_contract_error)?;
                let signature = command
                    .proof
                    .signature_bytes()
                    .map_err(map_security_contract_error)?;
                self.signature_verifier
                    .verify_ed25519(&public_key, &canonical, &signature)
                    .map_err(map_security_contract_error)?;

                if device.status != DeviceStatus::Active {
                    return Err(DeviceRequestVerificationError::DeviceInactive);
                }
                if key.status != DeviceProofKeyStatus::Active
                    || device.proof_key_id.as_deref() != Some(key.key_id.as_str())
                {
                    return Err(DeviceRequestVerificationError::DeviceKeyMismatch);
                }
                if binding
                    .as_ref()
                    .is_none_or(|binding| binding.status != AccountDeviceBindingStatus::Active)
                {
                    return Err(DeviceRequestVerificationError::BindingInactive);
                }
                if challenge.expires_at <= observed_at {
                    return Err(DeviceRequestVerificationError::ExpiredProof);
                }
                if challenge.consumed_at.is_some() {
                    return Err(DeviceRequestVerificationError::ReplayedProof);
                }
                if !tx
                    .consume_challenge_if_active(&challenge_digest, observed_at)
                    .map_err(DeviceRequestVerificationError::Store)?
                {
                    return Err(DeviceRequestVerificationError::ReplayedProof);
                }

                Ok(VerifiedDeviceRequest {
                    account_id: command.account_id,
                    device_id: device.id,
                    key_id: key.key_id,
                    key_version: key.version,
                    purpose: command.expected_purpose,
                    challenge_id: challenge.id,
                    verified_at: observed_at,
                })
            })
    }
}

fn validate_identifier(value: &str) -> Result<(), DeviceRequestVerificationError> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(DeviceRequestVerificationError::InvalidRequest);
    }
    Ok(())
}

fn map_security_contract_error(error: SecurityContractError) -> DeviceRequestVerificationError {
    match error {
        SecurityContractError::InvalidSignedAt => DeviceRequestVerificationError::ExpiredProof,
        _ => DeviceRequestVerificationError::InvalidProof,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};

    use base64ct::{Base64UrlUnpadded, Encoding};

    use super::*;
    use crate::{
        CanonicalHttpMethod, DeviceProofAlgorithm, DeviceProofProfile, SecurityContractError,
    };

    const NOW_SECS: u64 = 1_700_000_000;

    #[derive(Clone)]
    struct TestState {
        device: DeviceRecord,
        key: DeviceProofKeyRecord,
        binding: AccountDeviceBinding,
        challenge: DeviceProofChallengeRecord,
    }

    struct TestRunner {
        state: Mutex<TestState>,
    }

    struct TestTx<'a> {
        state: &'a mut TestState,
    }

    impl DeviceRequestVerificationTransactionRunner for TestRunner {
        type Transaction<'a> = TestTx<'a>;

        fn device_request_verification_transaction<R>(
            &self,
            run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, DeviceRequestVerificationError>,
        ) -> Result<R, DeviceRequestVerificationError> {
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

    impl DeviceRequestVerificationTransaction for TestTx<'_> {
        fn lock_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
            Ok((self.state.device.id == device_id).then(|| self.state.device.clone()))
        }

        fn lock_device_key(
            &mut self,
            key_id: &str,
        ) -> Result<Option<DeviceProofKeyRecord>, StoreError> {
            Ok((self.state.key.key_id == key_id).then(|| self.state.key.clone()))
        }

        fn lock_active_binding(
            &mut self,
            account_id: &str,
            device_id: &str,
        ) -> Result<Option<AccountDeviceBinding>, StoreError> {
            Ok((self.state.binding.account_id == account_id
                && self.state.binding.device_id == device_id)
                .then(|| self.state.binding.clone()))
        }

        fn lock_challenge(
            &mut self,
            digest: &[u8; 32],
        ) -> Result<Option<DeviceProofChallengeRecord>, StoreError> {
            Ok((self.state.challenge.challenge_digest == *digest)
                .then(|| self.state.challenge.clone()))
        }

        fn consume_challenge_if_active(
            &mut self,
            digest: &[u8; 32],
            observed_at: SystemTime,
        ) -> Result<bool, StoreError> {
            if self.state.challenge.challenge_digest != *digest
                || self.state.challenge.consumed_at.is_some()
                || self.state.challenge.expires_at <= observed_at
            {
                return Ok(false);
            }
            self.state.challenge.consumed_at = Some(observed_at);
            Ok(true)
        }
    }

    struct TestJwkParser;

    impl DevicePublicJwkParser for TestJwkParser {
        fn parse_ed25519_public_key(
            &self,
            canonical_public_jwk: &str,
        ) -> Result<[u8; 32], SecurityContractError> {
            (canonical_public_jwk == "test-jwk")
                .then_some([1_u8; 32])
                .ok_or(SecurityContractError::InvalidKeyId)
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

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW_SECS)
    }

    fn encoded(byte: u8, len: usize) -> String {
        Base64UrlUnpadded::encode_string(&vec![byte; len])
    }

    fn command() -> VerifyDeviceRequestCommand {
        let proof = DeviceProofPresentation {
            device_id: "device-1".to_string(),
            key_id: encoded(1, 32),
            challenge: encoded(2, 32),
            signature: encoded(3, 64),
            signed_at: now(),
        };
        VerifyDeviceRequestCommand {
            account_id: "account-1".to_string(),
            expected_purpose: DeviceProofPurpose::new("llm_invoke").unwrap(),
            binding: DeviceRequestBinding::new(
                DeviceProofProfile::new("SUT-DEVICE-PROOF-V1").unwrap(),
                "sut-api",
                CanonicalHttpMethod::Post,
                "/api/llm/invoke",
                [0_u8; 32],
            )
            .unwrap(),
            proof,
        }
    }

    fn service(
        accepts: bool,
    ) -> CoreDeviceRequestVerificationService<TestRunner, TestJwkParser, TestVerifier, TestClock>
    {
        let command = command();
        let key_id = command.proof.key_id.clone();
        let challenge_digest = digest_device_challenge(&command.proof.challenge).unwrap();
        CoreDeviceRequestVerificationService::new(
            TestRunner {
                state: Mutex::new(TestState {
                    device: DeviceRecord {
                        id: "device-1".to_string(),
                        client_id: "desktop-app".to_string(),
                        device_name: "Laptop".to_string(),
                        proof_key_id: Some(key_id.clone()),
                        status: DeviceStatus::Active,
                        registered_at: now(),
                        last_seen_at: Some(now()),
                    },
                    key: DeviceProofKeyRecord {
                        key_id,
                        device_id: "device-1".to_string(),
                        algorithm: DeviceProofAlgorithm::Ed25519,
                        public_jwk: "test-jwk".to_string(),
                        version: 1,
                        status: DeviceProofKeyStatus::Active,
                        registered_at: now(),
                        retired_at: None,
                    },
                    binding: AccountDeviceBinding {
                        id: "binding-1".to_string(),
                        account_id: "account-1".to_string(),
                        device_id: "device-1".to_string(),
                        status: AccountDeviceBindingStatus::Active,
                        bound_at: now(),
                        unbound_at: None,
                        last_authenticated_at: Some(now()),
                    },
                    challenge: DeviceProofChallengeRecord {
                        id: "challenge-1".to_string(),
                        device_id: "device-1".to_string(),
                        purpose: DeviceProofPurpose::new("llm_invoke").unwrap(),
                        challenge_digest,
                        issued_at: now(),
                        expires_at: now() + Duration::from_secs(60),
                        consumed_at: None,
                    },
                }),
            },
            TestJwkParser,
            TestVerifier { accepts },
            TestClock,
            30,
        )
    }

    #[test]
    fn verifies_and_consumes_a_protected_resource_proof_atomically() {
        let service = service(true);

        let verified = service.verify_device_request(command()).unwrap();

        assert_eq!(verified.account_id, "account-1");
        assert_eq!(verified.device_id, "device-1");
        assert_eq!(verified.key_version, 1);
        assert_eq!(verified.challenge_id, "challenge-1");
        assert!(service
            .store_runner
            .state
            .lock()
            .unwrap()
            .challenge
            .consumed_at
            .is_some());
        assert_eq!(
            service.verify_device_request(command()),
            Err(DeviceRequestVerificationError::ReplayedProof)
        );
    }

    #[test]
    fn invalid_signature_does_not_consume_the_challenge() {
        let service = service(false);

        assert_eq!(
            service.verify_device_request(command()),
            Err(DeviceRequestVerificationError::InvalidProof)
        );
        assert!(service
            .store_runner
            .state
            .lock()
            .unwrap()
            .challenge
            .consumed_at
            .is_none());
    }

    #[test]
    fn concurrent_verification_allows_one_challenge_use() {
        let service = std::sync::Arc::new(service(true));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let service = service.clone();
                std::thread::spawn(move || service.verify_device_request(command()))
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(outcome, Err(DeviceRequestVerificationError::ReplayedProof))
                })
                .count(),
            1
        );
    }
}

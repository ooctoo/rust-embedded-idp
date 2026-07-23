use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProof {
    pub key_id: String,
    pub challenge: String,
    pub signature: String,
    pub signed_at: SystemTime,
}

impl DeviceProof {
    pub fn validate(&self) -> Result<(), DeviceProofError> {
        if self.key_id.trim().is_empty() {
            return Err(DeviceProofError::MissingKeyId);
        }

        if self.challenge.trim().is_empty() {
            return Err(DeviceProofError::MissingChallenge);
        }

        if self.signature.trim().is_empty() {
            return Err(DeviceProofError::MissingSignature);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceProofError {
    MissingKeyId,
    MissingChallenge,
    MissingSignature,
    ProofExpired,
    VerifierRejected,
}

pub trait DeviceProofVerifier {
    fn verify(
        &self,
        proof: &DeviceProof,
        observed_at: SystemTime,
        allowed_skew_secs: u64,
    ) -> Result<(), DeviceProofError>;
}

pub fn validate_proof_freshness(
    signed_at: SystemTime,
    observed_at: SystemTime,
    allowed_skew_secs: u64,
) -> Result<(), DeviceProofError> {
    let diff = match observed_at.duration_since(signed_at) {
        Ok(duration) => duration,
        Err(_) => signed_at
            .duration_since(observed_at)
            .unwrap_or(Duration::from_secs(u64::MAX)),
    };

    if diff > Duration::from_secs(allowed_skew_secs) {
        return Err(DeviceProofError::ProofExpired);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{validate_proof_freshness, DeviceProof, DeviceProofError};

    #[test]
    fn proof_validation_accepts_complete_payload() {
        let proof = DeviceProof {
            key_id: "key-1".to_string(),
            challenge: "nonce-1".to_string(),
            signature: "sig".to_string(),
            signed_at: SystemTime::UNIX_EPOCH,
        };

        assert_eq!(proof.validate(), Ok(()));
    }

    #[test]
    fn proof_validation_rejects_missing_signature() {
        let proof = DeviceProof {
            key_id: "key-1".to_string(),
            challenge: "nonce-1".to_string(),
            signature: String::new(),
            signed_at: SystemTime::UNIX_EPOCH,
        };

        assert_eq!(proof.validate(), Err(DeviceProofError::MissingSignature));
    }

    #[test]
    fn freshness_rejects_large_clock_skew() {
        let signed_at = SystemTime::UNIX_EPOCH;
        let observed_at = signed_at + Duration::from_secs(45);

        assert_eq!(
            validate_proof_freshness(signed_at, observed_at, 30),
            Err(DeviceProofError::ProofExpired)
        );
    }
}

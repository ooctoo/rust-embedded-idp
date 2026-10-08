use super::super::{query::validate_id, validate_tenant_id};
use crate::SecretString;

pub const MAX_SCAN_RESULT_BYTES: usize = 64 * 1024;

/// Each payload has a distinct authentication domain and exact identity binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResultPayload {
    DevicePresentation {
        device_id: String,
        origin_operation_id: String,
    },
    PhonePresentation {
        source_session_id: String,
        origin_operation_id: String,
    },
    SessionBundle {
        device_id: String,
        session_id: String,
        issuance_operation_id: String,
    },
}

/// Trusted persistence metadata. Reconstruct from the locked grant, not JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResultContext {
    pub tenant_id: String,
    pub host_scope: String,
    pub entry_id: String,
    pub grant_id: String,
    pub expires_at_unix_secs: u64,
    pub payload: ScanResultPayload,
}

impl ScanResultContext {
    /// Stable, length-prefixed AAD shared by all encryption adapters.
    /// Expiry is authenticated metadata; the service must ALSO check its clock.
    pub fn authenticated_bytes(&self) -> Result<Vec<u8>, ScanResultCipherError> {
        validate_tenant_id(&self.tenant_id).map_err(|_| ScanResultCipherError::InvalidContext)?;
        for value in [&self.host_scope, &self.entry_id] {
            validate_id(value, 128, "scan_result_context")
                .map_err(|_| ScanResultCipherError::InvalidContext)?;
        }
        canonical_uuid(&self.grant_id)?;
        if self.expires_at_unix_secs == 0 {
            return Err(ScanResultCipherError::InvalidContext);
        }
        let (kind, identities): (&str, Vec<&str>) = match &self.payload {
            ScanResultPayload::DevicePresentation {
                device_id,
                origin_operation_id,
            } => ("device_presentation", vec![device_id, origin_operation_id]),
            ScanResultPayload::PhonePresentation {
                source_session_id,
                origin_operation_id,
            } => (
                "phone_presentation",
                vec![source_session_id, origin_operation_id],
            ),
            ScanResultPayload::SessionBundle {
                device_id,
                session_id,
                issuance_operation_id,
            } => (
                "session_bundle",
                vec![device_id, session_id, issuance_operation_id],
            ),
        };
        for id in &identities {
            canonical_uuid(id)?;
        }
        let mut bytes = b"EMBEDDED-IDP-SCAN-RESULT-V1\n".to_vec();
        for part in [
            kind,
            self.tenant_id.as_str(),
            self.host_scope.as_str(),
            self.entry_id.as_str(),
            self.grant_id.as_str(),
        ] {
            append_part(&mut bytes, part);
        }
        bytes.extend_from_slice(&self.expires_at_unix_secs.to_be_bytes());
        for id in identities {
            append_part(&mut bytes, id);
        }
        Ok(bytes)
    }
}

fn canonical_uuid(value: &str) -> Result<(), ScanResultCipherError> {
    if uuid::Uuid::parse_str(value)
        .is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == value)
    {
        Ok(())
    } else {
        Err(ScanResultCipherError::InvalidContext)
    }
}

pub(super) fn append_part(bytes: &mut Vec<u8>, part: &str) {
    bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
    bytes.extend_from_slice(part.as_bytes());
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedScanResult {
    pub key_id: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for EncryptedScanResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedScanResult")
            .field("key_id", &self.key_id)
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResultCipherError {
    InvalidContext,
    InvalidKeyConfiguration,
    ResultTooLarge,
    RandomFailure,
    EncryptionFailed,
    DecryptionFailed,
}

/// Local cryptographic adapter. Never fetch remote keys while an IDP lock is held.
/// Plaintext is a bounded UTF-8 serialization in SecretString, never a log DTO.
pub trait ScanResultCipher: Send + Sync {
    fn seal(
        &self,
        context: &ScanResultContext,
        plaintext: &SecretString,
    ) -> Result<EncryptedScanResult, ScanResultCipherError>;
    fn open(
        &self,
        context: &ScanResultContext,
        encrypted: &EncryptedScanResult,
    ) -> Result<SecretString, ScanResultCipherError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ScanResultContext {
        ScanResultContext {
            tenant_id: "t1".into(),
            host_scope: "host-a".into(),
            entry_id: "terminal-login".into(),
            grant_id: "22222222-2222-4222-8222-222222222222".into(),
            expires_at_unix_secs: 1700000120,
            payload: ScanResultPayload::SessionBundle {
                device_id: "88888888-8888-4888-8888-888888888888".into(),
                session_id: "77777777-7777-4777-8777-777777777777".into(),
                issuance_operation_id: "66666666-6666-4666-8666-666666666666".into(),
            },
        }
    }

    #[test]
    fn scan_result_context_binds_metadata_and_rejects_noncanonical_ids() {
        let original = context();
        let bytes = original.authenticated_bytes().unwrap();
        let mut changed = original.clone();
        changed.host_scope = "host-b".into();
        assert_ne!(bytes, changed.authenticated_bytes().unwrap());
        changed = original.clone();
        changed.expires_at_unix_secs += 1;
        assert_ne!(bytes, changed.authenticated_bytes().unwrap());
        for id in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "22222222222242228222222222222222",
        ] {
            changed = original.clone();
            changed.grant_id = id.into();
            assert_eq!(
                changed.authenticated_bytes(),
                Err(ScanResultCipherError::InvalidContext)
            );
        }
        changed = original;
        changed.expires_at_unix_secs = 0;
        assert_eq!(
            changed.authenticated_bytes(),
            Err(ScanResultCipherError::InvalidContext)
        );
    }
}

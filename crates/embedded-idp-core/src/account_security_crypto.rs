//! Cryptographic port for self-service security receipts and password recovery.
//! Persistence, expiry, guessing budgets and one-time consumption belong to the
//! caller's domain transaction, not to this port.
use std::fmt;

use uuid::Uuid;

use crate::SecretString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityCryptoContext {
    pub reference_id: Uuid,
    pub related_id: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityDigestPurpose {
    RecoveryHandle,
    ReceiptSecret,
    Command,
    RecoveryCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityEnvelopePurpose {
    RecoveryEmail,
    RecoveryStartReceipt,
}

/// Persist the key identifier together with the digest. It is not a secret,
/// and is never a license to try every available key during verification.
#[derive(Clone)]
pub struct SecurityDigest {
    pub key_id: String,
    pub bytes: [u8; 32],
}
impl fmt::Debug for SecurityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityDigest")
            .field("key_id", &self.key_id)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct SecurityEnvelope {
    pub key_id: String,
    pub ciphertext: Vec<u8>,
}
impl fmt::Debug for SecurityEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityEnvelope")
            .field("key_id", &self.key_id)
            .field("ciphertext_length", &self.ciphertext.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityCryptoError {
    InvalidInput,
    /// A configuration/rotation failure, not an incorrect verification code.
    UnknownKey,
    InvalidCiphertext,
    Unavailable,
}
impl fmt::Display for SecurityCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid security crypto input",
            Self::UnknownKey => "security crypto key unavailable",
            Self::InvalidCiphertext => "invalid security ciphertext",
            Self::Unavailable => "security crypto unavailable",
        })
    }
}
impl std::error::Error for SecurityCryptoError {}

/// Authority is trusted host configuration. Context IDs must be non-nil.
/// Digests and UTF-8 envelope plaintexts are limited to 16,384 bytes.
/// Implementations must use cryptographic randomness, authenticated encryption,
/// domain-separated keyed digests and constant-time digest verification.
/// Writes use the current key; reads select only the stored key ID.
/// A false verification result means a mismatch; UnknownKey must not be counted
/// as a wrong recovery code. This trait provides no runtime key generation.
pub trait AccountSecurityCrypto: Send + Sync {
    fn authority(&self) -> &str;
    /// 32 random bytes encoded as unpadded base64url (43 characters).
    fn random_token(&self) -> Result<SecretString, SecurityCryptoError>;
    /// Six unbiased decimal digits, including leading zeroes.
    fn random_code(&self) -> Result<SecretString, SecurityCryptoError>;
    /// Stable budget identity only: trim ASCII spaces then ASCII lowercase.
    /// This does not redefine the application's account email matching rules.
    fn subject_digest(&self, email: &str) -> Result<[u8; 32], SecurityCryptoError>;
    fn digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
    ) -> Result<SecurityDigest, SecurityCryptoError>;
    fn verify_digest(
        &self,
        purpose: SecurityDigestPurpose,
        context: &SecurityCryptoContext,
        payload: &[u8],
        stored: &SecurityDigest,
    ) -> Result<bool, SecurityCryptoError>;
    fn seal(
        &self,
        purpose: SecurityEnvelopePurpose,
        context: &SecurityCryptoContext,
        plaintext: &SecretString,
    ) -> Result<SecurityEnvelope, SecurityCryptoError>;
    fn open(
        &self,
        purpose: SecurityEnvelopePurpose,
        context: &SecurityCryptoContext,
        envelope: &SecurityEnvelope,
    ) -> Result<SecretString, SecurityCryptoError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_secrets_have_redacted_debug_output() {
        let digest = SecurityDigest {
            key_id: "current".into(),
            bytes: [81; 32],
        };
        let envelope = SecurityEnvelope {
            key_id: "current".into(),
            ciphertext: b"synthetic-secret-payload".to_vec(),
        };
        let text = format!("{digest:?} {envelope:?}");
        assert!(text.contains("current"));
        assert!(!text.contains("81"));
        assert!(!text.contains("synthetic-secret-payload"));
        assert!(!text.contains("115, 121"));
    }
}

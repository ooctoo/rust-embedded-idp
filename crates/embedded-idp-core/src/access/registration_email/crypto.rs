use crate::SecretString;

use super::{
    CanonicalRegistrationEmail, RegistrationEmailError, RegistrationEmailOperationKind,
    RegistrationEmailScope,
};

/// Provider-neutral cryptographic boundary for registration state.
///
/// Implementations own keys, random generation, keyed digests, and authenticated
/// encryption. The core never receives provider credentials or stores plaintext
/// passwords and codes.
pub trait RegistrationEmailCrypto: Send + Sync {
    fn subject(
        &self,
        scope: &RegistrationEmailScope,
        email: &CanonicalRegistrationEmail,
    ) -> [u8; 32];

    fn random_seed(&self) -> Result<[u8; 32], RegistrationEmailError>;

    fn context_token(&self, scope: &RegistrationEmailScope, seed: &[u8; 32]) -> SecretString;

    fn context_digest(&self, token: &str) -> [u8; 32];

    fn request_digest(
        &self,
        scope: &RegistrationEmailScope,
        kind: RegistrationEmailOperationKind,
        operation: &super::Uuid,
        payload: &[u8],
    ) -> [u8; 32];

    fn code_digest(
        &self,
        scope: &RegistrationEmailScope,
        context: &super::Uuid,
        code: &str,
    ) -> [u8; 32];

    fn digests_equal(&self, left: &[u8], right: &[u8]) -> bool;

    fn seal(
        &self,
        purpose: &str,
        scope: &RegistrationEmailScope,
        context: &super::Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RegistrationEmailError>;

    fn open(
        &self,
        purpose: &str,
        scope: &RegistrationEmailScope,
        context: &super::Uuid,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RegistrationEmailError>;

    fn random_code(&self) -> Result<SecretString, RegistrationEmailError>;
}

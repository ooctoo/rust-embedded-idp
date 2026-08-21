use embedded_idp_core::{DeviceSignatureVerifier, SecurityContractError};
use ring::signature::{UnparsedPublicKey, ED25519};

#[derive(Debug, Clone, Copy, Default)]
pub struct RingEd25519Verifier;

impl DeviceSignatureVerifier for RingEd25519Verifier {
    fn verify_ed25519(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), SecurityContractError> {
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .map_err(|_| SecurityContractError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use embedded_idp_core::{DeviceSignatureVerifier, SecurityContractError};
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    use super::RingEd25519Verifier;

    #[test]
    fn verifies_ed25519_and_rejects_changed_message() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
        let signature: [u8; 64] = key_pair.sign(b"bound-request").as_ref().try_into().unwrap();

        assert_eq!(
            RingEd25519Verifier.verify_ed25519(&public_key, b"bound-request", &signature),
            Ok(())
        );
        assert_eq!(
            RingEd25519Verifier.verify_ed25519(&public_key, b"changed", &signature),
            Err(SecurityContractError::InvalidSignature)
        );
    }
}

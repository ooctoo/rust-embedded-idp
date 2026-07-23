use argon2::{
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use rand_core::OsRng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSecretError {
    VerifierRejected(String),
    HasherRejected(String),
}

pub trait ClientSecretVerifier {
    fn verify_client_secret(
        &self,
        provided_secret: &str,
        stored_secret_hash: &str,
    ) -> Result<bool, ClientSecretError>;
}

pub trait ClientSecretHasher {
    fn hash_client_secret(&self, raw_secret: &str) -> Result<String, ClientSecretError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PhcClientSecretCodec;

impl ClientSecretHasher for PhcClientSecretCodec {
    fn hash_client_secret(&self, raw_secret: &str) -> Result<String, ClientSecretError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(raw_secret.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| ClientSecretError::HasherRejected(error.to_string()))
    }
}

impl ClientSecretVerifier for PhcClientSecretCodec {
    fn verify_client_secret(
        &self,
        provided_secret: &str,
        stored_secret_hash: &str,
    ) -> Result<bool, ClientSecretError> {
        let parsed_hash = PasswordHash::new(stored_secret_hash)
            .map_err(|error| ClientSecretError::VerifierRejected(error.to_string()))?;

        match Argon2::default().verify_password(provided_secret.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(PasswordHashError::Password) => Ok(false),
            Err(error) => Err(ClientSecretError::VerifierRejected(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientSecretHasher, ClientSecretVerifier, PhcClientSecretCodec};

    #[test]
    fn phc_client_secret_codec_round_trips() {
        let codec = PhcClientSecretCodec;
        let secret_hash = codec
            .hash_client_secret("top-secret")
            .expect("hash client secret");

        assert!(secret_hash.starts_with("$argon2id$"));
        assert_eq!(
            codec.verify_client_secret("top-secret", &secret_hash),
            Ok(true)
        );
    }

    #[test]
    fn phc_client_secret_codec_rejects_wrong_secret() {
        let codec = PhcClientSecretCodec;
        let secret_hash = codec
            .hash_client_secret("top-secret")
            .expect("hash client secret");

        assert_eq!(
            codec.verify_client_secret("wrong-secret", &secret_hash),
            Ok(false)
        );
    }
}

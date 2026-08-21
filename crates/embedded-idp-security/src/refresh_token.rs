use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    DeviceChallengeGenerator, RefreshTokenDigester, RefreshTokenGenerator, SecretString,
    SecurityContractError, TokenError,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Default)]
pub struct SecureRefreshTokenGenerator;

impl RefreshTokenGenerator for SecureRefreshTokenGenerator {
    fn generate_refresh_token(&self) -> Result<SecretString, TokenError> {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| TokenError::RefreshTokenGenerationFailed)?;
        Ok(SecretString::new(Base64UrlUnpadded::encode_string(&bytes)))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SecureDeviceChallengeGenerator;

impl DeviceChallengeGenerator for SecureDeviceChallengeGenerator {
    fn generate_device_challenge(&self) -> Result<SecretString, SecurityContractError> {
        let mut bytes = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| SecurityContractError::RandomGenerationFailed)?;
        Ok(SecretString::new(Base64UrlUnpadded::encode_string(&bytes)))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256RefreshTokenDigester;

impl RefreshTokenDigester for Sha256RefreshTokenDigester {
    fn digest_refresh_token(&self, raw_token: &str) -> Result<[u8; 32], TokenError> {
        if raw_token.len() != 43 || !raw_token.is_ascii() {
            return Err(TokenError::InvalidRefreshTokenEncoding);
        }
        let decoded = Base64UrlUnpadded::decode_vec(raw_token)
            .map_err(|_| TokenError::InvalidRefreshTokenEncoding)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| TokenError::InvalidRefreshTokenEncoding)?;
        if Base64UrlUnpadded::encode_string(&bytes) != raw_token {
            return Err(TokenError::InvalidRefreshTokenEncoding);
        }
        Ok(Sha256::digest(raw_token.as_bytes()).into())
    }
}

#[cfg(test)]
mod tests {
    use embedded_idp_core::{
        DeviceChallengeGenerator, RefreshTokenDigester, RefreshTokenGenerator, TokenError,
    };

    use super::{
        SecureDeviceChallengeGenerator, SecureRefreshTokenGenerator, Sha256RefreshTokenDigester,
    };

    #[test]
    fn generated_tokens_have_canonical_256_bit_encoding() {
        let first = SecureRefreshTokenGenerator
            .generate_refresh_token()
            .unwrap();
        let second = SecureRefreshTokenGenerator
            .generate_refresh_token()
            .unwrap();

        assert_eq!(first.expose_secret().len(), 43);
        assert_ne!(first, second);
        assert_ne!(format!("{first:?}"), first.expose_secret());
    }

    #[test]
    fn digest_is_deterministic_and_rejects_padding() {
        let token = SecureRefreshTokenGenerator
            .generate_refresh_token()
            .unwrap();
        let digester = Sha256RefreshTokenDigester;

        assert_eq!(
            digester
                .digest_refresh_token(token.expose_secret())
                .unwrap(),
            digester
                .digest_refresh_token(token.expose_secret())
                .unwrap()
        );
        assert_eq!(
            digester.digest_refresh_token(&format!("{}=", token.expose_secret())),
            Err(TokenError::InvalidRefreshTokenEncoding)
        );
    }

    #[test]
    fn generated_device_challenges_are_distinct_canonical_256_bit_values() {
        let first = SecureDeviceChallengeGenerator
            .generate_device_challenge()
            .unwrap();
        let second = SecureDeviceChallengeGenerator
            .generate_device_challenge()
            .unwrap();

        assert_eq!(first.expose_secret().len(), 43);
        assert_ne!(first, second);
        assert_ne!(format!("{first:?}"), first.expose_secret());
    }
}

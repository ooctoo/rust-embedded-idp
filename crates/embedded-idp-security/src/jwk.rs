use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    DevicePublicJwkParser, DevicePublicJwkValidator, SecurityContractError,
    ValidatedDevicePublicJwk,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEd25519Jwk {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub canonical_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwkValidationError {
    Malformed,
    WrongKeyType,
    WrongCurve,
    InvalidPublicKey,
    InvalidKeyId,
    ThumbprintMismatch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicOkpJwk {
    kty: String,
    crv: String,
    x: String,
    kid: String,
}

pub fn validate_ed25519_public_jwk(json: &str) -> Result<ValidatedEd25519Jwk, JwkValidationError> {
    let jwk: PublicOkpJwk =
        serde_json::from_str(json).map_err(|_| JwkValidationError::Malformed)?;
    if jwk.kty != "OKP" {
        return Err(JwkValidationError::WrongKeyType);
    }
    if jwk.crv != "Ed25519" {
        return Err(JwkValidationError::WrongCurve);
    }
    let public_key = decode_32(&jwk.x).map_err(|_| JwkValidationError::InvalidPublicKey)?;
    decode_32(&jwk.kid).map_err(|_| JwkValidationError::InvalidKeyId)?;

    let thumbprint_input = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        jwk.x
    );
    let thumbprint = Base64UrlUnpadded::encode_string(&Sha256::digest(thumbprint_input.as_bytes()));
    if thumbprint != jwk.kid {
        return Err(JwkValidationError::ThumbprintMismatch);
    }

    Ok(ValidatedEd25519Jwk {
        key_id: jwk.kid.clone(),
        public_key,
        canonical_json: format!(
            "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\",\"kid\":\"{}\"}}",
            jwk.x, jwk.kid
        ),
    })
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519PublicJwkParser;

impl DevicePublicJwkParser for Ed25519PublicJwkParser {
    fn parse_ed25519_public_key(
        &self,
        canonical_public_jwk: &str,
    ) -> Result<[u8; 32], SecurityContractError> {
        validate_ed25519_public_jwk(canonical_public_jwk)
            .map(|jwk| jwk.public_key)
            .map_err(|_| SecurityContractError::InvalidKeyId)
    }
}

impl DevicePublicJwkValidator for Ed25519PublicJwkParser {
    fn validate_ed25519_public_jwk(
        &self,
        public_jwk: &str,
    ) -> Result<ValidatedDevicePublicJwk, SecurityContractError> {
        let jwk = validate_ed25519_public_jwk(public_jwk)
            .map_err(|_| SecurityContractError::InvalidKeyId)?;
        Ok(ValidatedDevicePublicJwk {
            key_id: jwk.key_id,
            public_key: jwk.public_key,
            canonical_public_jwk: jwk.canonical_json,
        })
    }
}

fn decode_32(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 43 || !value.is_ascii() {
        return Err(());
    }
    let decoded = Base64UrlUnpadded::decode_vec(value).map_err(|_| ())?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| ())?;
    if Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use sha2::{Digest, Sha256};

    use super::{validate_ed25519_public_jwk, JwkValidationError};

    fn jwk(extra: &str) -> String {
        let x = Base64UrlUnpadded::encode_string(&[7_u8; 32]);
        let thumbprint_input = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
        let kid = Base64UrlUnpadded::encode_string(&Sha256::digest(thumbprint_input.as_bytes()));
        format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{x}\",\"kid\":\"{kid}\"{extra}}}")
    }

    #[test]
    fn validates_public_jwk_and_derives_thumbprint() {
        let validated = validate_ed25519_public_jwk(&jwk("")).unwrap();

        assert_eq!(validated.key_id.len(), 43);
        assert_eq!(validated.public_key, [7_u8; 32]);
        assert!(!validated.canonical_json.contains("\"d\""));
    }

    #[test]
    fn rejects_private_and_duplicate_members() {
        assert_eq!(
            validate_ed25519_public_jwk(&jwk(",\"d\":\"secret\"")),
            Err(JwkValidationError::Malformed)
        );
        let duplicate = jwk(",\"x\":\"duplicate\"");
        assert_eq!(
            validate_ed25519_public_jwk(&duplicate),
            Err(JwkValidationError::Malformed)
        );
    }
}

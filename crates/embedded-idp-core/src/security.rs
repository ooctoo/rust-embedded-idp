use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::{DeviceId, SecretString, TokenError};

pub const DEVICE_REGISTRATION_PURPOSE: &str = "device_registration";
pub const DEVICE_KEY_ROTATION_PURPOSE: &str = "device_key_rotation";
pub const REFRESH_PURPOSE: &str = "refresh";
pub const CLIENT_SYNC_TRANSPORT_PURPOSE: &str = "client_sync_transport";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceProofPurpose(String);

impl DeviceProofPurpose {
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityContractError> {
        let value = value.into();
        let mut chars = value.chars();
        let valid = value.len() <= 64
            && chars.next().is_some_and(|ch| ch.is_ascii_lowercase())
            && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
        if !valid {
            return Err(SecurityContractError::InvalidPurpose);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceProofProfile(String);

impl DeviceProofProfile {
    pub fn new(value: impl Into<String>) -> Result<Self, SecurityContractError> {
        let value = value.into();
        if !value.ends_with("-V2")
            || value.len() > 64
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(SecurityContractError::InvalidProfile);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalHttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl CanonicalHttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRequestBinding {
    /// Supplied by trusted tenant/session context, never inferred from proof headers.
    pub tenant_id: String,
    pub profile: DeviceProofProfile,
    pub audience: String,
    pub method: CanonicalHttpMethod,
    pub external_path: String,
    pub body_sha256: [u8; 32],
}

impl DeviceRequestBinding {
    pub fn new(
        tenant_id: impl Into<String>,
        profile: DeviceProofProfile,
        audience: impl Into<String>,
        method: CanonicalHttpMethod,
        external_path: impl Into<String>,
        body_sha256: [u8; 32],
    ) -> Result<Self, SecurityContractError> {
        let tenant_id = tenant_id.into();
        validate_proof_tenant(&tenant_id)?;
        let audience = audience.into();
        if !valid_line_value(&audience, 256) {
            return Err(SecurityContractError::InvalidAudience);
        }
        let external_path = external_path.into();
        validate_external_path(&external_path)?;
        Ok(Self {
            tenant_id,
            profile,
            audience,
            method,
            external_path,
            body_sha256,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceProofPresentation {
    pub device_id: DeviceId,
    pub key_id: String,
    pub challenge: String,
    pub signature: String,
    pub signed_at: SystemTime,
}

impl std::fmt::Debug for DeviceProofPresentation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceProofPresentation")
            .field("device_id", &self.device_id)
            .field("key_id", &self.key_id)
            .field("challenge", &"<redacted>")
            .field("signature", &"<redacted>")
            .field("signed_at", &self.signed_at)
            .finish()
    }
}

impl DeviceProofPresentation {
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        if !valid_line_value(&self.device_id, 128) {
            return Err(SecurityContractError::InvalidDeviceId);
        }
        decode_fixed::<32>(&self.key_id, 43).map_err(|_| SecurityContractError::InvalidKeyId)?;
        decode_fixed::<32>(&self.challenge, 43)
            .map_err(|_| SecurityContractError::InvalidChallenge)?;
        decode_fixed::<64>(&self.signature, 86)
            .map_err(|_| SecurityContractError::InvalidSignature)?;
        self.signed_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SecurityContractError::InvalidSignedAt)?;
        Ok(())
    }

    pub fn signature_bytes(&self) -> Result<[u8; 64], SecurityContractError> {
        decode_fixed::<64>(&self.signature, 86).map_err(|_| SecurityContractError::InvalidSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceRequest {
    pub tenant_id: String,
    pub account_id: String,
    pub device_id: DeviceId,
    pub key_id: String,
    pub key_version: u64,
    pub purpose: DeviceProofPurpose,
    pub challenge_id: String,
    pub verified_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeviceTransportRequest {
    pub tenant_id: String,
    pub client_id: String,
    pub device_id: DeviceId,
    pub device_version: u64,
    pub key_id: String,
    pub key_version: u64,
    pub challenge_id: String,
    pub verified_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityContractError {
    InvalidPurpose,
    InvalidProfile,
    InvalidTenantId,
    InvalidAudience,
    InvalidExternalPath,
    InvalidDeviceId,
    InvalidKeyId,
    InvalidKeyVersion,
    InvalidChallenge,
    InvalidSignature,
    InvalidSignedAt,
    RandomGenerationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDevicePublicJwk {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub canonical_public_jwk: String,
}

pub trait DeviceSignatureVerifier {
    fn verify_ed25519(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), SecurityContractError>;
}

pub trait DevicePublicJwkParser {
    fn parse_ed25519_public_key(
        &self,
        canonical_public_jwk: &str,
    ) -> Result<[u8; 32], SecurityContractError>;
}

pub trait DevicePublicJwkValidator {
    fn validate_ed25519_public_jwk(
        &self,
        public_jwk: &str,
    ) -> Result<ValidatedDevicePublicJwk, SecurityContractError>;
}

pub trait DeviceChallengeGenerator {
    fn generate_device_challenge(&self) -> Result<SecretString, SecurityContractError>;
}

pub fn digest_device_challenge(challenge: &str) -> Result<[u8; 32], SecurityContractError> {
    use sha2::{Digest, Sha256};

    let bytes =
        decode_fixed::<32>(challenge, 43).map_err(|_| SecurityContractError::InvalidChallenge)?;
    Ok(Sha256::digest(bytes).into())
}

pub fn decode_device_signature(signature: &str) -> Result<[u8; 64], SecurityContractError> {
    decode_fixed::<64>(signature, 86).map_err(|_| SecurityContractError::InvalidSignature)
}

pub fn build_device_registration_proof_bytes(
    tenant_id: &str,
    device_id: &str,
    key_id: &str,
    challenge: &str,
) -> Result<Vec<u8>, SecurityContractError> {
    validate_proof_tenant(tenant_id)?;
    if !valid_line_value(device_id, 128) {
        return Err(SecurityContractError::InvalidDeviceId);
    }
    decode_fixed::<32>(key_id, 43).map_err(|_| SecurityContractError::InvalidKeyId)?;
    decode_fixed::<32>(challenge, 43).map_err(|_| SecurityContractError::InvalidChallenge)?;
    Ok(format!(
        "EMBEDDED-IDP-DEVICE-REGISTRATION-V2\ntenant-id:{tenant_id}\ndevice-id:{device_id}\nkey-id:{key_id}\nchallenge:{challenge}\n"
    )
    .into_bytes())
}

pub fn build_device_key_rotation_proof_bytes(
    tenant_id: &str,
    device_id: &str,
    old_key_id: &str,
    new_key_id: &str,
    new_key_version: u64,
    challenge: &str,
) -> Result<Vec<u8>, SecurityContractError> {
    validate_proof_tenant(tenant_id)?;
    if !valid_line_value(device_id, 128) {
        return Err(SecurityContractError::InvalidDeviceId);
    }
    if new_key_version == 0 {
        return Err(SecurityContractError::InvalidKeyVersion);
    }
    decode_fixed::<32>(old_key_id, 43).map_err(|_| SecurityContractError::InvalidKeyId)?;
    decode_fixed::<32>(new_key_id, 43).map_err(|_| SecurityContractError::InvalidKeyId)?;
    decode_fixed::<32>(challenge, 43).map_err(|_| SecurityContractError::InvalidChallenge)?;
    Ok(format!(
        "EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2\ntenant-id:{tenant_id}\ndevice-id:{device_id}\nold-key-id:{old_key_id}\nnew-key-id:{new_key_id}\nnew-key-version:{new_key_version}\nchallenge:{challenge}\n"
    )
    .into_bytes())
}

pub trait RefreshTokenGenerator {
    fn generate_refresh_token(&self) -> Result<SecretString, TokenError>;
}

pub trait RefreshTokenDigester {
    fn digest_refresh_token(&self, raw_token: &str) -> Result<[u8; 32], TokenError>;
}

pub fn build_request_proof_bytes(
    binding: &DeviceRequestBinding,
    presentation: &DeviceProofPresentation,
) -> Result<Vec<u8>, SecurityContractError> {
    // Fields are public for host composition; revalidate at the signing boundary.
    validate_proof_tenant(&binding.tenant_id)?;
    if !valid_line_value(&binding.audience, 256) {
        return Err(SecurityContractError::InvalidAudience);
    }
    validate_external_path(&binding.external_path)?;
    presentation.validate()?;
    let signed_at = presentation
        .signed_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SecurityContractError::InvalidSignedAt)?
        .as_secs();
    let body_digest = Base64UrlUnpadded::encode_string(&binding.body_sha256);
    Ok(format!(
        "{}\ntenant-id:{}\naudience:{}\nmethod:{}\npath:{}\nbody-sha256:{}\nchallenge:{}\ndevice-id:{}\nkey-id:{}\nsigned-at:{}\n",
        binding.profile.as_str(),
        binding.tenant_id,
        binding.audience,
        binding.method.as_str(),
        binding.external_path,
        body_digest,
        presentation.challenge,
        presentation.device_id,
        presentation.key_id,
        signed_at,
    )
    .into_bytes())
}

pub fn validate_external_path(path: &str) -> Result<(), SecurityContractError> {
    let invalid = !path.starts_with('/')
        || !path.is_ascii()
        || path
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || path.contains('?')
        || path.contains('#')
        || path.contains('%')
        || path.contains("//")
        || (path.len() > 1 && path.ends_with('/'))
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..");
    if invalid {
        return Err(SecurityContractError::InvalidExternalPath);
    }
    Ok(())
}

fn validate_proof_tenant(value: &str) -> Result<(), SecurityContractError> {
    crate::access::validate_tenant_id(value).map_err(|_| SecurityContractError::InvalidTenantId)
}

fn valid_line_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

fn decode_fixed<const N: usize>(
    encoded: &str,
    encoded_len: usize,
) -> Result<[u8; N], SecurityContractError> {
    if encoded.len() != encoded_len || !encoded.is_ascii() {
        return Err(SecurityContractError::InvalidSignature);
    }
    let decoded = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|_| SecurityContractError::InvalidSignature)?;
    let bytes: [u8; N] = decoded
        .try_into()
        .map_err(|_| SecurityContractError::InvalidSignature)?;
    if Base64UrlUnpadded::encode_string(&bytes) != encoded {
        return Err(SecurityContractError::InvalidSignature);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use base64ct::{Base64UrlUnpadded, Encoding};

    use super::{
        build_device_key_rotation_proof_bytes, build_device_registration_proof_bytes,
        build_request_proof_bytes, validate_external_path, CanonicalHttpMethod,
        DeviceProofPresentation, DeviceProofProfile, DeviceProofPurpose, DeviceRequestBinding,
        SecurityContractError,
    };

    fn presentation() -> DeviceProofPresentation {
        DeviceProofPresentation {
            device_id: "device-1".to_string(),
            key_id: Base64UrlUnpadded::encode_string(&[1_u8; 32]),
            challenge: Base64UrlUnpadded::encode_string(&[2_u8; 32]),
            signature: Base64UrlUnpadded::encode_string(&[3_u8; 64]),
            signed_at: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        }
    }

    #[test]
    fn purpose_enforces_closed_syntax() {
        assert_eq!(
            DeviceProofPurpose::new("llm_invoke").unwrap().as_str(),
            "llm_invoke"
        );
        assert_eq!(
            DeviceProofPurpose::new("LLM invoke"),
            Err(SecurityContractError::InvalidPurpose)
        );
    }

    #[test]
    fn literal_external_path_rejects_ambiguous_forms() {
        assert_eq!(validate_external_path("/api/auth/refresh"), Ok(()));
        for path in ["api/auth", "/a//b", "/a/../b", "/a%2Fb", "/a?x=1", "/a/"] {
            assert_eq!(
                validate_external_path(path),
                Err(SecurityContractError::InvalidExternalPath)
            );
        }
    }

    #[test]
    fn presentation_rejects_padded_or_wrong_length_values() {
        let mut proof = presentation();
        proof.signature.push('=');
        assert_eq!(
            proof.validate(),
            Err(SecurityContractError::InvalidSignature)
        );
    }

    #[test]
    fn request_bytes_match_frozen_field_order() {
        let binding = DeviceRequestBinding::new(
            "0",
            DeviceProofProfile::new("SUT-DEVICE-PROOF-V2").unwrap(),
            "sut-api",
            CanonicalHttpMethod::Post,
            "/api/auth/refresh",
            [0_u8; 32],
        )
        .unwrap();
        let bytes = build_request_proof_bytes(&binding, &presentation()).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert!(
            text.starts_with("SUT-DEVICE-PROOF-V2\ntenant-id:0\naudience:sut-api\nmethod:POST\n")
        );
        assert!(text.contains("\npath:/api/auth/refresh\nbody-sha256:"));
        assert!(text.ends_with("signed-at:1700000000\n"));
    }

    #[test]
    fn registration_and_rotation_bytes_match_frozen_vectors() {
        let old_key = Base64UrlUnpadded::encode_string(&[1_u8; 32]);
        let new_key = Base64UrlUnpadded::encode_string(&[2_u8; 32]);
        let challenge = Base64UrlUnpadded::encode_string(&[3_u8; 32]);

        assert_eq!(
            String::from_utf8(
                build_device_registration_proof_bytes("0", "device-1", &new_key, &challenge).unwrap()
            )
            .unwrap(),
            format!(
                "EMBEDDED-IDP-DEVICE-REGISTRATION-V2\ntenant-id:0\ndevice-id:device-1\nkey-id:{new_key}\nchallenge:{challenge}\n"
            )
        );
        assert_eq!(
            String::from_utf8(
                build_device_key_rotation_proof_bytes(
                    "0",
                    "device-1",
                    &old_key,
                    &new_key,
                    2,
                    &challenge,
                )
                .unwrap()
            )
            .unwrap(),
            format!(
                "EMBEDDED-IDP-DEVICE-KEY-ROTATION-V2\ntenant-id:0\ndevice-id:device-1\nold-key-id:{old_key}\nnew-key-id:{new_key}\nnew-key-version:2\nchallenge:{challenge}\n"
            )
        );
    }

    #[test]
    fn tenant_and_profile_validation_prevents_ambiguous_proof_bytes() {
        for old in [
            "SUT-DEVICE-PROOF-V1",
            "EMBEDDED-IDP-DEVICE-REQUEST-V1",
            "unversioned",
        ] {
            assert_eq!(
                DeviceProofProfile::new(old),
                Err(SecurityContractError::InvalidProfile)
            );
        }
        let proof = presentation();
        let profile = DeviceProofProfile::new("EMBEDDED-IDP-DEVICE-REQUEST-V2").unwrap();
        for tenant in ["", "a/b", "t:1", "t\n1", "租户", &"a".repeat(129)] {
            assert_eq!(
                build_device_registration_proof_bytes(
                    tenant,
                    &proof.device_id,
                    &proof.key_id,
                    &proof.challenge
                ),
                Err(SecurityContractError::InvalidTenantId)
            );
            assert_eq!(
                build_device_key_rotation_proof_bytes(
                    tenant,
                    &proof.device_id,
                    &proof.key_id,
                    &proof.key_id,
                    2,
                    &proof.challenge
                ),
                Err(SecurityContractError::InvalidTenantId)
            );
            assert_eq!(
                DeviceRequestBinding::new(
                    tenant,
                    profile.clone(),
                    "api",
                    CanonicalHttpMethod::Get,
                    "/reports",
                    [0; 32]
                ),
                Err(SecurityContractError::InvalidTenantId)
            );
        }
        let mut binding = DeviceRequestBinding::new(
            "t1",
            profile,
            "api",
            CanonicalHttpMethod::Get,
            "/reports",
            [0; 32],
        )
        .unwrap();
        binding.tenant_id = "t1\naudience:other".into();
        assert_eq!(
            build_request_proof_bytes(&binding, &proof),
            Err(SecurityContractError::InvalidTenantId)
        );
        binding.tenant_id = "t1".into();
        binding.audience = "api\nmethod:POST".into();
        assert_eq!(
            build_request_proof_bytes(&binding, &proof),
            Err(SecurityContractError::InvalidAudience)
        );
        binding.audience = "api".into();
        binding.external_path = "/reports\nchallenge:other".into();
        assert_eq!(
            build_request_proof_bytes(&binding, &proof),
            Err(SecurityContractError::InvalidExternalPath)
        );
    }

    #[test]
    fn proof_debug_redacts_challenge_and_signature() {
        let challenge = Base64UrlUnpadded::encode_string(&[2_u8; 32]);
        let signature = Base64UrlUnpadded::encode_string(&[3_u8; 64]);
        let proof = DeviceProofPresentation {
            device_id: "device-1".to_string(),
            key_id: Base64UrlUnpadded::encode_string(&[1_u8; 32]),
            challenge: challenge.clone(),
            signature: signature.clone(),
            signed_at: UNIX_EPOCH,
        };

        let debug = format!("{proof:?}");
        assert!(!debug.contains(&challenge));
        assert!(!debug.contains(&signature));
    }
}

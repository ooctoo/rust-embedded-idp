use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use super::super::query::validate_id;
use super::result::append_part;
use crate::{
    build_request_proof_bytes, CanonicalHttpMethod, DeviceProofPresentation, DeviceProofPurpose,
    DeviceRequestBinding, SecurityContractError,
};

pub const SCAN_LOGIN_PROOF_PROFILE: &str = "EMBEDDED-IDP-DEVICE-SCAN-V2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanLoginAction {
    Create,
    Claim,
    Status,
    Lookup,
    Cancel,
    Exchange,
    Recover,
    Acknowledge,
    Abort,
}

impl ScanLoginAction {
    pub const fn purpose_str(self) -> &'static str {
        match self {
            Self::Create => "scan_login_create",
            Self::Claim => "scan_login_claim",
            Self::Status => "scan_login_status",
            Self::Lookup => "scan_login_lookup",
            Self::Cancel => "scan_login_cancel",
            Self::Exchange => "scan_login_exchange",
            Self::Recover => "scan_login_recover",
            Self::Acknowledge => "scan_login_ack",
            Self::Abort => "scan_login_abort",
        }
    }

    pub fn purpose(self) -> DeviceProofPurpose {
        DeviceProofPurpose::new(self.purpose_str()).expect("fixed scan purpose is valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanLoginProofError {
    InvalidClientId,
    InvalidEntryId,
    InvalidMethod,
    Security(SecurityContractError),
}

impl From<SecurityContractError> for ScanLoginProofError {
    fn from(error: SecurityContractError) -> Self {
        Self::Security(error)
    }
}

/// Action and target entry are trusted route configuration, not request headers.
pub fn scan_login_proof_context(
    action: ScanLoginAction,
    target_client_id: &str,
    entry_id: &str,
) -> Result<[u8; 32], ScanLoginProofError> {
    validate_id(target_client_id, 128, "scan_client")
        .map_err(|_| ScanLoginProofError::InvalidClientId)?;
    validate_id(entry_id, 128, "scan_entry").map_err(|_| ScanLoginProofError::InvalidEntryId)?;
    let mut bytes = b"EMBEDDED-IDP-SCAN-CONTEXT-V1\n".to_vec();
    for part in [action.purpose_str(), target_client_id, entry_id] {
        append_part(&mut bytes, part);
    }
    Ok(Sha256::digest(bytes).into())
}

/// Extends existing V2 bytes without changing any existing proof protocol.
/// This is a canonical builder, NOT device verification or challenge consumption.
pub fn build_scan_login_proof_bytes(
    binding: &DeviceRequestBinding,
    proof: &DeviceProofPresentation,
    action: ScanLoginAction,
    target_client_id: &str,
    entry_id: &str,
) -> Result<Vec<u8>, ScanLoginProofError> {
    if binding.profile.as_str() != SCAN_LOGIN_PROOF_PROFILE {
        return Err(SecurityContractError::InvalidProfile.into());
    }
    if binding.method != CanonicalHttpMethod::Post {
        return Err(ScanLoginProofError::InvalidMethod);
    }
    if !uuid::Uuid::parse_str(&proof.device_id)
        .is_ok_and(|id| !id.is_nil() && id.hyphenated().to_string() == proof.device_id)
    {
        return Err(SecurityContractError::InvalidDeviceId.into());
    }
    let context = scan_login_proof_context(action, target_client_id, entry_id)?;
    let mut bytes = build_request_proof_bytes(binding, proof)?;
    bytes.extend_from_slice(b"scan-context-sha256:");
    bytes.extend_from_slice(Base64UrlUnpadded::encode_string(&context).as_bytes());
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::DeviceProofProfile;

    #[test]
    fn scan_proof_context_separates_purpose_client_and_entry() {
        let original =
            scan_login_proof_context(ScanLoginAction::Exchange, "target", "entry").unwrap();
        for (action, client, entry) in [
            (ScanLoginAction::Recover, "target", "entry"),
            (ScanLoginAction::Exchange, "other", "entry"),
            (ScanLoginAction::Exchange, "target", "other"),
        ] {
            assert_ne!(
                original,
                scan_login_proof_context(action, client, entry).unwrap()
            );
        }
        assert_ne!(
            scan_login_proof_context(ScanLoginAction::Create, "ab", "c").unwrap(),
            scan_login_proof_context(ScanLoginAction::Create, "a", "bc").unwrap()
        );
        for value in ["", "client\n", "client:other", "租户"] {
            assert!(scan_login_proof_context(ScanLoginAction::Create, value, "entry").is_err());
            assert!(scan_login_proof_context(ScanLoginAction::Create, "client", value).is_err());
        }
    }

    #[test]
    fn scan_proof_requires_its_own_profile_method_and_canonical_device() {
        let mut binding = DeviceRequestBinding::new(
            "t1",
            DeviceProofProfile::new(SCAN_LOGIN_PROOF_PROFILE).unwrap(),
            "example-api",
            CanonicalHttpMethod::Post,
            "/api/auth/device-scan/create",
            [0; 32],
        )
        .unwrap();
        let mut proof = DeviceProofPresentation {
            device_id: "88888888-8888-4888-8888-888888888888".into(),
            key_id: Base64UrlUnpadded::encode_string(&[1; 32]),
            challenge: Base64UrlUnpadded::encode_string(&[2; 32]),
            signature: Base64UrlUnpadded::encode_string(&[3; 64]),
            signed_at: UNIX_EPOCH,
        };
        assert!(build_scan_login_proof_bytes(
            &binding,
            &proof,
            ScanLoginAction::Create,
            "target",
            "entry"
        )
        .is_ok());
        binding.method = CanonicalHttpMethod::Get;
        assert_eq!(
            build_scan_login_proof_bytes(
                &binding,
                &proof,
                ScanLoginAction::Create,
                "target",
                "entry"
            ),
            Err(ScanLoginProofError::InvalidMethod)
        );
        binding.method = CanonicalHttpMethod::Post;
        binding.profile = DeviceProofProfile::new("EMBEDDED-IDP-DEVICE-REQUEST-V2").unwrap();
        assert_eq!(
            build_scan_login_proof_bytes(
                &binding,
                &proof,
                ScanLoginAction::Create,
                "target",
                "entry"
            ),
            Err(ScanLoginProofError::Security(
                SecurityContractError::InvalidProfile
            ))
        );
        binding.profile = DeviceProofProfile::new(SCAN_LOGIN_PROOF_PROFILE).unwrap();
        proof.device_id = "device-1".into();
        assert_eq!(
            build_scan_login_proof_bytes(
                &binding,
                &proof,
                ScanLoginAction::Create,
                "target",
                "entry"
            ),
            Err(ScanLoginProofError::Security(
                SecurityContractError::InvalidDeviceId
            ))
        );
    }
}

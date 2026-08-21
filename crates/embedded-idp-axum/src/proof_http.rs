use std::time::{Duration, UNIX_EPOCH};

use axum::http::{HeaderMap, Method, Uri};
use embedded_idp_core::{
    CanonicalHttpMethod, DeviceProofPresentation, DeviceProofProfile, DeviceRequestBinding,
};

pub const AUTH_DEVICE_BODY_LIMIT_BYTES: usize = 16 * 1024;
pub const DEVICE_ID_HEADER: &str = "x-device-id";
pub const DEVICE_KEY_ID_HEADER: &str = "x-device-key-id";
pub const DEVICE_CHALLENGE_HEADER: &str = "x-device-challenge";
pub const DEVICE_SIGNATURE_HEADER: &str = "x-device-signature";
pub const DEVICE_SIGNED_AT_HEADER: &str = "x-device-signed-at";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofHttpError {
    ProofRequired,
    ProofInvalid,
    MethodMismatch,
    PathMismatch,
    QueryUnsupported,
}

pub fn parse_device_proof_headers(
    headers: &HeaderMap,
) -> Result<DeviceProofPresentation, ProofHttpError> {
    let device_id = one_ascii_header(headers, DEVICE_ID_HEADER)?;
    let key_id = one_ascii_header(headers, DEVICE_KEY_ID_HEADER)?;
    let challenge = one_ascii_header(headers, DEVICE_CHALLENGE_HEADER)?;
    let signature = one_ascii_header(headers, DEVICE_SIGNATURE_HEADER)?;
    let signed_at_text = one_ascii_header(headers, DEVICE_SIGNED_AT_HEADER)?;
    if signed_at_text.is_empty()
        || signed_at_text.starts_with('+')
        || signed_at_text.starts_with('-')
        || (signed_at_text.len() > 1 && signed_at_text.starts_with('0'))
        || !signed_at_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProofHttpError::ProofInvalid);
    }
    let signed_at_secs = signed_at_text
        .parse::<u64>()
        .map_err(|_| ProofHttpError::ProofInvalid)?;
    let signed_at = UNIX_EPOCH
        .checked_add(Duration::from_secs(signed_at_secs))
        .ok_or(ProofHttpError::ProofInvalid)?;
    let presentation = DeviceProofPresentation {
        device_id,
        key_id,
        challenge,
        signature,
        signed_at,
    };
    presentation
        .validate()
        .map_err(|_| ProofHttpError::ProofInvalid)?;
    Ok(presentation)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedRouteConfig {
    profile: DeviceProofProfile,
    audience: String,
    method: CanonicalHttpMethod,
    external_path: String,
}

impl ProtectedRouteConfig {
    pub fn new(
        profile: DeviceProofProfile,
        audience: impl Into<String>,
        method: CanonicalHttpMethod,
        external_path: impl Into<String>,
    ) -> Result<Self, ProofHttpError> {
        let audience = audience.into();
        let external_path = external_path.into();
        DeviceRequestBinding::new(
            profile.clone(),
            audience.clone(),
            method,
            external_path.clone(),
            [0_u8; 32],
        )
        .map_err(|_| ProofHttpError::ProofInvalid)?;
        Ok(Self {
            profile,
            audience,
            method,
            external_path,
        })
    }

    pub fn binding_for_request(
        &self,
        actual_method: &Method,
        original_uri: &Uri,
        body_sha256: [u8; 32],
    ) -> Result<DeviceRequestBinding, ProofHttpError> {
        if canonical_method(actual_method)? != self.method {
            return Err(ProofHttpError::MethodMismatch);
        }
        if original_uri.query().is_some() {
            return Err(ProofHttpError::QueryUnsupported);
        }
        if original_uri.path().as_bytes() != self.external_path.as_bytes() {
            return Err(ProofHttpError::PathMismatch);
        }
        DeviceRequestBinding::new(
            self.profile.clone(),
            self.audience.clone(),
            self.method,
            self.external_path.clone(),
            body_sha256,
        )
        .map_err(|_| ProofHttpError::ProofInvalid)
    }
}

fn one_ascii_header(headers: &HeaderMap, name: &'static str) -> Result<String, ProofHttpError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or(ProofHttpError::ProofRequired)?;
    if values.next().is_some() {
        return Err(ProofHttpError::ProofInvalid);
    }
    first
        .to_str()
        .map(str::to_owned)
        .map_err(|_| ProofHttpError::ProofInvalid)
}

fn canonical_method(method: &Method) -> Result<CanonicalHttpMethod, ProofHttpError> {
    match *method {
        Method::GET => Ok(CanonicalHttpMethod::Get),
        Method::POST => Ok(CanonicalHttpMethod::Post),
        Method::PUT => Ok(CanonicalHttpMethod::Put),
        Method::PATCH => Ok(CanonicalHttpMethod::Patch),
        Method::DELETE => Ok(CanonicalHttpMethod::Delete),
        _ => Err(ProofHttpError::MethodMismatch),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, Method, Uri};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use embedded_idp_core::{CanonicalHttpMethod, DeviceProofProfile};

    use super::{
        parse_device_proof_headers, ProofHttpError, ProtectedRouteConfig, DEVICE_CHALLENGE_HEADER,
        DEVICE_ID_HEADER, DEVICE_KEY_ID_HEADER, DEVICE_SIGNATURE_HEADER, DEVICE_SIGNED_AT_HEADER,
    };

    fn valid_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(DEVICE_ID_HEADER, HeaderValue::from_static("device-1"));
        headers.insert(
            DEVICE_KEY_ID_HEADER,
            HeaderValue::from_str(&Base64UrlUnpadded::encode_string(&[1_u8; 32])).unwrap(),
        );
        headers.insert(
            DEVICE_CHALLENGE_HEADER,
            HeaderValue::from_str(&Base64UrlUnpadded::encode_string(&[2_u8; 32])).unwrap(),
        );
        headers.insert(
            DEVICE_SIGNATURE_HEADER,
            HeaderValue::from_str(&Base64UrlUnpadded::encode_string(&[3_u8; 64])).unwrap(),
        );
        headers.insert(
            DEVICE_SIGNED_AT_HEADER,
            HeaderValue::from_static("1700000000"),
        );
        headers
    }

    #[test]
    fn parses_exact_five_header_contract() {
        let proof = parse_device_proof_headers(&valid_headers()).unwrap();

        assert_eq!(proof.device_id, "device-1");
        assert_eq!(proof.signature.len(), 86);
    }

    #[test]
    fn distinguishes_missing_from_duplicate_or_malformed() {
        let mut missing = valid_headers();
        missing.remove(DEVICE_SIGNATURE_HEADER);
        assert_eq!(
            parse_device_proof_headers(&missing),
            Err(ProofHttpError::ProofRequired)
        );

        let mut duplicate = valid_headers();
        duplicate.append(DEVICE_ID_HEADER, HeaderValue::from_static("device-2"));
        assert_eq!(
            parse_device_proof_headers(&duplicate),
            Err(ProofHttpError::ProofInvalid)
        );

        let mut leading_zero = valid_headers();
        leading_zero.insert(
            DEVICE_SIGNED_AT_HEADER,
            HeaderValue::from_static("01700000000"),
        );
        assert_eq!(
            parse_device_proof_headers(&leading_zero),
            Err(ProofHttpError::ProofInvalid)
        );
    }

    #[test]
    fn route_binding_uses_literal_original_uri() {
        let route = ProtectedRouteConfig::new(
            DeviceProofProfile::new("SUT-DEVICE-PROOF-V1").unwrap(),
            "sut-api",
            CanonicalHttpMethod::Post,
            "/api/auth/refresh",
        )
        .unwrap();

        assert!(route
            .binding_for_request(
                &Method::POST,
                &Uri::from_static("/api/auth/refresh"),
                [0_u8; 32],
            )
            .is_ok());
        assert_eq!(
            route.binding_for_request(
                &Method::POST,
                &Uri::from_static("/auth/refresh"),
                [0_u8; 32],
            ),
            Err(ProofHttpError::PathMismatch)
        );
        assert_eq!(
            route.binding_for_request(
                &Method::POST,
                &Uri::from_static("/api/auth/refresh?retry=1"),
                [0_u8; 32],
            ),
            Err(ProofHttpError::QueryUnsupported)
        );
    }
}

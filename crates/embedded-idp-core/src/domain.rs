use std::time::SystemTime;

pub type AccountId = String;
pub type SessionId = String;
pub type DeviceId = String;
pub type AccountDeviceBindingId = String;
pub type DeviceNonceId = String;
pub type ClientId = String;
pub type AuthorizationCodeId = String;
pub type RefreshTokenId = String;
pub type EmailVerificationId = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub status: AccountStatus,
    pub created_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountStatus {
    PendingVerification,
    Active,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailVerificationCode {
    pub id: EmailVerificationId,
    pub account_id: AccountId,
    pub email: String,
    pub code: String,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub id: DeviceId,
    pub client_id: ClientId,
    pub device_name: String,
    pub proof_key_id: Option<String>,
    pub status: DeviceStatus,
    pub registered_at: SystemTime,
    pub last_seen_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProofKeyRecord {
    pub key_id: String,
    pub device_id: DeviceId,
    pub algorithm: DeviceProofAlgorithm,
    pub public_jwk: String,
    pub version: u64,
    pub status: DeviceProofKeyStatus,
    pub registered_at: SystemTime,
    pub retired_at: Option<SystemTime>,
}

impl DeviceProofKeyRecord {
    pub fn validate(&self) -> Result<(), DeviceProofKeyValidationError> {
        if self.key_id.len() != 43 {
            return Err(DeviceProofKeyValidationError::InvalidKeyId);
        }
        if self.device_id.trim().is_empty() {
            return Err(DeviceProofKeyValidationError::MissingDeviceId);
        }
        if self.version == 0 {
            return Err(DeviceProofKeyValidationError::InvalidVersion);
        }
        match (&self.status, self.retired_at) {
            (DeviceProofKeyStatus::Active, None) | (DeviceProofKeyStatus::Retired, Some(_)) => {
                Ok(())
            }
            _ => Err(DeviceProofKeyValidationError::InvalidRetirementState),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProofAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProofKeyStatus {
    Active,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceProofKeyValidationError {
    InvalidKeyId,
    MissingDeviceId,
    InvalidVersion,
    InvalidRetirementState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    Pending,
    Active,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDeviceBinding {
    pub id: AccountDeviceBindingId,
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub status: AccountDeviceBindingStatus,
    pub bound_at: SystemTime,
    pub unbound_at: Option<SystemTime>,
    pub last_authenticated_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountDeviceBindingStatus {
    Active,
    Unbound,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNonceRecord {
    pub id: DeviceNonceId,
    pub device_id: DeviceId,
    pub challenge: String,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProofChallengeRecord {
    pub id: DeviceNonceId,
    pub device_id: DeviceId,
    pub purpose: crate::DeviceProofPurpose,
    pub challenge_digest: [u8; 32],
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthSession {
    pub id: SessionId,
    pub account_id: AccountId,
    pub client_id: ClientId,
    pub device_id: Option<DeviceId>,
    pub status: SessionStatus,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub refresh_token_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Pending,
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    pub id: RefreshTokenId,
    pub session_id: SessionId,
    pub token_digest: [u8; 32],
    pub token_version: u64,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub revoked_at: Option<SystemTime>,
    pub revocation_reason: Option<RefreshTokenRevocationReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTokenRevocationReason {
    Rotated,
    ReuseDetected,
    Logout,
    ClientRevocation,
    Administrative,
    SecurityCutover,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRecord {
    pub code: AuthorizationCodeId,
    pub account_id: AccountId,
    pub client_id: ClientId,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<PkceChallengeMethod>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub consumed_at: Option<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceChallengeMethod {
    Plain,
    S256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClient {
    pub client_id: ClientId,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub client_type: OidcClientType,
    pub pkce_required: bool,
    pub client_secret_hash: Option<String>,
}

impl OidcClient {
    pub fn validate(&self) -> Result<(), ClientValidationError> {
        if self.client_id.trim().is_empty() {
            return Err(ClientValidationError::MissingClientId);
        }

        if self.redirect_uris.is_empty() {
            return Err(ClientValidationError::MissingRedirectUri);
        }

        match self.client_type {
            OidcClientType::PublicDesktop => {
                if !self.pkce_required {
                    return Err(ClientValidationError::PublicClientMustRequirePkce);
                }
                if self
                    .client_secret_hash
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                {
                    return Err(ClientValidationError::PublicClientCannotHaveClientSecret);
                }
            }
            OidcClientType::ConfidentialWeb => {
                if self
                    .client_secret_hash
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
                {
                    return Err(ClientValidationError::ConfidentialClientRequiresSecret);
                }
            }
        }

        for uri in &self.redirect_uris {
            let valid = match self.client_type {
                OidcClientType::PublicDesktop => {
                    is_loopback_redirect(uri) || is_private_use_uri(uri)
                }
                OidcClientType::ConfidentialWeb => {
                    is_https_redirect(uri) || is_loopback_redirect(uri)
                }
            };

            if !valid {
                return Err(ClientValidationError::InvalidRedirectUri(uri.clone()));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcClientType {
    PublicDesktop,
    ConfidentialWeb,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientValidationError {
    MissingClientId,
    MissingRedirectUri,
    PublicClientMustRequirePkce,
    PublicClientCannotHaveClientSecret,
    ConfidentialClientRequiresSecret,
    InvalidRedirectUri(String),
}

fn is_loopback_redirect(value: &str) -> bool {
    value.starts_with("http://127.0.0.1") || value.starts_with("http://localhost")
}

fn is_https_redirect(value: &str) -> bool {
    value.starts_with("https://")
}

fn is_private_use_uri(value: &str) -> bool {
    let Some((scheme, _rest)) = value.split_once("://") else {
        return false;
    };

    !scheme.is_empty()
        && scheme != "http"
        && scheme != "https"
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::{ClientValidationError, OidcClient, OidcClientType};

    #[test]
    fn public_desktop_client_accepts_loopback_and_custom_scheme_redirects() {
        let client = OidcClient {
            client_id: "desktop-app".to_string(),
            client_name: "Desktop App".to_string(),
            redirect_uris: vec![
                "http://127.0.0.1:49152/callback".to_string(),
                "myapp://auth/callback".to_string(),
            ],
            client_type: OidcClientType::PublicDesktop,
            pkce_required: true,
            client_secret_hash: None,
        };

        assert_eq!(client.validate(), Ok(()));
    }

    #[test]
    fn public_desktop_client_rejects_https_redirect_without_pkce_rule() {
        let client = OidcClient {
            client_id: "desktop-app".to_string(),
            client_name: "Desktop App".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            client_type: OidcClientType::PublicDesktop,
            pkce_required: false,
            client_secret_hash: None,
        };

        assert_eq!(
            client.validate(),
            Err(ClientValidationError::PublicClientMustRequirePkce)
        );
    }

    #[test]
    fn confidential_client_rejects_non_https_non_loopback_redirects() {
        let client = OidcClient {
            client_id: "web-app".to_string(),
            client_name: "Web App".to_string(),
            redirect_uris: vec!["custom://callback".to_string()],
            client_type: OidcClientType::ConfidentialWeb,
            pkce_required: false,
            client_secret_hash: Some("secret-hash".to_string()),
        };

        assert_eq!(
            client.validate(),
            Err(ClientValidationError::InvalidRedirectUri(
                "custom://callback".to_string()
            ))
        );
    }

    #[test]
    fn confidential_client_requires_stored_secret_hash() {
        let client = OidcClient {
            client_id: "web-app".to_string(),
            client_name: "Web App".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            client_type: OidcClientType::ConfidentialWeb,
            pkce_required: false,
            client_secret_hash: None,
        };

        assert_eq!(
            client.validate(),
            Err(ClientValidationError::ConfidentialClientRequiresSecret)
        );
    }

    #[test]
    fn public_client_rejects_secret_hash_configuration() {
        let client = OidcClient {
            client_id: "desktop-app".to_string(),
            client_name: "Desktop App".to_string(),
            redirect_uris: vec!["http://127.0.0.1:49152/callback".to_string()],
            client_type: OidcClientType::PublicDesktop,
            pkce_required: true,
            client_secret_hash: Some("secret-hash".to_string()),
        };

        assert_eq!(
            client.validate(),
            Err(ClientValidationError::PublicClientCannotHaveClientSecret)
        );
    }
}

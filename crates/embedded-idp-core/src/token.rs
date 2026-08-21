use std::time::SystemTime;

use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq)]
pub struct IssuedTokenBundle {
    pub access_token: crate::SecretString,
    pub refresh_token: crate::SecretString,
    pub access_expires_at: SystemTime,
    pub refresh_expires_at: SystemTime,
    pub refresh_token_version: u64,
}

impl std::fmt::Debug for IssuedTokenBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedTokenBundle")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("refresh_token_version", &self.refresh_token_version)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedAccessToken {
    pub token: crate::SecretString,
    pub subject_account_id: String,
    pub session_id: String,
    pub client_id: String,
    pub scope: Option<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

impl std::fmt::Debug for ValidatedAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedAccessToken")
            .field("token", &self.token)
            .field("subject_account_id", &self.subject_account_id)
            .field("session_id", &self.session_id)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidRefreshRotation,
    RefreshTokenVersionOverflow,
    InvalidRefreshTokenEncoding,
    RefreshTokenGenerationFailed,
    IssuerRejected(String),
}

pub trait TokenIssuer {
    fn issue_session_tokens(
        &self,
        session_id: &str,
        account_id: &str,
        client_id: &str,
        refresh_token_version: u64,
        issued_at: SystemTime,
    ) -> Result<IssuedTokenBundle, TokenError>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct IssuedAccessToken {
    pub token: crate::SecretString,
    pub expires_at: SystemTime,
}

impl std::fmt::Debug for IssuedAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedAccessToken")
            .field("token", &self.token)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub trait AccessTokenIssuer {
    fn issue_access_token(
        &self,
        session_id: &str,
        account_id: &str,
        client_id: &str,
        issued_at: SystemTime,
    ) -> Result<IssuedAccessToken, TokenError>;
}

pub trait AccessTokenValidator {
    fn validate_access_token(
        &self,
        token: &str,
        observed_at: SystemTime,
    ) -> Result<Option<ValidatedAccessToken>, TokenError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenClaims {
    pub issuer: String,
    pub subject_account_id: String,
    pub audience: String,
    pub nonce: Option<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub auth_time: SystemTime,
}

pub trait IdTokenIssuer {
    fn issue_id_token(&self, claims: &IdTokenClaims) -> Result<crate::SecretString, TokenError>;
}

pub fn next_refresh_token_version(
    current_version: u64,
    expected_version: u64,
) -> Result<u64, TokenError> {
    if current_version != expected_version {
        return Err(TokenError::InvalidRefreshRotation);
    }

    current_version
        .checked_add(1)
        .ok_or(TokenError::RefreshTokenVersionOverflow)
}

pub fn digest_refresh_token(raw_token: &str) -> [u8; 32] {
    Sha256::digest(raw_token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{next_refresh_token_version, IssuedTokenBundle, TokenError};

    #[test]
    fn refresh_rotation_accepts_matching_version() {
        assert_eq!(next_refresh_token_version(4, 4), Ok(5));
    }

    #[test]
    fn refresh_rotation_rejects_stale_version() {
        assert_eq!(
            next_refresh_token_version(4, 3),
            Err(TokenError::InvalidRefreshRotation)
        );
    }

    #[test]
    fn refresh_rotation_rejects_overflow_boundary() {
        assert_eq!(
            next_refresh_token_version(u64::MAX, u64::MAX),
            Err(TokenError::RefreshTokenVersionOverflow)
        );
    }

    #[test]
    fn issued_token_bundle_debug_output_redacts_both_tokens() {
        let bundle = IssuedTokenBundle {
            access_token: crate::SecretString::new("access-token-material"),
            refresh_token: crate::SecretString::new("refresh-token-material"),
            access_expires_at: SystemTime::UNIX_EPOCH,
            refresh_expires_at: SystemTime::UNIX_EPOCH,
            refresh_token_version: 1,
        };

        let output = format!("{bundle:?}");
        assert!(!output.contains("access-token-material"));
        assert!(!output.contains("refresh-token-material"));
        assert_eq!(output.matches("<redacted>").count(), 2);
    }
}

use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedTokenBundle {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: SystemTime,
    pub refresh_expires_at: SystemTime,
    pub refresh_token_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAccessToken {
    pub token: String,
    pub subject_account_id: String,
    pub session_id: String,
    pub client_id: String,
    pub scope: Option<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidRefreshRotation,
    RefreshTokenVersionOverflow,
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
    fn issue_id_token(&self, claims: &IdTokenClaims) -> Result<String, TokenError>;
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

#[cfg(test)]
mod tests {
    use super::{next_refresh_token_version, TokenError};

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
}

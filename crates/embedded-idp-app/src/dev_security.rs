use std::time::{Duration, SystemTime, UNIX_EPOCH};

use embedded_idp_core::{
    validate_proof_freshness, AccessTokenValidator, DeviceProof, DeviceProofError,
    DeviceProofVerifier, IdGenerator, IdTokenClaims, IdTokenIssuer, IssuedTokenBundle,
    SecretString, TokenError, TokenIssuer, UuidV7IdGenerator, ValidatedAccessToken,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct DevIdGenerator;

impl IdGenerator for DevIdGenerator {
    fn next_id(&self, prefix: &str) -> String {
        UuidV7IdGenerator.next_id(prefix)
    }
}

#[derive(Debug, Clone)]
pub struct DevTokenIssuer {
    access_token_ttl_secs: u64,
    refresh_token_ttl_secs: u64,
}

impl DevTokenIssuer {
    pub fn new(access_token_ttl_secs: u64, refresh_token_ttl_secs: u64) -> Self {
        Self {
            access_token_ttl_secs,
            refresh_token_ttl_secs,
        }
    }
}

impl TokenIssuer for DevTokenIssuer {
    fn issue_session_tokens(
        &self,
        session_id: &str,
        account_id: &str,
        client_id: &str,
        refresh_token_version: u64,
        issued_at: SystemTime,
    ) -> Result<IssuedTokenBundle, TokenError> {
        let issued_at_unix = unix_secs(issued_at)?;
        let access_expires_at = issued_at + Duration::from_secs(self.access_token_ttl_secs);
        let refresh_expires_at = issued_at + Duration::from_secs(self.refresh_token_ttl_secs);

        Ok(IssuedTokenBundle {
            access_token: SecretString::new(format!(
                "access:{session_id}:{account_id}:{client_id}:{issued_at_unix}:{}",
                unix_secs(access_expires_at)?
            )),
            refresh_token: SecretString::new(format!(
                "refresh:{session_id}:{refresh_token_version}:{issued_at_unix}"
            )),
            access_expires_at,
            refresh_expires_at,
            refresh_token_version,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DevAccessTokenValidator;

impl AccessTokenValidator for DevAccessTokenValidator {
    fn validate_access_token(
        &self,
        token: &str,
        _observed_at: SystemTime,
    ) -> Result<Option<ValidatedAccessToken>, TokenError> {
        let mut parts = token.split(':');
        if parts.next() != Some("access") {
            return Ok(None);
        }

        let (
            Some(session_id),
            Some(account_id),
            Some(client_id),
            Some(issued_at_unix),
            Some(expires_at_unix),
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return Ok(None);
        };

        Ok(Some(ValidatedAccessToken {
            token: embedded_idp_core::SecretString::new(token),
            subject_account_id: account_id.to_string(),
            session_id: session_id.to_string(),
            client_id: client_id.to_string(),
            scope: Some("openid profile email offline_access".to_string()),
            issued_at: parse_unix_secs(issued_at_unix)?,
            expires_at: parse_unix_secs(expires_at_unix)?,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct DevIdTokenIssuer;

impl IdTokenIssuer for DevIdTokenIssuer {
    fn issue_id_token(&self, claims: &IdTokenClaims) -> Result<SecretString, TokenError> {
        Ok(SecretString::new(format!(
            "id:{}:{}:{}",
            claims.subject_account_id, claims.audience, claims.issuer
        )))
    }
}

#[derive(Debug, Clone)]
pub struct DevDeviceProofVerifier;

impl DeviceProofVerifier for DevDeviceProofVerifier {
    fn verify(
        &self,
        proof: &DeviceProof,
        observed_at: SystemTime,
        allowed_skew_secs: u64,
    ) -> Result<(), DeviceProofError> {
        validate_proof_freshness(proof.signed_at, observed_at, allowed_skew_secs)
    }
}

fn unix_secs(value: SystemTime) -> Result<u64, TokenError> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| TokenError::IssuerRejected(error.to_string()))
}

fn parse_unix_secs(value: &str) -> Result<SystemTime, TokenError> {
    let seconds = value
        .parse::<u64>()
        .map_err(|error| TokenError::IssuerRejected(error.to_string()))?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

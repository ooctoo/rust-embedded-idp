use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    AccessTokenIssuer, AccessTokenValidator, IdTokenClaims, IdTokenIssuer, IssuedAccessToken,
    IssuedTokenBundle, JsonWebKey, JwksDocument, OidcMetadataService, RefreshTokenGenerator,
    SecretString, ServiceError, TokenError, TokenIssuer, ValidatedAccessToken,
};
use rand_core::{OsRng, RngCore};
use ring::rand::SystemRandom;
use ring::rsa::{KeyPair as RsaKeyPair, PublicKeyComponents};
use ring::signature::{self, KeyPair};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_JWT_BYTES: usize = 16 * 1024;
const MAX_JWT_PART_BYTES: usize = 8 * 1024;
const MIN_RSA_MODULUS_BYTES: usize = 384;
const MAX_RSA_MODULUS_BYTES: usize = 1_024;

#[derive(Clone, PartialEq, Eq)]
pub struct RsaSigningKeyConfig {
    pub key_id: String,
    pub private_key_der: Vec<u8>,
}

impl std::fmt::Debug for RsaSigningKeyConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RsaSigningKeyConfig")
            .field("key_id", &self.key_id)
            .field("private_key_der", &"<redacted>")
            .finish()
    }
}

impl RsaSigningKeyConfig {
    pub fn from_private_key_der(private_key_der: Vec<u8>) -> Result<Self, JwtConfigurationError> {
        let key = parse_private_key(&private_key_der)?;
        let components: PublicKeyComponents<Vec<u8>> = key.public_key().into();
        validate_rsa_components(&components.n, &components.e)?;
        let modulus = Base64UrlUnpadded::encode_string(&components.n);
        let exponent = Base64UrlUnpadded::encode_string(&components.e);
        Ok(Self {
            key_id: rsa_thumbprint(&modulus, &exponent),
            private_key_der,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKeyConfig {
    pub key_id: String,
    pub modulus: String,
    pub exponent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionJwtConfig {
    pub issuer: String,
    pub audience: String,
    pub scope: String,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub clock_skew_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtConfigurationError {
    InvalidIssuer,
    InvalidAudience,
    InvalidScope,
    InvalidTtl,
    InvalidPrivateKey,
    RsaKeyTooSmall,
    InvalidPublicKey,
    KeyIdMismatch,
    DuplicateKeyId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIdToken {
    pub subject_account_id: String,
    pub audience: String,
    pub nonce: Option<String>,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub auth_time: SystemTime,
}

#[derive(Clone)]
struct RsaPublicKey {
    key_id: String,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

pub struct Rs256JwtService {
    config: ProductionJwtConfig,
    active_key: Arc<RsaKeyPair>,
    active_key_id: String,
    verification_keys: Vec<RsaPublicKey>,
    jwks: JwksDocument,
    jwks_etag: String,
}

impl std::fmt::Debug for Rs256JwtService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Rs256JwtService")
            .field("config", &self.config)
            .field("active_key_id", &self.active_key_id)
            .field("verification_key_count", &self.verification_keys.len())
            .field("jwks_etag", &self.jwks_etag)
            .finish()
    }
}

impl Rs256JwtService {
    pub fn new(
        config: ProductionJwtConfig,
        active: RsaSigningKeyConfig,
        overlap: Vec<RsaPublicKeyConfig>,
    ) -> Result<Self, JwtConfigurationError> {
        validate_config(&config)?;
        let active_key = parse_private_key(&active.private_key_der)?;
        let active_components: PublicKeyComponents<Vec<u8>> = active_key.public_key().into();
        validate_rsa_components(&active_components.n, &active_components.e)?;
        let active_public = validated_public_key(
            active.key_id,
            Base64UrlUnpadded::encode_string(&active_components.n),
            Base64UrlUnpadded::encode_string(&active_components.e),
        )?;

        let mut verification_keys = vec![active_public.clone()];
        for key in overlap {
            verification_keys.push(validated_public_key(key.key_id, key.modulus, key.exponent)?);
        }
        let mut unique_ids = HashSet::new();
        if verification_keys
            .iter()
            .any(|key| !unique_ids.insert(key.key_id.clone()))
        {
            return Err(JwtConfigurationError::DuplicateKeyId);
        }
        verification_keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        let jwks = JwksDocument {
            keys: verification_keys.iter().map(public_jwk).collect(),
        };
        let jwks_etag = jwks_etag(&verification_keys);

        Ok(Self {
            config,
            active_key: Arc::new(active_key),
            active_key_id: active_public.key_id,
            verification_keys,
            jwks,
            jwks_etag,
        })
    }

    pub fn validate_id_token(
        &self,
        token: &str,
        observed_at: SystemTime,
        expected_audience: &str,
        expected_nonce: Option<&str>,
    ) -> Option<ValidatedIdToken> {
        let claims: IdClaims = self.verify_and_decode(token)?;
        let observed = unix_secs(observed_at).ok()?;
        if claims.iss != self.config.issuer
            || claims.aud != expected_audience
            || claims.token_use != "id"
            || claims.sub.is_empty()
            || claims.exp <= observed.saturating_sub(self.config.clock_skew_secs)
            || claims.iat > observed.saturating_add(self.config.clock_skew_secs)
            || claims.exp <= claims.iat
            || claims.auth_time > claims.iat
            || claims.nonce.as_deref() != expected_nonce
        {
            return None;
        }
        Some(ValidatedIdToken {
            subject_account_id: claims.sub,
            audience: claims.aud,
            nonce: claims.nonce,
            issued_at: from_unix_secs(claims.iat)?,
            expires_at: from_unix_secs(claims.exp)?,
            auth_time: from_unix_secs(claims.auth_time)?,
        })
    }

    pub fn jwks_etag_value(&self) -> &str {
        &self.jwks_etag
    }

    pub fn active_public_key_config(&self) -> RsaPublicKeyConfig {
        let key = self
            .verification_keys
            .iter()
            .find(|key| key.key_id == self.active_key_id)
            .expect("the active key is always in the verification key ring");
        RsaPublicKeyConfig {
            key_id: key.key_id.clone(),
            modulus: Base64UrlUnpadded::encode_string(&key.modulus),
            exponent: Base64UrlUnpadded::encode_string(&key.exponent),
        }
    }

    fn sign<T: Serialize>(&self, claims: &T) -> Result<SecretString, TokenError> {
        let header = JwtHeader {
            alg: "RS256",
            typ: "JWT",
            kid: &self.active_key_id,
        };
        let header = serde_json::to_vec(&header)
            .map_err(|_| TokenError::IssuerRejected("serialize JWT header failed".to_string()))?;
        let claims = serde_json::to_vec(claims)
            .map_err(|_| TokenError::IssuerRejected("serialize JWT claims failed".to_string()))?;
        let signing_input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(&header),
            Base64UrlUnpadded::encode_string(&claims)
        );
        let mut signature = vec![0_u8; self.active_key.public().modulus_len()];
        self.active_key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| TokenError::IssuerRejected("sign JWT failed".to_string()))?;
        Ok(SecretString::new(format!(
            "{signing_input}.{}",
            Base64UrlUnpadded::encode_string(&signature)
        )))
    }

    fn verify_and_decode<T: DeserializeOwned>(&self, token: &str) -> Option<T> {
        if token.is_empty() || token.len() > MAX_JWT_BYTES || !token.is_ascii() {
            return None;
        }
        let mut parts = token.split('.');
        let header_part = parts.next()?;
        let claims_part = parts.next()?;
        let signature_part = parts.next()?;
        if parts.next().is_some()
            || header_part.len() > MAX_JWT_PART_BYTES
            || claims_part.len() > MAX_JWT_PART_BYTES
            || signature_part.len() > MAX_JWT_PART_BYTES
        {
            return None;
        }
        let header: OwnedJwtHeader = decode_json_part(header_part)?;
        if header.alg != "RS256" || header.typ != "JWT" || header.kid.is_empty() {
            return None;
        }
        let key = self
            .verification_keys
            .iter()
            .find(|key| key.key_id == header.kid)?;
        let signature = decode_canonical(signature_part)?;
        if signature.len() != key.modulus.len() {
            return None;
        }
        let signing_input = format!("{header_part}.{claims_part}");
        PublicKeyComponents {
            n: key.modulus.as_slice(),
            e: key.exponent.as_slice(),
        }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signing_input.as_bytes(),
            &signature,
        )
        .ok()?;
        decode_json_part(claims_part)
    }
}

impl AccessTokenIssuer for Rs256JwtService {
    fn issue_access_token(
        &self,
        session_id: &str,
        account_id: &str,
        client_id: &str,
        issued_at: SystemTime,
    ) -> Result<IssuedAccessToken, TokenError> {
        if !valid_claim_value(session_id, 256)
            || !valid_claim_value(account_id, 256)
            || !valid_claim_value(client_id, 256)
        {
            return Err(TokenError::IssuerRejected(
                "access token identity claims are invalid".to_string(),
            ));
        }
        let iat = unix_secs(issued_at)?;
        let expires_at = issued_at
            .checked_add(Duration::from_secs(self.config.access_token_ttl_secs))
            .ok_or_else(|| TokenError::IssuerRejected("access expiry overflow".to_string()))?;
        let claims = AccessClaims {
            iss: self.config.issuer.clone(),
            sub: account_id.to_string(),
            aud: self.config.audience.clone(),
            exp: unix_secs(expires_at)?,
            iat,
            nbf: iat,
            jti: random_jti()?,
            sid: session_id.to_string(),
            client_id: client_id.to_string(),
            scope: self.config.scope.clone(),
            token_use: "access".to_string(),
        };
        Ok(IssuedAccessToken {
            token: self.sign(&claims)?,
            expires_at,
        })
    }
}

impl AccessTokenValidator for Rs256JwtService {
    fn validate_access_token(
        &self,
        token: &str,
        observed_at: SystemTime,
    ) -> Result<Option<ValidatedAccessToken>, TokenError> {
        let Some(claims) = self.verify_and_decode::<AccessClaims>(token) else {
            return Ok(None);
        };
        let observed = unix_secs(observed_at)?;
        if claims.iss != self.config.issuer
            || claims.aud != self.config.audience
            || claims.scope != self.config.scope
            || claims.token_use != "access"
            || claims.exp <= observed.saturating_sub(self.config.clock_skew_secs)
            || claims.nbf > observed.saturating_add(self.config.clock_skew_secs)
            || claims.iat > observed.saturating_add(self.config.clock_skew_secs)
            || claims.nbf < claims.iat
            || claims.exp <= claims.iat
            || claims.jti.is_empty()
            || claims.sid.is_empty()
            || claims.client_id.is_empty()
            || claims.sub.is_empty()
        {
            return Ok(None);
        }
        Ok(Some(ValidatedAccessToken {
            token: SecretString::new(token),
            subject_account_id: claims.sub,
            session_id: claims.sid,
            client_id: claims.client_id,
            scope: Some(claims.scope),
            issued_at: from_unix_secs(claims.iat)
                .ok_or_else(|| TokenError::IssuerRejected("invalid JWT iat".to_string()))?,
            expires_at: from_unix_secs(claims.exp)
                .ok_or_else(|| TokenError::IssuerRejected("invalid JWT exp".to_string()))?,
        }))
    }
}

impl IdTokenIssuer for Rs256JwtService {
    fn issue_id_token(&self, claims: &IdTokenClaims) -> Result<SecretString, TokenError> {
        let issued_at = unix_secs(claims.issued_at)?;
        let expires_at = unix_secs(claims.expires_at)?;
        let auth_time = unix_secs(claims.auth_time)?;
        if claims.issuer != self.config.issuer
            || !valid_claim_value(&claims.subject_account_id, 256)
            || !valid_claim_value(&claims.audience, 256)
            || claims
                .nonce
                .as_deref()
                .is_some_and(|nonce| !valid_claim_value(nonce, 512))
            || expires_at <= issued_at
            || auth_time > issued_at
        {
            return Err(TokenError::IssuerRejected(
                "ID token claims are invalid".to_string(),
            ));
        }
        self.sign(&IdClaims {
            iss: claims.issuer.clone(),
            sub: claims.subject_account_id.clone(),
            aud: claims.audience.clone(),
            exp: expires_at,
            iat: issued_at,
            auth_time,
            nonce: claims.nonce.clone(),
            token_use: "id".to_string(),
        })
    }
}

impl TokenIssuer for Rs256JwtService {
    fn issue_session_tokens(
        &self,
        session_id: &str,
        account_id: &str,
        client_id: &str,
        refresh_token_version: u64,
        issued_at: SystemTime,
    ) -> Result<IssuedTokenBundle, TokenError> {
        let access = self.issue_access_token(session_id, account_id, client_id, issued_at)?;
        let refresh = crate::SecureRefreshTokenGenerator.generate_refresh_token()?;
        let refresh_expires_at = issued_at
            .checked_add(Duration::from_secs(self.config.refresh_token_ttl_secs))
            .ok_or_else(|| TokenError::IssuerRejected("refresh expiry overflow".to_string()))?;
        Ok(IssuedTokenBundle {
            access_token: access.token,
            refresh_token: refresh,
            access_expires_at: access.expires_at,
            refresh_expires_at,
            refresh_token_version,
        })
    }
}

impl OidcMetadataService for Rs256JwtService {
    fn jwks_document(&self) -> Result<JwksDocument, ServiceError> {
        Ok(self.jwks.clone())
    }

    fn jwks_etag(&self) -> Option<String> {
        Some(self.jwks_etag.clone())
    }
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedJwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    nbf: u64,
    jti: String,
    sid: String,
    client_id: String,
    scope: String,
    token_use: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    auth_time: u64,
    nonce: Option<String>,
    token_use: String,
}

fn validate_config(config: &ProductionJwtConfig) -> Result<(), JwtConfigurationError> {
    if !valid_claim_value(&config.issuer, 512) {
        return Err(JwtConfigurationError::InvalidIssuer);
    }
    if !valid_claim_value(&config.audience, 256) {
        return Err(JwtConfigurationError::InvalidAudience);
    }
    if !valid_claim_value(&config.scope, 1024) {
        return Err(JwtConfigurationError::InvalidScope);
    }
    if config.access_token_ttl_secs == 0
        || config.refresh_token_ttl_secs <= config.access_token_ttl_secs
        || config.clock_skew_secs >= config.access_token_ttl_secs
    {
        return Err(JwtConfigurationError::InvalidTtl);
    }
    Ok(())
}

fn parse_private_key(private_key_der: &[u8]) -> Result<RsaKeyPair, JwtConfigurationError> {
    RsaKeyPair::from_pkcs8(private_key_der)
        .or_else(|_| RsaKeyPair::from_der(private_key_der))
        .map_err(|_| JwtConfigurationError::InvalidPrivateKey)
}

fn validated_public_key(
    key_id: String,
    modulus: String,
    exponent: String,
) -> Result<RsaPublicKey, JwtConfigurationError> {
    let modulus_bytes =
        decode_canonical(&modulus).ok_or(JwtConfigurationError::InvalidPublicKey)?;
    let exponent_bytes =
        decode_canonical(&exponent).ok_or(JwtConfigurationError::InvalidPublicKey)?;
    validate_rsa_components(&modulus_bytes, &exponent_bytes)?;
    let expected_key_id = rsa_thumbprint(&modulus, &exponent);
    if key_id != expected_key_id {
        return Err(JwtConfigurationError::KeyIdMismatch);
    }
    Ok(RsaPublicKey {
        key_id,
        modulus: modulus_bytes,
        exponent: exponent_bytes,
    })
}

fn validate_rsa_components(modulus: &[u8], exponent: &[u8]) -> Result<(), JwtConfigurationError> {
    if modulus.len() < MIN_RSA_MODULUS_BYTES
        || (modulus.len() == MIN_RSA_MODULUS_BYTES && modulus.first() < Some(&0x80))
    {
        return Err(JwtConfigurationError::RsaKeyTooSmall);
    }
    if modulus.len() > MAX_RSA_MODULUS_BYTES
        || modulus.first() == Some(&0)
        || exponent.is_empty()
        || exponent.len() > 5
        || exponent.first() == Some(&0)
        || exponent.last().is_none_or(|last| last & 1 == 0)
        || exponent
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
            < 3
    {
        return Err(JwtConfigurationError::InvalidPublicKey);
    }
    Ok(())
}

fn rsa_thumbprint(modulus: &str, exponent: &str) -> String {
    let canonical = format!("{{\"e\":\"{exponent}\",\"kty\":\"RSA\",\"n\":\"{modulus}\"}}");
    Base64UrlUnpadded::encode_string(&Sha256::digest(canonical.as_bytes()))
}

fn public_jwk(key: &RsaPublicKey) -> JsonWebKey {
    JsonWebKey {
        key_id: key.key_id.clone(),
        key_type: "RSA".to_string(),
        algorithm: "RS256".to_string(),
        public_key_use: "sig".to_string(),
        curve: None,
        modulus: Some(Base64UrlUnpadded::encode_string(&key.modulus)),
        exponent: Some(Base64UrlUnpadded::encode_string(&key.exponent)),
        x: None,
        y: None,
    }
}

fn jwks_etag(keys: &[RsaPublicKey]) -> String {
    let canonical = keys
        .iter()
        .map(|key| {
            format!(
                "{{\"alg\":\"RS256\",\"e\":\"{}\",\"kid\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\",\"use\":\"sig\"}}",
                Base64UrlUnpadded::encode_string(&key.exponent),
                key.key_id,
                Base64UrlUnpadded::encode_string(&key.modulus),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let digest = Base64UrlUnpadded::encode_string(&Sha256::digest(
        format!("{{\"keys\":[{canonical}]}}").as_bytes(),
    ));
    format!("\"sha256-{digest}\"")
}

fn decode_json_part<T: DeserializeOwned>(part: &str) -> Option<T> {
    let bytes = decode_canonical(part)?;
    if bytes.len() > MAX_JWT_PART_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn decode_canonical(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let decoded = Base64UrlUnpadded::decode_vec(value).ok()?;
    if Base64UrlUnpadded::encode_string(&decoded) != value {
        return None;
    }
    Some(decoded)
}

fn valid_claim_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn random_jti() -> Result<String, TokenError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| TokenError::IssuerRejected("generate JWT ID failed".to_string()))?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

fn unix_secs(value: SystemTime) -> Result<u64, TokenError> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TokenError::IssuerRejected("time is before Unix epoch".to_string()))
}

fn from_unix_secs(value: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(value))
}

#[cfg(test)]
mod tests {
    use base64ct::Base64;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn service() -> Rs256JwtService {
        let private_key_der =
            Base64::decode_vec(include_str!("../tests/fixtures/rsa_3072_key_1.pk8.b64").trim())
                .unwrap();
        Rs256JwtService::new(
            ProductionJwtConfig {
                issuer: "https://idp.example.test".to_string(),
                audience: "embedded-api".to_string(),
                scope: "openid profile".to_string(),
                access_token_ttl_secs: 300,
                refresh_token_ttl_secs: 86_400,
                clock_skew_secs: 30,
            },
            RsaSigningKeyConfig::from_private_key_der(private_key_der).unwrap(),
            Vec::new(),
        )
        .unwrap()
    }

    fn claims() -> AccessClaims {
        AccessClaims {
            iss: "https://idp.example.test".to_string(),
            sub: "account-1".to_string(),
            aud: "embedded-api".to_string(),
            exp: NOW + 300,
            iat: NOW,
            nbf: NOW,
            jti: "jti-1".to_string(),
            sid: "session-1".to_string(),
            client_id: "desktop-app".to_string(),
            scope: "openid profile".to_string(),
            token_use: "access".to_string(),
        }
    }

    #[test]
    fn rejects_validly_signed_wrong_token_use_and_future_nbf() {
        let service = service();
        let mut wrong_use = claims();
        wrong_use.token_use = "id".to_string();
        let wrong_use = service.sign(&wrong_use).unwrap();
        assert!(service
            .validate_access_token(
                wrong_use.expose_secret(),
                UNIX_EPOCH + Duration::from_secs(NOW),
            )
            .unwrap()
            .is_none());

        let mut future_nbf = claims();
        future_nbf.nbf = NOW + 60;
        let future_nbf = service.sign(&future_nbf).unwrap();
        assert!(service
            .validate_access_token(
                future_nbf.expose_secret(),
                UNIX_EPOCH + Duration::from_secs(NOW),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejects_unknown_kid_even_when_signature_matches_the_active_key() {
        let service = service();
        let header = serde_json::to_vec(&JwtHeader {
            alg: "RS256",
            typ: "JWT",
            kid: "unknown-key-id",
        })
        .unwrap();
        let claims = serde_json::to_vec(&claims()).unwrap();
        let signing_input = format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(&header),
            Base64UrlUnpadded::encode_string(&claims),
        );
        let mut signature_bytes = vec![0_u8; service.active_key.public().modulus_len()];
        service
            .active_key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature_bytes,
            )
            .unwrap();
        let token = format!(
            "{signing_input}.{}",
            Base64UrlUnpadded::encode_string(&signature_bytes)
        );

        assert!(service
            .validate_access_token(&token, UNIX_EPOCH + Duration::from_secs(NOW))
            .unwrap()
            .is_none());
    }
}

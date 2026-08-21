use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    AccessTokenIssuer, AccessTokenValidator, IdTokenClaims, IdTokenIssuer, OidcMetadataService,
};
use embedded_idp_security::{
    JwtConfigurationError, ProductionJwtConfig, Rs256JwtService, RsaPublicKeyConfig,
    RsaSigningKeyConfig,
};
use serde_json::{json, Value};

const NOW_SECS: u64 = 1_800_000_000;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS)
}

fn config() -> ProductionJwtConfig {
    ProductionJwtConfig {
        issuer: "https://idp.example.test".to_string(),
        audience: "embedded-api".to_string(),
        scope: "openid profile".to_string(),
        access_token_ttl_secs: 300,
        refresh_token_ttl_secs: 86_400,
        clock_skew_secs: 30,
    }
}

fn key_one() -> RsaSigningKeyConfig {
    signing_key(include_str!("fixtures/rsa_3072_key_1.pk8.b64"))
}

fn key_two() -> RsaSigningKeyConfig {
    signing_key(include_str!("fixtures/rsa_3072_key_2.pk8.b64"))
}

fn signing_key(encoded: &str) -> RsaSigningKeyConfig {
    RsaSigningKeyConfig::from_private_key_der(Base64::decode_vec(encoded.trim()).unwrap()).unwrap()
}

fn service(config: ProductionJwtConfig, key: RsaSigningKeyConfig) -> Rs256JwtService {
    Rs256JwtService::new(config, key, Vec::new()).unwrap()
}

fn jwt_part(token: &str, index: usize) -> Value {
    let encoded = token.split('.').nth(index).unwrap();
    let bytes = Base64UrlUnpadded::decode_vec(encoded).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn access_tokens_use_exact_rs256_header_and_required_claims() {
    let service = service(config(), key_one());
    let issued = service
        .issue_access_token("session-1", "account-1", "desktop-app", now())
        .unwrap();
    let token = issued.token.expose_secret();

    assert_eq!(
        jwt_part(token, 0),
        json!({"alg": "RS256", "typ": "JWT", "kid": service.active_public_key_config().key_id})
    );
    let claims = jwt_part(token, 1);
    assert_eq!(claims["iss"], "https://idp.example.test");
    assert_eq!(claims["sub"], "account-1");
    assert_eq!(claims["aud"], "embedded-api");
    assert_eq!(claims["exp"], NOW_SECS + 300);
    assert_eq!(claims["iat"], NOW_SECS);
    assert_eq!(claims["nbf"], NOW_SECS);
    assert_eq!(claims["sid"], "session-1");
    assert_eq!(claims["client_id"], "desktop-app");
    assert_eq!(claims["scope"], "openid profile");
    assert_eq!(claims["token_use"], "access");
    assert!(claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()));

    let validated = service
        .validate_access_token(token, now())
        .unwrap()
        .unwrap();
    assert_eq!(validated.subject_account_id, "account-1");
    assert_eq!(validated.session_id, "session-1");
    assert_eq!(validated.client_id, "desktop-app");
    assert_eq!(validated.scope.as_deref(), Some("openid profile"));
    assert!(!format!("{validated:?}").contains(token));
}

#[test]
fn id_tokens_preserve_nonce_and_validate_expected_audience() {
    let service = service(config(), key_one());
    let token = service
        .issue_id_token(&IdTokenClaims {
            issuer: "https://idp.example.test".to_string(),
            subject_account_id: "account-1".to_string(),
            audience: "desktop-app".to_string(),
            nonce: Some("nonce-1".to_string()),
            issued_at: now(),
            expires_at: now() + Duration::from_secs(300),
            auth_time: now() - Duration::from_secs(10),
        })
        .unwrap();

    let claims = jwt_part(token.expose_secret(), 1);
    assert_eq!(claims["auth_time"], NOW_SECS - 10);
    assert_eq!(claims["nonce"], "nonce-1");
    assert_eq!(claims["token_use"], "id");
    assert!(service
        .validate_id_token(token.expose_secret(), now(), "desktop-app", Some("nonce-1"))
        .is_some());
    assert!(service
        .validate_id_token(
            token.expose_secret(),
            now(),
            "another-client",
            Some("nonce-1"),
        )
        .is_none());
    assert!(service
        .validate_id_token(
            token.expose_secret(),
            now(),
            "desktop-app",
            Some("wrong-nonce"),
        )
        .is_none());
}

#[test]
fn access_validation_rejects_tampering_and_algorithm_substitution() {
    let service = service(config(), key_one());
    let token = service
        .issue_access_token("session-1", "account-1", "desktop-app", now())
        .unwrap()
        .token
        .into_exposed();
    let mut parts = token.split('.').map(str::to_string).collect::<Vec<_>>();

    let mut signature = Base64UrlUnpadded::decode_vec(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = Base64UrlUnpadded::encode_string(&signature);
    assert!(service
        .validate_access_token(&parts.join("."), now())
        .unwrap()
        .is_none());

    let header = serde_json::to_vec(&json!({
        "alg": "none",
        "typ": "JWT",
        "kid": service.active_public_key_config().key_id,
    }))
    .unwrap();
    parts[0] = Base64UrlUnpadded::encode_string(&header);
    assert!(service
        .validate_access_token(&parts.join("."), now())
        .unwrap()
        .is_none());
}

#[test]
fn access_validation_enforces_issuer_audience_scope_and_time() {
    let trusted = service(config(), key_one());
    let cases = [
        {
            let mut value = config();
            value.issuer = "https://other.example.test".to_string();
            (value, now())
        },
        {
            let mut value = config();
            value.audience = "another-api".to_string();
            (value, now())
        },
        {
            let mut value = config();
            value.scope = "openid admin".to_string();
            (value, now())
        },
        (config(), now() - Duration::from_secs(400)),
        (config(), now() + Duration::from_secs(60)),
    ];

    for (issuer_config, issued_at) in cases {
        let untrusted = service(issuer_config, key_one());
        let token = untrusted
            .issue_access_token("session-1", "account-1", "desktop-app", issued_at)
            .unwrap()
            .token
            .into_exposed();
        assert!(trusted
            .validate_access_token(&token, now())
            .unwrap()
            .is_none());
    }
}

#[test]
fn rotation_overlap_accepts_old_tokens_until_public_key_is_retired() {
    let old = service(config(), key_one());
    let old_public_key = old.active_public_key_config();
    let old_token = old
        .issue_access_token("session-1", "account-1", "desktop-app", now())
        .unwrap()
        .token
        .into_exposed();

    let rotated = Rs256JwtService::new(config(), key_two(), vec![old_public_key]).unwrap();
    assert!(rotated
        .validate_access_token(&old_token, now())
        .unwrap()
        .is_some());
    let jwks = rotated.jwks_document().unwrap();
    assert_eq!(jwks.keys.len(), 2);
    assert!(jwks
        .keys
        .windows(2)
        .all(|keys| keys[0].key_id < keys[1].key_id));

    let retired = service(config(), key_two());
    assert!(retired
        .validate_access_token(&old_token, now())
        .unwrap()
        .is_none());
    assert_ne!(rotated.jwks_etag_value(), retired.jwks_etag_value());
}

#[test]
fn jwks_contains_only_public_rs256_material_with_deterministic_etag() {
    let first = service(config(), key_one());
    let second = service(config(), key_one());
    let document = first.jwks_document().unwrap();
    let key = &document.keys[0];

    assert_eq!(key.key_type, "RSA");
    assert_eq!(key.algorithm, "RS256");
    assert_eq!(key.public_key_use, "sig");
    assert!(key.modulus.as_ref().is_some_and(|value| !value.is_empty()));
    assert_eq!(key.exponent.as_deref(), Some("AQAB"));
    assert_eq!(key.curve, None);
    assert_eq!(key.x, None);
    assert_eq!(key.y, None);
    assert_eq!(first.jwks_etag_value(), second.jwks_etag_value());
    assert!(first.jwks_etag_value().starts_with("\"sha256-"));
    assert!(first.jwks_etag_value().ends_with('"'));
}

#[test]
fn invalid_or_ambiguous_key_configuration_fails_fast() {
    assert_eq!(
        RsaSigningKeyConfig::from_private_key_der(vec![1, 2, 3]),
        Err(JwtConfigurationError::InvalidPrivateKey)
    );

    let mut wrong_id = key_one();
    wrong_id.key_id = "caller-selected-id".to_string();
    assert!(matches!(
        Rs256JwtService::new(config(), wrong_id, Vec::new()),
        Err(JwtConfigurationError::KeyIdMismatch)
    ));

    let active = key_one();
    let active_service = service(config(), active.clone());
    assert!(matches!(
        Rs256JwtService::new(
            config(),
            active,
            vec![active_service.active_public_key_config()],
        ),
        Err(JwtConfigurationError::DuplicateKeyId)
    ));

    let too_small = RsaPublicKeyConfig {
        key_id: "too-small".to_string(),
        modulus: Base64UrlUnpadded::encode_string(&[0x7f; 384]),
        exponent: "AQAB".to_string(),
    };
    assert!(matches!(
        Rs256JwtService::new(config(), key_two(), vec![too_small]),
        Err(JwtConfigurationError::RsaKeyTooSmall)
    ));
}

#[test]
fn debug_output_redacts_private_and_token_material() {
    let key = key_one();
    let encoded_key = Base64::encode_string(&key.private_key_der);
    assert!(!format!("{key:?}").contains(&encoded_key));

    let service = service(config(), key);
    let issued = service
        .issue_access_token("session-1", "account-1", "desktop-app", now())
        .unwrap();
    assert!(!format!("{issued:?}").contains(issued.token.expose_secret()));
}

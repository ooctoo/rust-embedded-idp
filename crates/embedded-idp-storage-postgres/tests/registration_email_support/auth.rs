use super::fixture::{FixedClock, Fixture, TENANT};
use base64ct::{Base64, Encoding};
use embedded_idp_core::access::*;
use embedded_idp_core::{AuthConfig, UuidV7IdGenerator};
use embedded_idp_security::{
    ProductionJwtConfig, Rs256JwtService, RsaSigningKeyConfig, SecureRefreshTokenGenerator,
    Sha256RefreshTokenDigester,
};
use embedded_idp_storage_postgres::PostgresAccessStore;

pub type Auth = CoreTenantAuthenticationService<
    PostgresAccessStore,
    Rs256JwtService,
    SecureRefreshTokenGenerator,
    Sha256RefreshTokenDigester,
    FixedClock,
    UuidV7IdGenerator,
>;

pub fn service(fixture: &Fixture) -> Auth {
    let key = RsaSigningKeyConfig::from_private_key_der(
        Base64::decode_vec(
            include_str!("../../../embedded-idp-security/tests/fixtures/rsa_3072_key_1.pk8.b64")
                .trim(),
        )
        .expect("test signing key"),
    )
    .expect("test signing key");
    let tokens = Rs256JwtService::new(
        ProductionJwtConfig {
            issuer: "https://idp.example.test".to_string(),
            audience: "registration-email-test".to_string(),
            scope: "openid".to_string(),
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 600,
            clock_skew_secs: 0,
        },
        key,
        vec![],
    )
    .expect("test JWT service");
    CoreTenantAuthenticationService::new(
        TenancyMode::Enabled,
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 60,
            refresh_token_ttl_secs: 600,
            session_ttl_secs: 600,
            verification_code_ttl_secs: 60,
            password_min_length: 8,
            password_max_length: 128,
        },
        TenantLoginEntry {
            client_id: "web".to_string(),
            login_entry: "registration-email-test".to_string(),
            policy: LoginTenantPolicy::Fixed {
                tenant_id: TENANT.to_string(),
            },
            require_device_proof: false,
        },
        PostgresAccessStore::new(fixture.adapter.clone(), TenancyMode::Enabled)
            .expect("access store"),
        tokens,
        SecureRefreshTokenGenerator,
        Sha256RefreshTokenDigester,
        FixedClock,
        UuidV7IdGenerator,
    )
    .expect("authentication service")
}

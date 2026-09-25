#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedIdpConfig {
    pub issuer: String,
    pub auth: AuthConfig,
    pub device: DeviceConfig,
    pub oidc: OidcConfig,
}

impl EmbeddedIdpConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if !is_supported_issuer(&self.issuer) {
            return Err(ConfigValidationError::InvalidIssuer);
        }

        self.auth.validate()?;
        self.device.validate()?;
        self.oidc.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthConfig {
    pub allow_local_registration: bool,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub session_ttl_secs: u64,
    pub verification_code_ttl_secs: u64,
    pub password_min_length: usize,
    pub password_max_length: usize,
}

impl AuthConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.access_token_ttl_secs == 0 {
            return Err(ConfigValidationError::AccessTokenTtlMustBePositive);
        }

        if self.refresh_token_ttl_secs <= self.access_token_ttl_secs {
            return Err(ConfigValidationError::RefreshTokenTtlMustExceedAccessTokenTtl);
        }

        if self.session_ttl_secs < self.refresh_token_ttl_secs {
            return Err(ConfigValidationError::SessionTtlMustCoverRefreshTokenTtl);
        }

        if self.verification_code_ttl_secs == 0 {
            return Err(ConfigValidationError::VerificationCodeTtlMustBePositive);
        }

        if self.verification_code_ttl_secs > 3_600 {
            return Err(ConfigValidationError::VerificationCodeTtlTooLarge);
        }

        if self.password_min_length == 0 {
            return Err(ConfigValidationError::PasswordMinLengthMustBePositive);
        }

        if self.password_max_length < self.password_min_length {
            return Err(ConfigValidationError::PasswordMaxLengthMustCoverMinLength);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    pub nonce_ttl_secs: u64,
    pub proof_clock_skew_secs: u64,
    pub heartbeat_grace_period_secs: u64,
}

impl DeviceConfig {
    fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.nonce_ttl_secs == 0 {
            return Err(ConfigValidationError::DeviceNonceTtlMustBePositive);
        }

        if self.heartbeat_grace_period_secs < self.proof_clock_skew_secs {
            return Err(ConfigValidationError::HeartbeatGracePeriodTooSmall);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub authorization_code_ttl_secs: u64,
    pub require_pkce_for_public_clients: bool,
}

impl OidcConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.authorization_code_ttl_secs == 0 {
            return Err(ConfigValidationError::AuthorizationCodeTtlMustBePositive);
        }

        if self.authorization_code_ttl_secs > 600 {
            return Err(ConfigValidationError::AuthorizationCodeTtlTooLarge);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValidationError {
    InvalidIssuer,
    AccessTokenTtlMustBePositive,
    RefreshTokenTtlMustExceedAccessTokenTtl,
    SessionTtlMustCoverRefreshTokenTtl,
    VerificationCodeTtlMustBePositive,
    VerificationCodeTtlTooLarge,
    PasswordMinLengthMustBePositive,
    PasswordMaxLengthMustCoverMinLength,
    DeviceNonceTtlMustBePositive,
    HeartbeatGracePeriodTooSmall,
    AuthorizationCodeTtlMustBePositive,
    AuthorizationCodeTtlTooLarge,
}

pub(crate) fn is_supported_issuer(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::{AuthConfig, ConfigValidationError, DeviceConfig, EmbeddedIdpConfig, OidcConfig};

    fn valid_config() -> EmbeddedIdpConfig {
        EmbeddedIdpConfig {
            issuer: "http://127.0.0.1:8080".to_string(),
            auth: AuthConfig {
                allow_local_registration: true,
                access_token_ttl_secs: 900,
                refresh_token_ttl_secs: 86_400,
                session_ttl_secs: 604_800,
                verification_code_ttl_secs: 900,
                password_min_length: 8,
                password_max_length: 128,
            },
            device: DeviceConfig {
                nonce_ttl_secs: 300,
                proof_clock_skew_secs: 30,
                heartbeat_grace_period_secs: 60,
            },
            oidc: OidcConfig {
                authorization_code_ttl_secs: 300,
                require_pkce_for_public_clients: true,
            },
        }
    }

    #[test]
    fn config_accepts_local_loopback_issuer() {
        assert_eq!(valid_config().validate(), Ok(()));
    }

    #[test]
    fn config_rejects_refresh_token_ttl_shorter_than_access_token_ttl() {
        let mut config = valid_config();
        config.auth.refresh_token_ttl_secs = 600;

        assert_eq!(
            config.validate(),
            Err(ConfigValidationError::RefreshTokenTtlMustExceedAccessTokenTtl)
        );
    }

    #[test]
    fn config_rejects_oversized_authorization_code_ttl() {
        let mut config = valid_config();
        config.oidc.authorization_code_ttl_secs = 601;

        assert_eq!(
            config.validate(),
            Err(ConfigValidationError::AuthorizationCodeTtlTooLarge)
        );
    }

    #[test]
    fn config_rejects_zero_password_min_length() {
        let mut config = valid_config();
        config.auth.password_min_length = 0;

        assert_eq!(
            config.validate(),
            Err(ConfigValidationError::PasswordMinLengthMustBePositive)
        );
    }

    #[test]
    fn config_rejects_password_max_shorter_than_min() {
        let mut config = valid_config();
        config.auth.password_min_length = 12;
        config.auth.password_max_length = 8;

        assert_eq!(
            config.validate(),
            Err(ConfigValidationError::PasswordMaxLengthMustCoverMinLength)
        );
    }

    #[test]
    fn config_rejects_oversized_verification_code_ttl() {
        let mut config = valid_config();
        config.auth.verification_code_ttl_secs = 3_601;

        assert_eq!(
            config.validate(),
            Err(ConfigValidationError::VerificationCodeTtlTooLarge)
        );
    }
}

use argon2::{
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use rand_core::OsRng;

use crate::{AuthConfig, StoreError};

use super::ContractValidationError;

pub(crate) fn validate_registration_password(
    config: &AuthConfig,
    password: &str,
) -> Result<(), ContractValidationError> {
    let length = password.chars().count();
    if length < config.password_min_length {
        return Err(ContractValidationError::PasswordTooShort {
            min_length: config.password_min_length,
        });
    }

    if length > config.password_max_length {
        return Err(ContractValidationError::PasswordTooLong {
            max_length: config.password_max_length,
        });
    }

    if !password.chars().any(|value| value.is_ascii_alphabetic()) {
        return Err(ContractValidationError::PasswordRequiresLetter);
    }

    if !password.chars().any(|value| value.is_ascii_digit()) {
        return Err(ContractValidationError::PasswordRequiresNumber);
    }

    Ok(())
}

pub(crate) fn hash_password(password: &str) -> Result<String, StoreError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| StoreError::Backend(format!("password.hash_failed:{error}")))
}

pub(crate) fn verify_password(password_hash: &str, password: &str) -> Result<bool, StoreError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|error| StoreError::Backend(format!("password.hash_invalid:{error}")))?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(PasswordHashError::Password) => Ok(false),
        Err(error) => Err(StoreError::Backend(format!(
            "password.verify_failed:{error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crate::{AuthConfig, ContractValidationError, StoreError};

    use super::{hash_password, validate_registration_password, verify_password};

    #[test]
    fn hash_and_verify_round_trip() {
        let password_hash = hash_password("demo-password").expect("hash password");

        assert!(password_hash.starts_with("$argon2id$"));
        assert_eq!(verify_password(&password_hash, "demo-password"), Ok(true));
    }

    #[test]
    fn verify_password_rejects_wrong_password() {
        let password_hash = hash_password("demo-password").expect("hash password");

        assert_eq!(verify_password(&password_hash, "wrong-password"), Ok(false));
    }

    #[test]
    fn verify_password_rejects_invalid_hash_payload() {
        let result = verify_password("invalid-hash", "demo-password");

        assert!(matches!(result, Err(StoreError::Backend(_))));
    }

    fn auth_config() -> AuthConfig {
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86_400,
            session_ttl_secs: 604_800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        }
    }

    #[test]
    fn registration_password_rejects_short_password() {
        assert_eq!(
            validate_registration_password(&auth_config(), "short"),
            Err(ContractValidationError::PasswordTooShort { min_length: 8 })
        );
    }

    #[test]
    fn registration_password_rejects_oversized_password() {
        let password = "a".repeat(129);

        assert_eq!(
            validate_registration_password(&auth_config(), &password),
            Err(ContractValidationError::PasswordTooLong { max_length: 128 })
        );
    }

    #[test]
    fn registration_password_requires_letter_and_number() {
        assert_eq!(
            validate_registration_password(&auth_config(), "12345678"),
            Err(ContractValidationError::PasswordRequiresLetter)
        );
        assert_eq!(
            validate_registration_password(&auth_config(), "password"),
            Err(ContractValidationError::PasswordRequiresNumber)
        );
    }
}

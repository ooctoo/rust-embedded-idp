use crate::{AuthConfig, SecretString};

use super::RegistrationEmailError;

/// Validate and hash a registration password inside the IDP's existing
/// Argon2/password policy. Client-provided password hashes are never accepted.
pub fn prepare_registration_password(
    password: &SecretString,
) -> Result<SecretString, RegistrationEmailError> {
    let config = AuthConfig {
        allow_local_registration: true,
        access_token_ttl_secs: 1,
        refresh_token_ttl_secs: 2,
        session_ttl_secs: 2,
        verification_code_ttl_secs: 1,
        password_min_length: 8,
        password_max_length: 128,
    };
    crate::service::password::validate_registration_password(&config, password.expose_secret())
        .map_err(|_| RegistrationEmailError::InvalidInput("password"))?;
    let password_hash = crate::service::password::hash_password(password.expose_secret())
        .map_err(RegistrationEmailError::Store)?;
    Ok(SecretString::new(password_hash))
}

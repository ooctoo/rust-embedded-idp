use super::*;
use crate::SecretString;

/// Prepared only by the IDP core. No caller-supplied password hash enters this contract.
pub struct PreparedRegistrationEmail {
    scope: RegistrationEmailScope,
    operation: Uuid,
    context: Uuid,
    seed: [u8; 32],
    subject: [u8; 32],
    lookup: [u8; 32],
    request: [u8; 32],
    email_cipher: Vec<u8>,
    password_cipher: Vec<u8>,
}
impl std::fmt::Debug for PreparedRegistrationEmail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedRegistrationEmail(<redacted>)")
    }
}
impl PreparedRegistrationEmail {
    pub fn prepare(
        scope: &RegistrationEmailScope,
        crypto: &impl RegistrationEmailCrypto,
        operation: Uuid,
        email: &str,
        password: &SecretString,
        display_name: Option<&str>,
    ) -> Result<Self, RegistrationEmailError> {
        let email = CanonicalRegistrationEmail::parse(email)?;
        if display_name.is_some_and(|s| {
            s.is_empty() || s.chars().count() > 128 || s.chars().any(char::is_control)
        }) {
            return Err(RegistrationEmailError::InvalidInput("display_name"));
        }
        let hash = prepare_registration_password(password)?;
        let context = Uuid::now_v7();
        let seed = crypto.random_seed()?;
        let token = crypto.context_token(scope, &seed);
        let payload = encode_fields(&[
            email.identity().as_bytes(),
            password.expose_secret().as_bytes(),
            display_name.unwrap_or("").as_bytes(),
        ]);
        let candidate = encode_fields(&[
            hash.expose_secret().as_bytes(),
            display_name.unwrap_or("").as_bytes(),
        ]);
        Ok(Self {
            scope: scope.clone(),
            operation,
            context,
            seed,
            subject: crypto.subject(scope, &email),
            lookup: crypto.context_digest(token.expose_secret()),
            request: crypto.request_digest(
                scope,
                RegistrationEmailOperationKind::Register,
                &operation,
                &payload,
            ),
            email_cipher: crypto.seal("email", scope, &context, email.identity().as_bytes())?,
            password_cipher: crypto.seal("candidate", scope, &context, &candidate)?,
        })
    }
    pub fn scope(&self) -> &RegistrationEmailScope {
        &self.scope
    }
    pub fn operation(&self) -> Uuid {
        self.operation
    }
    pub fn context(&self) -> Uuid {
        self.context
    }
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
    pub fn subject(&self) -> &[u8; 32] {
        &self.subject
    }
    pub fn lookup(&self) -> &[u8; 32] {
        &self.lookup
    }
    pub fn request(&self) -> &[u8; 32] {
        &self.request
    }
    pub fn email_cipher(&self) -> &[u8] {
        &self.email_cipher
    }
    pub fn password_cipher(&self) -> &[u8] {
        &self.password_cipher
    }
}
fn encode_fields(values: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}
pub fn decode_registration_candidate(
    bytes: &[u8],
) -> Result<(SecretString, Option<String>), RegistrationEmailError> {
    let mut rest = bytes;
    let mut take = || -> Result<String, RegistrationEmailError> {
        if rest.len() < 4 {
            return Err(RegistrationEmailError::Unavailable);
        }
        let n = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        if n > 1024 || rest.len() < 4 + n {
            return Err(RegistrationEmailError::Unavailable);
        }
        let s = std::str::from_utf8(&rest[4..4 + n])
            .map_err(|_| RegistrationEmailError::Unavailable)?
            .to_string();
        rest = &rest[4 + n..];
        Ok(s)
    };
    let hash = take()?;
    let name = take()?;
    if !rest.is_empty()
        || !hash.starts_with("$argon2id$")
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
    {
        return Err(RegistrationEmailError::Unavailable);
    }
    Ok((
        SecretString::new(hash),
        if name.is_empty() { None } else { Some(name) },
    ))
}

use std::fmt;

use super::RegistrationEmailError;

/// The first registration profile accepts ASCII mailboxes only.
///
/// Domain labels are lower-cased for identity; the local part keeps its
/// spelling. Abuse accounting can use [`Self::abuse_identity`] separately,
/// which lower-cases the ASCII local part without applying provider aliases.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalRegistrationEmail(String);

impl CanonicalRegistrationEmail {
    pub fn parse(value: &str) -> Result<Self, RegistrationEmailError> {
        let value = value.trim_matches(' ');
        if value.is_empty() || value.len() > 254 {
            return Err(RegistrationEmailError::InvalidInput("email"));
        }
        if value
            .chars()
            .any(|character| !character.is_ascii() || character.is_ascii_control())
        {
            return Err(RegistrationEmailError::InvalidInput("email"));
        }
        if value.bytes().filter(|byte| *byte == b'@').count() != 1 {
            return Err(RegistrationEmailError::InvalidInput("email"));
        }

        let (local, domain) = value
            .split_once('@')
            .ok_or(RegistrationEmailError::InvalidInput("email"))?;
        if local.is_empty() || local.len() > 64 || !valid_dot_atom(local) {
            return Err(RegistrationEmailError::InvalidInput("email"));
        }

        let domain = domain.to_ascii_lowercase();
        if !valid_domain(&domain) {
            return Err(RegistrationEmailError::InvalidInput("email"));
        }

        let identity = format!("{local}@{domain}");
        if identity.len() > 254 {
            return Err(RegistrationEmailError::InvalidInput("email"));
        }
        Ok(Self(identity))
    }

    pub fn identity(&self) -> &str {
        &self.0
    }

    pub fn abuse_identity(&self) -> String {
        let (local, domain) = self
            .0
            .split_once('@')
            .expect("canonical email always contains one @");
        format!("{}@{domain}", local.to_ascii_lowercase())
    }
}

impl fmt::Debug for CanonicalRegistrationEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalRegistrationEmail(<redacted>)")
    }
}
impl fmt::Display for CanonicalRegistrationEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

fn valid_dot_atom(local: &str) -> bool {
    let bytes = local.as_bytes();
    !bytes.is_empty()
        && bytes[0] != b'.'
        && bytes[bytes.len() - 1] != b'.'
        && !local.contains("..")
        && bytes.iter().all(|byte| *byte == b'.' || is_atext(*byte))
}

fn is_atext(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
}

fn valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

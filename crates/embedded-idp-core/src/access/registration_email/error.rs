use std::fmt;

use crate::StoreError;

/// Errors shared by the registration core, storage, and crypto boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationEmailError {
    InvalidInput(&'static str),
    RequestExpired,
    RequestConflict,
    Unavailable,
    RegistrationClosed,
    Store(StoreError),
}

impl From<StoreError> for RegistrationEmailError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for RegistrationEmailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(formatter, "invalid registration input: {field}"),
            Self::RequestExpired => formatter.write_str("registration request expired"),
            Self::RequestConflict => formatter.write_str("registration request conflict"),
            Self::RegistrationClosed => formatter.write_str("registration closed"),
            Self::Unavailable => formatter.write_str("registration unavailable"),
            // Keep backend details out of a public error's Display implementation.
            Self::Store(_) => formatter.write_str("registration store unavailable"),
        }
    }
}

impl std::error::Error for RegistrationEmailError {}

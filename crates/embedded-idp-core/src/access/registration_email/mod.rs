//! Core contracts and deterministic policy helpers for email registration.
//!
//! This module is deliberately independent of HTTP, delivery, and persistence.
//! Storage adapters consume the scope, policy, freshness, and state helpers;
//! cryptographic adapters implement [`RegistrationEmailCrypto`].

mod crypto;
mod email;
mod error;
mod freshness;
mod material;
mod operation;
mod password;
mod policy;
mod rolling;
mod scope;
mod state;
mod validation;

pub use crypto::RegistrationEmailCrypto;
pub use email::CanonicalRegistrationEmail;
pub use error::RegistrationEmailError;
pub use freshness::check_registration_operation_freshness;
pub use material::{decode_registration_candidate, PreparedRegistrationEmail};
pub use operation::RegistrationEmailOperationKind;
pub use password::prepare_registration_password;
pub use policy::RegistrationEmailPolicy;
pub use rolling::{
    failure_block_until, fixed_block_until, rolling_allowed, rolling_history, trim_rolling_history,
};
pub use scope::RegistrationEmailScope;
pub use state::{classify_registration_email_code_state, RegistrationEmailCodeState};

// The crypto and storage adapters use the same UUID type as this core contract.
pub use uuid::Uuid;

#[cfg(test)]
mod tests;

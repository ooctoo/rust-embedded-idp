//! Tenant-scoped identity and authorization for trusted embedding hosts.
//!
//! Registration and authentication issue identities; authorization checks grants.
//! Hosts enforce resource ownership and choose trusted login entry policies.
//! PostgreSQL adapters live in storage; constructing these services does not
//! automatically mount HTTP routes or enable tenant-aware device flows.

mod admin;
mod authentication;
mod bootstrap;
mod device_operation;
mod device_proof;
mod model;
mod query;
mod registration;
mod scan_login;
mod service;
mod store;

pub use admin::*;
pub use authentication::*;
pub use bootstrap::*;
pub use device_operation::*;
pub use device_proof::*;
pub use model::*;
pub use query::*;
pub use registration::*;
pub use scan_login::*;
pub use service::*;
pub use store::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessError {
    InvalidInput(&'static str),
    InvalidCatalog(&'static str),
    InvalidCursor,
    ModeMismatch,
    FeatureDisabled,
    Forbidden,
    NotFound(&'static str),
    Conflict(&'static str),
    /// Backend failure is distinct from an ordinary Deny. Never grant on error.
    Store(crate::StoreError),
    InvalidStoreResponse,
}

impl From<crate::StoreError> for AccessError {
    fn from(error: crate::StoreError) -> Self {
        match error {
            crate::StoreError::Conflict(field) => Self::Conflict(field),
            crate::StoreError::NotFound(field) => Self::NotFound(field),
            error @ crate::StoreError::Backend(_) => Self::Store(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod admin_tests;

#[cfg(test)]
mod authentication_tests;

#[cfg(test)]
mod registration_tests;

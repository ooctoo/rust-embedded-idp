//! Explicit installation and inspection of the registration-email foundation.
//!
//! This module is intentionally separate from the `tenant_v6` migration.  A
//! normal host startup must only inspect this state; installation is an
//! operator action with a read/verify/apply transaction boundary.

mod apply;
mod catalog;
mod inspect;
mod inventory;

use embedded_idp_core::{access::TenancyMode, StoreError};
use postgres::GenericClient;

use crate::PostgresStorageAdapter;

pub use embedded_idp_core::access::RegistrationEmailScope;

pub const REGISTRATION_EMAIL_SCHEMA_VERSION: &str = "registration_email_v1";
pub const REGISTRATION_EMAIL_MIN_POSTGRES_VERSION: i32 = 170000;
pub(crate) const REGISTRATION_EMAIL_BACKEND_ERROR: &str = "registration storage unavailable";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEmailMigrationPlan {
    pub schema_name: String,
    pub database_name: String,
    pub mode: TenancyMode,
    pub version: String,
    pub access_schema_version: String,
    pub fingerprint: String,
    pub account_count: i64,
    /// Number of valid account identities whose stored spelling will change.
    pub normalized_count: i64,
    pub normalization_collision_count: i64,
    pub invalid_email_count: i64,
    pub legacy_code_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEmailFoundationFacts {
    pub schema_name: String,
    pub state_present: bool,
    pub version: Option<String>,
    pub authority: Option<String>,
    pub mode: Option<TenancyMode>,
    pub installed_at: Option<i64>,
    pub binding_present: bool,
    pub binding_matches: bool,
    pub tables_complete: bool,
    pub columns_complete: bool,
    pub indexes_complete: bool,
    pub triggers_complete: bool,
    pub constraints_complete: bool,
    pub legacy_codes_consumed: bool,
    /// The HTTP and worker profile is deliberately not claimed by I1.
    pub public_profile_ready: bool,
}

impl PostgresStorageAdapter {
    /// Read the account/email cutover inventory.  This never creates or
    /// changes a relation and is safe to call during ordinary readiness.
    pub fn registration_email_migration_plan(
        &self,
        mode: TenancyMode,
    ) -> Result<RegistrationEmailMigrationPlan, StoreError> {
        inventory::plan(self, mode)
    }

    /// Install the foundation after the caller has reviewed the exact plan.
    /// All account normalization, legacy-code consumption, DDL and state
    /// insertion commit as one transaction or are rolled back together.
    pub fn apply_registration_email_foundation(
        &self,
        plan: &RegistrationEmailMigrationPlan,
        authority: &str,
        mode: TenancyMode,
    ) -> Result<(), StoreError> {
        apply::foundation(self, plan, authority, mode)
    }

    /// Bind one trusted offline product/tenant scope after foundation install.
    pub fn bind_registration_email_product(
        &self,
        scope: &RegistrationEmailScope,
    ) -> Result<(), StoreError> {
        apply::bind_product(self, scope)
    }

    /// Read the foundation shape and the exact configured product binding.
    /// This method is read-only and intentionally reports the public profile
    /// as unavailable until the HTTP/worker slice is delivered.
    pub fn inspect_registration_email_foundation(
        &self,
        scope: &RegistrationEmailScope,
    ) -> Result<RegistrationEmailFoundationFacts, StoreError> {
        inspect::foundation(self, scope)
    }
}

pub(crate) fn mode_name(mode: TenancyMode) -> &'static str {
    match mode {
        TenancyMode::Disabled => "disabled",
        TenancyMode::Enabled => "enabled",
    }
}

pub(crate) fn parse_mode(value: &str) -> Result<TenancyMode, StoreError> {
    match value {
        "disabled" => Ok(TenancyMode::Disabled),
        "enabled" => Ok(TenancyMode::Enabled),
        _ => Err(StoreError::Backend(
            "registration email stored tenancy mode is invalid".to_string(),
        )),
    }
}

pub(crate) fn validate_namespace(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
        })
    {
        return Err(StoreError::Conflict(field));
    }
    Ok(())
}

pub(crate) fn validate_scope(scope: &RegistrationEmailScope) -> Result<(), StoreError> {
    validate_namespace(&scope.authority, "registration_email.authority")?;
    validate_namespace(&scope.product, "registration_email.product")?;
    scope
        .mode
        .validate_business_tenant(&scope.tenant)
        .map_err(|_| StoreError::Conflict("registration_email.tenant"))
}

pub(crate) const BOUNDED_TRANSACTION_SQL: &str = "set local transaction_timeout='10s'; \
             set local statement_timeout='10s'; \
             set local lock_timeout='10s'; \
             set local idle_in_transaction_session_timeout='10s'";

pub(crate) fn configure_bounded_transaction<C: GenericClient>(
    client: &mut C,
    backend_error: &'static str,
) -> Result<(), StoreError> {
    let version: i32 = client
        .query_one("select current_setting('server_version_num')::int", &[])
        .map_err(|_| StoreError::Backend(backend_error.to_string()))?
        .get(0);
    if version < REGISTRATION_EMAIL_MIN_POSTGRES_VERSION {
        return Err(StoreError::Conflict(
            "registration_email.unsupported_postgres",
        ));
    }
    client
        .batch_execute(BOUNDED_TRANSACTION_SQL)
        .map_err(|_| StoreError::Backend(backend_error.to_string()))
}

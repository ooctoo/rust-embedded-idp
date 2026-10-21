//! IDP-owned registration foundation. No HTTP route or mail worker is mounted here.
mod activation;
mod admission;
mod capacity;
mod maintenance;
mod processing;
mod runtime;
mod runtime_guard;
mod support;
mod types;
mod verification;
use crate::PostgresStorageAdapter;
use embedded_idp_core::access::*;
use std::sync::Arc;
pub use types::*;

#[derive(Clone)]
pub struct PostgresRegistrationEmailStore<C: RegistrationEmailCrypto> {
    adapter: PostgresStorageAdapter,
    scope: RegistrationEmailScope,
    policy: RegistrationEmailPolicy,
    crypto: Arc<C>,
    password_budget: embedded_idp_core::PasswordWorkBudget,
}
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub fn new(
        adapter: PostgresStorageAdapter,
        scope: RegistrationEmailScope,
        policy: RegistrationEmailPolicy,
        crypto: Arc<C>,
    ) -> Result<Self, RegistrationEmailError> {
        policy.validate()?;
        RegistrationEmailScope::new(&scope.authority, &scope.product, &scope.tenant, scope.mode)?;
        let facts = adapter
            .inspect_registration_email_foundation(&scope)
            .map_err(RegistrationEmailError::Store)?;
        if !facts.state_present
            || !facts.binding_matches
            || !facts.tables_complete
            || !facts.columns_complete
            || !facts.indexes_complete
            || !facts.constraints_complete
            || !facts.triggers_complete
            || !facts.legacy_codes_consumed
            || facts.mode != Some(scope.mode)
            || facts.version.as_deref() != Some(crate::REGISTRATION_EMAIL_SCHEMA_VERSION)
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        let mut connection = adapter.connect().map_err(RegistrationEmailError::Store)?;
        let version: i32 = connection
            .query_one("select current_setting('server_version_num')::int", &[])
            .map_err(support::db)?
            .get(0);
        if version < 170000 {
            return Err(RegistrationEmailError::Unavailable);
        }
        Ok(Self {
            adapter,
            scope,
            policy,
            crypto,
            password_budget: embedded_idp_core::PasswordWorkBudget::default(),
        })
    }
    pub fn with_password_work_budget(
        mut self,
        budget: embedded_idp_core::PasswordWorkBudget,
    ) -> Self {
        self.password_budget = budget;
        self
    }
    pub fn scope(&self) -> &RegistrationEmailScope {
        &self.scope
    }
    pub fn policy(&self) -> &RegistrationEmailPolicy {
        &self.policy
    }
}

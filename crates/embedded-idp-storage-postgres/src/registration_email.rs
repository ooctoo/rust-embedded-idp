//! IDP-owned registration foundation. No HTTP route or mail worker is mounted here.
mod activation;
mod admission;
mod capacity;
mod maintenance;
mod processing;
mod runtime;
mod runtime_guard;
mod support;
pub(crate) mod transport;
mod types;
mod verification;
use crate::PostgresStorageAdapter;
use embedded_idp_core::access::*;
use std::sync::Arc;
pub use types::*;

#[derive(Clone)]
pub struct PostgresRegistrationEmailStore<C: RegistrationEmailCrypto> {
    adapter: PostgresStorageAdapter,
    transport: transport::Transport,
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
        let transport = adapter.registration_transport()?;
        Ok(Self {
            adapter,
            transport,
            scope,
            policy,
            crypto,
            password_budget: embedded_idp_core::PasswordWorkBudget::default(),
        })
    }
    fn connect(&self) -> Result<transport::Client, RegistrationEmailError> {
        self.transport
            .connect(std::time::Duration::from_secs(
                self.policy.db_transaction_deadline_secs as u64,
            ))
            .map_err(support::db)
    }
    fn connect_readonly(&self) -> Result<transport::Client, RegistrationEmailError> {
        self.transport
            .connect(std::time::Duration::from_secs(5))
            .map_err(support::db)
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

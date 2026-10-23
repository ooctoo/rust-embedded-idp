mod legacy;
mod runners;
#[cfg(test)]
mod tests;
use crate::transport::{Client, Error, Transport};
use crate::{MigrationPlan, PgStorageConfig, PgStorageConfigError, SecurityCutoverPlan};
use embedded_idp_core::StoreError;
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};
/// An owned physical connection lease; no idle synchronous pool remains.
pub type PgPooledConnection = Client;
#[derive(Clone)]
pub struct PostgresStorageAdapter {
    config: PgStorageConfig,
    transport: Arc<Mutex<Option<Transport>>>,
}
impl fmt::Debug for PostgresStorageAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresStorageAdapter")
            .field("schema_name", &self.config.connection.schema_name)
            .field("application_name", &self.config.pool.application_name)
            .field("max_connections", &self.config.pool.max_connections)
            .finish_non_exhaustive()
    }
}
impl PartialEq for PostgresStorageAdapter {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}
impl Eq for PostgresStorageAdapter {}
impl PostgresStorageAdapter {
    pub fn new(config: PgStorageConfig) -> Result<Self, PgStorageConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            transport: Arc::new(Mutex::new(None)),
        })
    }
    pub(crate) fn transport(&self) -> Result<Transport, Error> {
        let mut slot = self.transport.lock().map_err(|_| Error::Closed)?;
        if let Some(transport) = slot.as_ref() {
            return Ok(transport.clone());
        }
        let transport = Transport::new(&self.config)?;
        *slot = Some(transport.clone());
        Ok(transport)
    }
    pub fn config(&self) -> &PgStorageConfig {
        &self.config
    }
    pub fn migration_plan(&self) -> MigrationPlan {
        MigrationPlan::for_schema(self.config.connection.schema_name.clone())
    }
    pub fn security_cutover_plan(&self) -> SecurityCutoverPlan {
        SecurityCutoverPlan::for_schema(self.config.connection.schema_name.clone())
    }
    /// Ten seconds across acquisition, caller idle time, all SQL and commit.
    pub fn connect(&self) -> Result<PgPooledConnection, StoreError> {
        self.connect_with_budget(Duration::from_secs(10))
    }
    /// Explicit setup only: existing script transaction/lock boundaries remain.
    pub(crate) fn connect_for_setup(&self) -> Result<Client, StoreError> {
        self.connect_with_budget(Duration::from_secs(60))
    }
    fn connect_with_budget(&self, budget: Duration) -> Result<Client, StoreError> {
        self.transport()
            .and_then(|t| t.connect(budget))
            .map_err(|_| StoreError::Backend("postgres connection unavailable".into()))
    }
}

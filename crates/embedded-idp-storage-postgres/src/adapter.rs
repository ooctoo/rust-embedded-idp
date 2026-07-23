use std::time::Duration;

use embedded_idp_core::{StoreError, StoreTransactionRunner};
use native_tls::{Certificate, TlsConnector};
use postgres::{Client, Config as PgClientConfig, NoTls};
use postgres_native_tls::MakeTlsConnector;

use crate::{
    MigrationPlan, PgStorageConfig, PgStorageConfigError, PgTlsMode, PostgresStoreTransaction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresStorageAdapter {
    config: PgStorageConfig,
}

impl PostgresStorageAdapter {
    pub fn new(config: PgStorageConfig) -> Result<Self, PgStorageConfigError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &PgStorageConfig {
        &self.config
    }

    pub fn migration_plan(&self) -> MigrationPlan {
        MigrationPlan::for_schema(self.config.connection.schema_name.clone())
    }

    pub fn connect(&self) -> Result<Client, StoreError> {
        let mut config = self
            .config
            .connection
            .connection_uri
            .parse::<PgClientConfig>()
            .map_err(|error| StoreError::Backend(format!("invalid postgres uri: {error}")))?;
        config.application_name(&self.config.pool.application_name);
        config.connect_timeout(Duration::from_secs(self.config.pool.connect_timeout_secs));

        match self.config.connection.tls_mode {
            PgTlsMode::Disable | PgTlsMode::Prefer => config
                .connect(NoTls)
                .map_err(|error| StoreError::Backend(format!("postgres connect failed: {error}"))),
            PgTlsMode::Require => config.connect(self.tls_connector()?).map_err(|error| {
                StoreError::Backend(format!("postgres tls connect failed: {error}"))
            }),
        }
    }

    pub fn schema_name(&self) -> &str {
        &self.config.connection.schema_name
    }

    pub fn apply_migrations(&self) -> Result<(), StoreError> {
        let mut client = self.connect()?;
        for step in self.migration_plan().steps {
            client.batch_execute(&step.sql).map_err(|error| {
                StoreError::Backend(format!("apply migration {} failed: {error}", step.version))
            })?;
        }
        Ok(())
    }

    fn tls_connector(&self) -> Result<MakeTlsConnector, StoreError> {
        let mut builder = TlsConnector::builder();

        if let Some(ca_cert_path) = self.config.connection.tls_ca_cert_path.as_deref() {
            let pem = std::fs::read(ca_cert_path).map_err(|error| {
                StoreError::Backend(format!("read postgres tls ca cert failed: {error}"))
            })?;
            let cert = Certificate::from_pem(&pem).map_err(|error| {
                StoreError::Backend(format!("parse postgres tls ca cert failed: {error}"))
            })?;
            builder.add_root_certificate(cert);
        }

        let connector = builder.build().map_err(|error| {
            StoreError::Backend(format!("build postgres tls connector failed: {error}"))
        })?;
        Ok(MakeTlsConnector::new(connector))
    }
}

impl StoreTransactionRunner for PostgresStorageAdapter {
    type Transaction<'a>
        = PostgresStoreTransaction<'a>
    where
        Self: 'a;

    fn transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut client = self.connect()?;
        let tx = client
            .transaction()
            .map_err(|error| StoreError::Backend(format!("begin transaction failed: {error}")))?;
        let mut wrapped = PostgresStoreTransaction::new(self.schema_name(), tx);

        let result = run(&mut wrapped);
        let tx = wrapped
            .into_inner()
            .expect("postgres transaction should be present");

        match result {
            Ok(value) => {
                tx.commit().map_err(|error| {
                    StoreError::Backend(format!("commit transaction failed: {error}"))
                })?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().map_err(|rollback_error| {
                    StoreError::Backend(format!("rollback transaction failed: {rollback_error}"))
                })?;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use embedded_idp_core::StoreError;

    use crate::{DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode};

    use super::PostgresStorageAdapter;

    fn config() -> PgStorageConfig {
        PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: "postgres://localhost:5432/embedded_idp".to_string(),
                schema_name: "embedded_idp".to_string(),
                tls_mode: PgTlsMode::Prefer,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "embedded-idp-host".to_string(),
                max_connections: 10,
                connect_timeout_secs: 5,
            },
        }
    }

    #[test]
    fn adapter_keeps_host_provided_config() {
        let adapter = PostgresStorageAdapter::new(config()).expect("config should be valid");

        assert_eq!(adapter.config().connection.schema_name, "embedded_idp");
        assert_eq!(
            adapter.config().connection.connection_uri,
            "postgres://localhost:5432/embedded_idp"
        );
    }

    #[test]
    fn migration_plan_uses_configured_schema() {
        let mut config = config();
        config.connection.schema_name = "tenant_a_idp".to_string();
        let adapter = PostgresStorageAdapter::new(config).expect("config should be valid");

        let plan = adapter.migration_plan();
        assert_eq!(plan.schema_name, "tenant_a_idp");
        assert_eq!(plan.tables[0], "accounts");
        assert_eq!(plan.tables[2], "account_device_bindings");
        assert_eq!(plan.tables[3], "oidc_clients");
        assert_eq!(plan.tables[6], "authorization_codes");
    }

    #[test]
    fn tls_require_builds_connector() {
        let mut config = config();
        config.connection.tls_mode = PgTlsMode::Require;
        let adapter = PostgresStorageAdapter::new(config).expect("config should be valid");

        adapter.tls_connector().expect("tls connector should build");
    }

    #[test]
    fn tls_require_rejects_missing_ca_file() {
        let mut config = config();
        config.connection.tls_mode = PgTlsMode::Require;
        config.connection.tls_ca_cert_path = Some("/tmp/embedded-idp-missing-ca.pem".to_string());
        let adapter = PostgresStorageAdapter::new(config).expect("config should be valid");

        match adapter.tls_connector() {
            Ok(_) => panic!("missing ca path should fail"),
            Err(error) => assert_eq!(
                error,
                StoreError::Backend(
                    "read postgres tls ca cert failed: No such file or directory (os error 2)"
                        .to_string()
                )
            ),
        }
    }

    #[test]
    fn apply_migrations_uses_rendered_plan_sql() {
        let adapter = PostgresStorageAdapter::new(config()).expect("config should be valid");
        let plan = adapter.migration_plan();

        assert_eq!(plan.steps.len(), 1);
        assert!(plan.steps[0]
            .sql
            .contains("create table if not exists embedded_idp.accounts"));
        assert!(plan.steps[0]
            .sql
            .contains("create table if not exists embedded_idp.oidc_clients"));
        assert!(plan.steps[0]
            .sql
            .contains("alter table if exists embedded_idp.auth_sessions"));
    }
}

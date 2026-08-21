use std::time::Duration;

use embedded_idp_core::{
    DeviceSecurityError, DeviceSecurityTransactionRunner, ProofBoundRefreshError,
    ProofBoundRefreshTransactionRunner, StoreError, StoreTransactionRunner,
};
use native_tls::{Certificate, TlsConnector};
use postgres::{Client, Config as PgClientConfig, NoTls};
use postgres_native_tls::MakeTlsConnector;

use crate::{
    MigrationPlan, PgStorageConfig, PgStorageConfigError, PgTlsMode, PostgresStoreTransaction,
    SchemaHealthFacts, SecurityCutoverPlan, MAXIMUM_ONLINE_SCHEMA_VERSION,
    MINIMUM_ONLINE_SCHEMA_VERSION, PRODUCTION_SECURITY_CUTOVER_ID,
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

    pub fn security_cutover_plan(&self) -> SecurityCutoverPlan {
        SecurityCutoverPlan::for_schema(self.config.connection.schema_name.clone())
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

    /// Performs the explicit, credential-invalidating security cutover.
    ///
    /// Hosts must drain every legacy identity writer and verify a backup before
    /// calling this operation. It is intentionally separate from additive
    /// migrations and is idempotent after its durable marker commits.
    pub fn apply_security_cutover(&self) -> Result<(), StoreError> {
        let mut client = self.connect()?;
        let plan = self.security_cutover_plan();
        client.batch_execute(&plan.sql).map_err(|error| {
            StoreError::Backend(format!(
                "apply security cutover {} failed: {error}",
                plan.version
            ))
        })
    }

    pub fn inspect_schema_health(&self) -> Result<SchemaHealthFacts, StoreError> {
        let mut client = self.connect()?;
        client
            .query_one("select 1", &[])
            .map_err(|error| StoreError::Backend(format!("postgres probe failed: {error}")))?;
        let schema = self.schema_name();
        let ledger_name = format!("{schema}.schema_versions");
        let ledger_exists = client
            .query_one("select to_regclass($1)::text", &[&ledger_name])
            .map_err(|error| {
                StoreError::Backend(format!("inspect schema version ledger failed: {error}"))
            })?
            .get::<_, Option<String>>(0)
            .is_some();
        if !ledger_exists {
            return Ok(SchemaHealthFacts {
                minimum_supported_schema: MINIMUM_ONLINE_SCHEMA_VERSION,
                maximum_supported_schema: MAXIMUM_ONLINE_SCHEMA_VERSION,
                observed_schema: None,
                security_cutover_present: false,
                invariants_valid: false,
                postgres_probe_succeeded: true,
            });
        }

        let version_sql = format!("select version from {schema}.schema_versions");
        let versions = client
            .query(&version_sql, &[])
            .map_err(|error| StoreError::Backend(format!("read schema versions failed: {error}")))?
            .into_iter()
            .map(|row| row.get::<_, String>("version"))
            .collect::<Vec<_>>();
        let observed_schema = observed_schema_version(&versions);
        let supported_versions = versions
            .iter()
            .all(|version| matches!(version.as_str(), "0001" | "0002_expand" | "0003_enforce"));

        let cutover_sql = format!(
            "select exists (select 1 from {schema}.security_cutovers where cutover_id = $1)"
        );
        let security_cutover_present = client
            .query_one(&cutover_sql, &[&PRODUCTION_SECURITY_CUTOVER_ID])
            .map_err(|error| {
                StoreError::Backend(format!("inspect security cutover failed: {error}"))
            })?
            .get::<_, bool>(0);

        let invariant_sql = format!(
            "select \
                not exists (select 1 from {schema}.refresh_tokens where octet_length(token_digest) <> 32 or (revoked_at_epoch is null) <> (revocation_reason is null) or (revocation_reason is not null and revocation_reason not in ('rotated', 'reuse_detected', 'logout', 'client_revocation', 'administrative', 'security_cutover'))) \
                and not exists (select 1 from {schema}.device_nonces where octet_length(challenge_digest) <> 32 or purpose !~ '^[a-z][a-z0-9_]{{0,63}}$') \
                and not exists (select 1 from {schema}.device_proof_keys where (status = 'active') <> (retired_at_epoch is null)) \
                and not exists (select device_id from {schema}.device_proof_keys where status = 'active' group by device_id having count(*) > 1)"
        );
        let row_invariants_valid = client
            .query_one(&invariant_sql, &[])
            .map_err(|error| {
                StoreError::Backend(format!("inspect schema invariants failed: {error}"))
            })?
            .get::<_, bool>(0);
        let column_sql = "select count(*) = 3 from information_schema.columns where table_schema = $1 and ((table_name = 'refresh_tokens' and column_name = 'token_digest' and is_nullable = 'NO') or (table_name = 'device_nonces' and column_name in ('purpose', 'challenge_digest') and is_nullable = 'NO'))";
        let enforced_columns = client
            .query_one(column_sql, &[&schema])
            .map_err(|error| {
                StoreError::Backend(format!("inspect enforced columns failed: {error}"))
            })?
            .get::<_, bool>(0);

        Ok(SchemaHealthFacts {
            minimum_supported_schema: MINIMUM_ONLINE_SCHEMA_VERSION,
            maximum_supported_schema: MAXIMUM_ONLINE_SCHEMA_VERSION,
            observed_schema,
            security_cutover_present,
            invariants_valid: supported_versions && row_invariants_valid && enforced_columns,
            postgres_probe_succeeded: true,
        })
    }

    pub fn verify_online_schema(&self) -> Result<SchemaHealthFacts, StoreError> {
        let facts = self.inspect_schema_health()?;
        if facts.observed_schema.as_deref() != Some(MINIMUM_ONLINE_SCHEMA_VERSION)
            || !facts.security_cutover_present
            || !facts.invariants_valid
        {
            return Err(StoreError::Backend(format!(
                "online schema is not production-ready: observed={:?}, cutover={}, invariants={}",
                facts.observed_schema, facts.security_cutover_present, facts.invariants_valid
            )));
        }
        Ok(facts)
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

fn observed_schema_version(versions: &[String]) -> Option<String> {
    ["0003_enforce", "0002_expand", "0001"]
        .into_iter()
        .find(|candidate| versions.iter().any(|version| version == candidate))
        .map(str::to_string)
        .or_else(|| versions.iter().max().cloned())
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

impl ProofBoundRefreshTransactionRunner for PostgresStorageAdapter {
    type Transaction<'a>
        = PostgresStoreTransaction<'a>
    where
        Self: 'a;

    fn proof_bound_refresh_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, ProofBoundRefreshError>,
    ) -> Result<R, ProofBoundRefreshError> {
        let mut client = self.connect().map_err(ProofBoundRefreshError::Store)?;
        let tx = client.transaction().map_err(|error| {
            ProofBoundRefreshError::Store(StoreError::Backend(format!(
                "begin proof-bound refresh transaction failed: {error}"
            )))
        })?;
        let mut wrapped = PostgresStoreTransaction::new(self.schema_name(), tx);
        let result = run(&mut wrapped);
        let tx = wrapped
            .into_inner()
            .expect("postgres transaction should be present");

        match result {
            Ok(value) => {
                tx.commit().map_err(|error| {
                    ProofBoundRefreshError::Store(StoreError::Backend(format!(
                        "commit proof-bound refresh transaction failed: {error}"
                    )))
                })?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().map_err(|rollback_error| {
                    ProofBoundRefreshError::Store(StoreError::Backend(format!(
                        "rollback proof-bound refresh transaction failed: {rollback_error}"
                    )))
                })?;
                Err(error)
            }
        }
    }
}

impl DeviceSecurityTransactionRunner for PostgresStorageAdapter {
    type Transaction<'a>
        = PostgresStoreTransaction<'a>
    where
        Self: 'a;

    fn device_security_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, DeviceSecurityError>,
    ) -> Result<R, DeviceSecurityError> {
        let mut client = self.connect().map_err(DeviceSecurityError::Store)?;
        let tx = client.transaction().map_err(|error| {
            DeviceSecurityError::Store(StoreError::Backend(format!(
                "begin device security transaction failed: {error}"
            )))
        })?;
        let mut wrapped = PostgresStoreTransaction::new(self.schema_name(), tx);
        let result = run(&mut wrapped);
        let tx = wrapped
            .into_inner()
            .expect("postgres transaction should be present");

        match result {
            Ok(value) => {
                tx.commit().map_err(|error| {
                    DeviceSecurityError::Store(StoreError::Backend(format!(
                        "commit device security transaction failed: {error}"
                    )))
                })?;
                Ok(value)
            }
            Err(error) => {
                tx.rollback().map_err(|rollback_error| {
                    DeviceSecurityError::Store(StoreError::Backend(format!(
                        "rollback device security transaction failed: {rollback_error}"
                    )))
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

    use super::{observed_schema_version, PostgresStorageAdapter};

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

        assert_eq!(plan.steps.len(), 2);
        assert!(plan.steps[0]
            .sql
            .contains("create table if not exists embedded_idp.accounts"));
        assert!(plan.steps[0]
            .sql
            .contains("create table if not exists embedded_idp.oidc_clients"));
        assert!(plan.steps[0]
            .sql
            .contains("alter table if exists embedded_idp.auth_sessions"));
        assert!(plan.steps[1]
            .sql
            .contains("create table if not exists embedded_idp.device_proof_keys"));
    }

    #[test]
    fn online_version_selection_is_closed_and_monotonic() {
        assert_eq!(
            observed_schema_version(&["0001".to_string(), "0002_expand".to_string()]),
            Some("0002_expand".to_string())
        );
        assert_eq!(
            observed_schema_version(&[
                "0001".to_string(),
                "0002_expand".to_string(),
                "0003_enforce".to_string(),
            ]),
            Some("0003_enforce".to_string())
        );
        assert_eq!(observed_schema_version(&[]), None);
    }
}

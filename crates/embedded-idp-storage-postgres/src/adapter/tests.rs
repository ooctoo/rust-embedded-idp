
use std::sync::Arc;

use crate::{DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode};

use super::{legacy::observed_schema_version, PostgresStorageAdapter};

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
fn adapter_construction_is_lazy_and_clones_share_transport_capacity() {
    let mut lazy_config = config();
    lazy_config.connection.connection_uri = "postgres://%".to_string();
    let adapter = PostgresStorageAdapter::new(lazy_config)
        .expect("new should validate host config without connecting or parsing it");
    let clone = adapter.clone();

    assert!(Arc::ptr_eq(&adapter.transport, &clone.transport));
    assert!(!format!("{adapter:?}").contains("postgres://%"));
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

    let mut config = adapter.config().clone();
    config.connection.connection_uri =
        "postgres://localhost:5432/embedded_idp?hostaddr=127.0.0.1".into();
    PostgresStorageAdapter::new(config)
        .unwrap()
        .transport()
        .expect("TLS transport should build");
}

#[test]
fn tls_require_rejects_missing_ca_file() {
    let mut config = config();
    config.connection.tls_mode = PgTlsMode::Require;
    config.connection.tls_ca_cert_path = Some("/tmp/embedded-idp-missing-ca.pem".to_string());
    let adapter = PostgresStorageAdapter::new(config).expect("config should be valid");

    assert!(adapter.transport().is_err());
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

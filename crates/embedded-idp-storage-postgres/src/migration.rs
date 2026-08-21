use crate::sql::{INITIAL_SCHEMA_SQL, SECURITY_ENFORCE_SQL, SECURITY_EXPAND_SQL};

pub const MINIMUM_ONLINE_SCHEMA_VERSION: &str = "0003_enforce";
pub const MAXIMUM_ONLINE_SCHEMA_VERSION: &str = "0003_enforce";
pub const PRODUCTION_SECURITY_CUTOVER_ID: &str = "production_security_v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStep {
    pub version: &'static str,
    pub description: &'static str,
    pub sql: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub schema_name: String,
    pub tables: [&'static str; 8],
    pub steps: Vec<MigrationStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCutoverPlan {
    pub schema_name: String,
    pub version: &'static str,
    pub description: &'static str,
    pub sql: String,
}

impl SecurityCutoverPlan {
    pub fn for_schema(schema_name: String) -> Self {
        Self {
            sql: render_security_enforce_sql(&schema_name),
            schema_name,
            version: "0003_enforce",
            description: "revoke legacy credentials and enforce production security schema",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaHealthFacts {
    pub minimum_supported_schema: &'static str,
    pub maximum_supported_schema: &'static str,
    pub observed_schema: Option<String>,
    pub security_cutover_present: bool,
    pub invariants_valid: bool,
    pub postgres_probe_succeeded: bool,
}

impl MigrationPlan {
    pub fn initial() -> Self {
        Self::for_schema("embedded_idp".to_string())
    }

    pub fn for_schema(schema_name: String) -> Self {
        let initial_sql = render_schema_sql(&schema_name);
        let security_expand_sql = render_security_expand_sql(&schema_name);
        Self {
            schema_name,
            tables: [
                "accounts",
                "devices",
                "account_device_bindings",
                "oidc_clients",
                "auth_sessions",
                "refresh_tokens",
                "authorization_codes",
                "device_nonces",
            ],
            steps: vec![
                MigrationStep {
                    version: "0001",
                    description: "initial embedded idp schema",
                    sql: initial_sql,
                },
                MigrationStep {
                    version: "0002_expand",
                    description: "production security additive schema",
                    sql: security_expand_sql,
                },
            ],
        }
    }
}

fn render_security_expand_sql(schema_name: &str) -> String {
    SECURITY_EXPAND_SQL.replace("__SCHEMA__", schema_name)
}

fn render_security_enforce_sql(schema_name: &str) -> String {
    SECURITY_ENFORCE_SQL.replace("__SCHEMA__", schema_name)
}

fn render_schema_sql(schema_name: &str) -> String {
    INITIAL_SCHEMA_SQL.replace("__SCHEMA__", schema_name)
}

#[cfg(test)]
mod tests {
    use super::{MigrationPlan, SecurityCutoverPlan};

    #[test]
    fn initial_plan_lists_core_tables() {
        let plan = MigrationPlan::initial();

        assert_eq!(plan.schema_name, "embedded_idp");
        assert_eq!(plan.tables[0], "accounts");
        assert_eq!(plan.tables[2], "account_device_bindings");
        assert_eq!(plan.tables[6], "authorization_codes");
        assert_eq!(plan.tables[7], "device_nonces");
        assert_eq!(plan.steps[0].version, "0001");
        assert_eq!(plan.steps[1].version, "0002_expand");
    }

    #[test]
    fn schema_can_be_overridden_by_host_config() {
        let plan = MigrationPlan::for_schema("custom_idp".to_string());

        assert_eq!(plan.schema_name, "custom_idp");
        assert_eq!(plan.tables[4], "auth_sessions");
        assert_eq!(plan.tables[6], "authorization_codes");
        assert!(plan.steps[0].sql.contains("custom_idp.accounts"));
        assert!(plan.steps[0]
            .sql
            .contains("create schema if not exists custom_idp;"));
    }

    #[test]
    fn initial_sql_mentions_all_v1_tables() {
        let sql = MigrationPlan::initial().steps[0].sql.clone();

        assert!(sql.contains("embedded_idp.accounts"));
        assert!(sql.contains("embedded_idp.oidc_clients"));
        assert!(sql.contains("embedded_idp.auth_sessions"));
        assert!(sql.contains("embedded_idp.devices"));
        assert!(sql.contains("embedded_idp.account_device_bindings"));
        assert!(sql.contains("embedded_idp.refresh_tokens"));
        assert!(sql.contains("embedded_idp.authorization_codes"));
        assert!(sql.contains("embedded_idp.device_nonces"));
    }

    #[test]
    fn devices_table_is_created_before_auth_sessions_device_fk() {
        let sql = MigrationPlan::initial().steps[0].sql.clone();
        let devices_pos = sql
            .find("create table if not exists embedded_idp.devices")
            .expect("devices table definition should exist");
        let sessions_pos = sql
            .find("create table if not exists embedded_idp.auth_sessions")
            .expect("auth_sessions table definition should exist");

        assert!(devices_pos < sessions_pos);
    }

    #[test]
    fn security_expand_adds_digest_and_key_storage_without_dropping_legacy_columns() {
        let sql = &MigrationPlan::initial().steps[1].sql;

        assert!(sql.contains("embedded_idp.device_proof_keys"));
        assert!(sql.contains("device_proof_keys_one_active_per_device"));
        assert!(sql.contains("unique (device_id, version)"));
        assert!(sql.contains("add column if not exists challenge_digest bytea null"));
        assert!(sql.contains("alter column challenge drop not null"));
        assert!(sql.contains("add column if not exists token_digest bytea null"));
        assert!(!sql.contains("drop column"));
        assert!(sql.contains("0002_expand"));
    }

    #[test]
    fn security_cutover_is_separate_idempotent_and_fail_closed() {
        let plan = SecurityCutoverPlan::for_schema("embedded_idp".to_string());

        assert_eq!(plan.version, "0003_enforce");
        assert!(plan.sql.contains("pg_advisory_lock"));
        assert!(plan.sql.contains("production_security_v2"));
        assert!(plan.sql.contains("set status = 'revoked'"));
        assert!(plan.sql.contains("update embedded_idp.authorization_codes"));
        assert!(plan.sql.contains("delete from embedded_idp.refresh_tokens"));
        assert!(plan.sql.contains("delete from embedded_idp.device_nonces"));
        assert!(plan.sql.contains("alter column token_digest set not null"));
        assert!(plan.sql.contains("octet_length(token_digest) = 32"));
        assert!(plan.sql.contains("revocation_reason is not null"));
        assert!(plan.sql.contains("octet_length(challenge_digest) = 32"));
        assert!(plan.sql.contains("0003_enforce"));
        assert!(!plan.sql.contains("drop column"));
    }
}

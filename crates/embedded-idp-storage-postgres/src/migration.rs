use crate::sql::INITIAL_SCHEMA_SQL;

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

impl MigrationPlan {
    pub fn initial() -> Self {
        Self::for_schema("embedded_idp".to_string())
    }

    pub fn for_schema(schema_name: String) -> Self {
        let initial_sql = render_schema_sql(&schema_name);
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
            steps: vec![MigrationStep {
                version: "0001",
                description: "initial embedded idp schema",
                sql: initial_sql,
            }],
        }
    }
}

fn render_schema_sql(schema_name: &str) -> String {
    INITIAL_SCHEMA_SQL.replace("__SCHEMA__", schema_name)
}

#[cfg(test)]
mod tests {
    use super::MigrationPlan;

    #[test]
    fn initial_plan_lists_core_tables() {
        let plan = MigrationPlan::initial();

        assert_eq!(plan.schema_name, "embedded_idp");
        assert_eq!(plan.tables[0], "accounts");
        assert_eq!(plan.tables[2], "account_device_bindings");
        assert_eq!(plan.tables[6], "authorization_codes");
        assert_eq!(plan.tables[7], "device_nonces");
        assert_eq!(plan.steps[0].version, "0001");
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
}

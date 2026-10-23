use super::*;
use crate::{
    SchemaHealthFacts, MAXIMUM_ONLINE_SCHEMA_VERSION, MINIMUM_ONLINE_SCHEMA_VERSION,
    PRODUCTION_SECURITY_CUTOVER_ID,
};
impl PostgresStorageAdapter {
    fn legacy_initialization_connection(&self) -> Result<Client, StoreError> {
        let mut client = self.connect_for_setup()?;
        client
            .query_one(
                "select pg_advisory_lock(hashtext($1))",
                &[&format!("{}:embedded-idp-migration", self.schema_name())],
            )
            .map_err(|_| StoreError::Backend("postgres initialization lock unavailable".into()))?;
        Ok(client)
    }

    pub fn schema_name(&self) -> &str {
        &self.config.connection.schema_name
    }

    pub fn apply_migrations(&self) -> Result<(), StoreError> {
        let mut client = self.legacy_initialization_connection()?;
        self.reject_access_schema_target(&mut client)?;
        for step in self.migration_plan().steps {
            if client.batch_execute(&step.sql).is_err() {
                return Err(StoreError::Backend(format!(
                    "apply migration {} failed",
                    step.version
                )));
            }
        }
        Ok(())
    }

    /// Performs the explicit, credential-invalidating security cutover.
    ///
    /// Hosts must drain every legacy identity writer and verify a backup before
    /// calling this operation. It is intentionally separate from additive
    /// migrations and is idempotent after its durable marker commits.
    pub fn apply_security_cutover(&self) -> Result<(), StoreError> {
        let mut client = self.legacy_initialization_connection()?;
        self.reject_access_schema_target(&mut client)?;
        let plan = self.security_cutover_plan();
        if client.batch_execute(&plan.sql).is_err() {
            return Err(StoreError::Backend(format!(
                "apply security cutover {} failed",
                plan.version
            )));
        }
        Ok(())
    }

    pub fn inspect_schema_health(&self) -> Result<SchemaHealthFacts, StoreError> {
        let mut client = self.connect_with_budget(Duration::from_secs(5))?;
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

    fn reject_access_schema_target(&self, client: &mut Client) -> Result<(), StoreError> {
        let has_access_state = client
            .query_one(
                "select exists (select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname='access_state')",
                &[&self.config.connection.schema_name],
            )
            .map_err(|_| {
                StoreError::Backend("inspect postgres schema target failed".to_string())
            })?
            .get::<_, bool>(0);
        if has_access_state {
            return Err(StoreError::Backend(
                "tenant access schema cannot use legacy migrations".to_string(),
            ));
        }
        Ok(())
    }
}

pub(super) fn observed_schema_version(versions: &[String]) -> Option<String> {
    ["0003_enforce", "0002_expand", "0001"]
        .into_iter()
        .find(|candidate| versions.iter().any(|version| version == candidate))
        .map(str::to_string)
        .or_else(|| versions.iter().max().cloned())
}

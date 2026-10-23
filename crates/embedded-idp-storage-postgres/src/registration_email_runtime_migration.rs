//! Explicit, separately versioned I2 runtime installation. Never invoked by startup.
use crate::{
    registration_email_migration::{
        configure_bounded_transaction, validate_scope, REGISTRATION_EMAIL_BACKEND_ERROR,
    },
    PgError, PgExecutor, PostgresStorageAdapter,
};
use embedded_idp_core::{access::RegistrationEmailScope, StoreError};

pub const REGISTRATION_EMAIL_RUNTIME_VERSION: &str = "registration_email_runtime_v1";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEmailRuntimeMigrationPlan {
    pub fingerprint: String,
    pub schema_name: String,
}
fn db(_: PgError) -> StoreError {
    StoreError::Backend(REGISTRATION_EMAIL_BACKEND_ERROR.into())
}
fn snapshot(
    c: &mut impl PgExecutor,
    schema: &str,
    scope: &RegistrationEmailScope,
) -> Result<RegistrationEmailRuntimeMigrationPlan, StoreError> {
    let exists: Option<String> = c
        .query_one(
            "select to_regclass($1)::text",
            &[&format!("{schema}.registration_email_runtime_state")],
        )
        .map_err(db)?
        .get(0);
    if exists.is_some() {
        return Err(StoreError::Conflict(
            "registration_email.runtime_already_installed",
        ));
    }
    let fingerprint: String = c.query_one(&format!("select encode(sha256(convert_to(concat_ws(chr(31), (select system_identifier::text from pg_control_system()), current_database(), (select oid::text from pg_database where datname=current_database()), (select oid::text from pg_namespace where nspname::text=$1::text), $1::text, s.authority, s.version, s.tenancy_mode, s.installed_at::text, p.product, p.tenant_id, a.module_version, '2', $5::text), 'UTF8')), 'hex') from {schema}.registration_email_state s join {schema}.registration_email_products p on p.authority=s.authority join {schema}.access_state a on a.singleton where s.authority=$2 and p.product=$3 and p.tenant_id=$4"), &[&schema,&scope.authority,&scope.product,&scope.tenant,&format!("{:?}",scope.mode)]).map_err(db)?.get(0);
    Ok(RegistrationEmailRuntimeMigrationPlan {
        fingerprint,
        schema_name: schema.into(),
    })
}
impl PostgresStorageAdapter {
    pub fn registration_email_runtime_migration_plan(
        &self,
        scope: &RegistrationEmailScope,
    ) -> Result<RegistrationEmailRuntimeMigrationPlan, StoreError> {
        validate_scope(scope)?;
        let facts = self.inspect_registration_email_foundation(scope)?;
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
            return Err(StoreError::Conflict("registration_email.foundation"));
        }
        let mut c = self.connect()?;
        let mut tx = c.transaction().map_err(db)?;
        tx.batch_execute("set transaction read only").map_err(db)?;
        configure_bounded_transaction(&mut tx, REGISTRATION_EMAIL_BACKEND_ERROR)?;
        let plan = snapshot(&mut tx, self.schema_name(), scope)?;
        tx.commit().map_err(db)?;
        Ok(plan)
    }
    pub fn apply_registration_email_runtime(
        &self,
        plan: &RegistrationEmailRuntimeMigrationPlan,
        scope: &RegistrationEmailScope,
    ) -> Result<(), StoreError> {
        validate_scope(scope)?;
        // The plan is re-read before obtaining write locks, then its target fingerprint
        // is checked again under those locks before executing DDL.
        if self.registration_email_runtime_migration_plan(scope)? != *plan {
            return Err(StoreError::Conflict(
                "registration_email.runtime_plan_drift",
            ));
        }
        let mut c = self.connect_for_setup()?;
        let mut tx = c.transaction().map_err(db)?;
        configure_bounded_transaction(&mut tx, REGISTRATION_EMAIL_BACKEND_ERROR)?;
        let s = self.schema_name();
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for update"),
            &[],
        )
        .map_err(db)?;
        tx.query_one(
            &format!("select id from {s}.access_tenants where id=$1 for update"),
            &[&scope.tenant],
        )
        .map_err(db)?;
        tx.query_one(
            &format!(
                "select authority from {s}.registration_email_state where authority=$1 for update"
            ),
            &[&scope.authority],
        )
        .map_err(db)?;
        if snapshot(&mut tx, s, scope)? != *plan {
            return Err(StoreError::Conflict(
                "registration_email.runtime_plan_drift",
            ));
        }
        tx.batch_execute(&format!("create table {s}.registration_email_runtime_state(authority text primary key references {s}.registration_email_state(authority),version text not null check(version='registration_email_runtime_v1'), paused boolean not null default true, policy_revision integer not null check(policy_revision=2), installed_at bigint not null, updated_at bigint not null) ")).map_err(db)?;
        tx.execute(&format!("insert into {s}.registration_email_runtime_state(authority,version,policy_revision,installed_at,updated_at) values($1,$2,2,floor(extract(epoch from clock_timestamp()))::bigint,floor(extract(epoch from clock_timestamp()))::bigint)"),&[&scope.authority,&REGISTRATION_EMAIL_RUNTIME_VERSION]).map_err(db)?;
        tx.commit().map_err(db)
    }
}

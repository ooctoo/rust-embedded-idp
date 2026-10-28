use embedded_idp_core::{access::TenancyMode, StoreError};

use crate::{
    security_foundation::{check_in_transaction, mode_name, validate_authority},
    PgExecutor, PostgresStorageAdapter, ACCESS_SCHEMA_VERSION,
};

const VERSION: &str = "security_runtime_v1";
const BACKEND: &str = "postgres security runtime operation failed";
const DDL: &str = include_str!("sql/security_runtime_v1.sql");
const TABLES: &[&str] = &[
    "security_runtime_state",
    "security_receipts",
    "password_recovery_budgets",
    "password_recovery_flows",
    "password_recovery_start_receipts",
    "security_email_outbox",
];

// Includes table relations and all named migration-created indexes/constraint
// indexes so plan/apply never adopts a pre-existing object by name.
const RELATIONS: &[&str] = &[
    "security_runtime_state",
    "security_runtime_state_pkey",
    "security_receipts",
    "security_receipts_pkey",
    "security_receipts_expiry_idx",
    "security_receipts_account_idx",
    "password_recovery_budgets",
    "password_recovery_budgets_pkey",
    "password_recovery_budgets_expiry_idx",
    "password_recovery_flows",
    "password_recovery_flows_pkey",
    "password_recovery_flows_subject_idx",
    "password_recovery_flows_account_idx",
    "password_recovery_flows_expiry_idx",
    "password_recovery_flows_state_expiry_idx",
    "password_recovery_start_receipts",
    "password_recovery_start_receipts_pkey",
    "password_recovery_start_receipts_flow_id_key",
    "password_recovery_start_receipts_expiry_idx",
    "security_email_outbox",
    "security_email_outbox_pkey",
    "security_email_outbox_flow_id_key",
    "security_email_outbox_claim_idx",
    "security_email_outbox_lease_idx",
    "security_email_outbox_expiry_idx",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRuntimePlan {
    pub schema_name: String,
    pub mode: TenancyMode,
    pub authority: String,
    pub fingerprint: String,
}

fn db_error(_: crate::PgError) -> StoreError {
    StoreError::Backend(BACKEND.into())
}

fn bounded(tx: &mut impl PgExecutor, read_only: bool) -> Result<(), StoreError> {
    tx.batch_execute(if read_only {
        "set transaction read only"
    } else {
        "set transaction read write"
    })
    .map_err(db_error)?;
    tx.batch_execute("set local statement_timeout = '5s'; set local lock_timeout = '5s'")
        .map_err(db_error)
}

fn object_conflicts(tx: &mut impl PgExecutor, schema: &str) -> Result<(), StoreError> {
    let occupied: bool = tx
        .query_one(
            "select exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname=any($2::text[]))",
            &[&schema, &RELATIONS],
        )
        .map_err(db_error)?
        .get(0);
    if occupied {
        return Err(StoreError::Conflict("security_runtime.object_conflict"));
    }
    Ok(())
}

fn target_fingerprint(
    tx: &mut impl PgExecutor,
    schema: &str,
    mode: TenancyMode,
    authority: &str,
    foundation_layout: &str,
) -> Result<String, StoreError> {
    let ddl = DDL.replace("__SCHEMA__", schema);
    let canonical = format!(
        "security-runtime-plan-v1\nschema={schema}\nmode={}\nauthority={}\nbase={}\nfoundation={foundation_layout}\nddl={ddl}",
        mode_name(mode),
        authority,
        ACCESS_SCHEMA_VERSION,
    );
    let row = tx
        .query_one(
            "select current_database(), (select oid::text from pg_database where datname=current_database()), (select oid::text from pg_namespace where nspname=$1)",
            &[&schema],
        )
        .map_err(db_error)?;
    let database: String = row.get(0);
    let database_oid: Option<String> = row.get(1);
    let schema_oid: Option<String> = row.get(2);
    let database_oid =
        database_oid.ok_or(StoreError::Conflict("security_runtime.schema_missing"))?;
    let schema_oid = schema_oid.ok_or(StoreError::Conflict("security_runtime.schema_missing"))?;
    let bound = format!("{database}\n{database_oid}\n{schema_oid}\n{canonical}");
    tx.query_one(
        "select encode(sha256(convert_to($1, 'UTF8')), 'hex')",
        &[&bound],
    )
    .map(|row| row.get(0))
    .map_err(db_error)
}

fn layout_fingerprint(tx: &mut impl PgExecutor, schema: &str) -> Result<String, StoreError> {
    // Include the actual definition of each owned table, its columns/defaults,
    // constraints, and indexes. Expected names remain in the signature if absent.
    let row = tx
        .query_one(
            "with expected(name) as (
               select unnest($2::text[])
             ), target_tables as (
               select e.name,c.oid,c.relkind from expected e
               left join pg_namespace n on n.nspname=$1
               left join pg_class c on c.relnamespace=n.oid and c.relname=e.name
             ), shapes as (
               select t.name, case when t.oid is null then null else jsonb_build_object(
                 'kind',t.relkind,
                 'columns',coalesce((select jsonb_agg(jsonb_build_object(
                   'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),
                   'notnull',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)
                 ) order by a.attnum) from pg_attribute a
                   left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum
                   where a.attrelid=t.oid and a.attnum>0 and not a.attisdropped),'[]'::jsonb),
                 'constraints',coalesce((select jsonb_agg(jsonb_build_object(
                   'name',c.conname,'type',c.contype,'valid',c.convalidated,
                   'definition',pg_get_constraintdef(c.oid,true)
                 ) order by c.conname) from pg_constraint c where c.conrelid=t.oid),'[]'::jsonb),
                 'indexes',coalesce((select jsonb_agg(jsonb_build_object(
                   'name',i.relname,'valid',x.indisvalid,'ready',x.indisready,
                   'definition',pg_get_indexdef(i.oid)
                 ) order by i.relname) from pg_index x join pg_class i on i.oid=x.indexrelid
                   where x.indrelid=t.oid),'[]'::jsonb)
               ) end as shape from target_tables t
             )
             select encode(sha256(convert_to(coalesce(jsonb_agg(
               jsonb_build_object('name',name,'shape',shape) order by name
             ),'[]'::jsonb)::text,'UTF8')),'hex') from shapes",
            &[&schema, &TABLES],
        )
        .map_err(db_error)?;
    Ok(row.get(0))
}

impl PostgresStorageAdapter {
    pub fn plan_security_runtime(
        &self,
        mode: TenancyMode,
        authority: &str,
    ) -> Result<SecurityRuntimePlan, StoreError> {
        validate_authority(authority)?;
        if !self.inspect_access_schema(mode)?.bootstrap_completed {
            return Err(StoreError::Conflict("security_runtime.base_not_ready"));
        }
        let mut client = self.connect()?;
        let mut tx = client.transaction().map_err(db_error)?;
        bounded(&mut tx, true)?;
        let schema = self.schema_name();
        let foundation_layout = check_in_transaction(&mut tx, schema, mode, authority)?;
        object_conflicts(&mut tx, schema)?;
        let fingerprint = target_fingerprint(&mut tx, schema, mode, authority, &foundation_layout)?;
        tx.commit().map_err(db_error)?;
        Ok(SecurityRuntimePlan {
            schema_name: schema.to_owned(),
            mode,
            authority: authority.to_owned(),
            fingerprint,
        })
    }

    pub fn apply_security_runtime(&self, plan: &SecurityRuntimePlan) -> Result<(), StoreError> {
        validate_authority(&plan.authority)?;
        if plan.schema_name != self.schema_name() {
            return Err(StoreError::Conflict(
                "security_runtime.plan_target_mismatch",
            ));
        }
        if self.plan_security_runtime(plan.mode, &plan.authority)? != *plan {
            return Err(StoreError::Conflict("security_runtime.plan_stale"));
        }
        let mut client = self.connect_for_setup()?;
        let mut tx = client.transaction().map_err(db_error)?;
        bounded(&mut tx, false)?;
        let schema = self.schema_name();
        tx.query_one(
            &format!("select singleton from {schema}.access_state where singleton for update"),
            &[],
        )
        .map_err(db_error)?;
        let foundation_layout = check_in_transaction(&mut tx, schema, plan.mode, &plan.authority)?;
        object_conflicts(&mut tx, schema)?;
        let actual = target_fingerprint(
            &mut tx,
            schema,
            plan.mode,
            &plan.authority,
            &foundation_layout,
        )?;
        if actual != plan.fingerprint {
            return Err(StoreError::Conflict("security_runtime.plan_stale"));
        }
        tx.batch_execute(&DDL.replace("__SCHEMA__", schema))
            .map_err(db_error)?;
        tx.execute(
            &format!("insert into {schema}.security_runtime_state(singleton,version,authority,tenancy_mode,installed_at_epoch,layout_fingerprint) values(true,$1,$2,$3,floor(extract(epoch from clock_timestamp()))::bigint,$4)"),
            &[&VERSION, &plan.authority, &mode_name(plan.mode), &"0".repeat(64)],
        )
        .map_err(db_error)?;
        let layout = layout_fingerprint(&mut tx, schema)?;
        tx.execute(
            &format!(
                "update {schema}.security_runtime_state set layout_fingerprint=$1 where singleton"
            ),
            &[&layout],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)
    }

    pub fn check_security_runtime(
        &self,
        mode: TenancyMode,
        authority: &str,
    ) -> Result<(), StoreError> {
        validate_authority(authority)?;
        if !self.inspect_access_schema(mode)?.bootstrap_completed {
            return Err(StoreError::Conflict("security_runtime.base_not_ready"));
        }
        let mut client = self.connect()?;
        let mut tx = client.transaction().map_err(db_error)?;
        bounded(&mut tx, true)?;
        let schema = self.schema_name();
        check_runtime_in_transaction(&mut tx, schema, mode, authority)?;
        tx.commit().map_err(db_error)
    }
}

pub(crate) fn check_runtime_in_transaction(
    tx: &mut impl PgExecutor,
    schema: &str,
    mode: TenancyMode,
    authority: &str,
) -> Result<(), StoreError> {
    check_in_transaction(tx, schema, mode, authority)?;
    let state = tx
            .query_opt(
                &format!("select version,authority,tenancy_mode,layout_fingerprint from {schema}.security_runtime_state where singleton"),
                &[],
            )
            .map_err(db_error)?
            .ok_or(StoreError::Conflict("security_runtime.not_installed"))?;
    let version: String = state.get(0);
    let stored_authority: String = state.get(1);
    let stored_mode: String = state.get(2);
    let stored_layout: String = state.get(3);
    if version != VERSION || stored_authority != authority || stored_mode != mode_name(mode) {
        return Err(StoreError::Conflict("security_runtime.binding_mismatch"));
    }
    if layout_fingerprint(tx, schema)? != stored_layout {
        return Err(StoreError::Conflict("security_runtime.layout_drift"));
    }
    Ok(())
}

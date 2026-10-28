use embedded_idp_core::{access::TenancyMode, StoreError};

use crate::{PgExecutor, PostgresStorageAdapter, ACCESS_SCHEMA_VERSION};

const VERSION: &str = "security_foundation_v1";
const BACKEND: &str = "postgres security foundation operation failed";
const DDL: &str = include_str!("sql/security_foundation_v1.sql");
const RELATIONS: &[&str] = &[
    "security_state",
    "security_events",
    "security_events_occurred_idx",
    "security_events_account_idx",
];
const TRIGGERS: &[&str] = &["security_foundation_account_credential_version_biu"];
const FUNCTIONS: &[&str] = &["security_foundation_account_credential_version"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFoundationPlan {
    pub schema_name: String,
    pub mode: TenancyMode,
    pub authority: String,
    pub fingerprint: String,
}

pub(crate) fn mode_name(mode: TenancyMode) -> &'static str {
    match mode {
        TenancyMode::Disabled => "disabled",
        TenancyMode::Enabled => "enabled",
    }
}

pub(crate) fn validate_authority(authority: &str) -> Result<(), StoreError> {
    if authority.is_empty()
        || authority.len() > 128
        || !authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(StoreError::Conflict(
            "security_foundation.invalid_authority",
        ));
    }
    Ok(())
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

fn base_ready(
    tx: &mut impl PgExecutor,
    schema: &str,
    mode: TenancyMode,
) -> Result<i64, StoreError> {
    let q = format!("select module_version, tenancy_mode, bootstrap_completed_at_epoch from {schema}.access_state where singleton");
    let row = tx
        .query_opt(&q, &[])
        .map_err(db_error)?
        .ok_or(StoreError::Conflict("security_foundation.base_not_ready"))?;
    let version: String = row.get(0);
    let observed_mode: String = row.get(1);
    let bootstrapped: Option<i64> = row.get(2);
    if version != ACCESS_SCHEMA_VERSION || observed_mode != mode_name(mode) {
        return Err(StoreError::Conflict(
            "security_foundation.base_binding_mismatch",
        ));
    }
    bootstrapped.ok_or(StoreError::Conflict("security_foundation.base_not_ready"))
}

fn conflicts(tx: &mut impl PgExecutor, schema: &str) -> Result<(), StoreError> {
    let row = tx.query_one(
        "select
          exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname=any($2::text[]))
          or exists(select 1 from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and t.tgname=any($3::text[]))
          or exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname=$1 and p.proname=any($4::text[]))
          or exists(select 1 from information_schema.columns where table_schema=$1 and table_name='accounts' and column_name='security_credential_version')
          or exists(select 1 from pg_constraint c join pg_class t on t.oid=c.conrelid join pg_namespace n on n.oid=t.relnamespace where n.nspname=$1 and c.conname='accounts_security_credential_version_ck')",
        &[&schema, &RELATIONS, &TRIGGERS, &FUNCTIONS],
    ).map_err(db_error)?;
    if row.get::<_, bool>(0) {
        return Err(StoreError::Conflict("security_foundation.object_conflict"));
    }
    Ok(())
}

fn target_fingerprint(
    tx: &mut impl PgExecutor,
    schema: &str,
    mode: TenancyMode,
    authority: &str,
    bootstrap_epoch: i64,
) -> Result<String, StoreError> {
    let ddl = DDL.replace("__SCHEMA__", schema);
    let canonical = format!(
        "security-foundation-plan-v1\nschema={schema}\nmode={}\nauthority={}\nbase={}\nbootstrap={}\nddl={}",
        mode_name(mode), authority, ACCESS_SCHEMA_VERSION, bootstrap_epoch, ddl
    );
    let row = tx.query_one(
        "select current_database(), (select oid::text from pg_database where datname=current_database()), (select oid::text from pg_namespace where nspname=$1)",
        &[&schema],
    ).map_err(db_error)?;
    let db: String = row.get(0);
    let db_oid: Option<String> = row.get(1);
    let schema_oid: Option<String> = row.get(2);
    let db_oid = db_oid.ok_or(StoreError::Conflict("security_foundation.schema_missing"))?;
    let schema_oid =
        schema_oid.ok_or(StoreError::Conflict("security_foundation.schema_missing"))?;
    // Bind catalog identities and the complete migration source into the plan hash.
    let identity = format!("{db}\n{db_oid}\n{schema_oid}\n{canonical}");
    let row = tx
        .query_one(
            "select encode(sha256(convert_to($1, 'UTF8')), 'hex')",
            &[&identity],
        )
        .map_err(db_error)?;
    Ok(row.get(0))
}

fn layout_fingerprint(tx: &mut impl PgExecutor, schema: &str) -> Result<String, StoreError> {
    // Definitions, enabled state, table columns, constraints and indexes are hashed;
    // unrelated accounts columns/triggers are intentionally outside this signature.
    let row = tx.query_one(
        "with target_tables as (
           select c.oid,c.relname,c.relkind from pg_class c join pg_namespace n on n.oid=c.relnamespace
           where n.nspname=$1 and c.relname=any(array['security_state','security_events'])
         ),
         table_shape as (
           select t.relname,jsonb_build_object('kind',t.relkind,'columns',coalesce((
             select jsonb_agg(jsonb_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) order by a.attnum)
             from pg_attribute a left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum where a.attrelid=t.oid and a.attnum>0 and not a.attisdropped), '[]'::jsonb),
             'constraints',coalesce((select jsonb_agg(jsonb_build_object('name',c.conname,'type',c.contype,'valid',c.convalidated,'definition',pg_get_constraintdef(c.oid,true)) order by c.conname) from pg_constraint c where c.conrelid=t.oid),'[]'::jsonb),
             'indexes',coalesce((select jsonb_agg(jsonb_build_object('name',i.relname,'valid',x.indisvalid,'ready',x.indisready,'definition',pg_get_indexdef(i.oid)) order by i.relname) from pg_index x join pg_class i on i.oid=x.indexrelid where x.indrelid=t.oid),'[]'::jsonb)) shape
           from target_tables t
         ),
         account_shape as (
           select jsonb_build_object('column', (select jsonb_build_object('type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) from pg_attribute a join pg_class t on t.oid=a.attrelid join pg_namespace n on n.oid=t.relnamespace left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum where n.nspname=$1 and t.relname='accounts' and a.attname='security_credential_version' and a.attnum>0 and not a.attisdropped),
             'constraint',(select jsonb_build_object('valid',c.convalidated,'definition',pg_get_constraintdef(c.oid,true)) from pg_constraint c join pg_class t on t.oid=c.conrelid join pg_namespace n on n.oid=t.relnamespace where n.nspname=$1 and t.relname='accounts' and c.conname='accounts_security_credential_version_ck')) shape
         ),
         trigger_shape as (
           select coalesce(jsonb_agg(jsonb_build_object('name',g.tgname,'table',c.relname,'definition',pg_get_triggerdef(g.oid,true),'enabled',g.tgenabled,'function',pg_get_functiondef(p.oid),'security_definer',p.prosecdef,'config',p.proconfig) order by g.tgname),'[]'::jsonb) shape
           from pg_trigger g join pg_class c on c.oid=g.tgrelid join pg_namespace n on n.oid=c.relnamespace join pg_proc p on p.oid=g.tgfoid
           where n.nspname=$1 and g.tgname='security_foundation_account_credential_version_biu'
         )
         select encode(sha256(convert_to(jsonb_build_object('tables',(select coalesce(jsonb_agg(jsonb_build_object('name',relname,'shape',shape) order by relname),'[]'::jsonb) from table_shape),'account',(select shape from account_shape),'triggers',(select shape from trigger_shape))::text,'UTF8')),'hex')",
        &[&schema],
    ).map_err(db_error)?;
    Ok(row.get(0))
}

/// Validate the installed foundation inside a caller-owned transaction. Runtime
/// migration uses this after acquiring the access-state write lock.
pub(crate) fn check_in_transaction(
    tx: &mut impl PgExecutor,
    schema: &str,
    mode: TenancyMode,
    authority: &str,
) -> Result<String, StoreError> {
    base_ready(tx, schema, mode)?;
    let state = tx
        .query_opt(
            &format!("select version,authority,tenancy_mode,layout_fingerprint from {schema}.security_state where singleton"),
            &[],
        )
        .map_err(db_error)?
        .ok_or(StoreError::Conflict("security_foundation.not_installed"))?;
    let version: String = state.get(0);
    let stored_authority: String = state.get(1);
    let stored_mode: String = state.get(2);
    let stored_layout: String = state.get(3);
    if version != VERSION || stored_authority != authority || stored_mode != mode_name(mode) {
        return Err(StoreError::Conflict("security_foundation.binding_mismatch"));
    }
    let actual_layout = layout_fingerprint(tx, schema)?;
    if actual_layout != stored_layout {
        return Err(StoreError::Conflict("security_foundation.layout_drift"));
    }
    Ok(actual_layout)
}

impl PostgresStorageAdapter {
    pub fn plan_security_foundation(
        &self,
        mode: TenancyMode,
        authority: &str,
    ) -> Result<SecurityFoundationPlan, StoreError> {
        validate_authority(authority)?;
        if !self.inspect_access_schema(mode)?.bootstrap_completed {
            return Err(StoreError::Conflict("security_foundation.base_not_ready"));
        }
        let mut client = self.connect()?;
        let mut tx = client.transaction().map_err(db_error)?;
        bounded(&mut tx, true)?;
        let bootstrap = base_ready(&mut tx, self.schema_name(), mode)?;
        conflicts(&mut tx, self.schema_name())?;
        let fingerprint =
            target_fingerprint(&mut tx, self.schema_name(), mode, authority, bootstrap)?;
        tx.commit().map_err(db_error)?;
        Ok(SecurityFoundationPlan {
            schema_name: self.schema_name().to_owned(),
            mode,
            authority: authority.to_owned(),
            fingerprint,
        })
    }

    pub fn apply_security_foundation(
        &self,
        plan: &SecurityFoundationPlan,
    ) -> Result<(), StoreError> {
        validate_authority(&plan.authority)?;
        if plan.schema_name != self.schema_name() {
            return Err(StoreError::Conflict(
                "security_foundation.plan_target_mismatch",
            ));
        }
        let expected = self.plan_security_foundation(plan.mode, &plan.authority)?;
        if expected != *plan {
            return Err(StoreError::Conflict("security_foundation.plan_stale"));
        }
        let mut client = self.connect_for_setup()?;
        let mut tx = client.transaction().map_err(db_error)?;
        bounded(&mut tx, false)?;
        let schema = self.schema_name();
        let state = format!("{schema}.access_state");
        tx.query_one(
            &format!("select singleton from {state} where singleton for update"),
            &[],
        )
        .map_err(db_error)?;
        let bootstrap = base_ready(&mut tx, schema, plan.mode)?;
        conflicts(&mut tx, schema)?;
        let actual = target_fingerprint(&mut tx, schema, plan.mode, &plan.authority, bootstrap)?;
        if actual != plan.fingerprint {
            return Err(StoreError::Conflict("security_foundation.plan_stale"));
        }
        tx.batch_execute(&DDL.replace("__SCHEMA__", schema))
            .map_err(db_error)?;
        tx.execute(
            &format!("insert into {schema}.security_state(singleton,version,authority,tenancy_mode,installed_at_epoch,layout_fingerprint) values(true,$1,$2,$3,floor(extract(epoch from clock_timestamp()))::bigint,$4)"),
            &[&VERSION, &plan.authority, &mode_name(plan.mode), &"0".repeat(64)],
        ).map_err(db_error)?;
        let layout = layout_fingerprint(&mut tx, schema)?;
        tx.execute(
            &format!("update {schema}.security_state set layout_fingerprint=$1 where singleton"),
            &[&layout],
        )
        .map_err(db_error)?;
        tx.commit().map_err(db_error)
    }

    pub fn check_security_foundation(
        &self,
        mode: TenancyMode,
        authority: &str,
    ) -> Result<(), StoreError> {
        validate_authority(authority)?;
        if !self.inspect_access_schema(mode)?.bootstrap_completed {
            return Err(StoreError::Conflict("security_foundation.base_not_ready"));
        }
        let mut client = self.connect()?;
        let mut tx = client.transaction().map_err(db_error)?;
        bounded(&mut tx, true)?;
        let schema = self.schema_name();
        check_in_transaction(&mut tx, schema, mode, authority)?;
        tx.commit().map_err(db_error)
    }
}

#[cfg(test)]
mod tests {
    use super::validate_authority;

    #[test]
    fn authority_is_bounded_ascii_identifier() {
        for value in ["a", "Tenant_01", "host.example-2"] {
            assert!(validate_authority(value).is_ok(), "{value}");
        }
        for value in ["", " spaces", "x/y", "ümlaut", &"a".repeat(129)] {
            assert!(validate_authority(value).is_err());
        }
    }
}

use embedded_idp_core::StoreError;

use super::{
    configure_bounded_transaction, parse_mode, validate_scope, RegistrationEmailFoundationFacts,
    RegistrationEmailScope, REGISTRATION_EMAIL_BACKEND_ERROR,
};
use crate::PostgresStorageAdapter;

use super::catalog::{COLUMNS, CONSTRAINTS, INDEXES, TABLES, TRIGGERS};

const BACKEND_ERROR: &str = REGISTRATION_EMAIL_BACKEND_ERROR;

pub(crate) fn foundation(
    adapter: &PostgresStorageAdapter,
    scope: &RegistrationEmailScope,
) -> Result<RegistrationEmailFoundationFacts, StoreError> {
    validate_scope(scope)?;
    let mut client = adapter.connect()?;
    let mut tx = client.transaction().map_err(|error| {
        let _ = error;
        StoreError::Backend(BACKEND_ERROR.to_string())
    })?;
    tx.batch_execute("set transaction read only")
        .map_err(db_error)?;
    configure_bounded_transaction(&mut tx, BACKEND_ERROR)?;
    let schema = adapter.schema_name();
    let state_relation = tx
        .query_one(
            "select to_regclass($1)::text",
            &[&format!("{schema}.registration_email_state")],
        )
        .map_err(db_error)?
        .get::<_, Option<String>>(0);
    if state_relation.is_none() {
        let facts = empty_facts(schema);
        tx.commit().map_err(db_error)?;
        return Ok(facts);
    }
    let state = tx
        .query_opt(
            &format!(
                "select version,tenancy_mode,installed_at from {schema}.registration_email_state where authority=$1"
            ),
            &[&scope.authority],
        )
        .map_err(db_error)?;
    let Some(state) = state else {
        let facts = empty_facts(schema);
        tx.commit().map_err(db_error)?;
        return Ok(facts);
    };
    let version: String = state.get("version");
    let mode = parse_mode(state.get("tenancy_mode"))?;
    let installed_at: i64 = state.get("installed_at");
    let tables_complete = relation_count(&mut tx, schema, TABLES)? == TABLES.len() as i64;
    let products_present = relation_exists(&mut tx, schema, "registration_email_products")?;
    let binding_present = products_present
        && tx
            .query_one(
                &format!(
                    "select exists(select 1 from {schema}.registration_email_products where authority=$1 and product=$2)"
                ),
                &[&scope.authority, &scope.product],
            )
            .map_err(db_error)?
            .get::<_, bool>(0);
    let binding_matches = products_present
        && tx
            .query_one(
                &format!(
                    "select exists(select 1 from {schema}.registration_email_products where authority=$1 and product=$2 and tenant_id=$3)"
                ),
                &[&scope.authority, &scope.product, &scope.tenant],
            )
            .map_err(db_error)?
            .get::<_, bool>(0);
    let columns_complete = column_count(&mut tx, schema)? == COLUMNS.len() as i64;
    let indexes_complete = index_count(&mut tx, schema)? == INDEXES.len() as i64;
    let triggers_complete = trigger_count(&mut tx, schema)? == TRIGGERS.len() as i64;
    let constraints_complete = constraint_count(&mut tx, schema)? == CONSTRAINTS.len() as i64;
    let legacy_codes_consumed = if relation_exists(&mut tx, schema, "email_verification_codes")? {
        tx.query_one(
            &format!(
                "select not exists(select 1 from {schema}.email_verification_codes where consumed_at_epoch is null)"
            ),
            &[],
        )
        .map_err(db_error)?
        .get::<_, bool>(0)
    } else {
        false
    };
    let facts = RegistrationEmailFoundationFacts {
        schema_name: schema.to_string(),
        state_present: true,
        version: Some(version),
        authority: Some(scope.authority.clone()),
        mode: Some(mode),
        installed_at: Some(installed_at),
        binding_present,
        binding_matches,
        tables_complete,
        columns_complete,
        indexes_complete,
        triggers_complete,
        constraints_complete,
        legacy_codes_consumed,
        public_profile_ready: false,
    };
    tx.commit().map_err(db_error)?;
    Ok(facts)
}

fn empty_facts(schema: &str) -> RegistrationEmailFoundationFacts {
    RegistrationEmailFoundationFacts {
        schema_name: schema.to_string(),
        state_present: false,
        version: None,
        authority: None,
        mode: None,
        installed_at: None,
        binding_present: false,
        binding_matches: false,
        tables_complete: false,
        columns_complete: false,
        indexes_complete: false,
        triggers_complete: false,
        constraints_complete: false,
        legacy_codes_consumed: false,
        public_profile_ready: false,
    }
}

fn relation_count<C: postgres::GenericClient>(
    client: &mut C,
    schema: &str,
    names: &[&str],
) -> Result<i64, StoreError> {
    let in_list = names
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(",");
    client
        .query_one(
            &format!(
                "select count(*)::bigint from information_schema.tables where table_schema=$1 and table_name in ({in_list})"
            ),
            &[&schema],
        )
        .map_err(db_error)
        .map(|row| row.get(0))
}

fn relation_exists<C: postgres::GenericClient>(
    client: &mut C,
    schema: &str,
    table: &str,
) -> Result<bool, StoreError> {
    client
        .query_one(
            "select exists(select 1 from information_schema.tables where table_schema=$1 and table_name=$2)",
            &[&schema, &table],
        )
        .map_err(db_error)
        .map(|row| row.get(0))
}

fn column_count<C: postgres::GenericClient>(
    client: &mut C,
    schema: &str,
) -> Result<i64, StoreError> {
    let mut count = 0_i64;
    for (table, column) in COLUMNS {
        if client
            .query_opt(
                "select 1 from information_schema.columns where table_schema=$1 and table_name=$2 and column_name=$3",
                &[&schema, table, column],
            )
            .map_err(db_error)?
            .is_some()
        {
            count += 1;
        }
    }
    Ok(count)
}

fn index_count<C: postgres::GenericClient>(
    client: &mut C,
    schema: &str,
) -> Result<i64, StoreError> {
    let in_list = INDEXES
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(",");
    client
        .query_one(
            &format!(
                "select count(*)::bigint from pg_class c join pg_namespace n on n.oid=c.relnamespace join pg_index i on i.indexrelid=c.oid where n.nspname=$1 and c.relname in ({in_list}) and i.indisvalid and i.indisready"
            ),
            &[&schema],
        )
        .map_err(db_error)
        .map(|row| row.get(0))
}

fn trigger_count<C: postgres::GenericClient>(
    client: &mut C,
    schema: &str,
) -> Result<i64, StoreError> {
    let clauses = TRIGGERS
        .iter()
        .map(|(table, trigger)| format!("(c.relname='{table}' and t.tgname='{trigger}')"))
        .collect::<Vec<_>>()
        .join(" or ");
    client
        .query_one(
            &format!("select count(*)::bigint from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and not t.tgisinternal and t.tgenabled in ('O','A') and ({clauses})"),
            &[&schema],
        )
        .map_err(db_error)
        .map(|row| row.get(0))
}

fn constraint_count<C: postgres::GenericClient>(
    client: &mut C,
    schema: &str,
) -> Result<i64, StoreError> {
    let clauses = CONSTRAINTS
        .iter()
        .map(|(table, constraint)| format!("(r.relname='{table}' and c.conname='{constraint}')"))
        .collect::<Vec<_>>()
        .join(" or ");
    client
        .query_one(
            &format!(
                "select count(*)::bigint from pg_constraint c join pg_class r on r.oid=c.conrelid join pg_namespace n on n.oid=r.relnamespace where n.nspname=$1 and c.contype='c' and c.convalidated and ({clauses})"
            ),
            &[&schema],
        )
        .map_err(db_error)
        .map(|row| row.get(0))
}

fn db_error(_error: postgres::Error) -> StoreError {
    StoreError::Backend(BACKEND_ERROR.to_string())
}

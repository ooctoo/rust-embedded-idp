use embedded_idp_core::{access::TenancyMode, StoreError};
use postgres::Transaction;

use super::{
    configure_bounded_transaction, mode_name, validate_namespace, validate_scope,
    RegistrationEmailMigrationPlan, RegistrationEmailScope, REGISTRATION_EMAIL_BACKEND_ERROR,
    REGISTRATION_EMAIL_SCHEMA_VERSION,
};
use crate::registration_email_migration::inventory;
use crate::PostgresStorageAdapter;

const FOUNDATION_SQL: &str = include_str!("../sql/registration_email_v1.sql");
const BACKEND_ERROR: &str = REGISTRATION_EMAIL_BACKEND_ERROR;

pub(crate) fn foundation(
    adapter: &PostgresStorageAdapter,
    plan: &RegistrationEmailMigrationPlan,
    authority: &str,
    mode: TenancyMode,
) -> Result<(), StoreError> {
    validate_namespace(authority, "registration_email.authority")?;
    if plan.mode != mode || plan.schema_name != adapter.schema_name() {
        return Err(StoreError::Conflict("registration_email.plan_scope"));
    }
    let mut client = adapter.connect()?;
    let tx = client.transaction().map_err(|error| {
        let _ = error;
        StoreError::Backend(BACKEND_ERROR.to_string())
    })?;
    let mut tx = tx;
    configure_bounded_transaction(&mut tx, BACKEND_ERROR)?;
    let schema = adapter.schema_name();
    tx.query_one(
        "select pg_advisory_xact_lock(hashtext($1))",
        &[&format!("{schema}:registration-email-foundation")],
    )
    .map_err(db_error)?;
    let installed = tx
        .query_one(
            "select to_regclass($1)::text",
            &[&format!("{schema}.registration_email_state")],
        )
        .map_err(db_error)?
        .get::<_, Option<String>>(0)
        .is_some();
    if installed {
        return rollback(
            tx,
            StoreError::Conflict("registration_email.already_installed"),
        );
    }
    tx.query_one(
        &format!(
            "select tenancy_mode,module_version from {schema}.access_state where singleton=true for update"
        ),
        &[],
    )
    .map_err(db_error)?;
    tx.batch_execute(&format!(
        "lock table {schema}.accounts, {schema}.access_memberships, {schema}.email_verification_codes in share row exclusive mode"
    ))
    .map_err(|_| StoreError::Backend(BACKEND_ERROR.to_string()))?;
    tx.query(
        &format!("select id from {schema}.accounts order by id for update"),
        &[],
    )
    .map_err(db_error)?;
    tx.query(
        &format!("select id from {schema}.email_verification_codes order by id for update"),
        &[],
    )
    .map_err(db_error)?;

    let current = inventory::snapshot(&mut tx, schema)?;
    inventory::validate_apply_plan(plan, &current, schema, mode)?;
    tx.batch_execute(&FOUNDATION_SQL.replace("__SCHEMA__", schema))
        .map_err(|_| StoreError::Backend(BACKEND_ERROR.to_string()))?;
    tx.execute(
        &format!(
            "insert into {schema}.registration_email_state(authority,version,tenancy_mode,installed_at) values($1,$2,$3,floor(extract(epoch from clock_timestamp()))::bigint)"
        ),
        &[&authority, &REGISTRATION_EMAIL_SCHEMA_VERSION, &mode_name(mode)],
    )
    .map_err(db_error)?;
    tx.execute(
        &format!("insert into {schema}.registration_email_capacity(authority) values($1)"),
        &[&authority],
    )
    .map_err(db_error)?;
    tx.commit().map_err(|error| {
        let _ = error;
        StoreError::Backend(BACKEND_ERROR.to_string())
    })
}

pub(crate) fn bind_product(
    adapter: &PostgresStorageAdapter,
    scope: &RegistrationEmailScope,
) -> Result<(), StoreError> {
    validate_scope(scope)?;
    let mut client = adapter.connect()?;
    let tx = client.transaction().map_err(|error| {
        let _ = error;
        StoreError::Backend(BACKEND_ERROR.to_string())
    })?;
    let mut tx = tx;
    configure_bounded_transaction(&mut tx, BACKEND_ERROR)?;
    let schema = adapter.schema_name();
    tx.query_one(
        "select pg_advisory_xact_lock(hashtext($1))",
        &[&format!("{schema}:registration-email-foundation")],
    )
    .map_err(db_error)?;
    let state_relation = tx
        .query_one(
            "select to_regclass($1)::text",
            &[&format!("{schema}.registration_email_state")],
        )
        .map_err(db_error)?
        .get::<_, Option<String>>(0);
    if state_relation.is_none() {
        return rollback(tx, StoreError::Conflict("registration_email.not_installed"));
    }
    let state = tx
        .query_opt(
            &format!(
                "select version,tenancy_mode from {schema}.registration_email_state where authority=$1 for update"
            ),
            &[&scope.authority],
        )
        .map_err(db_error)?
        .ok_or_else(|| StoreError::Conflict("registration_email.not_installed"))?;
    let version: String = state.get("version");
    let stored_mode: String = state.get("tenancy_mode");
    if version != REGISTRATION_EMAIL_SCHEMA_VERSION || stored_mode != mode_name(scope.mode) {
        return rollback(
            tx,
            StoreError::Conflict("registration_email.scope_mismatch"),
        );
    }
    let access = tx
        .query_one(
        &format!(
            "select module_version,tenancy_mode from {schema}.access_state where singleton=true for update"
        ),
        &[],
    )
    .map_err(db_error)?;
    let access_version: String = access.get("module_version");
    let access_mode: String = access.get("tenancy_mode");
    if access_version != "tenant_v6" || access_mode != mode_name(scope.mode) {
        return rollback(
            tx,
            StoreError::Conflict("registration_email.scope_mismatch"),
        );
    }
    let tenant_exists = tx
        .query_one(
            &format!("select exists(select 1 from {schema}.access_tenants where id=$1)"),
            &[&scope.tenant],
        )
        .map_err(db_error)?
        .get::<_, bool>(0);
    if !tenant_exists {
        return rollback(tx, StoreError::Conflict("registration_email.tenant"));
    }
    let duplicate = tx
        .query_one(
            &format!(
                "select exists(select 1 from {schema}.registration_email_products where authority=$1 and product=$2)"
            ),
            &[&scope.authority, &scope.product],
        )
        .map_err(db_error)?
        .get::<_, bool>(0);
    if duplicate {
        return rollback(
            tx,
            StoreError::Conflict("registration_email.product_already_bound"),
        );
    }
    tx.execute(
        &format!(
            "insert into {schema}.registration_email_products(authority,product,tenant_id) values($1,$2,$3)"
        ),
        &[&scope.authority, &scope.product, &scope.tenant],
    )
    .map_err(db_error)?;
    tx.commit().map_err(|error| {
        let _ = error;
        StoreError::Backend(BACKEND_ERROR.to_string())
    })
}

fn rollback<T>(tx: Transaction<'_>, error: StoreError) -> Result<T, StoreError> {
    tx.rollback()
        .map_err(|_| StoreError::Backend(BACKEND_ERROR.to_string()))?;
    Err(error)
}

fn db_error(_error: postgres::Error) -> StoreError {
    StoreError::Backend(BACKEND_ERROR.to_string())
}

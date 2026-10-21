use std::collections::BTreeMap;

use embedded_idp_core::{
    access::{CanonicalRegistrationEmail, TenancyMode},
    StoreError,
};
use postgres::{GenericClient, Row};

use super::{
    configure_bounded_transaction, parse_mode, RegistrationEmailMigrationPlan,
    REGISTRATION_EMAIL_BACKEND_ERROR, REGISTRATION_EMAIL_SCHEMA_VERSION,
};
use crate::PostgresStorageAdapter;

const BACKEND_ERROR: &str = REGISTRATION_EMAIL_BACKEND_ERROR;

pub(crate) struct Snapshot {
    pub database_name: String,
    pub access_mode: TenancyMode,
    pub access_schema_version: String,
    pub fingerprint: String,
    pub account_count: i64,
    pub normalized_count: i64,
    pub collision_count: i64,
    pub invalid_email_count: i64,
    pub legacy_code_count: i64,
}

pub(crate) fn plan(
    adapter: &PostgresStorageAdapter,
    requested_mode: TenancyMode,
) -> Result<RegistrationEmailMigrationPlan, StoreError> {
    let mut client = adapter.connect()?;
    let mut tx = client.transaction().map_err(|error| {
        let _ = error;
        StoreError::Backend(BACKEND_ERROR.to_string())
    })?;
    tx.batch_execute("set transaction read only")
        .map_err(db_error)?;
    configure_bounded_transaction(&mut tx, BACKEND_ERROR)?;
    let installed = tx
        .query_one(
            "select to_regclass($1)::text",
            &[&format!(
                "{}.registration_email_state",
                adapter.schema_name()
            )],
        )
        .map_err(db_error)?
        .get::<_, Option<String>>(0)
        .is_some();
    if installed {
        return Err(StoreError::Conflict("registration_email.already_installed"));
    }
    let snapshot = snapshot(&mut tx, adapter.schema_name())?;
    if snapshot.access_mode != requested_mode {
        return Err(StoreError::Conflict("registration_email.mode"));
    }
    let plan = RegistrationEmailMigrationPlan {
        schema_name: adapter.schema_name().to_string(),
        database_name: snapshot.database_name,
        mode: snapshot.access_mode,
        version: REGISTRATION_EMAIL_SCHEMA_VERSION.to_string(),
        access_schema_version: snapshot.access_schema_version,
        fingerprint: snapshot.fingerprint,
        account_count: snapshot.account_count,
        normalized_count: snapshot.normalized_count,
        normalization_collision_count: snapshot.collision_count,
        invalid_email_count: snapshot.invalid_email_count,
        legacy_code_count: snapshot.legacy_code_count,
    };
    tx.commit().map_err(db_error)?;
    Ok(plan)
}

pub(crate) fn snapshot<C: GenericClient>(
    client: &mut C,
    schema: &str,
) -> Result<Snapshot, StoreError> {
    let access = client
        .query_one(
            &format!(
                "select tenancy_mode,module_version from {schema}.access_state where singleton=true"
            ),
            &[],
        )
        .map_err(db_error)?;
    let access_mode = parse_mode(access.get("tenancy_mode"))?;
    let access_schema_version: String = access.get("module_version");
    if access_schema_version != "tenant_v6" {
        return Err(StoreError::Conflict("registration_email.access_version"));
    }
    let database_name = client
        .query_one("select current_database()", &[])
        .map_err(db_error)?
        .get::<_, String>(0);
    let accounts = client
        .query(
            &format!("select id,email from {schema}.accounts order by id"),
            &[],
        )
        .map_err(db_error)?;
    let (normalized_count, collision_count, invalid_email_count) = email_facts(&accounts);
    let fingerprint = client
        .query_one(&fingerprint_sql(schema), &[&schema])
        .map_err(db_error)?
        .get::<_, String>(0);
    let legacy_code_count = client
        .query_one(
            &format!("select count(*)::bigint from {schema}.email_verification_codes"),
            &[],
        )
        .map_err(db_error)?
        .get::<_, i64>(0);
    Ok(Snapshot {
        database_name,
        access_mode,
        access_schema_version,
        fingerprint,
        account_count: accounts.len() as i64,
        normalized_count,
        collision_count,
        invalid_email_count,
        legacy_code_count,
    })
}

fn email_facts(accounts: &[Row]) -> (i64, i64, i64) {
    let mut identities = BTreeMap::<String, usize>::new();
    let mut normalized_count = 0_i64;
    let mut invalid_count = 0_i64;
    for row in accounts {
        let email: String = row.get("email");
        let Some(identity) = canonical_identity(&email) else {
            invalid_count += 1;
            continue;
        };
        if identity != email {
            normalized_count += 1;
        }
        *identities.entry(identity).or_default() += 1;
    }
    let collision_count = identities.values().filter(|count| **count > 1).count() as i64;
    (normalized_count, collision_count, invalid_count)
}

pub(crate) fn canonical_identity(email: &str) -> Option<String> {
    CanonicalRegistrationEmail::parse(email)
        .ok()
        .map(|email| email.identity().to_string())
}

pub(crate) fn fingerprint_sql(schema: &str) -> String {
    format!(
        concat!(
            "select encode(sha256(convert_to(",
            "'cluster=' || (select system_identifier::text from pg_control_system()) || chr(31) || ",
            "'database=' || (select oid::text from pg_database where datname=current_database()) || chr(31) || ",
            "'schema=' || (select oid::text from pg_namespace where nspname=$1) || chr(31) || ",
            "coalesce(string_agg(a.id::text || chr(31) || a.registration_tenant_id || chr(31) || a.email || chr(31) || a.password_hash || chr(31) || a.status || chr(31) || a.created_at_epoch::text || chr(31) || coalesce(m.memberships, ''), chr(30) order by a.id::text), ''), ",
            "'UTF8')), 'hex') from {schema}.accounts a left join (select account_id, string_agg(tenant_id || ':' || status || ':' || version::text || ':' || joined_at_epoch::text || ':' || coalesce(removed_at_epoch::text, ''), chr(29) order by tenant_id) as memberships from {schema}.access_memberships group by account_id) m on m.account_id=a.id"
        ),
        schema = schema,
    )
}

pub(crate) fn db_error(_error: postgres::Error) -> StoreError {
    StoreError::Backend(BACKEND_ERROR.to_string())
}

pub(crate) fn validate_apply_plan(
    plan: &RegistrationEmailMigrationPlan,
    current: &Snapshot,
    schema: &str,
    requested_mode: TenancyMode,
) -> Result<(), StoreError> {
    if plan.schema_name != schema
        || plan.mode != requested_mode
        || plan.version != REGISTRATION_EMAIL_SCHEMA_VERSION
        || current.access_mode != requested_mode
        || plan.database_name != current.database_name
        || plan.access_schema_version != current.access_schema_version
        || plan.fingerprint != current.fingerprint
        || plan.account_count != current.account_count
        || plan.normalized_count != current.normalized_count
        || plan.normalization_collision_count != current.collision_count
        || plan.invalid_email_count != current.invalid_email_count
        || plan.legacy_code_count != current.legacy_code_count
    {
        return Err(StoreError::Conflict("registration_email.plan_drift"));
    }
    if current.invalid_email_count != 0 || current.collision_count != 0 {
        return Err(StoreError::Conflict(
            "registration_email.normalization_conflict",
        ));
    }
    Ok(())
}

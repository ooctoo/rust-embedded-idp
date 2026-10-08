mod admin;
mod authentication;
mod device_management;
mod device_proof;
mod oidc;
mod refresh;
mod registration;
mod scan_login;
pub use admin::PostgresAccessAdminTransaction;
pub use authentication::PostgresTenantAuthTransaction;
pub use registration::PostgresTenantEmailVerificationTransaction;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use embedded_idp_core::access::{
    AccessListScope, AccessPageRequest, AccessQuery, AccessReadStore, BatchAccessQuery,
    MembershipStatus, PermissionCatalog, PermissionCategory, PermissionDefinition, PermissionKey,
    Role, RoleKind, RoleStatus, SubjectTenant, TenancyMode, Tenant, TenantMembership,
    TenantRegistration, TenantRegistrationStore, TenantStatus,
};
use embedded_idp_core::StoreError;
use postgres::{GenericClient, Row};
use uuid::Uuid;

use crate::PostgresStorageAdapter;

pub const ACCESS_SCHEMA_VERSION: &str = "tenant_v5";
const DDL: &str = include_str!("sql/tenant_v5.sql");
const ACCESS_TABLES: &[&str] = &[
    "access_state",
    "access_tenants",
    "accounts",
    "access_memberships",
    "access_permissions",
    "access_roles",
    "access_role_permissions",
    "access_role_bindings",
    "access_audit_events",
    "oidc_clients",
    "devices",
    "auth_sessions",
    "account_device_bindings",
    "refresh_tokens",
    "authorization_codes",
    "email_verification_codes",
    "auth_tenant_selections",
    "device_proof_keys",
    "device_registrations",
    "device_nonces",
    "scan_login_grants",
    "scan_login_operations",
    "scan_login_deliveries",
    "scan_login_audit_events",
];

fn validate_layout(client: &mut impl GenericClient, schema: &str) -> Result<(), StoreError> {
    let triggers = [
        "account_requires_membership",
        "account_status_requires_membership",
        "membership_requires_membership",
        "access_domain_guard",
        "access_state_guard",
        "membership_identity_guard",
        "device_identity_guard",
        "role_identity_guard",
        "role_permission_guard",
        "role_binding_guard",
    ];
    let constraints = [
        "account_registration_membership",
        "device_current_key_tenant",
        "devices_tenant_id_id_client_id_key",
        "device_registrations_expected_key_id_key",
        "device_registrations_tenant_id_device_id_key",
        "device_registrations_tenant_id_device_id_client_id_fkey",
        "auth_session_scope_length",
        "auth_session_auth_time",
        "auth_session_purpose",
        "authorization_code_digest_length",
        "authorization_code_source_session",
        "authorization_code_pkce_pair",
        "access_role_bindings_tenant_id_account_id_fkey",
        "access_role_bindings_tenant_id_business_id_role_id_fkey",
    ];
    let row = client.query_one(
        "select not exists(select 1 from unnest($2::text[]) t(name) where not exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname=t.name and c.relkind='r'))
         and not exists(select 1 from unnest($3::text[]) t(name) where not exists(select 1 from pg_trigger g join pg_class c on c.oid=g.tgrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and g.tgname=t.name and g.tgenabled in ('O','A')))
         and not exists(select 1 from unnest($4::text[]) t(name) where not exists(select 1 from pg_constraint c join pg_namespace n on n.oid=c.connamespace where n.nspname=$1 and c.conname=t.name and c.convalidated))",
        &[&schema, &ACCESS_TABLES, &&triggers[..], &&constraints[..]],
    ).map_err(access_db_error)?;
    if !row.get::<_, bool>(0) {
        return Err(StoreError::Backend(
            "access schema layout is incomplete".into(),
        ));
    }
    let has_time_column: bool = client.query_one(
        "select exists(select 1 from information_schema.columns where table_schema=$1 and table_name='access_permissions' and column_name='created_at_epoch' and data_type='bigint')",
        &[&schema],
    ).map_err(access_db_error)?.get(0);
    if !has_time_column {
        return Err(StoreError::Conflict("access.list_time_migration_required"));
    }
    let business_layout: bool = client.query_one(
        "select not exists(select 1 from unnest(array['access_permissions','access_roles','access_role_permissions','access_role_bindings']) t(name) where not exists(select 1 from information_schema.columns c where c.table_schema=$1 and c.table_name=t.name and c.column_name='business_id' and c.data_type='text' and c.is_nullable='NO' and c.collation_name='C'))
         and exists(select 1 from information_schema.columns where table_schema=$1 and table_name='access_role_bindings' and column_name='scope_kind' and data_type='text' and is_nullable='NO')
         and exists(select 1 from information_schema.columns where table_schema=$1 and table_name='access_audit_events' and column_name='target_business_id' and data_type='text' and collation_name='C')
         and not exists(select 1 from unnest(array['access_business_admin_unique','access_binding_business_unique']) expected(name) where not exists(select 1 from pg_index i join pg_class c on c.oid=i.indexrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname=expected.name and i.indisunique and i.indisvalid))",
        &[&schema],
    ).map_err(access_db_error)?.get(0);
    if !business_layout {
        return Err(StoreError::Backend(
            "access business schema layout is incomplete".into(),
        ));
    }
    let device_versions: bool = client.query_one(
        "select not exists(select 1 from (values ('devices'),('account_device_bindings')) expected(table_name) where not exists(select 1 from information_schema.columns c where c.table_schema=$1 and c.table_name=expected.table_name and c.column_name='version' and c.data_type='bigint' and c.is_nullable='NO')) and exists(select 1 from pg_index i join pg_class c on c.oid=i.indexrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname='device_binding_device_page' and i.indisvalid) and (select count(*) from information_schema.columns where table_schema=$1 and table_name='access_audit_events' and column_name in ('device_operation_id','device_command_sha256'))=2 and exists(select 1 from pg_index i join pg_class c on c.oid=i.indexrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname='access_audit_device_operation' and i.indisunique and i.indisvalid)",
        &[&schema],
    ).map_err(access_db_error)?.get(0);
    if !device_versions {
        return Err(StoreError::Backend(
            "access device lifecycle layout is incomplete".into(),
        ));
    }
    let scan_layout: bool = client.query_one(
        "select (select count(*) from information_schema.columns where table_schema=$1 and table_name='scan_login_grants' and column_name in ('tenant_id','host_scope','entry_id','id','state','version','source_session_id','target_device_id','delivery_secret_hash'))=9
          and (select count(*) from information_schema.columns where table_schema=$1 and table_name='scan_login_deliveries' and column_name in ('grant_id','session_id','state','binding_id','binding_version','recover_until_epoch'))=6
          and exists(select 1 from pg_index i join pg_class c on c.oid=i.indrelid join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname='scan_login_deliveries' and i.indisunique)",
        &[&schema],
    ).map_err(access_db_error)?.get(0);
    if !scan_layout {
        return Err(StoreError::Backend(
            "access scan login schema layout is incomplete".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessSchemaFacts {
    pub version: String,
    pub mode: TenancyMode,
    /// Schema creation alone is NEVER administrator bootstrap or online readiness.
    pub bootstrap_completed: bool,
}

pub(crate) fn access_db_error(error: postgres::Error) -> StoreError {
    match error.code().map(|c| c.code()) {
        Some("23505") => StoreError::Conflict("access.unique"),
        Some("23503" | "23514" | "23502") => StoreError::Conflict("access.constraint"),
        Some("40001" | "40P01") => StoreError::Conflict("access.concurrent_write"),
        Some("42P07" | "42723" | "42710") => StoreError::Conflict("access.schema_object_conflict"),
        _ => StoreError::Backend("postgres access operation failed".into()),
    }
}
fn invalid() -> StoreError {
    StoreError::Backend("invalid access storage data".into())
}
fn mode_name(mode: TenancyMode) -> &'static str {
    match mode {
        TenancyMode::Disabled => "disabled",
        TenancyMode::Enabled => "enabled",
    }
}
fn category_name(category: PermissionCategory) -> &'static str {
    match category {
        PermissionCategory::Platform => "platform",
        PermissionCategory::Tenant => "tenant",
        PermissionCategory::Business => "business",
    }
}
fn epoch(value: SystemTime) -> Result<i64, StoreError> {
    i64::try_from(
        value
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs(),
    )
    .map_err(|_| invalid())
}
fn time(value: i64) -> Result<SystemTime, StoreError> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(
            u64::try_from(value).map_err(|_| invalid())?,
        ))
        .ok_or_else(invalid)
}

fn schema_facts(
    client: &mut impl GenericClient,
    schema: &str,
    mode: TenancyMode,
) -> Result<AccessSchemaFacts, StoreError> {
    let row = client.query_opt(&format!("select module_version, tenancy_mode, bootstrap_completed_at_epoch is not null as bootstrapped from {schema}.access_state where singleton"), &[]).map_err(access_db_error)?.ok_or_else(invalid)?;
    let version: String = row.get("module_version");
    if version != ACCESS_SCHEMA_VERSION || row.get::<_, String>("tenancy_mode") != mode_name(mode) {
        return Err(StoreError::Conflict("access.schema_mode_or_version"));
    }
    Ok(AccessSchemaFacts {
        version,
        mode,
        bootstrap_completed: row.get("bootstrapped"),
    })
}

impl PostgresStorageAdapter {
    /// Explicit initialization in a schema without conflicting IdP objects.
    /// Never migrates, resets or rewrites existing objects or permissions.
    pub fn initialize_access_schema(
        &self,
        mode: TenancyMode,
        catalog: &PermissionCatalog,
    ) -> Result<AccessSchemaFacts, StoreError> {
        let mut client = self.connect()?;
        let mut tx = client.transaction().map_err(access_db_error)?;
        let schema = self.schema_name();
        tx.query_one(
            "select pg_advisory_xact_lock(hashtext($1))",
            &[&format!("{schema}:embedded-idp-migration")],
        )
        .map_err(access_db_error)?;
        let state = format!("{schema}.access_state");
        let exists: bool = tx
            .query_one("select to_regclass($1) is not null", &[&state])
            .map_err(access_db_error)?
            .get(0);
        if exists {
            validate_layout(&mut tx, schema)?;
            let facts = schema_facts(&mut tx, schema, mode)?;
            tx.commit().map_err(access_db_error)?;
            return Ok(facts);
        }
        let conflicting_table = tx.query_opt(
            "select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname=any($2::text[]) limit 1",
            &[&schema, &ACCESS_TABLES],
        ).map_err(access_db_error)?;
        if conflicting_table.is_some() {
            return Err(StoreError::Conflict("access.schema_object_conflict"));
        }
        // schema is validated by PgStorageConfig; no business input enters SQL text.
        tx.batch_execute(&format!("create schema if not exists {schema}"))
            .map_err(access_db_error)?;
        tx.batch_execute(&DDL.replace("__SCHEMA__", schema))
            .map_err(access_db_error)?;
        tx.execute(&format!("insert into {schema}.access_state(singleton,tenancy_mode,module_version) values(true,$1,$2)"), &[&mode_name(mode), &ACCESS_SCHEMA_VERSION]).map_err(access_db_error)?;
        tx.execute(&format!("insert into {schema}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values('0','system','System','active',$1,extract(epoch from clock_timestamp())::bigint)"), &[&(mode == TenancyMode::Disabled)]).map_err(access_db_error)?;
        for definition in catalog.definitions() {
            if mode == TenancyMode::Enabled && definition.category == PermissionCategory::Business {
                continue;
            }
            tx.execute(&format!("insert into {schema}.access_permissions(tenant_id,business_id,resource_type,action,category,description,enabled,archived,version) values('0',$1,$2,$3,$4,$5,$6,$7,$8)"), &[&definition.key.business_id, &definition.key.resource_type, &definition.key.action, &category_name(definition.category), &definition.description, &definition.enabled, &definition.archived, &(definition.version as i64)]).map_err(access_db_error)?;
        }
        let facts = schema_facts(&mut tx, schema, mode)?;
        tx.commit().map_err(access_db_error)?;
        Ok(facts)
    }

    pub fn inspect_access_schema(
        &self,
        mode: TenancyMode,
    ) -> Result<AccessSchemaFacts, StoreError> {
        let mut client = self.connect()?;
        validate_layout(&mut *client, self.schema_name())?;
        schema_facts(&mut *client, self.schema_name(), mode)
    }
}

/// Shares the host-injected adapter/pool. Construction verifies the schema and
/// bootstrap marker; it neither initializes schema nor chooses tenancy mode.
#[derive(Clone)]
pub struct PostgresAccessStore {
    adapter: PostgresStorageAdapter,
    mode: TenancyMode,
}
impl PostgresAccessStore {
    pub fn new(adapter: PostgresStorageAdapter, mode: TenancyMode) -> Result<Self, StoreError> {
        if !adapter.inspect_access_schema(mode)?.bootstrap_completed {
            return Err(StoreError::Conflict("access.bootstrap_required"));
        }
        Ok(Self { adapter, mode })
    }

    /// Verifies that the prepared Access schema can serve traffic without
    /// changing schema, catalog, bootstrap, or user state.
    pub fn check_readiness(&self, catalog: &PermissionCatalog) -> Result<(), StoreError> {
        admin::check_readiness(self, catalog)
    }

    fn verify(&self, client: &mut impl GenericClient) -> Result<(), StoreError> {
        if !schema_facts(client, self.adapter.schema_name(), self.mode)?.bootstrap_completed {
            return Err(StoreError::Conflict("access.bootstrap_required"));
        }
        Ok(())
    }
}

impl AccessReadStore for PostgresAccessStore {
    fn check_active_grants(&self, queries: &[AccessQuery]) -> Result<Vec<bool>, StoreError> {
        check_grants(
            &mut *self.adapter.connect()?,
            self.adapter.schema_name(),
            self.mode,
            queries,
        )
    }

    fn list_subject_roles(
        &self,
        tenant: &str,
        business_id: &str,
        subject: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<Role>, StoreError> {
        page.validate(&AccessListScope::SubjectRoles {
            tenant_id: tenant.into(),
            business_id: business_id.into(),
            subject_id: subject.into(),
        })
        .map_err(|_| StoreError::Conflict("access.page"))?;
        let Ok(subject) = Uuid::parse_str(subject) else {
            return Ok(vec![]);
        };
        let after = page
            .cursor
            .as_ref()
            .map(|c| Uuid::parse_str(&c.after[0]))
            .transpose()
            .map_err(|_| StoreError::Conflict("access.cursor"))?;
        let mut client = self.adapter.connect()?;
        self.verify(&mut *client)?;
        let s = self.adapter.schema_name();
        client.query(&format!("select r.* from {s}.access_roles r where r.tenant_id=$1 and r.business_id=$2 and ($4::uuid is null or r.id>$4) and exists(select 1 from {s}.access_role_bindings b where b.tenant_id=r.tenant_id and b.business_id=r.business_id and b.role_id=r.id and b.account_id=$3) order by r.id limit $5"), &[&tenant,&business_id,&subject,&after,&(page.fetch_limit() as i64)]).map_err(access_db_error)?.iter().map(decode_role).collect()
    }
    fn list_role_permissions(
        &self,
        tenant: &str,
        business_id: &str,
        role: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<PermissionDefinition>, StoreError> {
        page.validate(&AccessListScope::RolePermissions {
            tenant_id: tenant.into(),
            business_id: business_id.into(),
            role_id: role.into(),
        })
        .map_err(|_| StoreError::Conflict("access.page"))?;
        let Ok(role) = Uuid::parse_str(role) else {
            return Ok(vec![]);
        };
        let resource = page.cursor.as_ref().map(|c| c.after[0].as_str());
        let action = page.cursor.as_ref().map(|c| c.after[1].as_str());
        let mut client = self.adapter.connect()?;
        self.verify(&mut *client)?;
        let s = self.adapter.schema_name();
        client.query(&format!("select p.* from {s}.access_role_permissions rp join {s}.access_permissions p using(tenant_id,business_id,resource_type,action) where rp.tenant_id=$1 and rp.business_id=$2 and rp.role_id=$3 and ($4::text is null or (p.resource_type,p.action)>($4 collate \"C\",$5 collate \"C\")) order by p.resource_type,p.action limit $6"), &[&tenant,&business_id,&role,&resource,&action,&(page.fetch_limit() as i64)]).map_err(access_db_error)?.iter().map(decode_permission).collect()
    }
    fn list_subject_tenants(
        &self,
        subject: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<SubjectTenant>, StoreError> {
        if self.mode != TenancyMode::Enabled {
            return Err(StoreError::Conflict("access.tenancy_disabled"));
        }
        page.validate(&AccessListScope::SubjectTenants {
            subject_id: subject.into(),
        })
        .map_err(|_| StoreError::Conflict("access.page"))?;
        let Ok(subject) = Uuid::parse_str(subject) else {
            return Ok(vec![]);
        };
        let after = page.cursor.as_ref().map(|c| c.after[0].as_str());
        let mut client = self.adapter.connect()?;
        self.verify(&mut *client)?;
        let s = self.adapter.schema_name();
        client.query(&format!("select t.*,m.account_id,m.status as member_status,m.version as member_version,m.joined_at_epoch from {s}.access_memberships m join {s}.access_tenants t on t.id=m.tenant_id where m.account_id=$1 and m.status<>'removed' and t.id<>'0' and ($2::text is null or t.id>$2 collate \"C\") order by t.id limit $3"), &[&subject,&after,&(page.fetch_limit() as i64)]).map_err(access_db_error)?.iter().map(|row| {
            let tenant = decode_tenant(row)?;
            Ok(SubjectTenant { membership: TenantMembership { tenant_id: tenant.id.clone(), subject_id: row.get::<_,Uuid>("account_id").to_string(), status: match row.get::<_,&str>("member_status") { "active"=>MembershipStatus::Active,"suspended"=>MembershipStatus::Suspended,"removed"=>MembershipStatus::Removed,_=>return Err(invalid()) }, joined_at: time(row.get("joined_at_epoch"))?, version: u64::try_from(row.get::<_,i64>("member_version")).map_err(|_| invalid())? }, tenant })
        }).collect()
    }
}

impl TenantRegistrationStore for PostgresAccessStore {
    fn create_registered_account(
        &self,
        registration: &TenantRegistration,
    ) -> Result<(), StoreError> {
        let tenant = registration.registration_tenant_id();
        self.mode
            .validate_business_tenant(tenant)
            .map_err(|_| StoreError::Conflict("access.tenant"))?;
        let account = registration.account();
        let verification = registration.verification();
        let account_id =
            Uuid::parse_str(&account.id).map_err(|_| StoreError::Conflict("account.id"))?;
        let verification_id = Uuid::parse_str(&verification.id)
            .map_err(|_| StoreError::Conflict("verification.id"))?;
        let mut client = self.adapter.connect()?;
        let mut tx = client.transaction().map_err(access_db_error)?;
        let s = self.adapter.schema_name();
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for share"),
            &[],
        )
        .map_err(access_db_error)?;
        self.verify(&mut tx)?;
        let row = tx.query_opt(&format!("select status,allow_registration from {s}.access_tenants where id=$1 for share"), &[&tenant]).map_err(access_db_error)?.ok_or(StoreError::NotFound("tenant"))?;
        if row.get::<_, &str>("status") != "active" || !row.get::<_, bool>("allow_registration") {
            return Err(StoreError::Conflict("tenant.registration_closed"));
        }
        tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,display_name,status,created_at_epoch) values($1,$2,$3,$4,$5,'pending_verification',$6)"), &[&account_id,&tenant,&account.email,&account.password_hash,&account.display_name,&epoch(account.created_at)?]).map_err(access_db_error)?;
        tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch) values($1,$2,'active',1,$3)"), &[&tenant,&account_id,&epoch(registration.membership().joined_at)?]).map_err(access_db_error)?;
        tx.execute(&format!("insert into {s}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7)"), &[&tenant,&verification_id,&account_id,&verification.email,&verification.code,&epoch(verification.issued_at)?,&epoch(verification.expires_at)?]).map_err(access_db_error)?;
        tx.commit().map_err(access_db_error)
    }
}

fn decode_role(row: &Row) -> Result<Role, StoreError> {
    Ok(Role {
        created_at: time(row.get("created_at_epoch"))?,
        id: row.get::<_, Uuid>("id").to_string(),
        tenant_id: row.get("tenant_id"),
        business_id: row.get("business_id"),
        key: row.get("key"),
        name: row.get("name"),
        status: match row.get::<_, &str>("status") {
            "active" => RoleStatus::Active,
            "disabled" => RoleStatus::Disabled,
            _ => return Err(invalid()),
        },
        kind: match row.get::<_, &str>("kind") {
            "business" => RoleKind::Business,
            "business_admin" => RoleKind::BusinessAdmin,
            "system_admin" => RoleKind::SystemAdmin,
            "tenant_security_admin" => RoleKind::TenantSecurityAdmin,
            _ => return Err(invalid()),
        },
        version: u64::try_from(row.get::<_, i64>("version")).map_err(|_| invalid())?,
    })
}
fn decode_permission(row: &Row) -> Result<PermissionDefinition, StoreError> {
    Ok(PermissionDefinition {
        created_at: row
            .get::<_, Option<i64>>("created_at_epoch")
            .map(time)
            .transpose()?,
        tenant_id: row.get("tenant_id"),
        key: PermissionKey {
            business_id: row.get("business_id"),
            resource_type: row.get("resource_type"),
            action: row.get("action"),
        },
        description: row.get("description"),
        enabled: row.get("enabled"),
        archived: row.get("archived"),
        version: u64::try_from(row.get::<_, i64>("version")).map_err(|_| invalid())?,
        category: match row.get::<_, &str>("category") {
            "platform" => PermissionCategory::Platform,
            "tenant" => PermissionCategory::Tenant,
            "business" => PermissionCategory::Business,
            _ => return Err(invalid()),
        },
    })
}
fn decode_tenant(row: &Row) -> Result<Tenant, StoreError> {
    Ok(Tenant {
        id: row.get("id"),
        name: row.get("name"),
        status: match row.get::<_, &str>("status") {
            "active" => TenantStatus::Active,
            "suspended" => TenantStatus::Suspended,
            "archived" => TenantStatus::Archived,
            _ => return Err(invalid()),
        },
        allow_registration: row.get("allow_registration"),
    })
}

fn check_grants(
    client: &mut impl GenericClient,
    schema: &str,
    mode: TenancyMode,
    queries: &[AccessQuery],
) -> Result<Vec<bool>, StoreError> {
    BatchAccessQuery {
        queries: queries.to_vec(),
    }
    .validate()
    .map_err(|_| StoreError::Conflict("access.query"))?;
    let first = &queries[0];
    let Ok(subject) = Uuid::parse_str(&first.subject_id) else {
        return Ok(vec![false; queries.len()]);
    };
    let types: Vec<_> = queries.iter().map(|q| q.resource_type.as_str()).collect();
    let actions: Vec<_> = queries.iter().map(|q| q.action.as_str()).collect();
    let ids: Vec<_> = queries.iter().map(|q| q.resource_id.as_deref()).collect();
    // One parameterized SQL statement, one snapshot, stable duplicate/input order.
    let sql = format!(
        r#"
with state as (select tenancy_mode=$7 and module_version='tenant_v5' and bootstrap_completed_at_epoch is not null as valid from {schema}.access_state where singleton)
select coalesce((select valid from state),false) as valid, exists (
 select 1 from {schema}.accounts a
 join {schema}.access_memberships m on m.account_id=a.id and m.tenant_id=$1
 join {schema}.access_tenants t on t.id=m.tenant_id
 join {schema}.access_permissions p on p.tenant_id=m.tenant_id and p.business_id=$2 and p.resource_type=q.resource_type and p.action=q.action
 where a.id=$3 and a.status='active' and m.status='active' and t.status='active' and p.enabled and not p.archived
 and ((p.category='business' and exists (
      select 1 from {schema}.access_role_bindings b
      join {schema}.access_roles r on r.tenant_id=b.tenant_id and r.business_id=b.business_id and r.id=b.role_id
      where b.tenant_id=m.tenant_id and b.business_id=$2 and b.account_id=m.account_id
        and b.scope_kind='business' and r.status='active' and r.kind='business_admin'
        and (($7='disabled' and $1='0') or ($7='enabled' and $1<>'0'))
 )) or exists (
      select 1 from {schema}.access_role_bindings b
      join {schema}.access_roles r on r.tenant_id=b.tenant_id and r.business_id=b.business_id and r.id=b.role_id
      join {schema}.access_role_permissions rp on rp.tenant_id=r.tenant_id and rp.business_id=r.business_id and rp.role_id=r.id
          and rp.resource_type=q.resource_type and rp.action=q.action
      where b.tenant_id=m.tenant_id and b.business_id=$2 and b.account_id=m.account_id and r.status='active'
        and b.scope_kind in ('type','instance') and b.resource_type=q.resource_type
        and (b.scope_kind='type' or b.resource_id=q.resource_id)
        and ((p.category='platform' and r.kind='system_admin' and $1='0')
          or (p.category='tenant' and r.kind='tenant_security_admin' and (($7='disabled' and $1='0') or ($7='enabled' and $1<>'0')))
          or (p.category='business' and r.kind='business' and (($7='disabled' and $1='0') or ($7='enabled' and $1<>'0'))))
        and (p.category='business' or (b.scope_kind='type' and q.resource_id is null))
 ))
) as allowed
from unnest($4::text[],$5::text[],$6::text[]) with ordinality q(resource_type,action,resource_id,n) order by q.n
"#
    );
    let rows = client
        .query(
            &sql,
            &[
                &first.tenant_id,
                &first.business_id,
                &subject,
                &types,
                &actions,
                &ids,
                &mode_name(mode),
            ],
        )
        .map_err(access_db_error)?;
    if rows.len() != queries.len() || rows.iter().any(|r| !r.get::<_, bool>("valid")) {
        return Err(invalid());
    }
    Ok(rows.iter().map(|r| r.get("allowed")).collect())
}

#[cfg(test)]
mod scan_login_schema_tests {
    use super::{ACCESS_SCHEMA_VERSION, DDL};

    #[test]
    fn tenant_v5_initial_schema_has_relational_scan_login_invariants() {
        assert_eq!(ACCESS_SCHEMA_VERSION, "tenant_v5");
        for required in [
            "scan_login_grants",
            "scan_login_operations",
            "scan_login_deliveries",
            "scan_login_audit_events",
            "foreign key(tenant_id,target_device_id,target_client_id)",
            "primary key(tenant_id,host_scope,entry_id,actor_id,action,operation_id)",
            "unique(tenant_id,session_id)",
        ] {
            assert!(DDL.contains(required), "missing {required}");
        }
    }
}

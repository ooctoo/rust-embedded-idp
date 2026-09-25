mod security_admins;
pub use security_admins::*;
mod account_security;
pub use account_security::*;
mod accounts;
pub use accounts::*;
mod clients;
pub use clients::*;
mod sessions;
pub use sessions::*;
mod devices;
pub use devices::*;
mod tenants;
pub use tenants::*;
mod roles;
pub use roles::*;
mod permissions;
pub use permissions::*;
mod diagnostic;
pub use diagnostic::*;
mod audit;
pub use audit::*;

use std::{collections::BTreeSet, time::SystemTime};

use super::{
    query::{validate_id, validate_name},
    AccessActor, AccessAdminOperation, AccessError, AccessQuery, MembershipStatus,
    PermissionCatalog, PermissionCategory, PermissionDefinition, PermissionKey, ResourceScope,
    Role, RoleBinding, RoleKind, RoleStatus, TenancyMode, Tenant, TenantMembership, TenantStatus,
    SYSTEM_TENANT_ID,
};
use crate::{Clock, DeviceStatus, IdGenerator, SessionStatus, StoreError};

pub const MAX_ROLE_PERMISSIONS: usize = 200;
pub const MAX_PERMISSION_CHANGES: usize = 200;

/// Constructed by the trusted management authentication adapter, never from a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAdminContext {
    pub actor: AccessActor,
    pub authentication_source: String,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessAdminMutation {
    RevokeSession {
        session_id: String,
    },
    RevokeSubjectSessions {
        subject_id: String,
    },
    SetDeviceStatus {
        device_id: String,
        status: DeviceStatus,
        expected_status: DeviceStatus,
    },
    CreateTenant {
        name: String,
        allow_registration: bool,
        administrator_subject_id: String,
    },
    UpdateTenant {
        name: String,
        status: TenantStatus,
        allow_registration: bool,
        expected_version: u64,
    },
    /// Keys must exist in the trusted host catalog; requests cannot supply definitions.
    SyncPermissions {
        permissions: Vec<PermissionKey>,
    },
    SetPermissionEnabled {
        permission: PermissionKey,
        enabled: bool,
        expected_enabled: bool,
    },
    CreatePermission {
        key: PermissionKey,
        description: String,
    },
    UpdatePermission {
        key: PermissionKey,
        description: String,
        expected_version: u64,
    },
    ArchivePermission {
        key: PermissionKey,
        expected_version: u64,
    },
    CreateRole {
        key: String,
        name: String,
    },
    UpdateRole {
        role_id: String,
        name: String,
        status: RoleStatus,
        expected_version: u64,
    },
    DeleteRole {
        role_id: String,
        expected_version: u64,
    },
    ReplaceRolePermissions {
        role_id: String,
        permissions: Vec<PermissionKey>,
        expected_version: u64,
    },
    GrantRole {
        subject_id: String,
        role_id: String,
        resource_type: String,
        scope: ResourceScope,
    },
    RevokeRole {
        binding_id: String,
    },
    BindMember {
        subject_id: String,
    },
    SetMemberStatus {
        subject_id: String,
        status: MembershipStatus,
        expected_version: u64,
    },
    /// Only platform access.manage may appoint/revoke protected administrators.
    SetSecurityAdmin {
        subject_id: String,
        appointed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAdminCommand {
    pub tenant_id: String,
    pub mutation: AccessAdminMutation,
}

/// The complete permission set participates in role versioning and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRoleRecord {
    pub role: Role,
    pub permissions: Vec<PermissionKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTenantRecord {
    pub tenant: Tenant,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPermissionChange {
    pub before: Option<PermissionDefinition>,
    pub after: PermissionDefinition,
}

/// Typed, secret-free audit records. Credentials use separate transaction primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessChange {
    PermissionChecked {
        query: AccessQuery,
        decision: super::AccessDecision,
    },
    AccountCreated {
        after: AccessAccountRecord,
    },
    AccountSecurity {
        before: AccessAccountRecord,
        after: AccessAccountRecord,
        password_changed: bool,
    },
    Client {
        before: Option<crate::AdminClientRecord>,
        after: crate::AdminClientRecord,
        secret_changed: bool,
    },
    Session {
        before: super::TenantSession,
        after: super::TenantSession,
    },
    SubjectSessionsRevoked {
        tenant_id: String,
        subject_id: String,
        active_session_count: u64,
    },
    Device {
        before: AccessDeviceRecord,
        after: AccessDeviceRecord,
    },
    TenantCreated {
        record: AccessTenantRecord,
        administrator: TenantMembership,
        permission_definitions: Vec<PermissionDefinition>,
        role: AccessRoleRecord,
        binding: RoleBinding,
    },
    Tenant {
        before: AccessTenantRecord,
        after: AccessTenantRecord,
    },
    Catalog {
        changes: Vec<AccessPermissionChange>,
    },
    Role {
        before: Option<AccessRoleRecord>,
        after: Option<AccessRoleRecord>,
    },
    Binding {
        before: Option<RoleBinding>,
        after: Option<RoleBinding>,
    },
    Membership {
        before: Option<TenantMembership>,
        after: TenantMembership,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAuditEvent {
    pub id: String,
    pub occurred_at: SystemTime,
    pub context: AccessAdminContext,
    pub tenant_id: String,
    pub operation: &'static str,
    pub change: AccessChange,
}

/// Locks precede every read/authorization. Use the persisted mode, not just config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessWriteScope {
    pub mode: TenancyMode,
    /// Exclusive for domain 0 writes and tenant creation (the target row does not
    /// exist yet); shared for ordinary writes to existing business domains.
    pub exclusive_state: bool,
    /// Lock domain rows in this sorted order, before account rows.
    pub tenant_ids: Vec<String>,
    /// Lock accounts in sorted order, including the actor and explicit target.
    pub subject_ids: Vec<String>,
}

/// Infrastructure primitives only. Core owns authorization and mutation rules.
pub trait AccessAdminTransaction {
    /// Insert tenant metadata inside a transaction that also establishes its administrator.
    fn insert_admin_tenant(
        &mut self,
        record: &AccessTenantRecord,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    fn insert_admin_account(
        &mut self,
        account: &AccessAccountRecord,
        password_hash: &crate::SecretString,
    ) -> Result<(), StoreError>;
    /// Update identity status/password and atomically retire credentials in ALL domains.
    fn update_account_security(
        &mut self,
        before: &AccessAccountRecord,
        status: AccountIdentityStatus,
        password_hash: Option<&crate::SecretString>,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    /// Active protected-admin memberships in active domains, sorted and bounded.
    fn account_admin_tenants(
        &mut self,
        subject: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, StoreError>;

    fn admin_account(
        &mut self,
        tenant: Option<&str>,
        account: &str,
    ) -> Result<Option<AccessAccountRecord>, StoreError>;
    fn admin_accounts(
        &mut self,
        tenant: Option<&str>,
        filter: &AdminAccountFilter,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<AccessAccountRecord>, StoreError>;

    fn admin_client(&mut self, id: &str) -> Result<Option<crate::OidcClient>, StoreError>;
    fn admin_clients(
        &mut self,
        filter: &AdminClientFilter,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<crate::AdminClientRecord>, StoreError>;
    /// Secret-bearing write, committed only with a separate secret-free audit event.
    fn upsert_admin_client(
        &mut self,
        client: &crate::OidcClient,
        now: SystemTime,
    ) -> Result<(), StoreError>;

    fn admin_session(
        &mut self,
        tenant: &str,
        session: &str,
    ) -> Result<Option<super::TenantSession>, StoreError>;
    fn admin_sessions(
        &mut self,
        tenant: &str,
        filter: &AdminSessionFilter,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<super::TenantSession>, StoreError>;
    fn active_subject_session_count(
        &mut self,
        tenant: &str,
        subject: &str,
    ) -> Result<u64, StoreError>;
    fn admin_device(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<AccessDeviceRecord>, StoreError>;
    /// Tenant-scoped ID keyset scan, returning at most limit + 1 records.
    /// Account filtering requires an active binding in this same tenant;
    /// without it, include unbound devices. Each device appears at most once.
    fn admin_devices(
        &mut self,
        tenant: &str,
        filter: &AdminDeviceFilter,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<AccessDeviceRecord>, StoreError>;
    /// Verify persisted mode/bootstrap readiness and acquire state -> domains ->
    /// accounts locks. Ordinary writes serialize per domain, NOT authorization reads.
    /// Keep locks through commit; cross-domain membership removal must serialize
    /// on the shared account and read fresh state after obtaining that lock.
    fn lock_scope(&mut self, scope: &AccessWriteScope) -> Result<(), AccessError>;
    /// Check current account/domain/membership AND the same-subject, same-domain,
    /// unexpired, unrevoked MANAGEMENT-purpose actor session after locks, at the supplied server time.
    fn actor_is_active(&mut self, actor: &AccessActor, now: SystemTime)
        -> Result<bool, StoreError>;
    /// Current grant predicate (RoleBinding::grants), never a preflight/cache result.
    fn check_permission(&mut self, query: &AccessQuery) -> Result<bool, StoreError>;
    fn tenant(&mut self, tenant_id: &str) -> Result<Option<Tenant>, StoreError>;
    fn tenant_record(&mut self, tenant_id: &str) -> Result<Option<AccessTenantRecord>, StoreError>;
    /// Platform-only real-tenant search; excludes reserved domain 0, orders by
    /// tenant ID and returns at most limit + 1 matching records.
    fn admin_tenants(
        &mut self,
        filter: &AdminTenantFilter,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<AccessTenantRecord>, StoreError>;
    /// Persisted category for this resource; mixed categories are a storage error.
    fn resource_category(
        &mut self,
        tenant_id: &str,
        resource_type: &str,
    ) -> Result<Option<PermissionCategory>, StoreError>;
    fn account_is_active(&mut self, subject_id: &str) -> Result<bool, StoreError>;
    fn membership(
        &mut self,
        tenant_id: &str,
        subject_id: &str,
    ) -> Result<Option<TenantMembership>, StoreError>;
    /// Complete versioned configuration, with unique permission keys ordered by
    /// (resource_type, action), bounded by MAX_ROLE_PERMISSIONS.
    fn role(
        &mut self,
        tenant_id: &str,
        role_id: &str,
    ) -> Result<Option<AccessRoleRecord>, StoreError>;
    /// Metadata only, including protected/disabled roles in exactly one tenant.
    /// ID keyset order, at most limit + 1 rows; do not expand permission sets.
    fn admin_roles(
        &mut self,
        tenant: &str,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<Role>, StoreError>;
    fn permission(
        &mut self,
        key: &PermissionKey,
    ) -> Result<Option<PermissionDefinition>, StoreError>;
    fn tenant_permission(
        &mut self,
        tenant_id: &str,
        key: &PermissionKey,
    ) -> Result<Option<PermissionDefinition>, StoreError>;
    /// Persisted directory, including disabled/retired-host entries, filtered by
    /// scope/category. Keyset order (resource_type, action), at most limit + 1.
    fn admin_permissions(
        &mut self,
        scope: &AdminPermissionScope,
        filter: &AdminPermissionFilter,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<PermissionDefinition>, StoreError>;
    fn binding(
        &mut self,
        tenant_id: &str,
        binding_id: &str,
    ) -> Result<Option<RoleBinding>, StoreError>;
    /// Configured assignments in exactly one tenant and subject, including
    /// protected roles. ID keyset order, at most limit + 1; no resource expansion.
    fn admin_role_bindings(
        &mut self,
        tenant: &str,
        subject: &str,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<RoleBinding>, StoreError>;
    /// Exactly one immutable protected role per (tenant, kind), seeded by bootstrap.
    fn security_role(
        &mut self,
        tenant_id: &str,
        kind: RoleKind,
    ) -> Result<Option<AccessRoleRecord>, StoreError>;
    fn security_binding(
        &mut self,
        tenant_id: &str,
        subject_id: &str,
        role_id: &str,
    ) -> Result<Option<RoleBinding>, StoreError>;
    /// Apply with uniqueness/FK checks and compare the before version where present.
    /// Role deletion removes its bindings. Removing a role's last action for a
    /// resource type deletes bindings for that type, so re-adding cannot revive them.
    /// Member suspension/removal revokes this domain's sessions/refresh families,
    /// authorization/verification codes and applicable selection tickets. Removal
    /// additionally deletes role bindings and unbinds devices. Rejoining restores
    /// NONE of those credentials/grants. All effects must use this transaction.
    /// Tenant creation includes its initial administrator and protected role.
    /// Tenant suspension/archive revokes credentials and device nonces in that
    /// tenant; retain memberships, grants and device bindings for explicit resume.
    fn apply_change(&mut self, change: &AccessChange, now: SystemTime) -> Result<(), StoreError>;
    fn has_non_removed_membership(&mut self, subject_id: &str) -> Result<bool, StoreError>;
    /// EXISTS an active account with active membership, active protected
    /// role, enabled required permissions and the correct type-wide binding.
    /// No business-role or partial/disabled grant qualifies as a security admin.
    fn has_effective_security_admin(
        &mut self,
        tenant_id: &str,
        kind: RoleKind,
    ) -> Result<bool, StoreError>;
    fn append_audit(&mut self, event: &AccessAuditEvent) -> Result<(), StoreError>;
    /// Metadata only, ordered by (occurred_at, id), at most limit + 1, exact target domain.
    fn admin_audit_events(
        &mut self,
        tenant: &str,
        filter: &AdminAuditFilter,
        page: &super::AccessPageRequest,
    ) -> Result<Vec<AdminAuditRecord>, StoreError>;
    /// Read the stored secret-free change projection in the same target domain.
    fn admin_audit_event(
        &mut self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<AdminAuditDetail>, StoreError>;
}

pub trait AccessAdminStore: Send + Sync {
    type Transaction<'a>: AccessAdminTransaction
    where
        Self: 'a;
    /// Commit only on Ok, including audit; rollback on EVERY error or panic.
    /// Never use the read service/preflight result as transaction authority.
    fn admin_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;
}

pub trait AccessAdminService: Send + Sync {
    fn execute(
        &self,
        context: AccessAdminContext,
        command: AccessAdminCommand,
    ) -> Result<AccessAuditEvent, AccessError>;
}

pub struct CoreAccessAdminService<S, C, I> {
    mode: TenancyMode,
    catalog: PermissionCatalog,
    store: S,
    clock: C,
    ids: I,
}

impl<S, C, I> CoreAccessAdminService<S, C, I> {
    pub fn new(mode: TenancyMode, catalog: PermissionCatalog, store: S, clock: C, ids: I) -> Self {
        Self {
            mode,
            catalog,
            store,
            clock,
            ids,
        }
    }
}

impl AccessAdminMutation {
    fn operation(&self) -> &'static str {
        match self {
            Self::RevokeSession { .. } => "session.revoke",
            Self::RevokeSubjectSessions { .. } => "subject.sessions.revoke",
            Self::SetDeviceStatus {
                status: DeviceStatus::Revoked,
                ..
            } => "device.revoke",
            Self::SetDeviceStatus { .. } => "device.disable",
            Self::CreateTenant { .. } => "tenant.create",
            Self::UpdateTenant { .. } => "tenant.update",
            Self::SyncPermissions { .. } => "catalog.sync",
            Self::SetPermissionEnabled { .. } => "catalog.enabled",
            Self::CreatePermission { .. } => "permission.create",
            Self::UpdatePermission { .. } => "permission.update",
            Self::ArchivePermission { .. } => "permission.archive",
            Self::CreateRole { .. } => "role.create",
            Self::UpdateRole { .. } => "role.update",
            Self::DeleteRole { .. } => "role.delete",
            Self::ReplaceRolePermissions { .. } => "role.permissions.replace",
            Self::GrantRole { .. } => "role.grant",
            Self::RevokeRole { .. } => "role.revoke",
            Self::BindMember { .. } => "member.bind",
            Self::SetMemberStatus { .. } => "member.status",
            Self::SetSecurityAdmin { .. } => "security_admin.set",
        }
    }

    fn subject(&self) -> Option<&str> {
        match self {
            Self::CreateTenant {
                administrator_subject_id,
                ..
            } => Some(administrator_subject_id),
            Self::RevokeSubjectSessions { subject_id }
            | Self::GrantRole { subject_id, .. }
            | Self::BindMember { subject_id }
            | Self::SetMemberStatus { subject_id, .. }
            | Self::SetSecurityAdmin { subject_id, .. } => Some(subject_id),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), AccessError> {
        if let Some(subject) = self.subject() {
            validate_id(subject, 128, "subject_id")?;
        }
        match self {
            Self::RevokeSession { session_id } => validate_id(session_id, 128, "session_id")?,
            Self::SetDeviceStatus {
                device_id, status, ..
            } => {
                validate_id(device_id, 128, "device_id")?;
                if !matches!(status, DeviceStatus::Disabled | DeviceStatus::Revoked) {
                    return Err(AccessError::InvalidInput("device_status"));
                }
            }
            Self::CreateTenant { name, .. } | Self::UpdateTenant { name, .. } => {
                if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control)
                {
                    return Err(AccessError::InvalidInput("tenant_name"));
                }
                if matches!(
                    self,
                    Self::UpdateTenant {
                        expected_version: 0,
                        ..
                    }
                ) {
                    return Err(AccessError::InvalidInput("expected_version"));
                }
            }
            Self::SyncPermissions { permissions } => {
                if permissions.is_empty() || permissions.len() > MAX_PERMISSION_CHANGES {
                    return Err(AccessError::InvalidInput("permissions_limit"));
                }
                let mut unique = BTreeSet::new();
                for permission in permissions {
                    permission.validate()?;
                    if !unique.insert(permission) {
                        return Err(AccessError::InvalidInput("duplicate_permission"));
                    }
                }
            }
            Self::SetPermissionEnabled { permission, .. } => permission.validate()?,
            Self::CreatePermission { key, description }
            | Self::UpdatePermission {
                key, description, ..
            } => {
                key.validate()?;
                validate_permission_description(description)?;
                if key.resource_type.starts_with("idp.") {
                    return Err(AccessError::Forbidden);
                }
                if let Self::UpdatePermission {
                    expected_version, ..
                } = self
                {
                    if *expected_version == 0 {
                        return Err(AccessError::InvalidInput("expected_version"));
                    }
                }
            }
            Self::ArchivePermission {
                key,
                expected_version,
            } => {
                key.validate()?;
                if key.resource_type.starts_with("idp.") {
                    return Err(AccessError::Forbidden);
                }
                if *expected_version == 0 {
                    return Err(AccessError::InvalidInput("expected_version"));
                }
            }
            Self::CreateRole { key, name } => {
                validate_name(key, "role_key")?;
                if matches!(key.as_str(), "system_admin" | "tenant_security_admin") {
                    return Err(AccessError::Forbidden);
                }
                validate_role_name(name)?;
            }
            Self::UpdateRole {
                role_id,
                name,
                expected_version,
                ..
            } => {
                validate_role_name(name)?;
                validate_version(role_id, *expected_version)?;
            }
            Self::DeleteRole {
                role_id,
                expected_version,
            } => validate_version(role_id, *expected_version)?,
            Self::ReplaceRolePermissions {
                role_id,
                permissions,
                expected_version,
            } => {
                validate_version(role_id, *expected_version)?;
                if permissions.len() > MAX_ROLE_PERMISSIONS {
                    return Err(AccessError::InvalidInput("permissions_limit"));
                }
                let mut unique = BTreeSet::new();
                for permission in permissions {
                    permission.validate()?;
                    if !unique.insert(permission) {
                        return Err(AccessError::InvalidInput("duplicate_permission"));
                    }
                }
            }
            Self::GrantRole {
                role_id,
                resource_type,
                scope,
                ..
            } => {
                validate_id(role_id, 128, "role_id")?;
                validate_name(resource_type, "resource_type")?;
                scope.validate()?;
            }
            Self::RevokeRole { binding_id } => validate_id(binding_id, 128, "binding_id")?,
            Self::SetMemberStatus {
                expected_version, ..
            } if *expected_version == 0 => {
                return Err(AccessError::InvalidInput("expected_version"))
            }
            _ => (),
        }
        Ok(())
    }
}

fn validate_role_name(name: &str) -> Result<(), AccessError> {
    if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
        return Err(AccessError::InvalidInput("role_name"));
    }
    Ok(())
}

fn validate_permission_description(description: &str) -> Result<(), AccessError> {
    if description.trim().is_empty()
        || description.len() > 256
        || description.chars().any(char::is_control)
    {
        return Err(AccessError::InvalidInput("permission_description"));
    }
    Ok(())
}

fn validate_version(id: &str, version: u64) -> Result<(), AccessError> {
    validate_id(id, 128, "role_id")?;
    if version == 0 {
        return Err(AccessError::InvalidInput("expected_version"));
    }
    Ok(())
}

fn next_version(current: u64, expected: u64) -> Result<u64, AccessError> {
    if current != expected {
        return Err(AccessError::Conflict("version"));
    }
    current
        .checked_add(1)
        .ok_or(AccessError::Conflict("version_exhausted"))
}

fn security_kind(tenant: &str) -> RoleKind {
    if tenant == SYSTEM_TENANT_ID {
        RoleKind::SystemAdmin
    } else {
        RoleKind::TenantSecurityAdmin
    }
}

impl<S, C, I> CoreAccessAdminService<S, C, I>
where
    S: AccessAdminStore,
    C: Clock,
    I: IdGenerator,
{
    fn new_id(&self, prefix: &str) -> Result<String, AccessError> {
        let id = self.ids.next_id(prefix);
        validate_id(&id, 128, "generated_id")?;
        Ok(id)
    }

    fn business_role(
        &self,
        tx: &mut impl AccessAdminTransaction,
        tenant: &str,
        role_id: &str,
    ) -> Result<AccessRoleRecord, AccessError> {
        let record = tx
            .role(tenant, role_id)?
            .ok_or(AccessError::NotFound("role"))?;
        if record.role.tenant_id != tenant || record.role.id != role_id {
            return Err(AccessError::InvalidStoreResponse);
        }
        if record.role.kind != RoleKind::Business {
            return Err(AccessError::Forbidden);
        }
        self.mode.validate_business_tenant(tenant)?;
        Ok(record)
    }

    fn active_member(
        &self,
        tx: &mut impl AccessAdminTransaction,
        tenant: &str,
        subject: &str,
    ) -> Result<TenantMembership, AccessError> {
        let member = tx
            .membership(tenant, subject)?
            .ok_or(AccessError::NotFound("membership"))?;
        if member.tenant_id != tenant || member.subject_id != subject {
            return Err(AccessError::InvalidStoreResponse);
        }
        if member.status != MembershipStatus::Active || !tx.account_is_active(subject)? {
            return Err(AccessError::Forbidden);
        }
        Ok(member)
    }

    fn business_permission(
        &self,
        tx: &mut impl AccessAdminTransaction,
        tenant: &str,
        key: &PermissionKey,
    ) -> Result<(), AccessError> {
        if key.resource_type.starts_with("idp.")
            || !self.mode.permits(tenant, PermissionCategory::Business)
        {
            return Err(AccessError::Forbidden);
        }
        let current = tx
            .tenant_permission(tenant, key)?
            .ok_or(AccessError::InvalidInput("unknown_permission"))?;
        if current.tenant_id != tenant
            || current.key != *key
            || current.category != PermissionCategory::Business
        {
            return Err(AccessError::InvalidStoreResponse);
        }
        if !current.enabled || current.archived {
            return Err(AccessError::InvalidInput("disabled_permission"));
        }
        Ok(())
    }

    fn prepare_tenant_creation(
        &self,
        tx: &mut impl AccessAdminTransaction,
        command: &AccessAdminCommand,
        now: SystemTime,
    ) -> Result<AccessChange, AccessError> {
        let tenant = &command.tenant_id;
        let AccessAdminMutation::CreateTenant {
            name,
            allow_registration,
            administrator_subject_id,
        } = &command.mutation
        else {
            return Err(AccessError::InvalidInput("tenant_creation"));
        };
        if tx.tenant(tenant)?.is_some() {
            return Err(AccessError::Conflict("tenant_exists"));
        }
        let mut permissions = Vec::new();
        let mut permission_definitions = Vec::new();
        for definition in self.catalog.definitions().filter(|p| {
            matches!(
                p.category,
                PermissionCategory::Tenant | PermissionCategory::Business
            )
        }) {
            if definition.category == PermissionCategory::Tenant {
                let current = tx
                    .permission(&definition.key)?
                    .ok_or(AccessError::InvalidStoreResponse)?;
                if current.key != definition.key
                    || current.category != PermissionCategory::Tenant
                    || !current.enabled
                {
                    return Err(AccessError::Forbidden);
                }
                permissions.push(definition.key.clone());
            }
            let mut scoped = definition.clone();
            scoped.tenant_id = tenant.clone();
            permission_definitions.push(scoped);
        }
        let role_id = self.new_id("role")?;
        Ok(AccessChange::TenantCreated {
            record: AccessTenantRecord {
                tenant: Tenant {
                    id: tenant.clone(),
                    name: name.clone(),
                    status: TenantStatus::Active,
                    allow_registration: *allow_registration,
                },
                version: 1,
            },
            administrator: TenantMembership {
                tenant_id: tenant.clone(),
                subject_id: administrator_subject_id.clone(),
                status: MembershipStatus::Active,
                joined_at: now,
                version: 1,
            },
            permission_definitions,
            role: AccessRoleRecord {
                role: Role {
                    id: role_id.clone(),
                    tenant_id: tenant.clone(),
                    key: "tenant_security_admin".into(),
                    name: "Tenant security administrator".into(),
                    status: RoleStatus::Active,
                    kind: RoleKind::TenantSecurityAdmin,
                    version: 1,
                },
                permissions,
            },
            binding: RoleBinding {
                id: self.new_id("binding")?,
                tenant_id: tenant.clone(),
                subject_id: administrator_subject_id.clone(),
                role_id,
                resource_type: "idp.tenant".into(),
                scope: ResourceScope::Type,
            },
        })
    }

    fn prepare_change(
        &self,
        tx: &mut impl AccessAdminTransaction,
        command: &AccessAdminCommand,
        now: SystemTime,
    ) -> Result<AccessChange, AccessError> {
        let tenant = &command.tenant_id;
        match &command.mutation {
            AccessAdminMutation::RevokeSession { session_id } => {
                self.mode.validate_business_tenant(tenant)?;
                let before = tx
                    .admin_session(tenant, session_id)?
                    .ok_or(AccessError::NotFound("session"))?;
                if before.tenant_id != *tenant || before.id != *session_id {
                    return Err(AccessError::InvalidStoreResponse);
                }
                let mut after = before.clone();
                after.status = SessionStatus::Revoked;
                Ok(AccessChange::Session { before, after })
            }
            AccessAdminMutation::RevokeSubjectSessions { subject_id } => {
                self.mode.validate_business_tenant(tenant)?;
                let member = tx
                    .membership(tenant, subject_id)?
                    .ok_or(AccessError::NotFound("membership"))?;
                if member.tenant_id != *tenant || member.subject_id != *subject_id {
                    return Err(AccessError::InvalidStoreResponse);
                }
                Ok(AccessChange::SubjectSessionsRevoked {
                    tenant_id: tenant.clone(),
                    subject_id: subject_id.clone(),
                    active_session_count: tx.active_subject_session_count(tenant, subject_id)?,
                })
            }
            AccessAdminMutation::SetDeviceStatus {
                device_id,
                status,
                expected_status,
            } => {
                self.mode.validate_business_tenant(tenant)?;
                let before = tx
                    .admin_device(tenant, device_id)?
                    .ok_or(AccessError::NotFound("device"))?;
                if before.device.tenant_id != *tenant || before.device.id != *device_id {
                    return Err(AccessError::InvalidStoreResponse);
                }
                if before.device.status != *expected_status
                    || (before.device.status == DeviceStatus::Revoked
                        && *status != DeviceStatus::Revoked)
                {
                    return Err(AccessError::Conflict("device_status"));
                }
                let mut after = before.clone();
                after.device.status = status.clone();
                Ok(AccessChange::Device { before, after })
            }
            AccessAdminMutation::CreateTenant {
                administrator_subject_id,
                ..
            } => {
                if !tx.account_is_active(administrator_subject_id)? {
                    return Err(AccessError::Forbidden);
                }
                self.prepare_tenant_creation(tx, command, now)
            }
            AccessAdminMutation::UpdateTenant {
                name,
                status,
                allow_registration,
                expected_version,
            } => {
                let before = tx
                    .tenant_record(tenant)?
                    .ok_or(AccessError::NotFound("tenant"))?;
                if before.tenant.id != *tenant {
                    return Err(AccessError::InvalidStoreResponse);
                }
                let after = AccessTenantRecord {
                    tenant: Tenant {
                        id: tenant.clone(),
                        name: name.clone(),
                        status: *status,
                        allow_registration: *allow_registration,
                    },
                    version: next_version(before.version, *expected_version)?,
                };
                Ok(AccessChange::Tenant { before, after })
            }
            AccessAdminMutation::SyncPermissions { permissions } => {
                self.mode.validate_business_tenant(tenant)?;
                let mut changes = Vec::new();
                for key in permissions {
                    let mut after = self
                        .catalog
                        .get(key)
                        .ok_or(AccessError::InvalidInput("unknown_permission"))?
                        .clone();
                    if after.category != PermissionCategory::Business {
                        return Err(AccessError::Forbidden);
                    }
                    after.tenant_id = tenant.clone();
                    if let Some(category) = tx.resource_category(tenant, &key.resource_type)? {
                        if category != after.category {
                            return Err(AccessError::Conflict("permission_category"));
                        }
                    }
                    if let Some(current) = tx.tenant_permission(tenant, key)? {
                        if current.tenant_id != *tenant
                            || current.key != *key
                            || current.category != after.category
                        {
                            return Err(AccessError::Conflict("permission_category"));
                        }
                        if current.archived {
                            return Err(AccessError::Conflict("permission_archived"));
                        }
                        continue;
                    }
                    changes.push(AccessPermissionChange {
                        before: None,
                        after,
                    });
                }
                Ok(AccessChange::Catalog { changes })
            }
            AccessAdminMutation::SetPermissionEnabled {
                permission,
                enabled,
                expected_enabled,
            } => {
                self.mode.validate_business_tenant(tenant)?;
                let before = tx
                    .tenant_permission(tenant, permission)?
                    .ok_or(AccessError::NotFound("permission"))?;
                if before.tenant_id != *tenant || before.key != *permission {
                    return Err(AccessError::InvalidStoreResponse);
                }
                if before.category != PermissionCategory::Business
                    || permission.resource_type.starts_with("idp.")
                    || before.archived
                {
                    return Err(AccessError::Forbidden);
                }
                if before.enabled != *expected_enabled {
                    return Err(AccessError::Conflict("permission_enabled"));
                }
                let mut after = before.clone();
                after.enabled = *enabled;
                after.version = next_version(before.version, before.version)?;
                Ok(AccessChange::Catalog {
                    changes: vec![AccessPermissionChange {
                        before: Some(before),
                        after,
                    }],
                })
            }
            AccessAdminMutation::CreatePermission { key, description } => {
                self.mode.validate_business_tenant(tenant)?;
                if tx.tenant_permission(tenant, key)?.is_some() {
                    return Err(AccessError::Conflict("permission_exists"));
                }
                if tx
                    .resource_category(tenant, &key.resource_type)?
                    .is_some_and(|category| category != PermissionCategory::Business)
                {
                    return Err(AccessError::Conflict("permission_category"));
                }
                Ok(AccessChange::Catalog {
                    changes: vec![AccessPermissionChange {
                        before: None,
                        after: PermissionDefinition {
                            tenant_id: tenant.clone(),
                            key: key.clone(),
                            description: description.clone(),
                            category: PermissionCategory::Business,
                            enabled: true,
                            archived: false,
                            version: 1,
                        },
                    }],
                })
            }
            AccessAdminMutation::UpdatePermission {
                key,
                description,
                expected_version,
            } => {
                self.mode.validate_business_tenant(tenant)?;
                let before = tx
                    .tenant_permission(tenant, key)?
                    .ok_or(AccessError::NotFound("permission"))?;
                if before.tenant_id != *tenant || before.key != *key {
                    return Err(AccessError::InvalidStoreResponse);
                }
                if before.category != PermissionCategory::Business || before.archived {
                    return Err(AccessError::Forbidden);
                }
                let mut after = before.clone();
                after.version = next_version(before.version, *expected_version)?;
                after.description = description.clone();
                Ok(AccessChange::Catalog {
                    changes: vec![AccessPermissionChange {
                        before: Some(before),
                        after,
                    }],
                })
            }
            AccessAdminMutation::ArchivePermission {
                key,
                expected_version,
            } => {
                self.mode.validate_business_tenant(tenant)?;
                let before = tx
                    .tenant_permission(tenant, key)?
                    .ok_or(AccessError::NotFound("permission"))?;
                if before.tenant_id != *tenant || before.key != *key {
                    return Err(AccessError::InvalidStoreResponse);
                }
                if before.category != PermissionCategory::Business || before.archived {
                    return Err(AccessError::Forbidden);
                }
                let mut after = before.clone();
                after.version = next_version(before.version, *expected_version)?;
                after.enabled = false;
                after.archived = true;
                Ok(AccessChange::Catalog {
                    changes: vec![AccessPermissionChange {
                        before: Some(before),
                        after,
                    }],
                })
            }
            AccessAdminMutation::CreateRole { key, name } => {
                self.mode.validate_business_tenant(tenant)?;
                Ok(AccessChange::Role {
                    before: None,
                    after: Some(AccessRoleRecord {
                        role: Role {
                            id: self.new_id("role")?,
                            tenant_id: tenant.clone(),
                            key: key.clone(),
                            name: name.clone(),
                            status: RoleStatus::Active,
                            kind: RoleKind::Business,
                            version: 1,
                        },
                        permissions: vec![],
                    }),
                })
            }
            AccessAdminMutation::UpdateRole {
                role_id,
                name,
                status,
                expected_version,
            } => {
                let before = self.business_role(tx, tenant, role_id)?;
                let mut after = before.clone();
                after.role.version = next_version(before.role.version, *expected_version)?;
                after.role.name = name.clone();
                after.role.status = *status;
                Ok(AccessChange::Role {
                    before: Some(before),
                    after: Some(after),
                })
            }
            AccessAdminMutation::DeleteRole {
                role_id,
                expected_version,
            } => {
                let before = self.business_role(tx, tenant, role_id)?;
                next_version(before.role.version, *expected_version)?;
                Ok(AccessChange::Role {
                    before: Some(before),
                    after: None,
                })
            }
            AccessAdminMutation::ReplaceRolePermissions {
                role_id,
                permissions,
                expected_version,
            } => {
                let before = self.business_role(tx, tenant, role_id)?;
                let mut after = before.clone();
                after.role.version = next_version(before.role.version, *expected_version)?;
                for key in permissions {
                    self.business_permission(tx, tenant, key)?;
                }
                after.permissions = permissions.clone();
                after.permissions.sort();
                Ok(AccessChange::Role {
                    before: Some(before),
                    after: Some(after),
                })
            }
            AccessAdminMutation::GrantRole {
                subject_id,
                role_id,
                resource_type,
                scope,
            } => {
                self.active_member(tx, tenant, subject_id)?;
                let role = self.business_role(tx, tenant, role_id)?;
                if role.role.status != RoleStatus::Active {
                    return Err(AccessError::Forbidden);
                }
                let keys: Vec<_> = role
                    .permissions
                    .iter()
                    .filter(|p| p.resource_type == *resource_type)
                    .collect();
                if keys.is_empty() {
                    return Err(AccessError::InvalidInput("role_resource_type"));
                }
                for key in keys {
                    self.business_permission(tx, tenant, key)?;
                }
                Ok(AccessChange::Binding {
                    before: None,
                    after: Some(RoleBinding {
                        id: self.new_id("binding")?,
                        tenant_id: tenant.clone(),
                        subject_id: subject_id.clone(),
                        role_id: role_id.clone(),
                        resource_type: resource_type.clone(),
                        scope: scope.clone(),
                    }),
                })
            }
            AccessAdminMutation::RevokeRole { binding_id } => {
                let before = tx
                    .binding(tenant, binding_id)?
                    .ok_or(AccessError::NotFound("binding"))?;
                if before.tenant_id != *tenant || before.id != *binding_id {
                    return Err(AccessError::InvalidStoreResponse);
                }
                self.business_role(tx, tenant, &before.role_id)?;
                Ok(AccessChange::Binding {
                    before: Some(before),
                    after: None,
                })
            }
            AccessAdminMutation::BindMember { subject_id } => {
                if !tx.account_is_active(subject_id)? {
                    return Err(AccessError::Forbidden);
                }
                let before = tx.membership(tenant, subject_id)?;
                if let Some(member) = &before {
                    if member.tenant_id != *tenant || member.subject_id != *subject_id {
                        return Err(AccessError::InvalidStoreResponse);
                    }
                    if member.status == MembershipStatus::Active {
                        return Ok(AccessChange::Membership {
                            before: Some(member.clone()),
                            after: member.clone(),
                        });
                    }
                    if member.status != MembershipStatus::Removed {
                        return Err(AccessError::Conflict("membership_exists"));
                    }
                }
                let version = match &before {
                    Some(m) => next_version(m.version, m.version)?,
                    None => 1,
                };
                Ok(AccessChange::Membership {
                    before,
                    after: TenantMembership {
                        tenant_id: tenant.clone(),
                        subject_id: subject_id.clone(),
                        status: MembershipStatus::Active,
                        joined_at: now,
                        version,
                    },
                })
            }
            AccessAdminMutation::SetMemberStatus {
                subject_id,
                status,
                expected_version,
            } => {
                let before = tx
                    .membership(tenant, subject_id)?
                    .ok_or(AccessError::NotFound("membership"))?;
                if before.tenant_id != *tenant || before.subject_id != *subject_id {
                    return Err(AccessError::InvalidStoreResponse);
                }
                // A removed membership may only rejoin through platform BindMember.
                if before.status == MembershipStatus::Removed {
                    return Err(AccessError::Conflict("membership_removed"));
                }
                if *status == MembershipStatus::Active && !tx.account_is_active(subject_id)? {
                    return Err(AccessError::Forbidden);
                }
                let mut after = before.clone();
                after.version = next_version(before.version, *expected_version)?;
                after.status = *status;
                Ok(AccessChange::Membership {
                    before: Some(before),
                    after,
                })
            }
            AccessAdminMutation::SetSecurityAdmin {
                subject_id,
                appointed,
            } => {
                if *appointed {
                    self.active_member(tx, tenant, subject_id)?;
                }
                let kind = security_kind(tenant);
                let role = tx
                    .security_role(tenant, kind)?
                    .ok_or(AccessError::NotFound("security_role"))?;
                if role.role.tenant_id != *tenant || role.role.kind != kind {
                    return Err(AccessError::InvalidStoreResponse);
                }
                let resource_type = if kind == RoleKind::SystemAdmin {
                    "idp.platform"
                } else {
                    "idp.tenant"
                };
                let before = tx.security_binding(tenant, subject_id, &role.role.id)?;
                if let Some(binding) = &before {
                    if binding.tenant_id != *tenant
                        || binding.subject_id != *subject_id
                        || binding.role_id != role.role.id
                        || binding.resource_type != resource_type
                        || binding.scope != ResourceScope::Type
                    {
                        return Err(AccessError::InvalidStoreResponse);
                    }
                }
                if before.is_some() == *appointed {
                    return Err(AccessError::Conflict("security_admin_state"));
                }
                if *appointed {
                    if role.role.status != RoleStatus::Active {
                        return Err(AccessError::Forbidden);
                    }
                    let expected: BTreeSet<_> = self
                        .catalog
                        .definitions()
                        .filter(|p| p.key.resource_type == resource_type)
                        .map(|p| &p.key)
                        .collect();
                    if role.permissions.iter().collect::<BTreeSet<_>>() != expected {
                        return Err(AccessError::InvalidStoreResponse);
                    }
                    for key in &role.permissions {
                        let permission = tx
                            .permission(key)?
                            .ok_or(AccessError::InvalidStoreResponse)?;
                        let category = if kind == RoleKind::SystemAdmin {
                            PermissionCategory::Platform
                        } else {
                            PermissionCategory::Tenant
                        };
                        if permission.key != *key
                            || permission.category != category
                            || !permission.enabled
                        {
                            return Err(AccessError::Forbidden);
                        }
                    }
                }
                let after = if *appointed {
                    Some(RoleBinding {
                        id: self.new_id("binding")?,
                        tenant_id: tenant.clone(),
                        subject_id: subject_id.clone(),
                        role_id: role.role.id,
                        resource_type: resource_type.into(),
                        scope: ResourceScope::Type,
                    })
                } else {
                    None
                };
                Ok(AccessChange::Binding { before, after })
            }
        }
    }
}

impl<S, C, I> AccessAdminService for CoreAccessAdminService<S, C, I>
where
    S: AccessAdminStore,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn execute(
        &self,
        context: AccessAdminContext,
        command: AccessAdminCommand,
    ) -> Result<AccessAuditEvent, AccessError> {
        validate_id(&context.authentication_source, 128, "authentication_source")?;
        validate_id(&context.request_id, 128, "request_id")?;
        command.mutation.validate()?;
        let actor = &context.actor;
        let operation = match command.mutation {
            AccessAdminMutation::RevokeSession { .. }
            | AccessAdminMutation::RevokeSubjectSessions { .. } => {
                AccessAdminOperation::ManageSessions
            }
            AccessAdminMutation::SetDeviceStatus { .. } => AccessAdminOperation::ManageDevices,
            AccessAdminMutation::CreateTenant { .. } | AccessAdminMutation::UpdateTenant { .. } => {
                AccessAdminOperation::ManageTenants
            }
            AccessAdminMutation::SyncPermissions { .. }
            | AccessAdminMutation::SetPermissionEnabled { .. }
            | AccessAdminMutation::CreatePermission { .. }
            | AccessAdminMutation::UpdatePermission { .. }
            | AccessAdminMutation::ArchivePermission { .. } => {
                AccessAdminOperation::ManageBusinessPermissions
            }
            AccessAdminMutation::CreateRole { .. }
            | AccessAdminMutation::UpdateRole { .. }
            | AccessAdminMutation::DeleteRole { .. }
            | AccessAdminMutation::ReplaceRolePermissions { .. } => {
                AccessAdminOperation::ManageRoles
            }
            AccessAdminMutation::GrantRole { .. } | AccessAdminMutation::RevokeRole { .. } => {
                AccessAdminOperation::ManageGrants
            }
            AccessAdminMutation::BindMember { .. } => AccessAdminOperation::BindUser,
            AccessAdminMutation::SetMemberStatus { .. } => AccessAdminOperation::ManageMembers,
            AccessAdminMutation::SetSecurityAdmin { .. } => {
                AccessAdminOperation::ManageSecurityAdmins
            }
        };
        let permission = super::service::admin_permission_query(
            self.mode,
            actor,
            &command.tenant_id,
            operation,
        )?;
        let mut tenant_ids = vec![actor.tenant_id.clone(), command.tenant_id.clone()];
        tenant_ids.sort();
        tenant_ids.dedup();
        let mut subject_ids = vec![actor.subject_id.clone()];
        if let Some(subject) = command.mutation.subject() {
            subject_ids.push(subject.into());
        }
        subject_ids.sort();
        subject_ids.dedup();
        let scope = AccessWriteScope {
            mode: self.mode,
            exclusive_state: command.tenant_id == SYSTEM_TENANT_ID
                || matches!(command.mutation, AccessAdminMutation::CreateTenant { .. }),
            tenant_ids,
            subject_ids,
        };
        self.store.admin_transaction(|tx| {
            tx.lock_scope(&scope)?;
            // Read the clock after waiting for locks: expired actors cannot use a stale time.
            let now = self.clock.now();
            if !tx.actor_is_active(actor, now)? || !tx.check_permission(&permission)? {
                return Err(AccessError::Forbidden);
            }
            if matches!(command.mutation, AccessAdminMutation::CreateTenant { .. }) {
                for action in ["users.bind", "access.manage"] {
                    let extra = AccessQuery {
                        action: action.into(),
                        ..permission.clone()
                    };
                    if !tx.check_permission(&extra)? {
                        return Err(AccessError::Forbidden);
                    }
                }
            } else {
                let tenant = tx
                    .tenant(&command.tenant_id)?
                    .ok_or(AccessError::NotFound("tenant"))?;
                if tenant.id != command.tenant_id {
                    return Err(AccessError::InvalidStoreResponse);
                }
                let cleanup = matches!(
                    command.mutation,
                    AccessAdminMutation::RevokeSession { .. }
                        | AccessAdminMutation::RevokeSubjectSessions { .. }
                        | AccessAdminMutation::SetDeviceStatus { .. }
                        | AccessAdminMutation::UpdateTenant { .. }
                        | AccessAdminMutation::RevokeRole { .. }
                        | AccessAdminMutation::DeleteRole { .. }
                        | AccessAdminMutation::SetSecurityAdmin {
                            appointed: false,
                            ..
                        }
                        | AccessAdminMutation::SetMemberStatus {
                            status: MembershipStatus::Removed | MembershipStatus::Suspended,
                            ..
                        }
                );
                if tenant.status != TenantStatus::Active
                    && !(actor.tenant_id == SYSTEM_TENANT_ID && cleanup)
                {
                    return Err(AccessError::Forbidden);
                }
            }
            let change = self.prepare_change(tx, &command, now)?;
            tx.apply_change(&change, now)?;
            if let AccessChange::Membership { after, .. } = &change {
                if after.status == MembershipStatus::Removed
                    && !tx.has_non_removed_membership(&after.subject_id)?
                {
                    return Err(AccessError::Conflict("last_membership"));
                }
            }
            let tenant = tx
                .tenant(&command.tenant_id)?
                .ok_or(AccessError::InvalidStoreResponse)?;
            if tenant.id != command.tenant_id {
                return Err(AccessError::InvalidStoreResponse);
            }
            if (tenant.id == SYSTEM_TENANT_ID || tenant.status == TenantStatus::Active)
                && !tx.has_effective_security_admin(&tenant.id, security_kind(&tenant.id))?
            {
                return Err(AccessError::Conflict("last_security_admin"));
            }
            let event = AccessAuditEvent {
                id: self.new_id("audit")?,
                occurred_at: now,
                context: context.clone(),
                tenant_id: command.tenant_id.clone(),
                operation: command.mutation.operation(),
                change,
            };
            tx.append_audit(&event)?;
            Ok(event)
        })
    }
}

impl<S: AccessAdminStore, C: Clock, I> CoreAccessAdminService<S, C, I> {
    fn authorize_management_read(
        &self,
        tx: &mut impl AccessAdminTransaction,
        context: &AccessAdminContext,
        tenant: &str,
        operation: AccessAdminOperation,
    ) -> Result<(), AccessError> {
        self.authorize_management(tx, context, tenant, operation, false, None)
            .map(|_| ())
    }

    fn authorize_management(
        &self,
        tx: &mut impl AccessAdminTransaction,
        context: &AccessAdminContext,
        tenant: &str,
        operation: AccessAdminOperation,
        exclusive_state: bool,
        subject: Option<&str>,
    ) -> Result<SystemTime, AccessError> {
        validate_id(&context.authentication_source, 128, "authentication_source")?;
        validate_id(&context.request_id, 128, "request_id")?;
        if !matches!(
            operation,
            AccessAdminOperation::ManageClients
                | AccessAdminOperation::ManageCatalog
                | AccessAdminOperation::ReadTenants
                | AccessAdminOperation::ReadAccounts
                | AccessAdminOperation::ManageAccountSecurity
        ) && !(matches!(
            operation,
            AccessAdminOperation::ReadAudit | AccessAdminOperation::ManageSecurityAdmins
        ) && tenant == SYSTEM_TENANT_ID)
        {
            self.mode.validate_business_tenant(tenant)?;
        }
        let permission =
            super::service::admin_permission_query(self.mode, &context.actor, tenant, operation)?;
        let mut tenants = vec![context.actor.tenant_id.clone(), tenant.into()];
        tenants.sort();
        tenants.dedup();
        let mut subjects = vec![context.actor.subject_id.clone()];
        if let Some(id) = subject {
            subjects.push(id.into());
        }
        subjects.sort();
        subjects.dedup();
        // ponytail: bounded management reads reuse the domain lock; separate read
        // snapshots only if measured admin traffic shows contention with login.
        tx.lock_scope(&AccessWriteScope {
            mode: self.mode,
            exclusive_state,
            tenant_ids: tenants,
            subject_ids: subjects,
        })?;
        let now = self.clock.now();
        if !tx.actor_is_active(&context.actor, now)? || !tx.check_permission(&permission)? {
            return Err(AccessError::Forbidden);
        }
        let target = tx.tenant(tenant)?.ok_or(AccessError::NotFound("tenant"))?;
        if target.id != tenant {
            return Err(AccessError::InvalidStoreResponse);
        }
        if target.status != TenantStatus::Active && context.actor.tenant_id != SYSTEM_TENANT_ID {
            return Err(AccessError::Forbidden);
        }
        Ok(now)
    }
}

fn validate_created_range(
    after: Option<SystemTime>,
    before: Option<SystemTime>,
) -> Result<(), AccessError> {
    for value in [after, before].into_iter().flatten() {
        let duration = value
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| AccessError::InvalidInput("created_time"))?;
        if duration.as_secs() > i64::MAX as u64 || duration.subsec_nanos() != 0 {
            return Err(AccessError::InvalidInput("created_time"));
        }
    }
    if matches!((after,before),(Some(a),Some(b)) if a>b) {
        return Err(AccessError::InvalidInput("created_time_range"));
    }
    Ok(())
}

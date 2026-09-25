use std::{collections::BTreeMap, time::SystemTime};

use super::{
    query::{validate_id, validate_name},
    AccessError, AccessQuery, PermissionKey, ResourceScope,
};

pub const SYSTEM_TENANT_ID: &str = "0";

/// Shared identifier syntax for tenant policies and signed token claims.
/// Syntax validation alone does not establish membership or authorize a tenant.
pub fn validate_tenant_id(tenant_id: &str) -> Result<(), AccessError> {
    validate_id(tenant_id, 128, "tenant_id")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenancyMode {
    Disabled,
    Enabled,
}

impl TenancyMode {
    pub fn validate_business_tenant(self, tenant_id: &str) -> Result<(), AccessError> {
        validate_tenant_id(tenant_id)?;
        if (self == Self::Disabled) != (tenant_id == SYSTEM_TENANT_ID) {
            return Err(AccessError::ModeMismatch);
        }
        Ok(())
    }

    pub fn permits(self, tenant_id: &str, category: PermissionCategory) -> bool {
        match category {
            PermissionCategory::Platform => tenant_id == SYSTEM_TENANT_ID,
            PermissionCategory::Tenant | PermissionCategory::Business => {
                self.validate_business_tenant(tenant_id).is_ok()
            }
        }
    }
}

/// Host-owned BUSINESS login entry policy. Platform login is a separate boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginTenantPolicy {
    Fixed { tenant_id: String },
    ChooseAfterAuthentication,
}

impl LoginTenantPolicy {
    pub fn validate(&self, mode: TenancyMode) -> Result<(), AccessError> {
        match self {
            Self::Fixed { tenant_id } => mode.validate_business_tenant(tenant_id),
            Self::ChooseAfterAuthentication if mode == TenancyMode::Enabled => Ok(()),
            Self::ChooseAfterAuthentication => Err(AccessError::ModeMismatch),
        }
    }

    /// Check entry policy only; the auth transaction must also recheck membership.
    pub fn validate_selection(
        &self,
        mode: TenancyMode,
        tenant_id: &str,
    ) -> Result<(), AccessError> {
        self.validate(mode)?;
        mode.validate_business_tenant(tenant_id)?;
        if let Self::Fixed { tenant_id: fixed } = self {
            if fixed != tenant_id {
                return Err(AccessError::Forbidden);
            }
        }
        Ok(())
    }
}

/// Constructed by the trusted host after authenticating the session, not from JSON hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessActor {
    pub tenant_id: String,
    pub subject_id: crate::AccountId,
    pub session_id: crate::SessionId,
}

impl AccessActor {
    pub fn validate(&self, mode: TenancyMode) -> Result<(), AccessError> {
        validate_id(&self.tenant_id, 128, "actor_tenant_id")?;
        validate_id(&self.subject_id, 128, "actor_subject_id")?;
        validate_id(&self.session_id, 128, "actor_session_id")?;
        if mode == TenancyMode::Disabled && self.tenant_id != SYSTEM_TENANT_ID {
            return Err(AccessError::ModeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    Active,
    Suspended,
    Archived,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipStatus {
    Active,
    Suspended,
    Removed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleStatus {
    Active,
    Disabled,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionCategory {
    Platform,
    Tenant,
    Business,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleKind {
    SystemAdmin,
    TenantSecurityAdmin,
    Business,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub status: TenantStatus,
    pub allow_registration: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantMembership {
    pub tenant_id: String,
    pub subject_id: crate::AccountId,
    pub status: MembershipStatus,
    pub joined_at: SystemTime,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectTenant {
    pub tenant: Tenant,
    pub membership: TenantMembership,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDefinition {
    pub tenant_id: String,
    pub key: PermissionKey,
    pub description: String,
    pub category: PermissionCategory,
    pub enabled: bool,
    pub archived: bool,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: String,
    pub tenant_id: String,
    pub key: String,
    pub name: String,
    pub status: RoleStatus,
    pub kind: RoleKind,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePermission {
    pub tenant_id: String,
    pub role_id: String,
    pub permission: PermissionKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBinding {
    pub id: String,
    pub tenant_id: String,
    pub subject_id: crate::AccountId,
    pub role_id: String,
    pub resource_type: String,
    pub scope: ResourceScope,
}

impl RoleBinding {
    pub fn validate(&self) -> Result<(), AccessError> {
        for (value, field) in [
            (&self.id, "binding_id"),
            (&self.tenant_id, "tenant_id"),
            (&self.subject_id, "subject_id"),
            (&self.role_id, "role_id"),
        ] {
            validate_id(value, 128, field)?;
        }
        validate_name(&self.resource_type, "resource_type")?;
        self.scope.validate()
    }

    /// Reference grant predicate for store adapters. Account/tenant/membership
    /// active state must ALSO be checked in the same database snapshot.
    pub fn grants(
        &self,
        query: &AccessQuery,
        role: &Role,
        link: &RolePermission,
        permission: &PermissionDefinition,
        mode: TenancyMode,
    ) -> bool {
        let correct_kind = matches!(
            (role.kind, permission.category),
            (RoleKind::SystemAdmin, PermissionCategory::Platform)
                | (RoleKind::TenantSecurityAdmin, PermissionCategory::Tenant)
                | (RoleKind::Business, PermissionCategory::Business)
        );
        query.validate().is_ok()
            && self.validate().is_ok()
            && permission.key.validate().is_ok()
            && mode.permits(&query.tenant_id, permission.category)
            && correct_kind
            && role.status == RoleStatus::Active
            && permission.enabled
            && self.tenant_id == query.tenant_id
            && self.subject_id == query.subject_id
            && role.tenant_id == self.tenant_id
            && role.id == self.role_id
            && link.tenant_id == role.tenant_id
            && link.role_id == role.id
            && link.permission == permission.key
            && permission.key == query.permission()
            && self.resource_type == query.resource_type
            && self.scope.covers(query.resource_id.as_deref())
            && (permission.category == PermissionCategory::Business
                || (self.scope == ResourceScope::Type && query.resource_id.is_none()))
    }
}

/// Catalog metadata is immutable. Enabled status is always read from the store,
/// not cached here; a committed revoke must be visible on the next read.
#[derive(Debug, Clone)]
pub struct PermissionCatalog {
    definitions: BTreeMap<PermissionKey, PermissionDefinition>,
}

impl PermissionCatalog {
    pub fn new(host_permissions: Vec<PermissionDefinition>) -> Result<Self, AccessError> {
        let mut catalog = Self {
            definitions: BTreeMap::new(),
        };
        for (resource, category, actions) in [
            (
                "idp.platform",
                PermissionCategory::Platform,
                &[
                    "users.read",
                    "users.security",
                    "tenants.manage",
                    "users.bind",
                    "clients.manage",
                    "access.manage",
                    "audit.read",
                ][..],
            ),
            (
                "idp.tenant",
                PermissionCategory::Tenant,
                &[
                    "members.manage",
                    "permissions.manage",
                    "roles.manage",
                    "grants.manage",
                    "access.read",
                    "devices.manage",
                    "sessions.manage",
                    "audit.read",
                ][..],
            ),
        ] {
            for action in actions {
                catalog.insert(PermissionDefinition {
                    tenant_id: SYSTEM_TENANT_ID.to_owned(),
                    key: PermissionKey {
                        resource_type: resource.to_owned(),
                        action: (*action).to_owned(),
                    },
                    description: format!("{resource}/{action}"),
                    category,
                    enabled: true,
                    archived: false,
                    version: 1,
                })?;
            }
        }
        for permission in host_permissions {
            if permission.key.resource_type.starts_with("idp.") {
                return Err(AccessError::InvalidCatalog("reserved_resource_type"));
            }
            if permission.category != PermissionCategory::Business
                || permission.tenant_id != SYSTEM_TENANT_ID
                || permission.archived
                || permission.version != 1
            {
                return Err(AccessError::InvalidCatalog("host_permission_template"));
            }
            catalog.insert(permission)?;
        }
        Ok(catalog)
    }

    fn insert(&mut self, permission: PermissionDefinition) -> Result<(), AccessError> {
        permission.key.validate()?;
        if self.definitions.contains_key(&permission.key) {
            return Err(AccessError::InvalidCatalog("duplicate_permission"));
        }
        if self.definitions.values().any(|existing| {
            existing.key.resource_type == permission.key.resource_type
                && existing.category != permission.category
        }) {
            return Err(AccessError::InvalidCatalog("resource_category_conflict"));
        }
        self.definitions.insert(permission.key.clone(), permission);
        Ok(())
    }

    pub fn get(&self, key: &PermissionKey) -> Option<&PermissionDefinition> {
        self.definitions.get(key)
    }

    pub fn definitions(&self) -> impl Iterator<Item = &PermissionDefinition> {
        self.definitions.values()
    }
}

/// Identity-linked write payload for tenant-aware registration.
/// The identity service must validate email/password and hash the password first.
/// No operation here creates an account without its first membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRegistration {
    account: crate::Account,
    membership: TenantMembership,
    verification: crate::EmailVerificationCode,
}

impl TenantRegistration {
    pub fn new(
        mode: TenancyMode,
        tenant_id: String,
        account: crate::Account,
        verification: crate::EmailVerificationCode,
    ) -> Result<Self, AccessError> {
        mode.validate_business_tenant(&tenant_id)?;
        validate_id(&account.id, 128, "subject_id")?;
        if account.email.trim().is_empty()
            || account.password_hash.is_empty()
            || account.status != crate::AccountStatus::PendingVerification
            || verification.account_id != account.id
            || verification.email != account.email
            || verification.consumed_at.is_some()
            || verification.expires_at <= verification.issued_at
        {
            return Err(AccessError::InvalidInput("registration_identity"));
        }
        let membership = TenantMembership {
            tenant_id,
            subject_id: account.id.clone(),
            status: MembershipStatus::Active,
            joined_at: account.created_at,
            version: 1,
        };
        Ok(Self {
            account,
            membership,
            verification,
        })
    }

    pub fn account(&self) -> &crate::Account {
        &self.account
    }
    pub fn membership(&self) -> &TenantMembership {
        &self.membership
    }
    pub fn verification(&self) -> &crate::EmailVerificationCode {
        &self.verification
    }
    pub fn registration_tenant_id(&self) -> &str {
        &self.membership.tenant_id
    }
}

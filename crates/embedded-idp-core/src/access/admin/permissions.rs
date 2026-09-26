use super::*;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminPermissionScope {
    Tenant(String),
    Platform,
}
impl AdminPermissionScope {
    pub fn validate(&self, mode: TenancyMode) -> Result<(), AccessError> {
        match self {
            Self::Tenant(t) => mode.validate_business_tenant(t),
            Self::Platform => Ok(()),
        }
    }
    pub fn permits(&self, mode: TenancyMode, category: PermissionCategory) -> bool {
        match self {
            Self::Tenant(t) => {
                mode.validate_business_tenant(t).is_ok() && mode.permits(t, category)
            }
            Self::Platform => {
                category == PermissionCategory::Platform
                    || (mode == TenancyMode::Disabled && mode.permits(SYSTEM_TENANT_ID, category))
            }
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminPermissionFilter {
    pub resource_type: Option<String>,
    pub category: Option<PermissionCategory>,
    pub enabled: Option<bool>,
}
impl AdminPermissionFilter {
    pub fn validate(&self) -> Result<(), AccessError> {
        if let Some(resource) = &self.resource_type {
            validate_name(resource, "resource_type")?;
        }
        Ok(())
    }
    pub fn matches(&self, p: &PermissionDefinition) -> bool {
        self.resource_type
            .as_ref()
            .is_none_or(|r| r == &p.key.resource_type)
            && self.category.is_none_or(|c| c == p.category)
            && self.enabled.is_none_or(|e| e == p.enabled)
    }
}
pub trait PermissionAdminService: AccessAdminService {
    /// Persisted configuration, not the host declaration list or effective grants.
    fn get_permission(
        &self,
        context: AccessAdminContext,
        tenant_id: String,
        key: PermissionKey,
    ) -> Result<PermissionDefinition, AccessError>;
    fn list_permissions(
        &self,
        context: AccessAdminContext,
        scope: AdminPermissionScope,
        filter: AdminPermissionFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<PermissionDefinition>, AccessError>;
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync>
    PermissionAdminService for CoreAccessAdminService<S, C, I>
{
    fn get_permission(
        &self,
        context: AccessAdminContext,
        tenant_id: String,
        key: PermissionKey,
    ) -> Result<PermissionDefinition, AccessError> {
        self.mode.validate_business_tenant(&tenant_id)?;
        key.validate()?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant_id,
                AccessAdminOperation::ReadAccess,
            )?;
            let permission = tx
                .tenant_permission(&tenant_id, &key)?
                .ok_or(AccessError::NotFound("permission"))?;
            if permission.tenant_id != tenant_id
                || permission.key != key
                || !self.mode.permits(&tenant_id, permission.category)
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(permission)
        })
    }

    fn list_permissions(
        &self,
        context: AccessAdminContext,
        scope: AdminPermissionScope,
        filter: AdminPermissionFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<PermissionDefinition>, AccessError> {
        scope.validate(self.mode)?;
        filter.validate()?;
        let cursor_scope = AccessListScope::AdminPermissions {
            scope: scope.clone(),
            filter: filter.clone(),
        };
        page.validate(&cursor_scope)?;
        self.store.admin_transaction(|tx| {
            let (tenant, operation) = match &scope {
                AdminPermissionScope::Tenant(t) => (t.as_str(), AccessAdminOperation::ReadAccess),
                AdminPermissionScope::Platform => {
                    (SYSTEM_TENANT_ID, AccessAdminOperation::ManageCatalog)
                }
            };
            self.authorize_management_read(tx, &context, tenant, operation)?;
            let rows = tx.admin_permissions(&scope, &filter, &page)?;
            if rows.iter().any(|p| {
                p.key.validate().is_err()
                    || !scope.permits(self.mode, p.category)
                    || match &scope {
                        AdminPermissionScope::Tenant(t) => &p.tenant_id != t,
                        AdminPermissionScope::Platform => p.tenant_id != SYSTEM_TENANT_ID,
                    }
                    || !filter.matches(p)
            }) {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, cursor_scope, |p| {
                let mut key = time_page_key(
                    p.created_at.unwrap_or(SystemTime::UNIX_EPOCH),
                    p.key.resource_type.clone(),
                );
                key.push(p.key.action.clone());
                key
            })
        })
    }
}

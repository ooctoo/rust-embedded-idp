use super::*;
use crate::access::validate_access_business_id;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest,
};

pub trait RoleAdminService: AccessAdminService {
    /// Configuration, not effective access: suspended members and disabled roles
    /// remain inspectable. The target must have a membership in this tenant.
    fn list_subject_role_bindings(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: Option<String>,
        subject: String,
        page: AccessPageRequest,
    ) -> Result<AccessPage<RoleBinding>, AccessError>;
    fn list_roles(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: Option<String>,
        page: AccessPageRequest,
    ) -> Result<AccessPage<Role>, AccessError>;
    /// Versioned configuration snapshot, including the complete permission key
    /// set (at most MAX_ROLE_PERMISSIONS). This is not an effective-access check.
    fn get_role(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: String,
        role: String,
    ) -> Result<AccessRoleRecord, AccessError>;
    fn get_business_administrator(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: String,
    ) -> Result<AccessRoleRecord, AccessError>;
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync> RoleAdminService
    for CoreAccessAdminService<S, C, I>
{
    fn list_subject_role_bindings(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: Option<String>,
        subject: String,
        page: AccessPageRequest,
    ) -> Result<AccessPage<RoleBinding>, AccessError> {
        if let Some(business_id) = &business_id {
            validate_access_business_id(business_id)?;
        }
        validate_id(&subject, 128, "subject_id")?;
        let scope = AccessListScope::AdminRoleBindings {
            tenant_id: tenant.clone(),
            business_id: business_id.clone(),
            subject_id: subject.clone(),
        };
        page.validate(&scope)?;
        if page.cursor.as_ref().is_some_and(|c| {
            uuid::Uuid::parse_str(&c.after[1]).map_or(true, |id| id.to_string() != c.after[1])
        }) {
            return Err(AccessError::InvalidCursor);
        }
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ReadAccess,
            )?;
            let member = tx
                .membership(&tenant, &subject)?
                .ok_or(AccessError::NotFound("membership"))?;
            if member.tenant_id != tenant || member.subject_id != subject {
                return Err(AccessError::InvalidStoreResponse);
            }
            let rows = tx.admin_role_bindings(&tenant, business_id.as_deref(), &subject, &page)?;
            if rows.iter().any(|b| {
                b.tenant_id != tenant
                    || business_id.as_ref().is_some_and(|id| &b.business_id != id)
                    || b.subject_id != subject
                    || b.validate().is_err()
            }) {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |b| {
                time_page_key(b.created_at, b.id.clone())
            })
        })
    }
    fn list_roles(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: Option<String>,
        page: AccessPageRequest,
    ) -> Result<AccessPage<Role>, AccessError> {
        if let Some(business_id) = &business_id {
            validate_access_business_id(business_id)?;
        }
        let scope = AccessListScope::AdminRoles {
            tenant_id: tenant.clone(),
            business_id: business_id.clone(),
        };
        page.validate(&scope)?;
        if page.cursor.as_ref().is_some_and(|c| {
            uuid::Uuid::parse_str(&c.after[1]).map_or(true, |id| id.to_string() != c.after[1])
        }) {
            return Err(AccessError::InvalidCursor);
        }
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ReadAccess,
            )?;
            let rows = tx.admin_roles(&tenant, business_id.as_deref(), &page)?;
            if rows.iter().any(|r| {
                r.tenant_id != tenant
                    || business_id.as_ref().is_some_and(|id| &r.business_id != id)
                    || r.version == 0
            }) {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |r| {
                time_page_key(r.created_at, r.id.clone())
            })
        })
    }
    fn get_role(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: String,
        role: String,
    ) -> Result<AccessRoleRecord, AccessError> {
        validate_access_business_id(&business_id)?;
        validate_id(&role, 128, "role_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ReadAccess,
            )?;
            let row = tx
                .role(&tenant, &business_id, &role)?
                .ok_or(AccessError::NotFound("role"))?;
            if row.role.tenant_id != tenant
                || row.role.business_id != business_id
                || row.role.id != role
                || row.role.version == 0
                || row.permissions.len() > MAX_ROLE_PERMISSIONS
                || row.permissions.iter().any(|p| p.validate().is_err())
                || row.permissions.windows(2).any(|p| p[0] >= p[1])
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(row)
        })
    }
    fn get_business_administrator(
        &self,
        context: AccessAdminContext,
        tenant: String,
        business_id: String,
    ) -> Result<AccessRoleRecord, AccessError> {
        validate_business_id(&business_id)?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ReadAccess,
            )?;
            let row = tx
                .business_admin_role(&tenant, &business_id)?
                .ok_or(AccessError::NotFound("business_admin"))?;
            if row.role.tenant_id != tenant
                || row.role.business_id != business_id
                || row.role.kind != RoleKind::BusinessAdmin
                || row.role.key != "business_admin"
                || !row.permissions.is_empty()
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(row)
        })
    }
}

use super::*;
use crate::access::{service::finish_page, AccessListScope, AccessPage, AccessPageRequest};

pub trait RoleAdminService: AccessAdminService {
    /// Configuration, not effective access: suspended members and disabled roles
    /// remain inspectable. The target must have a membership in this tenant.
    fn list_subject_role_bindings(
        &self,
        context: AccessAdminContext,
        tenant: String,
        subject: String,
        page: AccessPageRequest,
    ) -> Result<AccessPage<RoleBinding>, AccessError>;
    fn list_roles(
        &self,
        context: AccessAdminContext,
        tenant: String,
        page: AccessPageRequest,
    ) -> Result<AccessPage<Role>, AccessError>;
    /// Versioned configuration snapshot, including the complete permission key
    /// set (at most MAX_ROLE_PERMISSIONS). This is not an effective-access check.
    fn get_role(
        &self,
        context: AccessAdminContext,
        tenant: String,
        role: String,
    ) -> Result<AccessRoleRecord, AccessError>;
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync> RoleAdminService
    for CoreAccessAdminService<S, C, I>
{
    fn list_subject_role_bindings(
        &self,
        context: AccessAdminContext,
        tenant: String,
        subject: String,
        page: AccessPageRequest,
    ) -> Result<AccessPage<RoleBinding>, AccessError> {
        validate_id(&subject, 128, "subject_id")?;
        let scope = AccessListScope::AdminRoleBindings {
            tenant_id: tenant.clone(),
            subject_id: subject.clone(),
        };
        page.validate(&scope)?;
        if page.cursor.as_ref().is_some_and(|c| {
            uuid::Uuid::parse_str(&c.after[0]).map_or(true, |id| id.to_string() != c.after[0])
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
            let rows = tx.admin_role_bindings(&tenant, &subject, &page)?;
            if rows
                .iter()
                .any(|b| b.tenant_id != tenant || b.subject_id != subject || b.validate().is_err())
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |b| vec![b.id.clone()])
        })
    }
    fn list_roles(
        &self,
        context: AccessAdminContext,
        tenant: String,
        page: AccessPageRequest,
    ) -> Result<AccessPage<Role>, AccessError> {
        let scope = AccessListScope::AdminRoles {
            tenant_id: tenant.clone(),
        };
        page.validate(&scope)?;
        if page.cursor.as_ref().is_some_and(|c| {
            uuid::Uuid::parse_str(&c.after[0]).map_or(true, |id| id.to_string() != c.after[0])
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
            let rows = tx.admin_roles(&tenant, &page)?;
            if rows.iter().any(|r| r.tenant_id != tenant || r.version == 0) {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |r| vec![r.id.clone()])
        })
    }
    fn get_role(
        &self,
        context: AccessAdminContext,
        tenant: String,
        role: String,
    ) -> Result<AccessRoleRecord, AccessError> {
        validate_id(&role, 128, "role_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ReadAccess,
            )?;
            let row = tx
                .role(&tenant, &role)?
                .ok_or(AccessError::NotFound("role"))?;
            if row.role.tenant_id != tenant
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
}

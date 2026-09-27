use super::*;
use crate::access::IDP_BUSINESS_ID;

/// Secret-free snapshot for the dedicated protected-administrator workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAdministrator {
    pub tenant: Tenant,
    pub account: AccessAccountRecord,
    pub role: Role,
    pub binding: Option<RoleBinding>,
}

pub trait SecurityAdminService: AccessAdminService {
    fn get_security_administrator(
        &self,
        context: AccessAdminContext,
        tenant: String,
        subject: String,
    ) -> Result<SecurityAdministrator, AccessError>;
}

impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync> SecurityAdminService
    for CoreAccessAdminService<S, C, I>
{
    fn get_security_administrator(
        &self,
        context: AccessAdminContext,
        tenant: String,
        subject: String,
    ) -> Result<SecurityAdministrator, AccessError> {
        validate_id(&subject, 128, "subject_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageSecurityAdmins,
                false,
                Some(&subject),
            )?;
            let target = tx.tenant(&tenant)?.ok_or(AccessError::NotFound("tenant"))?;
            let mut account = tx
                .admin_account(None, &subject)?
                .ok_or(AccessError::NotFound("account"))?;
            if target.id != tenant || account.account_id != subject || account.membership.is_some()
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            account.membership = tx.membership(&tenant, &subject)?;
            if account
                .membership
                .as_ref()
                .is_some_and(|m| m.tenant_id != tenant || m.subject_id != subject || m.version == 0)
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            let kind = security_kind(&tenant);
            let role = tx
                .security_role(&tenant, kind)?
                .ok_or(AccessError::NotFound("security_role"))?
                .role;
            if role.tenant_id != tenant || role.kind != kind || role.version == 0 {
                return Err(AccessError::InvalidStoreResponse);
            }
            let binding = tx.security_binding(&tenant, &subject, &role.id)?;
            let resource = if kind == RoleKind::SystemAdmin {
                "idp.platform"
            } else {
                "idp.tenant"
            };
            if binding.as_ref().is_some_and(|b| {
                b.tenant_id != tenant
                    || b.subject_id != subject
                    || b.role_id != role.id
                    || b.business_id != IDP_BUSINESS_ID
                    || b.scope
                        != RoleBindingScope::Resource {
                            resource_type: resource.into(),
                            scope: ResourceScope::Type,
                        }
            }) {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(SecurityAdministrator {
                tenant: target,
                account,
                role,
                binding,
            })
        })
    }
}

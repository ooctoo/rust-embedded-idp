use super::*;
use crate::access::{service::finish_page, AccessListScope, AccessPage, AccessPageRequest};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminTenantFilter {
    pub tenant_id: Option<String>,
    /// Literal substring; ASCII case-insensitive, without SQL wildcards.
    pub name: Option<String>,
    pub status: Option<TenantStatus>,
}
impl AdminTenantFilter {
    pub fn validate(&self) -> Result<(), AccessError> {
        if let Some(id) = &self.tenant_id {
            TenancyMode::Enabled.validate_business_tenant(id)?;
        }
        if self.name.as_ref().is_some_and(|name| {
            name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control)
        }) {
            return Err(AccessError::InvalidInput("tenant_name_filter"));
        }
        Ok(())
    }
    pub fn matches(&self, record: &AccessTenantRecord) -> bool {
        let t = &record.tenant;
        self.tenant_id.as_ref().is_none_or(|id| id == &t.id)
            && self.name.as_ref().is_none_or(|name| {
                t.name
                    .to_ascii_lowercase()
                    .contains(&name.to_ascii_lowercase())
            })
            && self.status.is_none_or(|status| status == t.status)
    }
}

/// Platform management search, distinct from a user's tenant selection list.
pub trait TenantAdminService: AccessAdminService {
    fn list_tenants(
        &self,
        context: AccessAdminContext,
        filter: AdminTenantFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessTenantRecord>, AccessError>;
    fn get_tenant(
        &self,
        context: AccessAdminContext,
        tenant: String,
    ) -> Result<AccessTenantRecord, AccessError>;
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync> TenantAdminService
    for CoreAccessAdminService<S, C, I>
{
    fn list_tenants(
        &self,
        context: AccessAdminContext,
        filter: AdminTenantFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessTenantRecord>, AccessError> {
        filter.validate()?;
        let scope = AccessListScope::AdminTenants {
            filter: filter.clone(),
        };
        page.validate(&scope)?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                SYSTEM_TENANT_ID,
                AccessAdminOperation::ReadTenants,
            )?;
            let rows = tx.admin_tenants(&filter, &page)?;
            if rows.iter().any(|r| {
                TenancyMode::Enabled
                    .validate_business_tenant(&r.tenant.id)
                    .is_err()
                    || r.version == 0
                    || !filter.matches(r)
            }) {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |r| vec![r.tenant.id.clone()])
        })
    }
    fn get_tenant(
        &self,
        context: AccessAdminContext,
        tenant: String,
    ) -> Result<AccessTenantRecord, AccessError> {
        TenancyMode::Enabled.validate_business_tenant(&tenant)?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                SYSTEM_TENANT_ID,
                AccessAdminOperation::ReadTenants,
            )?;
            let row = tx
                .tenant_record(&tenant)?
                .ok_or(AccessError::NotFound("tenant"))?;
            if row.tenant.id != tenant || row.version == 0 {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(row)
        })
    }
}

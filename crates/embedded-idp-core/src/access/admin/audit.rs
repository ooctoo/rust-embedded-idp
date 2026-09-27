use super::*;
use crate::access::validate_access_business_id;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuditRecord {
    pub id: String,
    pub occurred_at: SystemTime,
    pub actor_id: String,
    pub actor_domain: String,
    pub actor_session_id: Option<String>,
    pub authentication_source: String,
    pub target_domain: String,
    pub target_business_id: Option<String>,
    pub operation: String,
    pub request_id: String,
}
impl AdminAuditRecord {
    pub fn validate(&self) -> Result<(), AccessError> {
        if uuid::Uuid::parse_str(&self.id).map_or(true, |id| id.to_string() != self.id) {
            return Err(AccessError::InvalidInput("audit_id"));
        }
        for id in [
            &self.id,
            &self.actor_id,
            &self.actor_domain,
            &self.target_domain,
            &self.authentication_source,
            &self.request_id,
        ] {
            validate_id(id, 128, "audit_record")?;
        }
        validate_name(&self.operation, "operation")?;
        if let Some(id) = &self.actor_session_id {
            validate_id(id, 128, "actor_session_id")?;
        }
        if let Some(business_id) = &self.target_business_id {
            validate_access_business_id(business_id)?;
        }
        validate_created_range(Some(self.occurred_at), None)?;
        Ok(())
    }
    pub fn page_key(&self) -> Vec<String> {
        time_page_key(self.occurred_at, self.id.clone())
    }
}
/// The existing secret-free audit projection, not a serialized credential/domain model.
/// Storage provides valid JSON; transport decodes it without adding JSON dependencies to Core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuditDetail {
    pub event: AdminAuditRecord,
    pub change_json: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminAuditFilter {
    pub business_id: Option<String>,
    pub actor_id: Option<String>,
    pub operation: Option<String>,
    pub occurred_after: Option<SystemTime>,
    pub occurred_before: Option<SystemTime>,
}
impl AdminAuditFilter {
    pub fn validate(&self) -> Result<(), AccessError> {
        if let Some(id) = &self.actor_id {
            validate_id(id, 128, "actor_id")?;
        }
        if let Some(operation) = &self.operation {
            validate_name(operation, "operation")?;
        }
        if let Some(business_id) = &self.business_id {
            validate_access_business_id(business_id)?;
        }
        validate_created_range(self.occurred_after, self.occurred_before)
    }
    pub fn matches(&self, event: &AdminAuditRecord) -> bool {
        self.actor_id
            .as_ref()
            .is_none_or(|id| id == &event.actor_id)
            && self
                .business_id
                .as_ref()
                .is_none_or(|business_id| event.target_business_id.as_ref() == Some(business_id))
            && self
                .operation
                .as_ref()
                .is_none_or(|op| op == &event.operation)
            && self.occurred_after.is_none_or(|t| event.occurred_at >= t)
            && self.occurred_before.is_none_or(|t| event.occurred_at <= t)
    }
}
pub trait AuditAdminService: Send + Sync {
    /// Metadata only; exactly one target domain. Platform domain 0 is explicit.
    fn list_audit_events(
        &self,
        context: AccessAdminContext,
        tenant: String,
        filter: AdminAuditFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AdminAuditRecord>, AccessError>;
    fn get_audit_event(
        &self,
        context: AccessAdminContext,
        tenant: String,
        id: String,
    ) -> Result<AdminAuditDetail, AccessError>;
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync> AuditAdminService
    for CoreAccessAdminService<S, C, I>
{
    fn list_audit_events(
        &self,
        context: AccessAdminContext,
        tenant: String,
        filter: AdminAuditFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AdminAuditRecord>, AccessError> {
        filter.validate()?;
        let scope = AccessListScope::AdminAudit {
            tenant_id: tenant.clone(),
            filter: filter.clone(),
        };
        page.validate(&scope)?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(tx, &context, &tenant, AccessAdminOperation::ReadAudit)?;
            let rows = tx.admin_audit_events(&tenant, &filter, &page)?;
            if rows
                .iter()
                .any(|r| r.target_domain != tenant || r.validate().is_err() || !filter.matches(r))
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, AdminAuditRecord::page_key)
        })
    }
    fn get_audit_event(
        &self,
        context: AccessAdminContext,
        tenant: String,
        id: String,
    ) -> Result<AdminAuditDetail, AccessError> {
        validate_id(&id, 128, "audit_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(tx, &context, &tenant, AccessAdminOperation::ReadAudit)?;
            let record = tx
                .admin_audit_event(&tenant, &id)?
                .ok_or(AccessError::NotFound("audit_event"))?;
            if record.event.id != id
                || record.event.target_domain != tenant
                || record.event.validate().is_err()
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(record)
        })
    }
}

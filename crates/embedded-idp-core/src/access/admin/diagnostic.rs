use super::*;
use crate::access::{service::query_is_permitted, AccessDecision};

pub trait AccessDiagnosticService: Send + Sync {
    /// Audited point-in-time decision for a member of the selected business domain.
    /// Never a credential or reusable authorization for a later resource request.
    fn diagnose_permission(
        &self,
        context: AccessAdminContext,
        query: AccessQuery,
    ) -> Result<AccessAuditEvent, AccessError>;
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync>
    AccessDiagnosticService for CoreAccessAdminService<S, C, I>
{
    fn diagnose_permission(
        &self,
        context: AccessAdminContext,
        query: AccessQuery,
    ) -> Result<AccessAuditEvent, AccessError> {
        query.validate()?;
        self.store.admin_transaction(|tx| {
            let now = self.authorize_management(
                tx,
                &context,
                &query.tenant_id,
                AccessAdminOperation::ReadAccess,
                false,
                Some(&query.subject_id),
            )?;
            let member = tx
                .membership(&query.tenant_id, &query.subject_id)?
                .ok_or(AccessError::NotFound("membership"))?;
            if member.tenant_id != query.tenant_id || member.subject_id != query.subject_id {
                return Err(AccessError::InvalidStoreResponse);
            }
            let decision = if query_is_permitted(self.mode, &self.catalog, &query)
                && tx.check_permission(&query)?
            {
                AccessDecision::Allow
            } else {
                AccessDecision::Deny
            };
            let event = AccessAuditEvent {
                id: self.new_id("audit")?,
                occurred_at: now,
                context,
                tenant_id: query.tenant_id.clone(),
                operation: "access.check",
                change: AccessChange::PermissionChecked { query, decision },
            };
            tx.append_audit(&event)?;
            Ok(event)
        })
    }
}

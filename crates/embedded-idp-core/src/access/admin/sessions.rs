use super::*;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest, TenantSession,
};
use crate::SessionStatus;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminSessionFilter {
    pub account_id: Option<String>,
    pub client_id: Option<String>,
    pub device_id: Option<String>,
    pub status: Option<SessionStatus>,
    pub created_after: Option<SystemTime>,
    pub created_before: Option<SystemTime>,
}
impl AdminSessionFilter {
    pub fn validate(&self) -> Result<(), AccessError> {
        for (value, field) in [
            (&self.account_id, "account_id"),
            (&self.client_id, "client_id"),
            (&self.device_id, "device_id"),
        ] {
            if let Some(value) = value {
                validate_id(value, 128, field)?;
            }
        }
        validate_created_range(self.created_after, self.created_before)
    }

    pub fn matches(&self, s: &TenantSession) -> bool {
        self.account_id
            .as_ref()
            .is_none_or(|id| id == &s.account_id)
            && self.client_id.as_ref().is_none_or(|id| id == &s.client_id)
            && self
                .device_id
                .as_ref()
                .is_none_or(|id| Some(id) == s.device_id.as_ref())
            && self
                .status
                .as_ref()
                .is_none_or(|status| status == &s.status)
            && self.created_after.is_none_or(|t| s.created_at >= t)
            && self.created_before.is_none_or(|t| s.created_at <= t)
    }
}
pub trait TenantSessionAdminService: AccessAdminService {
    fn list_sessions(
        &self,
        context: AccessAdminContext,
        tenant: String,
        filter: AdminSessionFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<TenantSession>, AccessError>;
    fn get_session(
        &self,
        context: AccessAdminContext,
        tenant: String,
        session: String,
    ) -> Result<TenantSession, AccessError>;
}
impl<S, C, I> TenantSessionAdminService for CoreAccessAdminService<S, C, I>
where
    S: AccessAdminStore,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn list_sessions(
        &self,
        context: AccessAdminContext,
        tenant: String,
        filter: AdminSessionFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<TenantSession>, AccessError> {
        filter.validate()?;
        let scope = AccessListScope::AdminSessions {
            tenant_id: tenant.clone(),
            filter: filter.clone(),
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
                AccessAdminOperation::ManageSessions,
            )?;
            let rows = tx.admin_sessions(&tenant, &filter, &page)?;
            if rows
                .iter()
                .any(|s| s.tenant_id != tenant || !filter.matches(s))
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |s| {
                time_page_key(s.created_at, s.id.clone())
            })
        })
    }
    fn get_session(
        &self,
        context: AccessAdminContext,
        tenant: String,
        session: String,
    ) -> Result<TenantSession, AccessError> {
        validate_id(&session, 128, "session_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageSessions,
            )?;
            let row = tx
                .admin_session(&tenant, &session)?
                .ok_or(AccessError::NotFound("session"))?;
            if row.tenant_id != tenant || row.id != session {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(row)
        })
    }
}

use super::*;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest,
};

/// Identity state is separate from each tenant membership. Includes stored closed
/// identities rather than silently treating them as active or disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountIdentityStatus {
    PendingVerification,
    Active,
    Disabled,
    Closed,
}
/// No password hash, registration tenant or other tenant memberships.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAccountRecord {
    pub account_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: AccountIdentityStatus,
    pub created_at: SystemTime,
    pub membership: Option<TenantMembership>,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminAccountFilter {
    pub status: Option<AccountIdentityStatus>,
    pub membership_status: Option<MembershipStatus>,
    /// Literal substring, case-insensitive for ASCII email characters.
    pub email: Option<String>,
    pub created_after: Option<SystemTime>,
    pub created_before: Option<SystemTime>,
}
impl AdminAccountFilter {
    pub fn validate(&self, tenant: Option<&str>) -> Result<(), AccessError> {
        if tenant.is_none() && self.membership_status.is_some() {
            return Err(AccessError::InvalidInput(
                "membership_filter_requires_tenant",
            ));
        }
        if self.email.as_ref().is_some_and(|v| {
            v.trim().is_empty() || v.len() > 254 || v.chars().any(char::is_control)
        }) {
            return Err(AccessError::InvalidInput("email_filter"));
        }
        validate_created_range(self.created_after, self.created_before)
    }
    pub fn matches(&self, record: &AccessAccountRecord) -> bool {
        self.status.is_none_or(|s| record.status == s)
            && self
                .membership_status
                .is_none_or(|s| record.membership.as_ref().is_some_and(|m| m.status == s))
            && self.email.as_ref().is_none_or(|e| {
                record
                    .email
                    .to_ascii_lowercase()
                    .contains(&e.to_ascii_lowercase())
            })
            && self.created_after.is_none_or(|t| record.created_at >= t)
            && self.created_before.is_none_or(|t| record.created_at <= t)
    }
}
/// Some(tenant) is a tenant member projection; None is a platform-only user search.
pub trait AccountAdminService: AccessAdminService {
    fn list_accounts(
        &self,
        context: AccessAdminContext,
        tenant: Option<String>,
        filter: AdminAccountFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessAccountRecord>, AccessError>;
    fn get_account(
        &self,
        context: AccessAdminContext,
        tenant: Option<String>,
        account: String,
    ) -> Result<AccessAccountRecord, AccessError>;
}
impl<S: AccessAdminStore, C: Clock + Send + Sync, I: IdGenerator + Send + Sync> AccountAdminService
    for CoreAccessAdminService<S, C, I>
{
    fn list_accounts(
        &self,
        context: AccessAdminContext,
        tenant: Option<String>,
        filter: AdminAccountFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessAccountRecord>, AccessError> {
        filter.validate(tenant.as_deref())?;
        let scope = AccessListScope::AdminAccounts {
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
            self.authorize_account_read(tx, &context, tenant.as_deref())?;
            let rows = tx.admin_accounts(tenant.as_deref(), &filter, &page)?;
            if rows
                .iter()
                .any(|r| !account_scope_matches(r, tenant.as_deref()) || !filter.matches(r))
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |r| {
                time_page_key(
                    r.membership.as_ref().map_or(r.created_at, |m| m.joined_at),
                    r.account_id.clone(),
                )
            })
        })
    }
    fn get_account(
        &self,
        context: AccessAdminContext,
        tenant: Option<String>,
        account: String,
    ) -> Result<AccessAccountRecord, AccessError> {
        validate_id(&account, 128, "account_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_account_read(tx, &context, tenant.as_deref())?;
            let row = tx
                .admin_account(tenant.as_deref(), &account)?
                .ok_or(AccessError::NotFound("account"))?;
            if row.account_id != account || !account_scope_matches(&row, tenant.as_deref()) {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(row)
        })
    }
}
impl<S: AccessAdminStore, C: Clock, I> CoreAccessAdminService<S, C, I> {
    fn authorize_account_read(
        &self,
        tx: &mut impl AccessAdminTransaction,
        context: &AccessAdminContext,
        tenant: Option<&str>,
    ) -> Result<(), AccessError> {
        if let Some(t) = tenant {
            self.mode.validate_business_tenant(t)?;
        } else if context.actor.tenant_id != SYSTEM_TENANT_ID {
            return Err(AccessError::Forbidden);
        }
        self.authorize_management_read(
            tx,
            context,
            tenant.unwrap_or(SYSTEM_TENANT_ID),
            AccessAdminOperation::ReadAccounts,
        )
    }
}
fn account_scope_matches(record: &AccessAccountRecord, tenant: Option<&str>) -> bool {
    match (tenant, &record.membership) {
        (None, None) => true,
        (Some(t), Some(m)) => m.tenant_id == t && m.subject_id == record.account_id,
        _ => false,
    }
}

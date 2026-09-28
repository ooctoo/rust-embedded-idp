use super::{
    query::{validate_access_business_id, validate_business_id, validate_id, IDP_BUSINESS_ID},
    AccessActor, AccessDecision, AccessError, AccessQuery, AccessReadStore, BatchAccessQuery,
    LoginTenantPolicy, MembershipStatus, PermissionCatalog, PermissionCategory,
    PermissionDefinition, Role, SubjectTenant, TenancyMode, SYSTEM_TENANT_ID,
};
use crate::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessListScope {
    AdminAudit {
        tenant_id: String,
        filter: super::AdminAuditFilter,
    },
    AdminPermissions {
        scope: super::AdminPermissionScope,
        filter: super::AdminPermissionFilter,
    },
    AdminRoleBindings {
        tenant_id: String,
        business_id: Option<String>,
        subject_id: String,
    },
    AdminRoles {
        tenant_id: String,
        business_id: Option<String>,
    },
    AdminTenants {
        filter: super::AdminTenantFilter,
    },
    AdminAccounts {
        tenant_id: Option<String>,
        filter: super::AdminAccountFilter,
    },
    AdminClients {
        filter: super::AdminClientFilter,
    },
    AdminSessions {
        tenant_id: String,
        filter: super::AdminSessionFilter,
    },
    AdminDevices {
        tenant_id: String,
        filter: super::AdminDeviceFilter,
    },
    AdminDeviceBindings {
        tenant_id: String,
        device_id: String,
        status: Option<crate::AccountDeviceBindingStatus>,
    },
    SubjectDevices {
        tenant_id: String,
        subject_id: String,
        client_id: String,
    },
    SubjectRoles {
        tenant_id: String,
        business_id: String,
        subject_id: String,
    },
    RolePermissions {
        tenant_id: String,
        business_id: String,
        role_id: String,
    },
    SubjectTenants {
        subject_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSortOrder {
    Asc,
    Desc,
}

impl AccessListScope {
    fn is_management(&self) -> bool {
        matches!(
            self,
            Self::AdminAudit { .. }
                | Self::AdminPermissions { .. }
                | Self::AdminRoleBindings { .. }
                | Self::AdminRoles { .. }
                | Self::AdminTenants { .. }
                | Self::AdminAccounts { .. }
                | Self::AdminClients { .. }
                | Self::AdminSessions { .. }
                | Self::AdminDevices { .. }
                | Self::AdminDeviceBindings { .. }
        )
    }

    fn cursor_version(&self) -> u8 {
        match self {
            Self::AdminPermissions { .. }
            | Self::AdminRoleBindings { .. }
            | Self::AdminRoles { .. } => 3,
            Self::SubjectRoles { .. } | Self::RolePermissions { .. } => 2,
            _ if self.is_management() => 2,
            _ => 1,
        }
    }
}

/// Typed library cursor. An HTTP adapter can encode it; it is never authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCursor {
    pub version: u8,
    pub scope: AccessListScope,
    /// Management cursors use `[19-digit epoch seconds, stable_id]`; v3 permission
    /// lists use `[19-digit epoch seconds, resource_type, action, business_id]`.
    /// Self-service scopes retain their existing ascending keys.
    pub after: Vec<String>,
    /// `None` is the legacy/default direction for the cursor scope.
    pub sort_order: Option<AccessSortOrder>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPageRequest {
    pub limit: u32,
    pub cursor: Option<AccessCursor>,
    /// `None` defaults to descending management lists and ascending self-service lists.
    pub sort_order: Option<AccessSortOrder>,
}

impl Default for AccessPageRequest {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            cursor: None,
            sort_order: None,
        }
    }
}

impl AccessPageRequest {
    pub fn fetch_limit(&self) -> usize {
        self.limit as usize + 1
    }

    pub fn effective_sort_order(&self, scope: &AccessListScope) -> AccessSortOrder {
        self.sort_order.unwrap_or(if scope.is_management() {
            AccessSortOrder::Desc
        } else {
            AccessSortOrder::Asc
        })
    }

    pub fn validate(&self, scope: &AccessListScope) -> Result<(), AccessError> {
        if self.limit == 0 || self.limit > MAX_PAGE_LIMIT {
            return Err(AccessError::InvalidInput("page_limit"));
        }
        if !scope.is_management() && self.sort_order == Some(AccessSortOrder::Desc) {
            return Err(AccessError::InvalidInput("sort_order"));
        }
        if let Some(cursor) = &self.cursor {
            let management = scope.is_management();
            let expected = match scope {
                AccessListScope::AdminPermissions { .. } => 4,
                AccessListScope::RolePermissions { .. } => 2,
                _ if management => 2,
                _ => 1,
            };
            if cursor.version != scope.cursor_version()
                || &cursor.scope != scope
                || cursor.after.len() != expected
                || cursor.sort_order.unwrap_or(if scope.is_management() {
                    AccessSortOrder::Desc
                } else {
                    AccessSortOrder::Asc
                }) != self.effective_sort_order(scope)
            {
                return Err(AccessError::InvalidCursor);
            }
            for key in &cursor.after {
                validate_id(key, 128, "cursor_key").map_err(|_| AccessError::InvalidCursor)?;
            }
            if management {
                let timestamp = &cursor.after[0];
                if timestamp.len() != 19
                    || !timestamp.bytes().all(|b| b.is_ascii_digit())
                    || timestamp
                        .parse::<u64>()
                        .map_or(true, |value| value > i64::MAX as u64)
                {
                    return Err(AccessError::InvalidCursor);
                }
            }
            if matches!(scope, AccessListScope::AdminAudit { .. })
                && uuid::Uuid::parse_str(&cursor.after[1])
                    .map_or(true, |id| id.to_string() != cursor.after[1])
            {
                return Err(AccessError::InvalidCursor);
            }
            if matches!(scope, AccessListScope::AdminPermissions { .. }) {
                super::PermissionKey {
                    business_id: cursor.after[3].clone(),
                    resource_type: cursor.after[1].clone(),
                    action: cursor.after[2].clone(),
                }
                .validate()
                .map_err(|_| AccessError::InvalidCursor)?;
            } else if matches!(scope, AccessListScope::RolePermissions { .. }) {
                super::PermissionKey {
                    business_id: IDP_BUSINESS_ID.into(),
                    resource_type: cursor.after[0].clone(),
                    action: cursor.after[1].clone(),
                }
                .validate()
                .map_err(|_| AccessError::InvalidCursor)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<AccessCursor>,
    pub has_more: bool,
}

pub trait AuthorizationService: Send + Sync {
    /// Trusted host call. The HTTP adapter must derive subject from authentication.
    fn check(&self, query: AccessQuery) -> Result<AccessDecision, AccessError>;
    fn check_many(&self, query: BatchAccessQuery) -> Result<Vec<AccessDecision>, AccessError>;
}

/// Trusted host read API; exposing another subject's data requires admin auth.
/// No method treats an omitted tenant as permission to search all tenants.
pub trait AccessQueryService: Send + Sync {
    fn list_subject_roles(
        &self,
        tenant_id: &str,
        business_id: &str,
        subject_id: &str,
        page: AccessPageRequest,
    ) -> Result<AccessPage<Role>, AccessError>;
    fn list_role_permissions(
        &self,
        tenant_id: &str,
        business_id: &str,
        role_id: &str,
        page: AccessPageRequest,
    ) -> Result<AccessPage<PermissionDefinition>, AccessError>;
    fn list_subject_tenants(
        &self,
        subject_id: &str,
        policy: &LoginTenantPolicy,
        page: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, AccessError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessAdminOperation {
    ManageAccountSecurity,
    ReadAccounts,
    ManageClients,
    ManageSessions,
    ManageDevices,
    ManageTenants,
    ReadTenants,
    ManageCatalog,
    ManageBusinessPermissions,
    ReadAccess,
    ReadAudit,
    ManageMembers,
    ManageRoles,
    ManageGrants,
    BindUser,
    ManageSecurityAdmins,
}

pub(super) fn admin_permission_query(
    mode: TenancyMode,
    actor: &AccessActor,
    target_tenant_id: &str,
    operation: AccessAdminOperation,
) -> Result<AccessQuery, AccessError> {
    actor.validate(mode)?;
    validate_id(target_tenant_id, 128, "tenant_id")?;
    if matches!(
        operation,
        AccessAdminOperation::ManageTenants
            | AccessAdminOperation::ReadTenants
            | AccessAdminOperation::ManageCatalog
            | AccessAdminOperation::ManageClients
            | AccessAdminOperation::ManageAccountSecurity
    ) {
        if actor.tenant_id != SYSTEM_TENANT_ID {
            return Err(AccessError::Forbidden);
        }
        if operation == AccessAdminOperation::ReadTenants && mode != TenancyMode::Enabled {
            return Err(AccessError::FeatureDisabled);
        }
        if operation == AccessAdminOperation::ManageTenants {
            if mode != TenancyMode::Enabled {
                return Err(AccessError::FeatureDisabled);
            }
            mode.validate_business_tenant(target_tenant_id)?;
        } else if target_tenant_id != SYSTEM_TENANT_ID {
            return Err(AccessError::ModeMismatch);
        }
        return Ok(AccessQuery {
            tenant_id: SYSTEM_TENANT_ID.into(),
            business_id: IDP_BUSINESS_ID.into(),
            subject_id: actor.subject_id.clone(),
            resource_type: "idp.platform".into(),
            action: if matches!(
                operation,
                AccessAdminOperation::ManageTenants | AccessAdminOperation::ReadTenants
            ) {
                "tenants.manage"
            } else if operation == AccessAdminOperation::ManageAccountSecurity {
                "users.security"
            } else if operation == AccessAdminOperation::ManageClients {
                "clients.manage"
            } else {
                "access.manage"
            }
            .into(),
            resource_id: None,
        });
    }
    if mode == TenancyMode::Disabled {
        if target_tenant_id != SYSTEM_TENANT_ID {
            return Err(AccessError::ModeMismatch);
        }
        if matches!(
            operation,
            AccessAdminOperation::BindUser | AccessAdminOperation::ManageMembers
        ) {
            return Err(AccessError::FeatureDisabled);
        }
    }
    if operation == AccessAdminOperation::BindUser {
        mode.validate_business_tenant(target_tenant_id)?;
    }
    let (resource_type, action) = if actor.tenant_id == SYSTEM_TENANT_ID {
        (
            "idp.platform",
            if operation == AccessAdminOperation::ReadAudit {
                "audit.read"
            } else if operation == AccessAdminOperation::ReadAccounts {
                "users.read"
            } else if operation == AccessAdminOperation::BindUser {
                "users.bind"
            } else {
                "access.manage"
            },
        )
    } else {
        if actor.tenant_id != target_tenant_id
            || matches!(
                operation,
                AccessAdminOperation::BindUser | AccessAdminOperation::ManageSecurityAdmins
            )
        {
            return Err(AccessError::Forbidden);
        }
        (
            "idp.tenant",
            match operation {
                AccessAdminOperation::ReadAccounts => "members.manage",
                AccessAdminOperation::ManageSessions => "sessions.manage",
                AccessAdminOperation::ManageDevices => "devices.manage",
                AccessAdminOperation::ReadAccess => "access.read",
                AccessAdminOperation::ReadAudit => "audit.read",
                AccessAdminOperation::ManageMembers => "members.manage",
                AccessAdminOperation::ManageBusinessPermissions => "permissions.manage",
                AccessAdminOperation::ManageRoles => "roles.manage",
                AccessAdminOperation::ManageGrants => "grants.manage",
                AccessAdminOperation::BindUser
                | AccessAdminOperation::ManageSecurityAdmins
                | AccessAdminOperation::ManageTenants
                | AccessAdminOperation::ReadTenants
                | AccessAdminOperation::ManageCatalog
                | AccessAdminOperation::ManageClients
                | AccessAdminOperation::ManageAccountSecurity => {
                    unreachable!()
                }
            },
        )
    };
    Ok(AccessQuery {
        tenant_id: actor.tenant_id.clone(),
        business_id: IDP_BUSINESS_ID.into(),
        subject_id: actor.subject_id.clone(),
        resource_type: resource_type.into(),
        action: action.into(),
        resource_id: None,
    })
}

/// Reuses an injected store; never reads environment variables or owns a DB.
pub struct CoreAccessService<S> {
    mode: TenancyMode,
    catalog: PermissionCatalog,
    store: S,
}

impl<S: AccessReadStore> CoreAccessService<S> {
    pub fn new(mode: TenancyMode, catalog: PermissionCatalog, store: S) -> Self {
        Self {
            mode,
            catalog,
            store,
        }
    }

    fn valid_domain(&self, tenant: &str, business_id: &str) -> Result<(), AccessError> {
        validate_id(tenant, 128, "tenant_id")?;
        if self.mode == TenancyMode::Disabled && tenant != SYSTEM_TENANT_ID {
            return Err(AccessError::ModeMismatch);
        }
        validate_access_business_id(business_id)?;
        Ok(())
    }

    /// Preflight only, NOT a reusable authorization token. Management mutations
    /// use CoreAccessAdminService to recheck authority inside their transaction.
    pub fn require_admin_access(
        &self,
        actor: &AccessActor,
        target_tenant_id: &str,
        operation: AccessAdminOperation,
    ) -> Result<(), AccessError> {
        match self.check(admin_permission_query(
            self.mode,
            actor,
            target_tenant_id,
            operation,
        )?)? {
            AccessDecision::Allow => Ok(()),
            AccessDecision::Deny => Err(AccessError::Forbidden),
        }
    }
}

impl<S: AccessReadStore> AuthorizationService for CoreAccessService<S> {
    fn check(&self, query: AccessQuery) -> Result<AccessDecision, AccessError> {
        let decisions = self.check_many(BatchAccessQuery {
            queries: vec![query],
        })?;
        Ok(decisions[0])
    }

    fn check_many(&self, batch: BatchAccessQuery) -> Result<Vec<AccessDecision>, AccessError> {
        batch.validate()?;
        let mut decisions = vec![AccessDecision::Deny; batch.queries.len()];
        let mut positions = Vec::new();
        let mut eligible = Vec::new();
        for (position, query) in batch.queries.into_iter().enumerate() {
            if query_is_permitted(self.mode, &self.catalog, &query) {
                positions.push(position);
                eligible.push(query);
            }
        }
        if eligible.is_empty() {
            return Ok(decisions);
        }
        let allowed = self.store.check_active_grants(&eligible)?;
        if allowed.len() != positions.len() {
            return Err(AccessError::InvalidStoreResponse);
        }
        for (position, allowed) in positions.into_iter().zip(allowed) {
            if allowed {
                decisions[position] = AccessDecision::Allow;
            }
        }
        Ok(decisions)
    }
}

impl<S: AccessReadStore> AccessQueryService for CoreAccessService<S> {
    fn list_subject_roles(
        &self,
        tenant_id: &str,
        business_id: &str,
        subject_id: &str,
        page: AccessPageRequest,
    ) -> Result<AccessPage<Role>, AccessError> {
        self.valid_domain(tenant_id, business_id)?;
        validate_id(subject_id, 128, "subject_id")?;
        let scope = AccessListScope::SubjectRoles {
            tenant_id: tenant_id.into(),
            business_id: business_id.into(),
            subject_id: subject_id.into(),
        };
        page.validate(&scope)?;
        let rows = self
            .store
            .list_subject_roles(tenant_id, business_id, subject_id, &page)?;
        if rows.iter().any(|r| {
            r.tenant_id != tenant_id
                || r.business_id != business_id
                || validate_id(&r.id, 128, "role_id").is_err()
        }) {
            return Err(AccessError::InvalidStoreResponse);
        }
        finish_page(rows, page, scope, |r| vec![r.id.clone()])
    }

    fn list_role_permissions(
        &self,
        tenant_id: &str,
        business_id: &str,
        role_id: &str,
        page: AccessPageRequest,
    ) -> Result<AccessPage<PermissionDefinition>, AccessError> {
        self.valid_domain(tenant_id, business_id)?;
        validate_id(role_id, 128, "role_id")?;
        let scope = AccessListScope::RolePermissions {
            tenant_id: tenant_id.into(),
            business_id: business_id.into(),
            role_id: role_id.into(),
        };
        page.validate(&scope)?;
        let rows = self
            .store
            .list_role_permissions(tenant_id, business_id, role_id, &page)?;
        if rows.iter().any(|p| {
            p.key.validate().is_err()
                || p.tenant_id != tenant_id
                || p.key.business_id != business_id
                || !self.mode.permits(tenant_id, p.category)
                || (p.category != PermissionCategory::Business
                    && self
                        .catalog
                        .get(&p.key)
                        .is_none_or(|known| known.category != p.category))
        }) {
            return Err(AccessError::InvalidStoreResponse);
        }
        finish_page(rows, page, scope, |p| {
            vec![p.key.resource_type.clone(), p.key.action.clone()]
        })
    }

    fn list_subject_tenants(
        &self,
        subject_id: &str,
        policy: &LoginTenantPolicy,
        page: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, AccessError> {
        policy.validate(self.mode)?;
        if self.mode != TenancyMode::Enabled
            || *policy != LoginTenantPolicy::ChooseAfterAuthentication
        {
            return Err(AccessError::FeatureDisabled);
        }
        validate_id(subject_id, 128, "subject_id")?;
        let scope = AccessListScope::SubjectTenants {
            subject_id: subject_id.into(),
        };
        page.validate(&scope)?;
        let rows = self.store.list_subject_tenants(subject_id, &page)?;
        if rows.iter().any(|r| {
            self.mode.validate_business_tenant(&r.tenant.id).is_err()
                || r.membership.tenant_id != r.tenant.id
                || r.membership.subject_id != subject_id
                || r.membership.status == MembershipStatus::Removed
        }) {
            return Err(AccessError::InvalidStoreResponse);
        }
        finish_page(rows, page, scope, |r| vec![r.tenant.id.clone()])
    }
}

pub(super) fn finish_page<T>(
    mut rows: Vec<T>,
    page: AccessPageRequest,
    scope: AccessListScope,
    key: impl Fn(&T) -> Vec<String>,
) -> Result<AccessPage<T>, AccessError> {
    if rows.len() > page.fetch_limit() {
        return Err(AccessError::InvalidStoreResponse);
    }
    let order = page.effective_sort_order(&scope);
    let mut previous = page.cursor.as_ref().map(|c| c.after.clone());
    for row in &rows {
        let current = key(row);
        let unordered = if order == AccessSortOrder::Desc {
            previous.as_ref().is_some_and(|last| last <= &current)
        } else {
            previous.as_ref().is_some_and(|last| last >= &current)
        };
        if unordered {
            return Err(AccessError::InvalidStoreResponse);
        }
        previous = Some(current);
    }
    let has_more = rows.len() > page.limit as usize;
    rows.truncate(page.limit as usize);
    let next_cursor = if has_more {
        let cursor_sort_order = scope.is_management().then_some(order);
        rows.last().map(|last| AccessCursor {
            version: scope.cursor_version(),
            scope,
            after: key(last),
            sort_order: cursor_sort_order,
        })
    } else {
        None
    };
    Ok(AccessPage {
        items: rows,
        next_cursor,
        has_more,
    })
}

pub(crate) fn time_page_key(time: SystemTime, entity_id: String) -> Vec<String> {
    vec![
        format!(
            "{:019}",
            time.duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
        entity_id,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_scope() -> AccessListScope {
        AccessListScope::AdminDevices {
            tenant_id: "tenant".into(),
            filter: super::super::AdminDeviceFilter::default(),
        }
    }

    #[test]
    fn management_pages_are_newest_first_and_use_stable_ties() {
        let scope = device_scope();
        let rows = vec![
            vec!["0000000000000000002".into(), "a".into()],
            vec!["0000000000000000001".into(), "z".into()],
            vec!["0000000000000000001".into(), "a".into()],
        ];
        let first = finish_page(
            rows[..].to_vec(),
            AccessPageRequest {
                limit: 2,
                cursor: None,
                sort_order: None,
            },
            scope.clone(),
            Clone::clone,
        )
        .unwrap();
        assert_eq!(first.items, rows[..2]);
        assert_eq!(
            first.next_cursor.as_ref().unwrap().sort_order,
            Some(AccessSortOrder::Desc)
        );
        let second = finish_page(
            rows[2..].to_vec(),
            AccessPageRequest {
                limit: 2,
                cursor: first.next_cursor,
                sort_order: None,
            },
            scope,
            Clone::clone,
        )
        .unwrap();
        assert_eq!(second.items, rows[2..]);
    }

    #[test]
    fn management_pages_accept_ascending_and_reject_direction_switches() {
        let scope = device_scope();
        let rows = vec![
            vec!["0000000000000000001".into(), "a".into()],
            vec!["0000000000000000001".into(), "z".into()],
            vec!["0000000000000000002".into(), "a".into()],
        ];
        let first = finish_page(
            rows[..].to_vec(),
            AccessPageRequest {
                limit: 2,
                cursor: None,
                sort_order: Some(AccessSortOrder::Asc),
            },
            scope.clone(),
            Clone::clone,
        )
        .unwrap();
        assert_eq!(first.items, rows[..2]);
        assert_eq!(
            first.next_cursor.as_ref().unwrap().sort_order,
            Some(AccessSortOrder::Asc)
        );
        assert_eq!(
            AccessPageRequest {
                limit: 2,
                cursor: first.next_cursor.clone(),
                sort_order: Some(AccessSortOrder::Desc),
            }
            .validate(&scope),
            Err(AccessError::InvalidCursor)
        );
        let second = finish_page(
            rows[2..].to_vec(),
            AccessPageRequest {
                limit: 2,
                cursor: first.next_cursor,
                sort_order: Some(AccessSortOrder::Asc),
            },
            scope,
            Clone::clone,
        )
        .unwrap();
        assert_eq!(second.items, rows[2..]);
    }

    #[test]
    fn legacy_management_cursor_defaults_to_descending_and_v1_stays_ascending() {
        let management = device_scope();
        let legacy = AccessCursor {
            version: 2,
            scope: management.clone(),
            after: vec!["0000000000000000001".into(), "id".into()],
            sort_order: None,
        };
        assert!(AccessPageRequest {
            limit: 1,
            cursor: Some(legacy),
            sort_order: None,
        }
        .validate(&management)
        .is_ok());

        let subject = AccessListScope::SubjectRoles {
            tenant_id: "tenant".into(),
            business_id: "f_01".into(),
            subject_id: "subject".into(),
        };
        assert_eq!(
            AccessPageRequest::default().effective_sort_order(&subject),
            AccessSortOrder::Asc
        );
        assert_eq!(
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: Some(AccessSortOrder::Desc),
            }
            .validate(&subject),
            Err(AccessError::InvalidInput("sort_order"))
        );
    }

    #[test]
    fn management_cursors_reject_v1_and_invalid_epoch_seconds() {
        let scope = device_scope();
        for (version, after) in [
            (1, vec!["0000000000000000001".into(), "id".into()]),
            (2, vec!["9999999999999999999".into(), "id".into()]),
        ] {
            assert_eq!(
                AccessPageRequest {
                    limit: 1,
                    cursor: Some(AccessCursor {
                        version,
                        scope: scope.clone(),
                        after,
                        sort_order: None,
                    }),
                    sort_order: None,
                }
                .validate(&scope),
                Err(AccessError::InvalidCursor)
            );
        }
    }
}

// Shared eligibility gate for host authorization and audited management diagnosis.
pub(super) fn query_is_permitted(
    mode: TenancyMode,
    catalog: &PermissionCatalog,
    query: &AccessQuery,
) -> bool {
    if query.business_id != IDP_BUSINESS_ID {
        return validate_business_id(&query.business_id).is_ok()
            && !query.resource_type.starts_with("idp.")
            && mode.permits(&query.tenant_id, PermissionCategory::Business);
    }
    catalog.get(&query.permission()).is_some_and(|definition| {
        mode.permits(&query.tenant_id, definition.category)
            && (definition.category == PermissionCategory::Business || query.resource_id.is_none())
    })
}

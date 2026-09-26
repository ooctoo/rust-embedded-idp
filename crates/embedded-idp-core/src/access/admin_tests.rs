use super::*;
use crate::access::service::time_page_key;
use crate::{Clock, IdGenerator, StoreError};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct Data {
    passwords: BTreeMap<String, String>,
    account_records: Vec<AccessAccountRecord>,
    clients: Vec<crate::OidcClient>,
    admin_sessions: Vec<TenantSession>,
    devices: Vec<AccessDeviceRecord>,
    active_device_bindings: Vec<(String, String, String)>,
    mode: TenancyMode,
    accounts: BTreeMap<String, bool>,
    tenants: BTreeMap<String, Tenant>,
    tenant_versions: BTreeMap<String, u64>,
    memberships: Vec<TenantMembership>,
    roles: Vec<AccessRoleRecord>,
    bindings: Vec<RoleBinding>,
    permissions: BTreeMap<PermissionKey, PermissionDefinition>,
    sessions: BTreeMap<String, (String, String, bool)>,
    audits: Vec<AccessAuditEvent>,
    fail_audit: bool,
    revoke_before_permission: bool,
    lock_clock: Option<Arc<AtomicU64>>,
    locked: bool,
    session_expires_at: SystemTime,
}
#[derive(Clone)]
struct Store(Arc<Mutex<Data>>);
struct Tx {
    data: Data,
}
#[derive(Clone, Copy)]
struct FixedClock;
#[derive(Clone, Copy)]
struct SeqIds;
impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1000)
    }
}
impl IdGenerator for SeqIds {
    fn next_id(&self, prefix: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        format!("{prefix}-test-{}", NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

fn key(resource: &str, action: &str) -> PermissionKey {
    PermissionKey {
        resource_type: resource.into(),
        action: action.into(),
    }
}
fn perm(resource: &str, action: &str, category: PermissionCategory) -> PermissionDefinition {
    PermissionDefinition {
        tenant_id: "0".into(),
        key: key(resource, action),
        description: action.into(),
        category,
        enabled: true,
        archived: false,
        version: 1,
        created_at: None,
    }
}
fn permission_page_key(permission: &PermissionDefinition) -> Vec<String> {
    let mut key = time_page_key(
        permission.created_at.unwrap_or(UNIX_EPOCH),
        permission.key.resource_type.clone(),
    );
    key.push(permission.key.action.clone());
    key
}
fn management_after(key: Vec<String>, page: &AccessPageRequest) -> bool {
    page.cursor
        .as_ref()
        .is_none_or(|cursor| match page.sort_order {
            Some(AccessSortOrder::Asc) => key > cursor.after,
            None | Some(AccessSortOrder::Desc) => key < cursor.after,
        })
}
fn sort_management<T>(rows: &mut [T], page: &AccessPageRequest, key: impl Fn(&T) -> Vec<String>) {
    rows.sort_by(|left, right| {
        let order = key(left).cmp(&key(right));
        if page.sort_order == Some(AccessSortOrder::Asc) {
            order
        } else {
            order.reverse()
        }
    });
}
fn role(
    id: &str,
    tenant: &str,
    kind: RoleKind,
    permissions: Vec<PermissionKey>,
) -> AccessRoleRecord {
    AccessRoleRecord {
        role: Role {
            id: id.into(),
            tenant_id: tenant.into(),
            key: id.into(),
            name: id.into(),
            status: RoleStatus::Active,
            kind,
            version: 1,
            created_at: UNIX_EPOCH,
        },
        permissions,
    }
}
fn membership(tenant: &str, subject: &str) -> TenantMembership {
    TenantMembership {
        tenant_id: tenant.into(),
        subject_id: subject.into(),
        status: MembershipStatus::Active,
        joined_at: UNIX_EPOCH,
        version: 1,
    }
}
fn binding(id: &str, tenant: &str, subject: &str, role_id: &str, resource: &str) -> RoleBinding {
    RoleBinding {
        id: id.into(),
        tenant_id: tenant.into(),
        subject_id: subject.into(),
        role_id: role_id.into(),
        resource_type: resource.into(),
        scope: ResourceScope::Type,
        created_at: UNIX_EPOCH,
    }
}
fn catalog() -> (
    PermissionCatalog,
    BTreeMap<PermissionKey, PermissionDefinition>,
) {
    let host = perm("report", "read", PermissionCategory::Business);
    let catalog = PermissionCatalog::new(vec![host]).unwrap();
    let permissions = catalog
        .definitions()
        .cloned()
        .map(|p| (p.key.clone(), p))
        .collect();
    (catalog, permissions)
}
fn seeded() -> Store {
    let (catalog, permissions) = catalog();
    let mut accounts = BTreeMap::new();
    for id in ["u1", "u2", "u3"] {
        accounts.insert(id.into(), true);
    }
    let mut tenants = BTreeMap::new();
    let mut tenant_versions = BTreeMap::new();
    for id in ["0", "t1", "t2"] {
        tenants.insert(
            id.into(),
            Tenant {
                id: id.into(),
                name: id.into(),
                status: TenantStatus::Active,
                allow_registration: true,
            },
        );
        tenant_versions.insert(id.into(), 1);
    }
    let platform: Vec<_> = catalog
        .definitions()
        .filter(|p| p.category == PermissionCategory::Platform)
        .map(|p| p.key.clone())
        .collect();
    let tenant: Vec<_> = catalog
        .definitions()
        .filter(|p| p.category == PermissionCategory::Tenant)
        .map(|p| p.key.clone())
        .collect();
    let roles = vec![
        role("sys", "0", RoleKind::SystemAdmin, platform),
        role("sec1", "t1", RoleKind::TenantSecurityAdmin, tenant.clone()),
        role("sec2", "t2", RoleKind::TenantSecurityAdmin, tenant),
    ];
    let memberships = [
        membership("0", "u1"),
        membership("t1", "u1"),
        membership("t1", "u2"),
        membership("t2", "u1"),
        membership("t2", "u2"),
    ]
    .into();
    let bindings = vec![
        binding("bsys", "0", "u1", "sys", "idp.platform"),
        binding("bsec1", "t1", "u1", "sec1", "idp.tenant"),
        binding("bsec2", "t2", "u1", "sec2", "idp.tenant"),
    ];
    let sessions = [
        ("s0", "0", "u1"),
        ("s1", "t1", "u1"),
        ("s2", "t1", "u2"),
        ("s3", "t2", "u1"),
    ]
    .into_iter()
    .map(|(s, t, u)| (s.into(), (t.into(), u.into(), true)))
    .collect();
    Store(Arc::new(Mutex::new(Data {
        passwords: BTreeMap::new(),
        account_records: vec![],
        clients: vec![],
        admin_sessions: vec![],
        devices: vec![],
        active_device_bindings: vec![],
        mode: TenancyMode::Enabled,
        accounts,
        tenants,
        tenant_versions,
        memberships,
        roles,
        bindings,
        permissions,
        sessions,
        audits: vec![],
        fail_audit: false,
        revoke_before_permission: false,
        lock_clock: None,
        locked: false,
        session_expires_at: UNIX_EPOCH + Duration::from_secs(2000),
    })))
}
fn service(store: Store) -> (CoreAccessAdminService<Store, FixedClock, SeqIds>, Store) {
    let (c, _) = catalog();
    (
        CoreAccessAdminService::new(TenancyMode::Enabled, c, store.clone(), FixedClock, SeqIds),
        store,
    )
}
fn ctx(tenant: &str, subject: &str, session: &str) -> AccessAdminContext {
    AccessAdminContext {
        actor: AccessActor {
            tenant_id: tenant.into(),
            subject_id: subject.into(),
            session_id: session.into(),
        },
        authentication_source: "test".into(),
        request_id: "req".into(),
    }
}
fn command(tenant: &str, mutation: AccessAdminMutation) -> AccessAdminCommand {
    AccessAdminCommand {
        tenant_id: tenant.into(),
        mutation,
    }
}
fn report() -> PermissionKey {
    key("report", "read")
}
impl AccessAdminStore for Store {
    type Transaction<'a> = Tx;
    fn admin_transaction<R>(
        &self,
        run: impl FnOnce(&mut Tx) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        // Test-only serialization, not a model of PostgreSQL row-lock concurrency.
        let mut guard = self.0.lock().unwrap();
        let mut tx = Tx {
            data: guard.clone(),
        };
        tx.data.locked = false;
        let result = run(&mut tx);
        if result.is_ok() {
            *guard = tx.data;
        }
        result
    }
}
impl AccessAdminTransaction for Tx {
    fn insert_admin_tenant(
        &mut self,
        record: &AccessTenantRecord,
        _: SystemTime,
    ) -> Result<(), StoreError> {
        if self.data.tenants.contains_key(&record.tenant.id) {
            return Err(StoreError::Conflict("tenant.exists"));
        }
        self.data
            .tenants
            .insert(record.tenant.id.clone(), record.tenant.clone());
        self.data
            .tenant_versions
            .insert(record.tenant.id.clone(), record.version);
        Ok(())
    }

    fn insert_admin_account(
        &mut self,
        account: &AccessAccountRecord,
        hash: &crate::SecretString,
    ) -> Result<(), StoreError> {
        if self
            .data
            .account_records
            .iter()
            .any(|r| r.email == account.email)
        {
            return Err(StoreError::Conflict("account.email"));
        }
        let mut record = account.clone();
        self.data
            .memberships
            .push(record.membership.take().unwrap());
        self.data.account_records.push(record);
        self.data.accounts.insert(account.account_id.clone(), true);
        self.data
            .passwords
            .insert(account.account_id.clone(), hash.expose_secret().into());
        Ok(())
    }
    fn update_account_security(
        &mut self,
        before: &AccessAccountRecord,
        status: AccountIdentityStatus,
        hash: Option<&crate::SecretString>,
        _: SystemTime,
    ) -> Result<(), StoreError> {
        let row = self
            .data
            .account_records
            .iter_mut()
            .find(|r| r.account_id == before.account_id)
            .unwrap();
        row.status = status;
        self.data.accounts.insert(
            before.account_id.clone(),
            status == AccountIdentityStatus::Active,
        );
        if let Some(hash) = hash {
            self.data
                .passwords
                .insert(before.account_id.clone(), hash.expose_secret().into());
        }
        if hash.is_some() || before.status != status {
            for (_, subject, active) in self.data.sessions.values_mut() {
                if subject == &before.account_id {
                    *active = false;
                }
            }
        }
        Ok(())
    }
    fn account_admin_tenants(
        &mut self,
        subject: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .memberships
            .iter()
            .filter(|m| {
                m.subject_id == subject
                    && m.status == MembershipStatus::Active
                    && self.data.tenants[&m.tenant_id].status == TenantStatus::Active
                    && self.data.bindings.iter().any(|b| {
                        b.tenant_id == m.tenant_id
                            && b.subject_id == subject
                            && b.scope == ResourceScope::Type
                            && self.data.roles.iter().any(|r| {
                                r.role.id == b.role_id
                                    && r.role.tenant_id == m.tenant_id
                                    && r.role.status == RoleStatus::Active
                                    && r.role.kind != RoleKind::Business
                            })
                    })
                    && after.is_none_or(|a| m.tenant_id.as_str() > a)
            })
            .map(|m| m.tenant_id.clone())
            .collect();
        rows.sort();
        rows.truncate(limit as usize);
        Ok(rows)
    }

    fn admin_account(
        &mut self,
        tenant: Option<&str>,
        account: &str,
    ) -> Result<Option<AccessAccountRecord>, StoreError> {
        Ok(self
            .account_projections(tenant)
            .into_iter()
            .find(|r| r.account_id == account))
    }
    fn admin_accounts(
        &mut self,
        tenant: Option<&str>,
        filter: &AdminAccountFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AccessAccountRecord>, StoreError> {
        let mut records: Vec<_> = self
            .account_projections(tenant)
            .into_iter()
            .filter(|r| {
                filter.matches(r)
                    && management_after(
                        time_page_key(
                            r.membership.as_ref().map_or(r.created_at, |m| m.joined_at),
                            r.account_id.clone(),
                        ),
                        page,
                    )
            })
            .collect();
        sort_management(&mut records, page, |r| {
            time_page_key(
                r.membership.as_ref().map_or(r.created_at, |m| m.joined_at),
                r.account_id.clone(),
            )
        });
        records.truncate(page.fetch_limit());
        Ok(records)
    }

    fn admin_client(&mut self, id: &str) -> Result<Option<crate::OidcClient>, StoreError> {
        Ok(self
            .data
            .clients
            .iter()
            .find(|c| c.client_id == id)
            .cloned())
    }
    fn admin_clients(
        &mut self,
        filter: &AdminClientFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<crate::AdminClientRecord>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .clients
            .iter()
            .cloned()
            .map(client_metadata)
            .filter(|c| {
                filter.matches(c)
                    && management_after(
                        time_page_key(c.created_at.unwrap_or(UNIX_EPOCH), c.client_id.clone()),
                        page,
                    )
            })
            .collect();
        sort_management(&mut rows, page, |c| {
            time_page_key(c.created_at.unwrap_or(UNIX_EPOCH), c.client_id.clone())
        });
        rows.truncate(page.fetch_limit());
        Ok(rows)
    }
    fn upsert_admin_client(
        &mut self,
        client: &crate::OidcClient,
        _: SystemTime,
    ) -> Result<(), StoreError> {
        self.data
            .clients
            .retain(|c| c.client_id != client.client_id);
        self.data.clients.push(client.clone());
        Ok(())
    }

    fn admin_session(&mut self, t: &str, id: &str) -> Result<Option<TenantSession>, StoreError> {
        Ok(self
            .data
            .admin_sessions
            .iter()
            .find(|s| s.tenant_id == t && s.id == id)
            .cloned())
    }
    fn admin_sessions(
        &mut self,
        t: &str,
        f: &AdminSessionFilter,
        p: &AccessPageRequest,
    ) -> Result<Vec<TenantSession>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .admin_sessions
            .iter()
            .filter(|s| {
                s.tenant_id == t
                    && f.matches(s)
                    && management_after(time_page_key(s.created_at, s.id.clone()), p)
            })
            .cloned()
            .collect();
        sort_management(&mut rows, p, |s| time_page_key(s.created_at, s.id.clone()));
        rows.truncate(p.fetch_limit());
        Ok(rows)
    }
    fn active_subject_session_count(&mut self, t: &str, subject: &str) -> Result<u64, StoreError> {
        Ok(self
            .data
            .admin_sessions
            .iter()
            .filter(|s| {
                s.tenant_id == t
                    && s.account_id == subject
                    && matches!(
                        s.status,
                        crate::SessionStatus::Active | crate::SessionStatus::Pending
                    )
            })
            .count() as u64)
    }

    fn admin_device(&mut self, t: &str, d: &str) -> Result<Option<AccessDeviceRecord>, StoreError> {
        Ok(self
            .data
            .devices
            .iter()
            .find(|r| r.device.tenant_id == t && r.device.id == d)
            .cloned())
    }
    fn admin_devices(
        &mut self,
        t: &str,
        filter: &AdminDeviceFilter,
        p: &AccessPageRequest,
    ) -> Result<Vec<AccessDeviceRecord>, StoreError> {
        let mut rows: Vec<_> =
            self.data
                .devices
                .iter()
                .filter(|r| {
                    r.device.tenant_id == t
                        && filter.matches_metadata(r)
                        && filter.account_id.as_ref().is_none_or(|account| {
                            self.data.active_device_bindings.iter().any(
                                |(tenant, subject, device)| {
                                    tenant == t && subject == account && device == &r.device.id
                                },
                            )
                        })
                        && management_after(time_page_key(r.registered_at, r.device.id.clone()), p)
                })
                .cloned()
                .collect();
        sort_management(&mut rows, p, |r| {
            time_page_key(r.registered_at, r.device.id.clone())
        });
        rows.truncate(p.fetch_limit());
        Ok(rows)
    }

    fn lock_scope(&mut self, scope: &AccessWriteScope) -> Result<(), AccessError> {
        if self.data.mode != scope.mode {
            return Err(AccessError::ModeMismatch);
        }
        assert!(scope.tenant_ids.windows(2).all(|p| p[0] < p[1]));
        assert!(scope.subject_ids.windows(2).all(|p| p[0] < p[1]));
        if let Some(clock) = &self.data.lock_clock {
            clock.store(2000, Ordering::SeqCst);
        }
        self.data.locked = true;
        Ok(())
    }
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        assert!(self.data.locked);
        Ok(now < self.data.session_expires_at
            && self
                .data
                .sessions
                .get(&actor.session_id)
                .is_some_and(|(t, s, a)| t == &actor.tenant_id && s == &actor.subject_id && *a)
            && self.data.accounts.get(&actor.subject_id) == Some(&true)
            && self
                .data
                .tenants
                .get(&actor.tenant_id)
                .is_some_and(|t| t.status == TenantStatus::Active)
            && self.data.memberships.iter().any(|m| {
                m.tenant_id == actor.tenant_id
                    && m.subject_id == actor.subject_id
                    && m.status == MembershipStatus::Active
            }))
    }
    fn check_permission(&mut self, q: &AccessQuery) -> Result<bool, StoreError> {
        assert!(self.data.locked);
        if self.data.revoke_before_permission {
            self.data
                .bindings
                .retain(|b| !(b.tenant_id == q.tenant_id && b.subject_id == q.subject_id));
        }
        let active = self.data.accounts.get(&q.subject_id) == Some(&true)
            && self
                .data
                .tenants
                .get(&q.tenant_id)
                .is_some_and(|t| t.status == TenantStatus::Active)
            && self.data.memberships.iter().any(|m| {
                m.tenant_id == q.tenant_id
                    && m.subject_id == q.subject_id
                    && m.status == MembershipStatus::Active
            });
        let Some(permission) = self.data.permissions.get(&q.permission()) else {
            return Ok(false);
        };
        Ok(active
            && self.data.bindings.iter().any(|b| {
                self.data.roles.iter().any(|r| {
                    r.permissions.iter().any(|key| {
                        let link = RolePermission {
                            tenant_id: r.role.tenant_id.clone(),
                            role_id: r.role.id.clone(),
                            permission: key.clone(),
                        };
                        b.grants(q, &r.role, &link, permission, self.data.mode)
                    })
                })
            }))
    }
    fn tenant(&mut self, id: &str) -> Result<Option<Tenant>, StoreError> {
        Ok(self.data.tenants.get(id).cloned())
    }
    fn tenant_record(&mut self, id: &str) -> Result<Option<AccessTenantRecord>, StoreError> {
        Ok(self
            .data
            .tenants
            .get(id)
            .cloned()
            .map(|tenant| AccessTenantRecord {
                version: self.data.tenant_versions.get(id).copied().unwrap_or(1),
                tenant,
                created_at: UNIX_EPOCH,
            }))
    }
    fn admin_tenants(
        &mut self,
        filter: &AdminTenantFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AccessTenantRecord>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .tenants
            .values()
            .filter(|t| t.id != "0")
            .map(|tenant| AccessTenantRecord {
                tenant: tenant.clone(),
                version: self
                    .data
                    .tenant_versions
                    .get(&tenant.id)
                    .copied()
                    .unwrap_or(1),
                created_at: UNIX_EPOCH,
            })
            .filter(|t| filter.matches(t))
            .filter(|t| management_after(time_page_key(t.created_at, t.tenant.id.clone()), page))
            .collect();
        sort_management(&mut rows, page, |t| {
            time_page_key(t.created_at, t.tenant.id.clone())
        });
        rows.truncate(page.fetch_limit());
        Ok(rows)
    }
    fn resource_category(
        &mut self,
        _tenant_id: &str,
        resource_type: &str,
    ) -> Result<Option<PermissionCategory>, StoreError> {
        let mut categories = self
            .data
            .permissions
            .values()
            .filter(|permission| permission.key.resource_type == resource_type)
            .map(|permission| permission.category);
        let Some(first) = categories.next() else {
            return Ok(None);
        };
        if categories.any(|category| category != first) {
            return Err(StoreError::Conflict("permission_category"));
        }
        Ok(Some(first))
    }
    fn account_is_active(&mut self, id: &str) -> Result<bool, StoreError> {
        Ok(self.data.accounts.get(id).copied().unwrap_or(false))
    }
    fn membership(&mut self, t: &str, s: &str) -> Result<Option<TenantMembership>, StoreError> {
        Ok(self
            .data
            .memberships
            .iter()
            .find(|m| m.tenant_id == t && m.subject_id == s)
            .cloned())
    }
    fn role(&mut self, t: &str, id: &str) -> Result<Option<AccessRoleRecord>, StoreError> {
        Ok(self
            .data
            .roles
            .iter()
            .find(|r| r.role.tenant_id == t && r.role.id == id)
            .cloned())
    }
    fn admin_roles(
        &mut self,
        tenant: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<Role>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .roles
            .iter()
            .map(|r| r.role.clone())
            .filter(|r| {
                r.tenant_id == tenant
                    && management_after(time_page_key(r.created_at, r.id.clone()), page)
            })
            .collect();
        sort_management(&mut rows, page, |r| {
            time_page_key(r.created_at, r.id.clone())
        });
        rows.truncate(page.fetch_limit());
        Ok(rows)
    }
    fn permission(
        &mut self,
        k: &PermissionKey,
    ) -> Result<Option<PermissionDefinition>, StoreError> {
        Ok(self.data.permissions.get(k).cloned())
    }
    fn tenant_permission(
        &mut self,
        tenant: &str,
        key: &PermissionKey,
    ) -> Result<Option<PermissionDefinition>, StoreError> {
        Ok(self.data.permissions.get(key).cloned().map(|mut p| {
            p.tenant_id = tenant.into();
            p
        }))
    }
    fn admin_permissions(
        &mut self,
        scope: &AdminPermissionScope,
        filter: &AdminPermissionFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<PermissionDefinition>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .permissions
            .values()
            .filter(|p| {
                scope.permits(self.data.mode, p.category)
                    && filter.matches(p)
                    && management_after(permission_page_key(p), page)
            })
            .cloned()
            .map(|mut p| {
                p.tenant_id = match scope {
                    AdminPermissionScope::Tenant(t) => t.clone(),
                    AdminPermissionScope::Platform => SYSTEM_TENANT_ID.into(),
                };
                p
            })
            .collect();
        sort_management(&mut rows, page, permission_page_key);
        rows.truncate(page.fetch_limit());
        Ok(rows)
    }
    fn binding(&mut self, t: &str, id: &str) -> Result<Option<RoleBinding>, StoreError> {
        Ok(self
            .data
            .bindings
            .iter()
            .find(|b| b.tenant_id == t && b.id == id)
            .cloned())
    }
    fn admin_role_bindings(
        &mut self,
        tenant: &str,
        subject: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<RoleBinding>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .bindings
            .iter()
            .filter(|b| {
                b.tenant_id == tenant
                    && b.subject_id == subject
                    && management_after(time_page_key(b.created_at, b.id.clone()), page)
            })
            .cloned()
            .collect();
        sort_management(&mut rows, page, |b| {
            time_page_key(b.created_at, b.id.clone())
        });
        rows.truncate(page.fetch_limit());
        Ok(rows)
    }
    fn security_role(
        &mut self,
        t: &str,
        k: RoleKind,
    ) -> Result<Option<AccessRoleRecord>, StoreError> {
        Ok(self
            .data
            .roles
            .iter()
            .find(|r| r.role.tenant_id == t && r.role.kind == k)
            .cloned())
    }
    fn security_binding(
        &mut self,
        t: &str,
        s: &str,
        r: &str,
    ) -> Result<Option<RoleBinding>, StoreError> {
        Ok(self
            .data
            .bindings
            .iter()
            .find(|b| b.tenant_id == t && b.subject_id == s && b.role_id == r)
            .cloned())
    }
    fn apply_change(&mut self, c: &AccessChange, _: SystemTime) -> Result<(), StoreError> {
        match c {
            AccessChange::PermissionChecked { .. }
            | AccessChange::Client { .. }
            | AccessChange::AccountCreated { .. }
            | AccessChange::AccountSecurity { .. } => {
                unreachable!("client writes use their secret-bearing primitive")
            }
            AccessChange::Session { before, after } => {
                *self
                    .data
                    .admin_sessions
                    .iter_mut()
                    .find(|s| s.tenant_id == before.tenant_id && s.id == before.id)
                    .unwrap() = after.clone();
            }
            AccessChange::SubjectSessionsRevoked {
                tenant_id,
                subject_id,
                ..
            } => {
                for s in &mut self.data.admin_sessions {
                    if s.tenant_id == *tenant_id
                        && s.account_id == *subject_id
                        && matches!(
                            s.status,
                            crate::SessionStatus::Active | crate::SessionStatus::Pending
                        )
                    {
                        s.status = crate::SessionStatus::Revoked;
                    }
                }
            }
            AccessChange::Device { before, after } => {
                let row = self
                    .data
                    .devices
                    .iter_mut()
                    .find(|r| {
                        r.device.id == before.device.id
                            && r.device.tenant_id == before.device.tenant_id
                    })
                    .unwrap();
                *row = after.clone();
            }
            AccessChange::TenantCreated {
                record,
                administrator,
                permission_definitions,
                role,
                binding,
            } => {
                if self.data.tenants.contains_key(&record.tenant.id)
                    || self
                        .data
                        .roles
                        .iter()
                        .any(|current| current.role.id == role.role.id)
                    || self
                        .data
                        .bindings
                        .iter()
                        .any(|current| current.id == binding.id)
                {
                    return Err(StoreError::Conflict("tenant.exists"));
                }
                self.data
                    .tenants
                    .insert(record.tenant.id.clone(), record.tenant.clone());
                self.data
                    .tenant_versions
                    .insert(record.tenant.id.clone(), record.version);
                self.data.memberships.push(administrator.clone());
                for permission in permission_definitions {
                    self.data
                        .permissions
                        .insert(permission.key.clone(), permission.clone());
                }
                self.data.roles.push(role.clone());
                self.data.bindings.push(binding.clone());
            }
            AccessChange::Tenant { before, after } => {
                let current = self.data.tenants.get(&before.tenant.id).cloned();
                if current.as_ref() != Some(&before.tenant)
                    || self.data.tenant_versions.get(&before.tenant.id).copied()
                        != Some(before.version)
                {
                    return Err(StoreError::Conflict("tenant.version"));
                }
                self.data
                    .tenants
                    .insert(after.tenant.id.clone(), after.tenant.clone());
                self.data
                    .tenant_versions
                    .insert(after.tenant.id.clone(), after.version);
            }
            AccessChange::Catalog { changes } => {
                for change in changes {
                    if let Some(before) = &change.before {
                        if self.data.permissions.get(&before.key) != Some(before) {
                            return Err(StoreError::Conflict("permission.version"));
                        }
                    }
                    self.data
                        .permissions
                        .insert(change.after.key.clone(), change.after.clone());
                }
            }
            AccessChange::Role { before, after } => {
                if let Some(b) = before {
                    if !self.data.roles.contains(b) {
                        return Err(StoreError::Conflict("role.version"));
                    }
                    self.data
                        .roles
                        .retain(|r| r.role.tenant_id != b.role.tenant_id || r.role.id != b.role.id);
                    self.data.bindings.retain(|x| {
                        x.tenant_id != b.role.tenant_id
                            || x.role_id != b.role.id
                            || after.as_ref().is_some_and(|a| {
                                a.permissions
                                    .iter()
                                    .any(|p| p.resource_type == x.resource_type)
                            })
                    });
                }
                if let Some(a) = after {
                    if self.data.roles.iter().any(|r| {
                        r.role.tenant_id == a.role.tenant_id
                            && (r.role.id == a.role.id || r.role.key == a.role.key)
                    }) {
                        return Err(StoreError::Conflict("role.key"));
                    }
                    self.data.roles.push(a.clone());
                }
            }
            AccessChange::Binding { before, after } => {
                if let Some(b) = before {
                    if !self.data.bindings.contains(b) {
                        return Err(StoreError::Conflict("binding"));
                    }
                    self.data.bindings.retain(|x| x.id != b.id);
                }
                if let Some(a) = after {
                    if self.data.bindings.iter().any(|b| {
                        b.id == a.id
                            || (b.tenant_id == a.tenant_id
                                && b.subject_id == a.subject_id
                                && b.role_id == a.role_id
                                && b.resource_type == a.resource_type
                                && b.scope == a.scope)
                    }) {
                        return Err(StoreError::Conflict("binding"));
                    }
                    self.data.bindings.push(a.clone());
                }
            }
            AccessChange::Membership { before, after } => {
                let current =
                    self.data.memberships.iter().find(|m| {
                        m.tenant_id == after.tenant_id && m.subject_id == after.subject_id
                    });
                if current != before.as_ref() {
                    return Err(StoreError::Conflict("membership.version"));
                }
                self.data
                    .memberships
                    .retain(|m| m.tenant_id != after.tenant_id || m.subject_id != after.subject_id);
                self.data.memberships.push(after.clone());
                if after.status != MembershipStatus::Active {
                    for (t, s, active) in self.data.sessions.values_mut() {
                        if t == &after.tenant_id && s == &after.subject_id {
                            *active = false;
                        }
                    }
                }
                if after.status == MembershipStatus::Removed {
                    self.data.bindings.retain(|b| {
                        !(b.tenant_id == after.tenant_id && b.subject_id == after.subject_id)
                    });
                }
            }
        }
        Ok(())
    }
    fn has_non_removed_membership(&mut self, s: &str) -> Result<bool, StoreError> {
        Ok(self
            .data
            .memberships
            .iter()
            .any(|m| m.subject_id == s && m.status != MembershipStatus::Removed))
    }
    fn has_effective_security_admin(
        &mut self,
        t: &str,
        kind: RoleKind,
    ) -> Result<bool, StoreError> {
        let resource = if kind == RoleKind::SystemAdmin {
            "idp.platform"
        } else {
            "idp.tenant"
        };
        let required: Vec<_> = catalog()
            .0
            .definitions()
            .filter(|p| p.key.resource_type == resource)
            .cloned()
            .collect();
        Ok(self.data.roles.iter().any(|r| {
            r.role.tenant_id == t
                && r.role.kind == kind
                && r.role.status == RoleStatus::Active
                && r.permissions.len() == required.len()
                && required.iter().all(|p| {
                    r.permissions.contains(&p.key)
                        && self.data.permissions.get(&p.key).is_some_and(|current| {
                            current.enabled && current.category == p.category
                        })
                })
                && self.data.bindings.iter().any(|b| {
                    b.tenant_id == t
                        && b.role_id == r.role.id
                        && b.resource_type == resource
                        && b.scope == ResourceScope::Type
                        && self.data.accounts.get(&b.subject_id) == Some(&true)
                        && self.data.memberships.iter().any(|m| {
                            m.tenant_id == t
                                && m.subject_id == b.subject_id
                                && m.status == MembershipStatus::Active
                        })
                })
        }))
    }
    fn admin_audit_events(
        &mut self,
        tenant: &str,
        filter: &AdminAuditFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AdminAuditRecord>, StoreError> {
        let mut rows: Vec<_> = self
            .data
            .audits
            .iter()
            .map(audit_metadata)
            .filter(|r| {
                r.target_domain == tenant
                    && filter.matches(r)
                    && management_after(r.page_key(), page)
            })
            .collect();
        sort_management(&mut rows, page, AdminAuditRecord::page_key);
        rows.truncate(page.fetch_limit());
        Ok(rows)
    }
    fn admin_audit_event(
        &mut self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<AdminAuditDetail>, StoreError> {
        Ok(self
            .data
            .audits
            .iter()
            .find(|e| e.tenant_id == tenant && e.id == id)
            .map(|e| AdminAuditDetail {
                event: audit_metadata(e),
                change_json: "{}".into(),
            }))
    }
    fn append_audit(&mut self, e: &AccessAuditEvent) -> Result<(), StoreError> {
        if self.data.fail_audit {
            return Err(StoreError::Backend("audit".into()));
        }
        if self.data.audits.iter().any(|a| a.id == e.id) {
            return Err(StoreError::Conflict("audit.id"));
        }
        self.data.audits.push(e.clone());
        Ok(())
    }
}

#[test]
fn role_crud_permissions_binding_and_cleanup() {
    let store = seeded();
    let (svc, store) = service(store);
    let e = svc
        .execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::CreateRole {
                    key: "reader".into(),
                    name: "Reader".into(),
                },
            ),
        )
        .unwrap();
    let id = match e.change {
        AccessChange::Role { after: Some(a), .. } => a.role.id,
        _ => panic!(),
    };
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::ReplaceRolePermissions {
                role_id: id.clone(),
                permissions: vec![report()],
                expected_version: 1,
            },
        ),
    )
    .unwrap();
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::GrantRole {
                subject_id: "u2".into(),
                role_id: id.clone(),
                resource_type: "report".into(),
                scope: ResourceScope::Type,
            },
        ),
    )
    .unwrap();
    assert_eq!(
        store
            .0
            .lock()
            .unwrap()
            .bindings
            .iter()
            .filter(|b| b.role_id == id)
            .count(),
        1
    );
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::DeleteRole {
                role_id: id.clone(),
                expected_version: 2,
            },
        ),
    )
    .unwrap();
    assert!(store
        .0
        .lock()
        .unwrap()
        .bindings
        .iter()
        .all(|b| b.role_id != id));
}
#[test]
fn rejects_invalid_session_cross_domain_version_and_permissions() {
    let store = seeded();
    let (svc, store) = service(store);
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "bad"),
            command(
                "t1",
                AccessAdminMutation::CreateRole {
                    key: "x".into(),
                    name: "X".into()
                }
            )
        ),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t2",
                AccessAdminMutation::CreateRole {
                    key: "x".into(),
                    name: "X".into()
                }
            )
        ),
        Err(AccessError::Forbidden)
    );
    let id = svc
        .execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::CreateRole {
                    key: "x".into(),
                    name: "X".into(),
                },
            ),
        )
        .unwrap();
    let id = match id.change {
        AccessChange::Role { after: Some(a), .. } => a.role.id,
        _ => panic!(),
    };
    assert!(matches!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::ReplaceRolePermissions {
                    role_id: id.clone(),
                    permissions: vec![key("unknown", "read")],
                    expected_version: 1
                }
            )
        ),
        Err(AccessError::InvalidInput("unknown_permission"))
    ));
    assert!(matches!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::UpdateRole {
                    role_id: id,
                    name: "Y".into(),
                    status: RoleStatus::Active,
                    expected_version: 9
                }
            )
        ),
        Err(AccessError::Conflict("version"))
    ));
    assert!(store.0.lock().unwrap().audits.len() >= 1);
}
#[test]
fn protected_roles_only_security_path_and_last_admin_rollback() {
    let store = seeded();
    let (svc, store) = service(store);
    assert_eq!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "0",
                AccessAdminMutation::UpdateRole {
                    role_id: "sys".into(),
                    name: "x".into(),
                    status: RoleStatus::Active,
                    expected_version: 1
                }
            )
        ),
        Err(AccessError::Forbidden)
    );
    assert!(svc
        .execute(
            ctx("0", "u1", "s0"),
            command(
                "t1",
                AccessAdminMutation::SetSecurityAdmin {
                    subject_id: "u2".into(),
                    appointed: true
                }
            )
        )
        .is_ok());
    assert!(svc
        .execute(
            ctx("0", "u1", "s0"),
            command(
                "t1",
                AccessAdminMutation::SetSecurityAdmin {
                    subject_id: "u2".into(),
                    appointed: false,
                },
            ),
        )
        .is_ok());
    assert!(matches!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "t1",
                AccessAdminMutation::SetSecurityAdmin {
                    subject_id: "u1".into(),
                    appointed: false
                }
            )
        ),
        Err(AccessError::Conflict("last_security_admin"))
    ));
    assert!(store
        .0
        .lock()
        .unwrap()
        .bindings
        .iter()
        .any(|b| b.id == "bsec1"));
}

#[test]
fn tenant_creation_requires_platform_capabilities_and_is_atomic() {
    for action in ["tenants.manage", "users.bind", "access.manage"] {
        let (svc, store) = service(seeded());
        store
            .0
            .lock()
            .unwrap()
            .permissions
            .get_mut(&key("idp.platform", action))
            .unwrap()
            .enabled = false;
        assert_eq!(
            svc.execute(
                ctx("0", "u1", "s0"),
                command(
                    "t3",
                    AccessAdminMutation::CreateTenant {
                        name: "Tenant 3".into(),
                        allow_registration: true,
                        administrator_subject_id: "u2".into(),
                    }
                )
            ),
            Err(AccessError::Forbidden)
        );
        assert!(!store.0.lock().unwrap().tenants.contains_key("t3"));
    }
    let (svc, store) = service(seeded());
    let event = svc
        .execute(
            ctx("0", "u1", "s0"),
            command(
                "t3",
                AccessAdminMutation::CreateTenant {
                    name: "Tenant 3".into(),
                    allow_registration: true,
                    administrator_subject_id: "u2".into(),
                },
            ),
        )
        .unwrap();
    assert!(matches!(event.change, AccessChange::TenantCreated { .. }));
    let data = store.0.lock().unwrap();
    assert_eq!(data.tenants["t3"].status, TenantStatus::Active);
    assert_eq!(data.tenant_versions["t3"], 1);
    assert!(data
        .memberships
        .iter()
        .any(|m| m.tenant_id == "t3" && m.subject_id == "u2"));
    assert!(data
        .roles
        .iter()
        .any(|r| r.role.tenant_id == "t3" && r.role.kind == RoleKind::TenantSecurityAdmin));
    assert!(data
        .bindings
        .iter()
        .any(|b| b.tenant_id == "t3" && b.subject_id == "u2"));

    let disabled = seeded();
    disabled.0.lock().unwrap().mode = TenancyMode::Disabled;
    let (catalog, _) = catalog();
    let disabled_service =
        CoreAccessAdminService::new(TenancyMode::Disabled, catalog, disabled, FixedClock, SeqIds);
    assert_eq!(
        disabled_service.execute(
            ctx("0", "u1", "s0"),
            command(
                "t3",
                AccessAdminMutation::CreateTenant {
                    name: "Tenant 3".into(),
                    allow_registration: true,
                    administrator_subject_id: "u2".into(),
                }
            ),
        ),
        Err(AccessError::FeatureDisabled)
    );

    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t3",
                AccessAdminMutation::CreateTenant {
                    name: "Tenant 4".into(),
                    allow_registration: true,
                    administrator_subject_id: "u2".into(),
                }
            ),
        ),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "0",
                AccessAdminMutation::CreateTenant {
                    name: "System".into(),
                    allow_registration: true,
                    administrator_subject_id: "u2".into(),
                }
            ),
        ),
        Err(AccessError::ModeMismatch)
    );
}

#[test]
fn tenant_update_version_and_last_admin_failure_roll_back() {
    let (svc, store) = service(seeded());
    svc.execute(
        ctx("0", "u1", "s0"),
        command(
            "t3",
            AccessAdminMutation::CreateTenant {
                name: "Tenant 3".into(),
                allow_registration: true,
                administrator_subject_id: "u2".into(),
            },
        ),
    )
    .unwrap();
    svc.execute(
        ctx("0", "u1", "s0"),
        command(
            "t3",
            AccessAdminMutation::UpdateTenant {
                name: "Suspended".into(),
                status: TenantStatus::Suspended,
                allow_registration: false,
                expected_version: 1,
            },
        ),
    )
    .unwrap();
    {
        let mut data = store.0.lock().unwrap();
        data.bindings.retain(|b| b.tenant_id != "t3");
    }
    assert_eq!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "t3",
                AccessAdminMutation::UpdateTenant {
                    name: "Active again".into(),
                    status: TenantStatus::Active,
                    allow_registration: true,
                    expected_version: 2,
                }
            ),
        ),
        Err(AccessError::Conflict("last_security_admin"))
    );
    let data = store.0.lock().unwrap();
    assert_eq!(data.tenants["t3"].status, TenantStatus::Suspended);
    assert_eq!(data.tenant_versions["t3"], 2);
}

#[test]
fn tenant_creation_audit_failure_rolls_back_everything() {
    let store = seeded();
    store.0.lock().unwrap().fail_audit = true;
    let (svc, store) = service(store);
    assert!(matches!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "t3",
                AccessAdminMutation::CreateTenant {
                    name: "Tenant 3".into(),
                    allow_registration: true,
                    administrator_subject_id: "u2".into(),
                }
            ),
        ),
        Err(AccessError::Store(StoreError::Backend(_)))
    ));
    let data = store.0.lock().unwrap();
    assert!(!data.tenants.contains_key("t3"));
    assert!(data.memberships.iter().all(|m| m.tenant_id != "t3"));
    assert!(data.roles.iter().all(|r| r.role.tenant_id != "t3"));
    assert!(data.bindings.iter().all(|b| b.tenant_id != "t3"));
}

#[test]
fn catalog_sync_preserves_omitted_and_enabled_state_and_checks_categories() {
    let store = seeded();
    {
        let mut data = store.0.lock().unwrap();
        let permission = data.permissions.get_mut(&report()).unwrap();
        permission.enabled = false;
        permission.description = "Tenant-specific report meaning".into();
    }
    let (svc, store) = service(store);
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::SyncPermissions {
                permissions: vec![report()],
            },
        ),
    )
    .unwrap();
    assert!(!store.0.lock().unwrap().permissions[&report()].enabled);
    assert_eq!(
        store.0.lock().unwrap().permissions[&report()].description,
        "Tenant-specific report meaning"
    );

    assert!(matches!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::SyncPermissions {
                    permissions: vec![key("unknown", "read")]
                }
            ),
        ),
        Err(AccessError::InvalidInput("unknown_permission"))
    ));
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&report())
        .unwrap()
        .category = PermissionCategory::Tenant;
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::SyncPermissions {
                    permissions: vec![report()]
                }
            ),
        ),
        Err(AccessError::Conflict("permission_category"))
    );
}

#[test]
fn permission_enable_changes_are_business_only_and_compare_expected_state() {
    let (svc, _) = service(seeded());
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::SetPermissionEnabled {
                    permission: key("idp.platform", "access.manage"),
                    enabled: false,
                    expected_enabled: true,
                }
            ),
        ),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::SetPermissionEnabled {
                    permission: report(),
                    enabled: false,
                    expected_enabled: false,
                }
            ),
        ),
        Err(AccessError::Conflict("permission_enabled"))
    );
}

#[test]
fn manually_created_permission_is_versioned_and_archive_is_terminal() {
    let (svc, _) = service(seeded());
    let invoice = key("invoice", "read");
    let create = || {
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::CreatePermission {
                    key: invoice.clone(),
                    description: "Read invoices".into(),
                },
            ),
        )
    };
    create().unwrap();
    let initial = svc
        .get_permission(ctx("t1", "u1", "s1"), "t1".into(), invoice.clone())
        .unwrap();
    assert_eq!(initial.version, 1);
    assert_eq!(initial.description, "Read invoices");
    assert_eq!(create(), Err(AccessError::Conflict("permission_exists")));
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::UpdatePermission {
                    key: invoice.clone(),
                    description: "Updated".into(),
                    expected_version: 2,
                }
            )
        ),
        Err(AccessError::Conflict("version"))
    );
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::UpdatePermission {
                key: invoice.clone(),
                description: "Updated".into(),
                expected_version: 1,
            },
        ),
    )
    .unwrap();
    let updated = svc
        .get_permission(ctx("t1", "u1", "s1"), "t1".into(), invoice.clone())
        .unwrap();
    assert_eq!(updated.version, 2);
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::ArchivePermission {
                key: invoice.clone(),
                expected_version: 2,
            },
        ),
    )
    .unwrap();
    let archived = svc
        .get_permission(ctx("t1", "u1", "s1"), "t1".into(), invoice.clone())
        .unwrap();
    assert!(archived.archived);
    assert!(!archived.enabled);
    assert_eq!(archived.version, 3);
    assert_eq!(create(), Err(AccessError::Conflict("permission_exists")));
}

#[test]
fn removal_rejoin_has_no_old_grant() {
    let store = seeded();
    let (svc, store) = service(store);
    let id = svc
        .execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::CreateRole {
                    key: "r".into(),
                    name: "R".into(),
                },
            ),
        )
        .unwrap();
    let id = match id.change {
        AccessChange::Role { after: Some(a), .. } => a.role.id,
        _ => panic!(),
    };
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::ReplaceRolePermissions {
                role_id: id.clone(),
                permissions: vec![report()],
                expected_version: 1,
            },
        ),
    )
    .unwrap();
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::GrantRole {
                subject_id: "u2".into(),
                role_id: id,
                resource_type: "report".into(),
                scope: ResourceScope::Type,
            },
        ),
    )
    .unwrap();
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::SetMemberStatus {
                subject_id: "u2".into(),
                status: MembershipStatus::Removed,
                expected_version: 1,
            },
        ),
    )
    .unwrap();
    assert!(store
        .0
        .lock()
        .unwrap()
        .bindings
        .iter()
        .all(|b| b.subject_id != "u2" || b.tenant_id != "t1"));
    svc.execute(
        ctx("0", "u1", "s0"),
        command(
            "t1",
            AccessAdminMutation::BindMember {
                subject_id: "u2".into(),
            },
        ),
    )
    .unwrap();
    assert!(store
        .0
        .lock()
        .unwrap()
        .bindings
        .iter()
        .all(|b| b.subject_id != "u2" || b.tenant_id != "t1"));
    svc.execute(
        ctx("t2", "u1", "s3"),
        command(
            "t2",
            AccessAdminMutation::SetMemberStatus {
                subject_id: "u2".into(),
                status: MembershipStatus::Removed,
                expected_version: 1,
            },
        ),
    )
    .unwrap();
    assert!(store
        .0
        .lock()
        .unwrap()
        .memberships
        .iter()
        .any(|m| m.tenant_id == "t2"
            && m.subject_id == "u2"
            && m.status == MembershipStatus::Removed));
}
#[test]
fn audit_failure_and_transaction_time_revocation_rollback() {
    let store = seeded();
    let (svc, store) = service(store.clone());
    store.0.lock().unwrap().fail_audit = true;
    assert!(matches!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::CreateRole {
                    key: "x".into(),
                    name: "X".into()
                }
            )
        ),
        Err(AccessError::Store(StoreError::Backend(_)))
    ));
    assert!(store
        .0
        .lock()
        .unwrap()
        .roles
        .iter()
        .all(|r| r.role.key != "x"));
    store.0.lock().unwrap().fail_audit = false;
    store.0.lock().unwrap().revoke_before_permission = true;
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::CreateRole {
                    key: "y".into(),
                    name: "Y".into()
                }
            )
        ),
        Err(AccessError::Forbidden)
    );
}
#[test]
fn disabled_mode_keeps_role_management_but_disables_member_management() {
    let store = seeded();
    store.0.lock().unwrap().mode = TenancyMode::Disabled;
    let (c, _) = catalog();
    let svc =
        CoreAccessAdminService::new(TenancyMode::Disabled, c, store.clone(), FixedClock, SeqIds);
    assert!(matches!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "0",
                AccessAdminMutation::CreateRole {
                    key: "local".into(),
                    name: "Local".into()
                }
            )
        ),
        Ok(_)
    ));
    assert!(matches!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "0",
                AccessAdminMutation::BindMember {
                    subject_id: "u3".into()
                }
            )
        ),
        Err(AccessError::FeatureDisabled)
    ));
}

fn seed_business(store: &Store, tenant: &str) {
    let mut d = store.0.lock().unwrap();
    d.roles
        .push(role("reader", tenant, RoleKind::Business, vec![report()]));
    d.bindings.push(binding(
        &format!("reader-{tenant}"),
        tenant,
        "u2",
        "reader",
        "report",
    ));
}

#[test]
fn role_updates_preserve_scope_and_removing_last_permission_cannot_revive_bindings() {
    let (svc, store) = service(seeded());
    seed_business(&store, "t1");
    seed_business(&store, "t2"); // Same role ID, independent tenant.
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::UpdateRole {
                role_id: "reader".into(),
                name: "Renamed".into(),
                status: RoleStatus::Disabled,
                expected_version: 1,
            },
        ),
    )
    .unwrap();
    assert!(store
        .0
        .lock()
        .unwrap()
        .bindings
        .iter()
        .any(|b| b.id == "reader-t1"));
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::ReplaceRolePermissions {
                role_id: "reader".into(),
                permissions: vec![],
                expected_version: 2,
            },
        ),
    )
    .unwrap();
    svc.execute(
        ctx("t1", "u1", "s1"),
        command(
            "t1",
            AccessAdminMutation::ReplaceRolePermissions {
                role_id: "reader".into(),
                permissions: vec![report()],
                expected_version: 3,
            },
        ),
    )
    .unwrap();
    let d = store.0.lock().unwrap();
    assert!(!d.bindings.iter().any(|b| b.id == "reader-t1"));
    assert!(d.bindings.iter().any(|b| b.id == "reader-t2"));
    assert_eq!(
        d.roles
            .iter()
            .find(|r| r.role.tenant_id == "t2" && r.role.id == "reader")
            .unwrap()
            .role
            .version,
        1
    );
}

#[test]
fn permission_and_assignment_validation_cannot_escalate_or_implicitly_bind() {
    let (svc, store) = service(seeded());
    seed_business(&store, "t1");
    for permissions in [
        vec![key("idp.tenant", "roles.manage")],
        vec![report(), report()],
        vec![report(); MAX_ROLE_PERMISSIONS + 1],
    ] {
        assert!(svc
            .execute(
                ctx("t1", "u1", "s1"),
                command(
                    "t1",
                    AccessAdminMutation::ReplaceRolePermissions {
                        role_id: "reader".into(),
                        permissions,
                        expected_version: 1,
                    }
                )
            )
            .is_err());
    }
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&report())
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::ReplaceRolePermissions {
                    role_id: "reader".into(),
                    permissions: vec![report()],
                    expected_version: 1,
                }
            )
        ),
        Err(AccessError::InvalidInput("disabled_permission"))
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&report())
        .unwrap()
        .enabled = true;
    for (subject, resource, scope) in [
        ("u3", "report", ResourceScope::Type),
        ("u2", "dataset", ResourceScope::Type),
        ("u2", "report", ResourceScope::Instance(String::new())),
    ] {
        assert!(svc
            .execute(
                ctx("t1", "u1", "s1"),
                command(
                    "t1",
                    AccessAdminMutation::GrantRole {
                        subject_id: subject.into(),
                        role_id: "reader".into(),
                        resource_type: resource.into(),
                        scope,
                    }
                )
            )
            .is_err());
    }
    for mutation in [
        AccessAdminMutation::BindMember {
            subject_id: "u3".into(),
        },
        AccessAdminMutation::SetSecurityAdmin {
            subject_id: "u2".into(),
            appointed: true,
        },
    ] {
        assert_eq!(
            svc.execute(ctx("t1", "u1", "s1"), command("t1", mutation)),
            Err(AccessError::Forbidden)
        );
    }
    assert!(store.0.lock().unwrap().audits.is_empty());
    let event = svc
        .execute(
            ctx("0", "u1", "s0"),
            command(
                "t1",
                AccessAdminMutation::BindMember {
                    subject_id: "u3".into(),
                },
            ),
        )
        .unwrap();
    assert_eq!(event.occurred_at, FixedClock.now());
    assert_eq!(
        event.context.authentication_source,
        ctx("0", "u1", "s0").authentication_source
    );
    assert!(matches!(
        event.change,
        AccessChange::Membership {
            before: None,
            after: TenantMembership { version: 1, .. }
        }
    ));
}

#[test]
fn concurrent_writers_preserve_last_membership_and_reject_stale_role_version() {
    // These races prove Core + serial transaction semantics, not real SQL locking.
    let (svc, store) = service(seeded());
    let barrier = std::sync::Barrier::new(3);
    let results = std::thread::scope(|threads| {
        let handles: Vec<_> = [("t1", "s1"), ("t2", "s3")]
            .into_iter()
            .map(|(tenant, session)| {
                let svc = &svc;
                let barrier = &barrier;
                threads.spawn(move || {
                    barrier.wait();
                    svc.execute(
                        ctx(tenant, "u1", session),
                        command(
                            tenant,
                            AccessAdminMutation::SetMemberStatus {
                                subject_id: "u2".into(),
                                status: MembershipStatus::Removed,
                                expected_version: 1,
                            },
                        ),
                    )
                })
            })
            .collect();
        barrier.wait();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(AccessError::Conflict("last_membership")))
            .count(),
        1
    );
    assert_eq!(
        store
            .0
            .lock()
            .unwrap()
            .memberships
            .iter()
            .filter(|m| m.subject_id == "u2" && m.status != MembershipStatus::Removed)
            .count(),
        1
    );
    assert_eq!(store.0.lock().unwrap().audits.len(), 1);

    let (svc, store) = service(seeded());
    seed_business(&store, "t1");
    let results = std::thread::scope(|threads| {
        let handles: Vec<_> = ["First", "Second"]
            .into_iter()
            .map(|name| {
                let svc = &svc;
                let barrier = &barrier;
                threads.spawn(move || {
                    barrier.wait();
                    svc.execute(
                        ctx("t1", "u1", "s1"),
                        command(
                            "t1",
                            AccessAdminMutation::UpdateRole {
                                role_id: "reader".into(),
                                name: name.into(),
                                status: RoleStatus::Active,
                                expected_version: 1,
                            },
                        ),
                    )
                })
            })
            .collect();
        barrier.wait();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(AccessError::Conflict("version")))
            .count(),
        1
    );
}

#[test]
fn platform_and_tenant_last_admin_checks_count_only_effective_grants() {
    let (svc, store) = service(seeded());
    for tenant in ["0", "t1"] {
        assert_eq!(
            svc.execute(
                ctx("0", "u1", "s0"),
                command(
                    tenant,
                    AccessAdminMutation::SetSecurityAdmin {
                        subject_id: "u1".into(),
                        appointed: false,
                    }
                )
            ),
            Err(AccessError::Conflict("last_security_admin"))
        );
    }
    svc.execute(
        ctx("0", "u1", "s0"),
        command(
            "t1",
            AccessAdminMutation::SetSecurityAdmin {
                subject_id: "u2".into(),
                appointed: true,
            },
        ),
    )
    .unwrap();
    store.0.lock().unwrap().accounts.insert("u2".into(), false);
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::SetMemberStatus {
                    subject_id: "u1".into(),
                    status: MembershipStatus::Suspended,
                    expected_version: 1,
                }
            )
        ),
        Err(AccessError::Conflict("last_security_admin"))
    );
    assert!(store
        .0
        .lock()
        .unwrap()
        .memberships
        .iter()
        .any(|m| m.tenant_id == "t1"
            && m.subject_id == "u1"
            && m.status == MembershipStatus::Active));
    assert_eq!(store.0.lock().unwrap().audits.len(), 1);
}

#[test]
fn audit_failure_rolls_back_cleanup_and_suspension_never_restores_a_session() {
    let (svc, store) = service(seeded());
    seed_business(&store, "t1");
    store
        .0
        .lock()
        .unwrap()
        .sessions
        .insert("user-session".into(), ("t1".into(), "u2".into(), true));
    store.0.lock().unwrap().fail_audit = true;
    assert!(svc
        .execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::SetMemberStatus {
                    subject_id: "u2".into(),
                    status: MembershipStatus::Removed,
                    expected_version: 1,
                }
            )
        )
        .is_err());
    {
        let d = store.0.lock().unwrap();
        assert!(d.bindings.iter().any(|b| b.id == "reader-t1"));
        assert!(d.sessions["user-session"].2);
        assert!(d.audits.is_empty());
    }
    store.0.lock().unwrap().fail_audit = false;
    for (status, version) in [
        (MembershipStatus::Suspended, 1),
        (MembershipStatus::Active, 2),
    ] {
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::SetMemberStatus {
                    subject_id: "u2".into(),
                    status,
                    expected_version: version,
                },
            ),
        )
        .unwrap();
    }
    let d = store.0.lock().unwrap();
    assert!(!d.sessions["user-session"].2);
    assert!(d.bindings.iter().any(|b| b.id == "reader-t1"));
}

#[test]
fn actor_expiry_is_checked_after_lock_wait_and_mode_mismatch_never_writes() {
    struct MovingClock(Arc<AtomicU64>);
    impl Clock for MovingClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::SeqCst))
        }
    }
    let store = seeded();
    let ticks = Arc::new(AtomicU64::new(1000));
    store.0.lock().unwrap().lock_clock = Some(ticks.clone());
    let svc = CoreAccessAdminService::new(
        TenancyMode::Enabled,
        catalog().0,
        store.clone(),
        MovingClock(ticks.clone()),
        SeqIds,
    );
    let create = || {
        command(
            "t1",
            AccessAdminMutation::CreateRole {
                key: "x".into(),
                name: "X".into(),
            },
        )
    };
    assert_eq!(
        svc.execute(ctx("t1", "u1", "s1"), create()),
        Err(AccessError::Forbidden)
    );
    assert!(store.0.lock().unwrap().audits.is_empty());
    ticks.store(1000, Ordering::SeqCst);
    assert_eq!(
        svc.diagnose_permission(
            ctx("t1", "u1", "s1"),
            AccessQuery {
                tenant_id: "t1".into(),
                subject_id: "u2".into(),
                resource_type: "report".into(),
                action: "read".into(),
                resource_id: None,
            }
        ),
        Err(AccessError::Forbidden)
    );
    assert!(store.0.lock().unwrap().audits.is_empty());
    store.0.lock().unwrap().mode = TenancyMode::Disabled;
    assert_eq!(
        svc.execute(ctx("t1", "u1", "s1"), create()),
        Err(AccessError::ModeMismatch)
    );
}

#[test]
fn binding_revocation_is_tenant_scoped_and_platform_can_clean_inactive_tenants() {
    let (svc, store) = service(seeded());
    seed_business(&store, "t1");
    assert_eq!(
        svc.execute(
            ctx("0", "u1", "s0"),
            command(
                "t2",
                AccessAdminMutation::RevokeRole {
                    binding_id: "reader-t1".into()
                }
            )
        ),
        Err(AccessError::NotFound("binding"))
    );
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::RevokeRole {
                    binding_id: "bsec1".into()
                }
            )
        ),
        Err(AccessError::Forbidden)
    );
    store
        .0
        .lock()
        .unwrap()
        .tenants
        .get_mut("t1")
        .unwrap()
        .status = TenantStatus::Suspended;
    let grant = || {
        command(
            "t1",
            AccessAdminMutation::GrantRole {
                subject_id: "u2".into(),
                role_id: "reader".into(),
                resource_type: "report".into(),
                scope: ResourceScope::Instance("r2".into()),
            },
        )
    };
    assert_eq!(
        svc.execute(ctx("0", "u1", "s0"), grant()),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            command(
                "t1",
                AccessAdminMutation::RevokeRole {
                    binding_id: "reader-t1".into()
                }
            )
        ),
        Err(AccessError::Forbidden)
    );
    svc.execute(
        ctx("0", "u1", "s0"),
        command(
            "t1",
            AccessAdminMutation::RevokeRole {
                binding_id: "reader-t1".into(),
            },
        ),
    )
    .unwrap();
    let d = store.0.lock().unwrap();
    assert!(!d.bindings.iter().any(|b| b.id == "reader-t1"));
    assert_eq!(d.audits.len(), 1);
}

#[test]
fn device_admin_requires_current_permission_and_audits_terminal_state_changes_atomically() {
    use crate::DeviceStatus;
    let store = seeded();
    let id = uuid::Uuid::from_u128(1).to_string();
    let row = AccessDeviceRecord {
        device: TenantProofDevice {
            tenant_id: "t1".into(),
            id: id.clone(),
            client_id: "web".into(),
            proof_key_id: None,
            status: DeviceStatus::Active,
        },
        name: "Device".into(),
        registered_at: UNIX_EPOCH,
        last_seen_at: None,
    };
    store.0.lock().unwrap().devices.push(row.clone());
    let (svc, store) = service(store);
    let mutation = |status, expected_status| {
        command(
            "t1",
            AccessAdminMutation::SetDeviceStatus {
                device_id: id.clone(),
                status,
                expected_status,
            },
        )
    };
    assert_eq!(
        svc.get_device(ctx("t1", "u2", "s2"), "t1".into(), id.clone()),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.execute(
            ctx("t2", "u1", "s3"),
            mutation(DeviceStatus::Disabled, DeviceStatus::Active)
        ),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            mutation(DeviceStatus::Active, DeviceStatus::Active)
        ),
        Err(AccessError::InvalidInput("device_status"))
    );
    assert_eq!(
        svc.execute(
            ctx("t1", "u1", "s1"),
            mutation(DeviceStatus::Disabled, DeviceStatus::Pending)
        ),
        Err(AccessError::Conflict("device_status"))
    );
    store.0.lock().unwrap().fail_audit = true;
    assert!(svc
        .execute(
            ctx("t1", "u1", "s1"),
            mutation(DeviceStatus::Revoked, DeviceStatus::Active)
        )
        .is_err());
    assert_eq!(store.0.lock().unwrap().devices[0], row);
    assert!(store.0.lock().unwrap().audits.is_empty());
    store.0.lock().unwrap().fail_audit = false;
    let event = svc
        .execute(
            ctx("t1", "u1", "s1"),
            mutation(DeviceStatus::Disabled, DeviceStatus::Active),
        )
        .unwrap();
    assert_eq!(event.operation, "device.disable");
    assert_eq!(
        svc.get_device(ctx("0", "u1", "s0"), "t1".into(), id.clone())
            .unwrap()
            .device
            .status,
        DeviceStatus::Disabled
    );
    svc.execute(
        ctx("0", "u1", "s0"),
        mutation(DeviceStatus::Revoked, DeviceStatus::Disabled),
    )
    .unwrap();
    assert_eq!(
        svc.execute(
            ctx("0", "u1", "s0"),
            mutation(DeviceStatus::Disabled, DeviceStatus::Revoked)
        ),
        Err(AccessError::Conflict("device_status"))
    );
    store.0.lock().unwrap().session_expires_at = FixedClock.now();
    assert_eq!(
        svc.list_devices(
            ctx("0", "u1", "s0"),
            "t1".into(),
            AdminDeviceFilter::default(),
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
    assert_eq!(store.0.lock().unwrap().audits.len(), 2);
}

#[test]
fn session_admin_filters_bind_cursors_and_revocation_requires_permission_and_atomic_audit() {
    use crate::SessionStatus;
    let store = seeded();
    let record = TenantSession {
        purpose: crate::AccessTokenPurpose::Business,
        tenant_id: "t1".into(),
        id: uuid::Uuid::from_u128(1).to_string(),
        account_id: "u2".into(),
        client_id: "web".into(),
        device_id: None,
        scope: None,
        authenticated_at: UNIX_EPOCH,
        status: SessionStatus::Active,
        created_at: UNIX_EPOCH,
        expires_at: FixedClock.now(),
        refresh_token_version: 1,
    };
    let mut other = record.clone();
    other.id = uuid::Uuid::from_u128(2).to_string();
    store.0.lock().unwrap().admin_sessions = vec![record.clone(), other];
    let (svc, store) = service(store);
    let filter = AdminSessionFilter {
        account_id: Some("u2".into()),
        ..Default::default()
    };
    let page = svc
        .list_sessions(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            filter.clone(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert!(page.has_more);
    assert_eq!(
        svc.list_sessions(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            AdminSessionFilter::default(),
            AccessPageRequest {
                limit: 1,
                cursor: page.next_cursor,
                sort_order: None,
            }
        ),
        Err(AccessError::InvalidCursor)
    );
    assert_eq!(
        svc.get_session(ctx("t1", "u2", "s2"), "t1".into(), record.id.clone()),
        Err(AccessError::Forbidden)
    );
    let command = command(
        "t1",
        AccessAdminMutation::RevokeSubjectSessions {
            subject_id: "u2".into(),
        },
    );
    store.0.lock().unwrap().fail_audit = true;
    assert!(svc.execute(ctx("t1", "u1", "s1"), command.clone()).is_err());
    assert_eq!(
        store.0.lock().unwrap().admin_sessions[0].status,
        SessionStatus::Active
    );
    store.0.lock().unwrap().fail_audit = false;
    let event = svc.execute(ctx("0", "u1", "s0"), command).unwrap();
    assert!(matches!(
        event.change,
        AccessChange::SubjectSessionsRevoked {
            active_session_count: 2,
            ..
        }
    ));
    assert!(store
        .0
        .lock()
        .unwrap()
        .admin_sessions
        .iter()
        .all(|s| s.status == SessionStatus::Revoked));
    let invalid = AdminSessionFilter {
        created_after: Some(FixedClock.now()),
        created_before: Some(UNIX_EPOCH),
        ..Default::default()
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn client_admin_keeps_secrets_out_of_audit_and_requires_current_platform_authority() {
    use crate::{ClientSecretError, ClientSecretHasher, OidcClientType, SecretString};
    struct Hasher;
    impl ClientSecretHasher for Hasher {
        fn hash_client_secret(&self, raw: &str) -> Result<String, ClientSecretError> {
            Ok(format!("test-hash:{raw}"))
        }
    }
    let (admin, store) = service(seeded());
    let clients = CoreClientAdminService::new(admin, Hasher);
    let platform = ctx("0", "u1", "s0");
    let command = AdminUpsertClient {
        client_id: "web".into(),
        client_name: "Web".into(),
        redirect_uris: vec!["https://example.test/callback".into()],
        client_type: OidcClientType::ConfidentialWeb,
        pkce_required: true,
        client_secret: Some(SecretString::new("exact secret ")),
    };
    assert!(!format!("{command:?}").contains("exact secret"));
    assert_eq!(
        clients.upsert_client(ctx("t1", "u1", "s1"), command.clone()),
        Err(AccessError::Forbidden)
    );
    let event = clients
        .upsert_client(platform.clone(), command.clone())
        .unwrap();
    assert!(!format!("{event:?}").contains("exact secret"));
    assert!(matches!(
        event.change,
        AccessChange::Client {
            secret_changed: true,
            ..
        }
    ));
    let stored = store.0.lock().unwrap().clients[0].clone();
    assert_eq!(
        stored.client_secret_hash.as_deref(),
        Some("test-hash:exact secret ")
    );
    let mut edit = command.clone();
    edit.client_secret = None;
    edit.client_name = "Updated".into();
    assert!(matches!(
        clients
            .upsert_client(platform.clone(), edit.clone())
            .unwrap()
            .change,
        AccessChange::Client {
            secret_changed: false,
            ..
        }
    ));
    store.0.lock().unwrap().fail_audit = true;
    edit.client_secret = Some(SecretString::new("replacement"));
    assert!(clients
        .upsert_client(platform.clone(), edit.clone())
        .is_err());
    assert_eq!(
        store.0.lock().unwrap().clients[0].client_secret_hash,
        stored.client_secret_hash
    );
    store.0.lock().unwrap().fail_audit = false;
    edit.client_id = "z-web".into();
    clients.upsert_client(platform.clone(), edit).unwrap();
    let page = clients
        .list_clients(
            platform.clone(),
            AdminClientFilter::default(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert!(page.has_more);
    assert_eq!(
        clients.list_clients(
            platform.clone(),
            AdminClientFilter {
                pkce_required: Some(true),
                client_type: None
            },
            AccessPageRequest {
                limit: 1,
                cursor: page.next_cursor.clone(),
                sort_order: None,
            }
        ),
        Err(AccessError::InvalidCursor)
    );
    let next = clients
        .list_clients(
            platform.clone(),
            AdminClientFilter::default(),
            AccessPageRequest {
                limit: 1,
                cursor: page.next_cursor,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(next.items[0].client_id, "web");
    let mut public = command;
    public.client_type = OidcClientType::PublicDesktop;
    public.redirect_uris = vec!["http://127.0.0.1:4567/callback".into()];
    assert!(matches!(
        clients.upsert_client(platform.clone(), public.clone()),
        Err(AccessError::InvalidInput("client_secret"))
    ));
    public.client_secret = None;
    clients.upsert_client(platform.clone(), public).unwrap();
    assert!(
        !clients
            .get_client(platform.clone(), "web".into())
            .unwrap()
            .client_secret_configured
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.platform", "clients.manage"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        clients.get_client(platform, "web".into()),
        Err(AccessError::Forbidden)
    );
}

#[test]
fn client_admin_rejects_invalid_config_and_redacts_hasher_errors() {
    use crate::{ClientSecretError, ClientSecretHasher, OidcClientType, SecretString};
    struct FailingHasher;
    impl ClientSecretHasher for FailingHasher {
        fn hash_client_secret(&self, raw: &str) -> Result<String, ClientSecretError> {
            Err(ClientSecretError::HasherRejected(raw.into()))
        }
    }
    let (admin, store) = service(seeded());
    let service = CoreClientAdminService::new(admin, FailingHasher);
    let context = ctx("0", "u1", "s0");
    let mut command = AdminUpsertClient {
        client_id: "web".into(),
        client_name: "Web".into(),
        redirect_uris: vec!["https://example.test/callback".into()],
        client_type: OidcClientType::ConfidentialWeb,
        pkce_required: true,
        client_secret: Some(SecretString::new("must-not-leak")),
    };
    let err = service
        .upsert_client(context.clone(), command.clone())
        .unwrap_err();
    assert!(!format!("{err:?}").contains("must-not-leak"));
    command.client_secret = None;
    assert_eq!(
        service.upsert_client(context.clone(), command.clone()),
        Err(AccessError::InvalidInput("client_config"))
    );
    command.client_type = OidcClientType::PublicDesktop;
    command.pkce_required = false;
    assert_eq!(
        service.upsert_client(context.clone(), command.clone()),
        Err(AccessError::InvalidInput("client_config"))
    );
    command.pkce_required = true;
    assert_eq!(
        service.upsert_client(context, command),
        Err(AccessError::InvalidInput("client_config"))
    );
    assert!(store.0.lock().unwrap().clients.is_empty());
    assert!(store.0.lock().unwrap().audits.is_empty());
}

#[test]
fn client_secret_hashing_cannot_commit_after_management_session_expires() {
    use crate::{ClientSecretError, ClientSecretHasher, OidcClientType, SecretString};
    struct MovingClock(Arc<AtomicU64>);
    impl Clock for MovingClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.0.load(Ordering::SeqCst))
        }
    }
    struct SlowHasher(Arc<AtomicU64>);
    impl ClientSecretHasher for SlowHasher {
        fn hash_client_secret(&self, _: &str) -> Result<String, ClientSecretError> {
            self.0.store(2000, Ordering::SeqCst);
            Ok("test-hash".into())
        }
    }
    let store = seeded();
    let ticks = Arc::new(AtomicU64::new(1000));
    let admin = CoreAccessAdminService::new(
        TenancyMode::Enabled,
        catalog().0,
        store.clone(),
        MovingClock(ticks.clone()),
        SeqIds,
    );
    let service = CoreClientAdminService::new(admin, SlowHasher(ticks));
    let command = AdminUpsertClient {
        client_id: "slow".into(),
        client_name: "Slow".into(),
        redirect_uris: vec!["https://example.test/callback".into()],
        client_type: OidcClientType::ConfidentialWeb,
        pkce_required: true,
        client_secret: Some(SecretString::new("fixture-only")),
    };
    assert_eq!(
        service.upsert_client(ctx("0", "u1", "s0"), command),
        Err(AccessError::Forbidden)
    );
    let data = store.0.lock().unwrap();
    assert!(data.clients.is_empty());
    assert!(data.audits.is_empty());
}

impl Tx {
    fn account_projections(&self, tenant: Option<&str>) -> Vec<AccessAccountRecord> {
        self.data
            .account_records
            .iter()
            .filter_map(|r| {
                let mut record = r.clone();
                record.membership = match tenant {
                    Some(t) => Some(
                        self.data
                            .memberships
                            .iter()
                            .find(|m| m.tenant_id == t && m.subject_id == r.account_id)?
                            .clone(),
                    ),
                    None => None,
                };
                Some(record)
            })
            .collect()
    }
}

#[test]
fn account_queries_enforce_projection_scope_permissions_and_filter_bound_cursors() {
    let (svc, store) = service(seeded());
    let ids: Vec<String> = (1..=3)
        .map(|i| uuid::Uuid::from_u128(i).to_string())
        .collect();
    {
        let mut data = store.0.lock().unwrap();
        data.account_records = ids
            .iter()
            .enumerate()
            .map(|(i, id)| AccessAccountRecord {
                account_id: id.clone(),
                email: format!("User_{i}@Example.test"),
                display_name: None,
                status: if i == 1 {
                    AccountIdentityStatus::Closed
                } else {
                    AccountIdentityStatus::Active
                },
                created_at: FixedClock.now(),
                membership: None,
            })
            .collect();
        for id in &ids[..2] {
            data.memberships.push(membership("t1", id));
        }
        for id in [&ids[0], &ids[2]] {
            data.memberships.push(membership("t2", id));
        }
    }
    let platform = ctx("0", "u1", "s0");
    let tenant = ctx("t1", "u1", "s1");
    let all = svc
        .list_accounts(
            platform.clone(),
            None,
            AdminAccountFilter::default(),
            AccessPageRequest::default(),
        )
        .unwrap();
    assert_eq!(all.items.len(), 3);
    assert!(all.items.iter().all(|r| r.membership.is_none()));
    let page = svc
        .list_accounts(
            tenant.clone(),
            Some("t1".into()),
            AdminAccountFilter::default(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert!(page.has_more);
    assert_eq!(page.items[0].membership.as_ref().unwrap().tenant_id, "t1");
    let next = svc
        .list_accounts(
            tenant.clone(),
            Some("t1".into()),
            AdminAccountFilter::default(),
            AccessPageRequest {
                limit: 1,
                cursor: page.next_cursor.clone(),
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(next.items[0].status, AccountIdentityStatus::Active);
    assert_eq!(
        svc.list_accounts(
            platform.clone(),
            None,
            AdminAccountFilter::default(),
            AccessPageRequest {
                limit: 1,
                cursor: page.next_cursor.clone(),
                sort_order: None,
            }
        ),
        Err(AccessError::InvalidCursor)
    );
    assert_eq!(
        svc.list_accounts(
            tenant.clone(),
            Some("t1".into()),
            AdminAccountFilter {
                email: Some("user".into()),
                ..Default::default()
            },
            AccessPageRequest {
                limit: 1,
                cursor: page.next_cursor,
                sort_order: None,
            }
        ),
        Err(AccessError::InvalidCursor)
    );
    assert_eq!(
        svc.get_account(tenant.clone(), Some("t1".into()), ids[2].clone()),
        Err(AccessError::NotFound("account"))
    );
    assert_eq!(
        svc.get_account(tenant.clone(), None, ids[0].clone()),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.get_account(tenant.clone(), Some("t2".into()), ids[0].clone()),
        Err(AccessError::Forbidden)
    );
    let filter = AdminAccountFilter {
        email: Some("USER_1@".into()),
        created_after: Some(FixedClock.now()),
        created_before: Some(FixedClock.now()),
        ..Default::default()
    };
    assert_eq!(
        svc.list_accounts(
            tenant.clone(),
            Some("t1".into()),
            filter,
            AccessPageRequest::default()
        )
        .unwrap()
        .items
        .len(),
        1
    );
    assert!(AdminAccountFilter {
        membership_status: Some(MembershipStatus::Active),
        ..Default::default()
    }
    .validate(None)
    .is_err());
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.platform", "users.read"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.get_account(platform, Some("t1".into()), ids[0].clone()),
        Err(AccessError::Forbidden)
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.tenant", "members.manage"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.get_account(tenant, Some("t1".into()), ids[0].clone()),
        Err(AccessError::Forbidden)
    );
}

#[test]
fn repeated_member_binding_keeps_version_join_time_and_grants_unchanged() {
    let (svc, store) = service(seeded());
    let before = store
        .0
        .lock()
        .unwrap()
        .memberships
        .iter()
        .find(|m| m.tenant_id == "t1" && m.subject_id == "u2")
        .unwrap()
        .clone();
    let event = svc
        .execute(
            ctx("0", "u1", "s0"),
            command(
                "t1",
                AccessAdminMutation::BindMember {
                    subject_id: "u2".into(),
                },
            ),
        )
        .unwrap();
    assert_eq!(
        event.change,
        AccessChange::Membership {
            before: Some(before.clone()),
            after: before
        }
    );
    let data = store.0.lock().unwrap();
    assert_eq!(
        data.memberships
            .iter()
            .filter(|m| m.tenant_id == "t1" && m.subject_id == "u2")
            .count(),
        1
    );
    assert!(!data.bindings.iter().any(|b| b.subject_id == "u2"));
}

fn security_config() -> crate::AuthConfig {
    crate::AuthConfig {
        allow_local_registration: false,
        access_token_ttl_secs: 60,
        refresh_token_ttl_secs: 600,
        session_ttl_secs: 1200,
        verification_code_ttl_secs: 300,
        password_min_length: 8,
        password_max_length: 128,
    }
}
fn security_service() -> (CoreAccountSecurityService<Store, FixedClock, SeqIds>, Store) {
    let (admin, store) = service(seeded());
    {
        let mut data = store.0.lock().unwrap();
        data.account_records = ["u1", "u2"]
            .into_iter()
            .map(|id| AccessAccountRecord {
                account_id: id.into(),
                email: format!("{id}@example.test"),
                display_name: None,
                status: AccountIdentityStatus::Active,
                created_at: FixedClock.now(),
                membership: None,
            })
            .collect();
    }
    (
        CoreAccountSecurityService::new(admin, security_config()).unwrap(),
        store,
    )
}
#[test]
fn account_security_creation_requires_platform_permissions_and_initial_membership() {
    use crate::SecretString;
    let (svc, store) = security_service();
    let command = AdminCreateAccount {
        tenant_id: "t1".into(),
        email: "created@example.test".into(),
        password: SecretString::new("Fixture-created-123"),
        display_name: None,
    };
    assert_eq!(
        svc.create_account(ctx("t1", "u1", "s1"), command.clone()),
        Err(AccessError::Forbidden)
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.platform", "users.bind"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.create_account(ctx("0", "u1", "s0"), command.clone()),
        Err(AccessError::Forbidden)
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.platform", "users.bind"))
        .unwrap()
        .enabled = true;
    store.0.lock().unwrap().fail_audit = true;
    assert!(svc
        .create_account(ctx("0", "u1", "s0"), command.clone())
        .is_err());
    assert_eq!(store.0.lock().unwrap().account_records.len(), 2);
    store.0.lock().unwrap().fail_audit = false;
    let event = svc.create_account(ctx("0", "u1", "s0"), command).unwrap();
    assert!(!format!("{event:?}").contains("Fixture-created-123"));
    assert!(!format!("{event:?}").contains("argon2"));
    let AccessChange::AccountCreated { after } = event.change else {
        panic!()
    };
    assert_eq!(after.membership.unwrap().tenant_id, "t1");
    let data = store.0.lock().unwrap();
    assert!(data.passwords[&after.account_id].starts_with("$argon2id$"));
    assert!(!data
        .bindings
        .iter()
        .any(|b| b.subject_id == after.account_id));
}
#[test]
fn account_security_revokes_all_sessions_and_preserves_last_administrators() {
    use crate::SecretString;
    let (svc, store) = security_service();
    let platform = ctx("0", "u1", "s0");
    let disable = AdminSetAccountStatus {
        account_id: "u2".into(),
        status: AccountIdentityStatus::Disabled,
        expected_status: AccountIdentityStatus::Active,
    };
    assert_eq!(
        svc.set_account_status(ctx("t1", "u1", "s1"), disable.clone()),
        Err(AccessError::Forbidden)
    );
    store.0.lock().unwrap().fail_audit = true;
    assert!(svc
        .set_account_status(platform.clone(), disable.clone())
        .is_err());
    assert!(store.0.lock().unwrap().sessions["s2"].2);
    store.0.lock().unwrap().fail_audit = false;
    svc.set_account_status(platform.clone(), disable.clone())
        .unwrap();
    assert!(!store.0.lock().unwrap().sessions["s2"].2);
    assert_eq!(
        svc.set_account_status(platform.clone(), disable),
        Err(AccessError::Conflict("account_status"))
    );
    svc.set_account_status(
        platform.clone(),
        AdminSetAccountStatus {
            account_id: "u2".into(),
            status: AccountIdentityStatus::Active,
            expected_status: AccountIdentityStatus::Disabled,
        },
    )
    .unwrap();
    assert!(!store.0.lock().unwrap().sessions["s2"].2);
    assert_eq!(
        svc.set_account_status(
            platform.clone(),
            AdminSetAccountStatus {
                account_id: "u1".into(),
                status: AccountIdentityStatus::Disabled,
                expected_status: AccountIdentityStatus::Active
            }
        ),
        Err(AccessError::Conflict("last_security_admin"))
    );
    assert!(store.0.lock().unwrap().sessions["s0"].2);
    let event = svc
        .set_account_password(
            platform,
            AdminSetAccountPassword {
                account_id: "u1".into(),
                new_password: SecretString::new("Changed-fixture-123"),
            },
        )
        .unwrap();
    assert!(!format!("{event:?}").contains("Changed-fixture"));
    let data = store.0.lock().unwrap();
    assert!(!data.sessions["s0"].2);
    assert!(!data.sessions["s1"].2);
    assert!(!data.sessions["s3"].2);
}

#[test]
fn account_security_rechecks_actor_after_password_hashing() {
    struct StepClock(AtomicU64);
    impl Clock for StepClock {
        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.0.fetch_add(1000, Ordering::SeqCst))
        }
    }
    for create in [true, false] {
        let (_, store) = security_service();
        let admin = CoreAccessAdminService::new(
            TenancyMode::Enabled,
            catalog().0,
            store.clone(),
            StepClock(AtomicU64::new(1000)),
            SeqIds,
        );
        let service = CoreAccountSecurityService::new(admin, security_config()).unwrap();
        let result = if create {
            service.create_account(
                ctx("0", "u1", "s0"),
                AdminCreateAccount {
                    tenant_id: "t1".into(),
                    email: "expires@example.test".into(),
                    password: crate::SecretString::new("Expiry-fixture-123"),
                    display_name: None,
                },
            )
        } else {
            service.set_account_password(
                ctx("0", "u1", "s0"),
                AdminSetAccountPassword {
                    account_id: "u2".into(),
                    new_password: crate::SecretString::new("Expiry-fixture-123"),
                },
            )
        };
        assert_eq!(result, Err(AccessError::Forbidden));
        let data = store.0.lock().unwrap();
        assert_eq!(data.account_records.len(), 2);
        assert!(data.passwords.is_empty());
        assert!(data.audits.is_empty());
    }
}
#[test]
fn account_disable_checks_protected_administrator_domains_beyond_the_first_page() {
    let (svc, store) = security_service();
    {
        let mut data = store.0.lock().unwrap();
        data.memberships.push(membership("0", "u2"));
        for (t, r, resource) in [
            ("0", "sys", "idp.platform"),
            ("t1", "sec1", "idp.tenant"),
            ("t2", "sec2", "idp.tenant"),
        ] {
            data.bindings
                .push(binding(&format!("backup-{r}"), t, "u2", r, resource));
        }
        let permissions = data
            .roles
            .iter()
            .find(|r| r.role.id == "sec1")
            .unwrap()
            .permissions
            .clone();
        for i in 0..101 {
            let tenant = format!("a{i:03}");
            let role_id = format!("sec-{tenant}");
            data.tenants.insert(
                tenant.clone(),
                Tenant {
                    id: tenant.clone(),
                    name: tenant.clone(),
                    status: TenantStatus::Active,
                    allow_registration: false,
                },
            );
            data.roles.push(role(
                &role_id,
                &tenant,
                RoleKind::TenantSecurityAdmin,
                permissions.clone(),
            ));
            data.memberships.push(membership(&tenant, "u1"));
            data.bindings.push(binding(
                &format!("target-{tenant}"),
                &tenant,
                "u1",
                &role_id,
                "idp.tenant",
            ));
            if i != 100 {
                data.memberships.push(membership(&tenant, "u2"));
                data.bindings.push(binding(
                    &format!("backup-{tenant}"),
                    &tenant,
                    "u2",
                    &role_id,
                    "idp.tenant",
                ));
            }
        }
    }
    assert_eq!(
        svc.set_account_status(
            ctx("0", "u1", "s0"),
            AdminSetAccountStatus {
                account_id: "u1".into(),
                status: AccountIdentityStatus::Disabled,
                expected_status: AccountIdentityStatus::Active
            }
        ),
        Err(AccessError::Conflict("last_security_admin"))
    );
    let data = store.0.lock().unwrap();
    assert_eq!(data.accounts["u1"], true);
    assert!(data.sessions["s0"].2);
    assert!(data.audits.is_empty());
}

#[test]
fn device_admin_filters_validate_bounds_and_bind_every_cursor_condition() {
    use crate::DeviceStatus;
    let store = seeded();
    let row = AccessDeviceRecord {
        device: TenantProofDevice {
            tenant_id: "t1".into(),
            id: uuid::Uuid::from_u128(1).to_string(),
            client_id: "web".into(),
            proof_key_id: None,
            status: DeviceStatus::Active,
        },
        name: "Device".into(),
        registered_at: FixedClock.now(),
        last_seen_at: None,
    };
    let mut second = row.clone();
    second.device.id = uuid::Uuid::from_u128(2).to_string();
    {
        let mut d = store.0.lock().unwrap();
        d.devices = vec![row.clone(), second.clone()];
        d.active_device_bindings = vec![
            ("t1".into(), "u2".into(), row.device.id.clone()),
            ("t1".into(), "u2".into(), second.device.id.clone()),
        ];
    }
    let (svc, _) = service(store);
    let filter = AdminDeviceFilter {
        account_id: Some("u2".into()),
        client_id: Some("web".into()),
        status: Some(DeviceStatus::Active),
        registered_after: Some(FixedClock.now()),
        registered_before: Some(FixedClock.now()),
    };
    let page = svc
        .list_devices(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            filter.clone(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(page.items, vec![second.clone()]);
    assert!(page.has_more);
    let cursor = page.next_cursor.unwrap();
    let request = AccessPageRequest {
        limit: 1,
        cursor: Some(cursor.clone()),
        sort_order: None,
    };
    assert_eq!(
        svc.list_devices(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            filter.clone(),
            request.clone()
        )
        .unwrap()
        .items,
        vec![row]
    );
    for changed in [
        AdminDeviceFilter {
            account_id: None,
            ..filter.clone()
        },
        AdminDeviceFilter {
            client_id: None,
            ..filter.clone()
        },
        AdminDeviceFilter {
            status: None,
            ..filter.clone()
        },
        AdminDeviceFilter {
            registered_after: None,
            ..filter.clone()
        },
        AdminDeviceFilter {
            registered_before: None,
            ..filter.clone()
        },
    ] {
        assert_eq!(
            svc.list_devices(ctx("t1", "u1", "s1"), "t1".into(), changed, request.clone()),
            Err(AccessError::InvalidCursor)
        );
    }
    assert_eq!(
        svc.list_devices(ctx("0", "u1", "s0"), "t2".into(), filter.clone(), request),
        Err(AccessError::InvalidCursor)
    );
    let mut malformed = cursor;
    malformed.after.clear();
    assert_eq!(
        svc.list_devices(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            filter.clone(),
            AccessPageRequest {
                limit: 1,
                cursor: Some(malformed),
                sort_order: None,
            }
        ),
        Err(AccessError::InvalidCursor)
    );
    assert_eq!(
        AdminDeviceFilter {
            registered_after: Some(FixedClock.now() + Duration::from_secs(1)),
            ..filter.clone()
        }
        .validate(),
        Err(AccessError::InvalidInput("registered_time_range"))
    );
    for invalid in [
        UNIX_EPOCH - Duration::from_secs(1),
        UNIX_EPOCH + Duration::from_nanos(1),
    ] {
        assert_eq!(
            AdminDeviceFilter {
                registered_after: Some(invalid),
                ..Default::default()
            }
            .validate(),
            Err(AccessError::InvalidInput("registered_time"))
        );
    }
    assert!(AdminDeviceFilter {
        account_id: Some(String::new()),
        ..Default::default()
    }
    .validate()
    .is_err());
    assert!(AdminDeviceFilter {
        client_id: Some("x".repeat(129)),
        ..Default::default()
    }
    .validate()
    .is_err());
    assert_eq!(
        svc.list_devices(
            ctx("t1", "u2", "s2"),
            "t1".into(),
            filter,
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
}

#[test]
fn tenant_management_queries_require_platform_authority_and_bind_search_cursors() {
    let store = seeded();
    {
        let mut data = store.0.lock().unwrap();
        data.tenants.get_mut("t1").unwrap().name = "Alpha%_One".into();
        data.tenants.get_mut("t2").unwrap().name = "ALPHA Two".into();
    }
    let (svc, store) = service(store);
    let filter = AdminTenantFilter {
        name: Some("alpha".into()),
        status: Some(TenantStatus::Active),
        ..Default::default()
    };
    let page = svc
        .list_tenants(
            ctx("0", "u1", "s0"),
            filter.clone(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(page.items[0].tenant.id, "t2");
    assert!(page.has_more);
    let request = AccessPageRequest {
        limit: 1,
        cursor: page.next_cursor,
        sort_order: None,
    };
    let next = svc
        .list_tenants(ctx("0", "u1", "s0"), filter.clone(), request.clone())
        .unwrap();
    assert_eq!(next.items[0].tenant.id, "t1");
    assert!(!next.has_more);
    for changed in [
        AdminTenantFilter {
            name: None,
            ..filter.clone()
        },
        AdminTenantFilter {
            status: None,
            ..filter.clone()
        },
        AdminTenantFilter {
            tenant_id: Some("t2".into()),
            ..filter.clone()
        },
    ] {
        assert_eq!(
            svc.list_tenants(ctx("0", "u1", "s0"), changed, request.clone()),
            Err(AccessError::InvalidCursor)
        );
    }
    let literal = svc
        .list_tenants(
            ctx("0", "u1", "s0"),
            AdminTenantFilter {
                name: Some("%_".into()),
                ..Default::default()
            },
            AccessPageRequest::default(),
        )
        .unwrap();
    assert_eq!(literal.items.len(), 1);
    assert_eq!(
        svc.list_tenants(
            ctx("t1", "u1", "s1"),
            AdminTenantFilter::default(),
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.get_tenant(ctx("0", "u1", "s0"), "0".into()),
        Err(AccessError::ModeMismatch)
    );
    assert_eq!(
        svc.get_tenant(ctx("0", "u1", "s0"), "missing".into()),
        Err(AccessError::NotFound("tenant"))
    );
    store
        .0
        .lock()
        .unwrap()
        .tenants
        .get_mut("t1")
        .unwrap()
        .status = TenantStatus::Archived;
    assert_eq!(
        svc.get_tenant(ctx("0", "u1", "s0"), "t1".into())
            .unwrap()
            .tenant
            .status,
        TenantStatus::Archived
    );
    for invalid in [
        AdminTenantFilter {
            tenant_id: Some("0".into()),
            ..Default::default()
        },
        AdminTenantFilter {
            name: Some(" ".into()),
            ..Default::default()
        },
        AdminTenantFilter {
            name: Some("x".repeat(257)),
            ..Default::default()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.platform", "tenants.manage"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.list_tenants(ctx("0", "u1", "s0"), filter.clone(), request.clone()),
        Err(AccessError::Forbidden)
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.platform", "tenants.manage"))
        .unwrap()
        .enabled = true;
    store.0.lock().unwrap().session_expires_at = FixedClock.now();
    assert_eq!(
        svc.list_tenants(ctx("0", "u1", "s0"), filter, request),
        Err(AccessError::Forbidden)
    );
    let (catalog, _) = catalog();
    let disabled =
        CoreAccessAdminService::new(TenancyMode::Disabled, catalog, store, FixedClock, SeqIds);
    assert_eq!(
        disabled.list_tenants(
            ctx("0", "u1", "s0"),
            AdminTenantFilter::default(),
            AccessPageRequest::default()
        ),
        Err(AccessError::FeatureDisabled)
    );
    assert_eq!(
        disabled.get_tenant(ctx("0", "u1", "s0"), "t1".into()),
        Err(AccessError::FeatureDisabled)
    );
}

#[test]
fn role_admin_queries_bind_tenant_and_validate_bounded_configuration_snapshots() {
    let store = seeded();
    let first = uuid::Uuid::from_u128(1).to_string();
    let second = uuid::Uuid::from_u128(2).to_string();
    {
        let mut data = store.0.lock().unwrap();
        data.roles.push(role(
            &first,
            "t1",
            RoleKind::Business,
            vec![key("report", "read")],
        ));
        data.roles
            .push(role(&second, "t1", RoleKind::Business, vec![]));
        data.roles
            .push(role(&first, "t2", RoleKind::Business, vec![]));
        data.roles
            .iter_mut()
            .find(|role| role.role.id == "sec1")
            .unwrap()
            .role
            .created_at = UNIX_EPOCH;
        for role in data
            .roles
            .iter_mut()
            .filter(|role| role.role.id == first || role.role.id == second)
        {
            role.role.created_at = UNIX_EPOCH + Duration::from_secs(1);
        }
    }
    let (svc, store) = service(store);
    let page = svc
        .list_roles(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(page.items[0].id, second);
    let request = AccessPageRequest {
        limit: 1,
        cursor: page.next_cursor,
        sort_order: None,
    };
    assert_eq!(
        svc.list_roles(ctx("t1", "u1", "s1"), "t1".into(), request.clone())
            .unwrap()
            .items[0]
            .id,
        first
    );
    assert_eq!(
        svc.list_roles(ctx("0", "u1", "s0"), "t2".into(), request),
        Err(AccessError::InvalidCursor)
    );
    assert_eq!(
        svc.get_role(ctx("t1", "u1", "s1"), "t1".into(), first.clone())
            .unwrap()
            .permissions,
        vec![key("report", "read")]
    );
    assert!(svc
        .get_role(ctx("0", "u1", "s0"), "t2".into(), first.clone())
        .unwrap()
        .permissions
        .is_empty());
    assert_eq!(
        svc.get_role(ctx("t1", "u1", "s1"), "t2".into(), first.clone()),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.get_role(ctx("t1", "u2", "s2"), "t1".into(), first.clone()),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.get_role(ctx("t1", "u1", "s1"), "t1".into(), "missing".into()),
        Err(AccessError::NotFound("role"))
    );
    store
        .0
        .lock()
        .unwrap()
        .roles
        .iter_mut()
        .find(|r| r.role.id == first && r.role.tenant_id == "t1")
        .unwrap()
        .permissions = vec![key("report", "read"); MAX_ROLE_PERMISSIONS + 1];
    assert_eq!(
        svc.get_role(ctx("t1", "u1", "s1"), "t1".into(), first.clone()),
        Err(AccessError::InvalidStoreResponse)
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.tenant", "access.read"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.list_roles(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.tenant", "access.read"))
        .unwrap()
        .enabled = true;
    store.0.lock().unwrap().session_expires_at = FixedClock.now();
    assert_eq!(
        svc.list_roles(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
}

#[test]
fn subject_binding_queries_preserve_scopes_and_bind_both_tenant_and_subject() {
    let store = seeded();
    let mut one = binding(
        &uuid::Uuid::from_u128(1).to_string(),
        "t1",
        "u2",
        "reader",
        "report",
    );
    one.scope = ResourceScope::Instance("report-1".into());
    let two = binding(
        &uuid::Uuid::from_u128(2).to_string(),
        "t1",
        "u2",
        "reader",
        "report",
    );
    store.0.lock().unwrap().bindings.extend([
        one.clone(),
        two.clone(),
        binding("other", "t2", "u2", "reader", "report"),
    ]);
    let (svc, store) = service(store);
    let page = svc
        .list_subject_role_bindings(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            "u2".into(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(page.items, vec![two]);
    let request = AccessPageRequest {
        limit: 1,
        cursor: page.next_cursor,
        sort_order: None,
    };
    let page = svc
        .list_subject_role_bindings(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            "u2".into(),
            request.clone(),
        )
        .unwrap();
    assert_eq!(page.items, vec![one]);
    assert!(!page.has_more);
    for (tenant, subject) in [("t2", "u2"), ("t1", "u1")] {
        assert_eq!(
            svc.list_subject_role_bindings(
                ctx("0", "u1", "s0"),
                tenant.into(),
                subject.into(),
                request.clone()
            ),
            Err(AccessError::InvalidCursor)
        );
    }
    assert_eq!(
        svc.list_subject_role_bindings(
            ctx("t1", "u2", "s2"),
            "t1".into(),
            "u2".into(),
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.list_subject_role_bindings(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            "u3".into(),
            AccessPageRequest::default()
        ),
        Err(AccessError::NotFound("membership"))
    );
    store
        .0
        .lock()
        .unwrap()
        .memberships
        .iter_mut()
        .find(|m| m.tenant_id == "t1" && m.subject_id == "u2")
        .unwrap()
        .status = MembershipStatus::Suspended;
    assert_eq!(
        svc.list_subject_role_bindings(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            "u2".into(),
            AccessPageRequest::default()
        )
        .unwrap()
        .items
        .len(),
        2
    );
    store
        .0
        .lock()
        .unwrap()
        .bindings
        .iter_mut()
        .find(|b| b.tenant_id == "t1" && b.subject_id == "u2")
        .unwrap()
        .scope = ResourceScope::Instance(String::new());
    assert_eq!(
        svc.list_subject_role_bindings(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            "u2".into(),
            AccessPageRequest::default()
        ),
        Err(AccessError::InvalidStoreResponse)
    );
    store.0.lock().unwrap().session_expires_at = FixedClock.now();
    assert_eq!(
        svc.list_subject_role_bindings(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            "u2".into(),
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
}

#[test]
fn permission_directory_queries_bound_category_filters_and_compound_cursors() {
    let store = seeded();
    store.0.lock().unwrap().permissions.insert(
        key("report", "update"),
        perm("report", "update", PermissionCategory::Business),
    );
    let (svc, store) = service(store);
    let scope = AdminPermissionScope::Tenant("t1".into());
    let filter = AdminPermissionFilter {
        resource_type: Some("report".into()),
        category: Some(PermissionCategory::Business),
        enabled: Some(true),
    };
    let first = svc
        .list_permissions(
            ctx("t1", "u1", "s1"),
            scope.clone(),
            filter.clone(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(first.items[0].key, key("report", "update"));
    let request = AccessPageRequest {
        limit: 1,
        cursor: first.next_cursor,
        sort_order: None,
    };
    assert_eq!(request.cursor.as_ref().unwrap().after.len(), 3);
    let last = svc
        .list_permissions(
            ctx("t1", "u1", "s1"),
            scope.clone(),
            filter.clone(),
            request.clone(),
        )
        .unwrap();
    assert_eq!(last.items[0].key, key("report", "read"));
    assert!(!last.has_more);
    for changed in [
        AdminPermissionFilter {
            enabled: None,
            ..filter.clone()
        },
        AdminPermissionFilter {
            category: None,
            ..filter.clone()
        },
        AdminPermissionFilter {
            resource_type: None,
            ..filter.clone()
        },
    ] {
        assert_eq!(
            svc.list_permissions(
                ctx("t1", "u1", "s1"),
                scope.clone(),
                changed,
                request.clone()
            ),
            Err(AccessError::InvalidCursor)
        );
    }
    for changed in [
        AdminPermissionScope::Tenant("t2".into()),
        AdminPermissionScope::Platform,
    ] {
        assert_eq!(
            svc.list_permissions(
                ctx("0", "u1", "s0"),
                changed,
                filter.clone(),
                request.clone()
            ),
            Err(AccessError::InvalidCursor)
        );
    }
    let mut malformed = request.clone();
    malformed.cursor.as_mut().unwrap().after.pop();
    assert_eq!(
        svc.list_permissions(
            ctx("t1", "u1", "s1"),
            scope.clone(),
            filter.clone(),
            malformed
        ),
        Err(AccessError::InvalidCursor)
    );
    let tenant = svc
        .list_permissions(
            ctx("t1", "u1", "s1"),
            scope.clone(),
            AdminPermissionFilter::default(),
            AccessPageRequest::default(),
        )
        .unwrap();
    assert!(tenant
        .items
        .iter()
        .all(|p| p.category != PermissionCategory::Platform));
    let platform = svc
        .list_permissions(
            ctx("0", "u1", "s0"),
            AdminPermissionScope::Platform,
            AdminPermissionFilter::default(),
            AccessPageRequest::default(),
        )
        .unwrap();
    assert!(platform
        .items
        .iter()
        .any(|p| p.category == PermissionCategory::Platform));
    assert_eq!(
        svc.list_permissions(
            ctx("t1", "u1", "s1"),
            AdminPermissionScope::Platform,
            AdminPermissionFilter::default(),
            AccessPageRequest::default()
        ),
        Err(AccessError::Forbidden)
    );
    store.0.lock().unwrap().session_expires_at = FixedClock.now();
    assert_eq!(
        svc.list_permissions(ctx("t1", "u1", "s1"), scope, filter, request),
        Err(AccessError::Forbidden)
    );
}

#[test]
fn permission_diagnosis_reuses_grants_and_commits_allow_and_deny_audits() {
    let (svc, store) = service(seeded());
    {
        let mut data = store.0.lock().unwrap();
        data.roles.push(role(
            "reader",
            "t1",
            RoleKind::Business,
            vec![key("report", "read")],
        ));
        let mut grant = binding("reader1", "t1", "u2", "reader", "report");
        grant.scope = ResourceScope::Instance("r1".into());
        data.bindings.push(grant);
    }
    let query = AccessQuery {
        tenant_id: "t1".into(),
        subject_id: "u2".into(),
        resource_type: "report".into(),
        action: "read".into(),
        resource_id: Some("r1".into()),
    };
    for (resource_id, expected) in [
        (Some("r1"), AccessDecision::Allow),
        (Some("r2"), AccessDecision::Deny),
        (None, AccessDecision::Deny),
    ] {
        let q = AccessQuery {
            resource_id: resource_id.map(str::to_owned),
            ..query.clone()
        };
        let event = svc
            .diagnose_permission(ctx("t1", "u1", "s1"), q.clone())
            .unwrap();
        assert_eq!(event.operation, "access.check");
        assert_eq!(event.occurred_at, FixedClock.now());
        assert_eq!(
            event.change,
            AccessChange::PermissionChecked {
                query: q,
                decision: expected
            }
        );
        assert_eq!(store.0.lock().unwrap().audits.last(), Some(&event));
    }
    for q in [
        AccessQuery {
            action: "unknown".into(),
            ..query.clone()
        },
        AccessQuery {
            resource_type: "idp.platform".into(),
            action: "access.manage".into(),
            resource_id: None,
            ..query.clone()
        },
    ] {
        assert!(matches!(
            svc.diagnose_permission(ctx("0", "u1", "s0"), q)
                .unwrap()
                .change,
            AccessChange::PermissionChecked {
                decision: AccessDecision::Deny,
                ..
            }
        ));
    }
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("report", "read"))
        .unwrap()
        .enabled = false;
    assert!(matches!(
        svc.diagnose_permission(ctx("0", "u1", "s0"), query.clone())
            .unwrap()
            .change,
        AccessChange::PermissionChecked {
            decision: AccessDecision::Deny,
            ..
        }
    ));
    let count = store.0.lock().unwrap().audits.len();
    store.0.lock().unwrap().fail_audit = true;
    assert!(matches!(
        svc.diagnose_permission(ctx("t1", "u1", "s1"), query.clone()),
        Err(AccessError::Store(_))
    ));
    assert_eq!(store.0.lock().unwrap().audits.len(), count);
    store.0.lock().unwrap().fail_audit = false;
    assert_eq!(
        svc.diagnose_permission(ctx("t1", "u2", "s2"), query.clone()),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.diagnose_permission(ctx("t2", "u1", "s3"), query.clone()),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        svc.diagnose_permission(
            ctx("t1", "u1", "s1"),
            AccessQuery {
                subject_id: "u3".into(),
                ..query.clone()
            }
        ),
        Err(AccessError::NotFound("membership"))
    );
    store.0.lock().unwrap().session_expires_at = FixedClock.now();
    assert_eq!(
        svc.diagnose_permission(ctx("t1", "u1", "s1"), query),
        Err(AccessError::Forbidden)
    );
    assert_eq!(store.0.lock().unwrap().audits.len(), count);
}

fn audit_metadata(event: &AccessAuditEvent) -> AdminAuditRecord {
    AdminAuditRecord {
        id: event.id.clone(),
        occurred_at: event.occurred_at,
        actor_id: event.context.actor.subject_id.clone(),
        actor_domain: event.context.actor.tenant_id.clone(),
        actor_session_id: Some(event.context.actor.session_id.clone()),
        authentication_source: event.context.authentication_source.clone(),
        target_domain: event.tenant_id.clone(),
        operation: event.operation.into(),
        request_id: event.context.request_id.clone(),
    }
}

#[test]
fn audit_queries_bind_domain_filters_and_numeric_time_and_require_audit_permission() {
    let (svc, store) = service(seeded());
    for tenant in ["t1", "t1", "t1", "t2"] {
        svc.diagnose_permission(
            ctx("0", "u1", "s0"),
            AccessQuery {
                tenant_id: tenant.into(),
                subject_id: "u2".into(),
                resource_type: "report".into(),
                action: "read".into(),
                resource_id: None,
            },
        )
        .unwrap();
    }
    {
        let mut d = store.0.lock().unwrap();
        for (i, e) in d.audits.iter_mut().enumerate() {
            e.id = uuid::Uuid::from_u128(i as u128 + 1).to_string();
            e.occurred_at = UNIX_EPOCH + Duration::from_secs(if i == 0 { 9 } else { 10 });
        }
        d.permissions
            .get_mut(&key("idp.tenant", "access.read"))
            .unwrap()
            .enabled = false;
        d.permissions
            .get_mut(&key("idp.platform", "access.manage"))
            .unwrap()
            .enabled = false;
    }
    let filter = AdminAuditFilter {
        actor_id: Some("u1".into()),
        operation: Some("access.check".into()),
        occurred_after: Some(UNIX_EPOCH + Duration::from_secs(9)),
        occurred_before: Some(UNIX_EPOCH + Duration::from_secs(10)),
    };
    let first = svc
        .list_audit_events(
            ctx("t1", "u1", "s1"),
            "t1".into(),
            filter.clone(),
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert_eq!(
        first.items[0].occurred_at,
        UNIX_EPOCH + Duration::from_secs(10)
    );
    let request = AccessPageRequest {
        limit: 2,
        cursor: first.next_cursor,
        sort_order: None,
    };
    let rest = svc
        .list_audit_events(
            ctx("0", "u1", "s0"),
            "t1".into(),
            filter.clone(),
            request.clone(),
        )
        .unwrap();
    assert_eq!(rest.items.len(), 2);
    assert!(!rest.has_more);
    assert!(rest.items[0].id > rest.items[1].id);
    for changed in [
        AdminAuditFilter {
            actor_id: None,
            ..filter.clone()
        },
        AdminAuditFilter {
            operation: None,
            ..filter.clone()
        },
        AdminAuditFilter {
            occurred_after: None,
            ..filter.clone()
        },
        AdminAuditFilter {
            occurred_before: None,
            ..filter.clone()
        },
    ] {
        assert_eq!(
            svc.list_audit_events(ctx("0", "u1", "s0"), "t1".into(), changed, request.clone()),
            Err(AccessError::InvalidCursor)
        );
    }
    assert_eq!(
        svc.list_audit_events(
            ctx("0", "u1", "s0"),
            "t2".into(),
            filter.clone(),
            request.clone()
        ),
        Err(AccessError::InvalidCursor)
    );
    for keys in [
        vec!["9".into(), first.items[0].id.clone()],
        vec!["9999999999999999999".into(), first.items[0].id.clone()],
        vec!["0000000000000000009".into(), "not-uuid".into()],
    ] {
        let mut invalid = request.clone();
        invalid.cursor.as_mut().unwrap().after = keys;
        assert_eq!(
            svc.list_audit_events(ctx("0", "u1", "s0"), "t1".into(), filter.clone(), invalid),
            Err(AccessError::InvalidCursor)
        );
    }
    let id = first.items[0].id.clone();
    assert!(svc
        .get_audit_event(ctx("t1", "u1", "s1"), "t1".into(), id.clone())
        .is_ok());
    assert_eq!(
        svc.get_audit_event(ctx("t2", "u1", "s3"), "t2".into(), id.clone()),
        Err(AccessError::NotFound("audit_event"))
    );
    assert_eq!(
        svc.get_audit_event(ctx("t2", "u1", "s3"), "t1".into(), id.clone()),
        Err(AccessError::Forbidden)
    );
    assert!(svc
        .list_audit_events(
            ctx("0", "u1", "s0"),
            "0".into(),
            AdminAuditFilter::default(),
            AccessPageRequest::default()
        )
        .is_ok());
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.tenant", "audit.read"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.get_audit_event(ctx("t1", "u1", "s1"), "t1".into(), id.clone()),
        Err(AccessError::Forbidden)
    );
    store.0.lock().unwrap().session_expires_at = FixedClock.now();
    assert_eq!(
        svc.get_audit_event(ctx("0", "u1", "s0"), "t1".into(), id),
        Err(AccessError::Forbidden)
    );
    assert_eq!(store.0.lock().unwrap().audits.len(), 4);
}

fn new_tenant_administrator_command() -> AdminCreateTenant {
    AdminCreateTenant {
        tenant_id: "created-tenant".into(),
        name: "Created tenant".into(),
        allow_registration: false,
        administrator: InitialTenantAdministrator::New {
            email: "new-admin@example.test".into(),
            password: crate::SecretString::new("Fixture-new-admin-123"),
            display_name: None,
        },
    }
}
#[test]
fn tenant_creation_with_new_administrator_is_atomic_and_has_secret_free_audits() {
    let (svc, store) = security_service();
    let event = svc
        .create_tenant(ctx("0", "u1", "s0"), new_tenant_administrator_command())
        .unwrap();
    let AccessChange::TenantCreated { administrator, .. } = &event.change else {
        panic!("expected tenant");
    };
    let data = store.0.lock().unwrap();
    let id = &administrator.subject_id;
    assert!(data.accounts[id]);
    assert_eq!(
        data.memberships
            .iter()
            .filter(|m| m.subject_id == *id)
            .count(),
        1
    );
    assert!(data
        .bindings
        .iter()
        .any(|b| b.subject_id == *id && b.tenant_id == "created-tenant"));
    assert!(crate::service::password::verify_password(
        &data.passwords[id],
        "Fixture-new-admin-123"
    )
    .unwrap());
    assert_eq!(
        data.audits.iter().map(|a| a.operation).collect::<Vec<_>>(),
        vec!["account.create", "tenant.create"]
    );
    let audit = format!("{:?}", data.audits);
    assert!(!audit.contains("Fixture-new-admin-123"));
    assert!(!audit.contains("$argon2"));
}
#[test]
fn tenant_creation_with_new_administrator_rechecks_all_platform_permissions() {
    for action in [
        "users.security",
        "tenants.manage",
        "users.bind",
        "access.manage",
    ] {
        let (svc, store) = security_service();
        store
            .0
            .lock()
            .unwrap()
            .permissions
            .get_mut(&key("idp.platform", action))
            .unwrap()
            .enabled = false;
        assert_eq!(
            svc.create_tenant(ctx("0", "u1", "s0"), new_tenant_administrator_command()),
            Err(AccessError::Forbidden)
        );
        assert!(!store
            .0
            .lock()
            .unwrap()
            .tenants
            .contains_key("created-tenant"));
    }
    let (svc, _) = security_service();
    assert_eq!(
        svc.create_tenant(ctx("t1", "u1", "s1"), new_tenant_administrator_command()),
        Err(AccessError::Forbidden)
    );
    let mut command = new_tenant_administrator_command();
    command.tenant_id = "0".into();
    assert!(svc.create_tenant(ctx("0", "u1", "s0"), command).is_err());
    let mut command = new_tenant_administrator_command();
    command.administrator = InitialTenantAdministrator::New {
        email: "new@example.test".into(),
        password: crate::SecretString::new("weak"),
        display_name: None,
    };
    assert_eq!(
        svc.create_tenant(ctx("0", "u1", "s0"), command),
        Err(AccessError::InvalidInput("password"))
    );
}
#[test]
fn new_tenant_administrator_duplicate_email_and_audit_failure_leave_no_partial_state() {
    for duplicate in [false, true] {
        let (svc, store) = security_service();
        if duplicate {
            store.0.lock().unwrap().account_records[0].email = "new-admin@example.test".into();
        } else {
            store.0.lock().unwrap().fail_audit = true;
        }
        let before = store.0.lock().unwrap().clone();
        assert!(svc
            .create_tenant(ctx("0", "u1", "s0"), new_tenant_administrator_command())
            .is_err());
        let data = store.0.lock().unwrap();
        assert_eq!(data.tenants, before.tenants);
        assert_eq!(data.memberships, before.memberships);
        assert_eq!(data.accounts, before.accounts);
        assert_eq!(data.passwords, before.passwords);
        assert_eq!(data.roles, before.roles);
        assert_eq!(data.bindings, before.bindings);
        assert_eq!(data.audits, before.audits);
    }
}

#[test]
fn administrator_snapshot_is_platform_authorized_and_never_creates_membership() {
    let (_, store) = security_service();
    let (svc, store) = service(store);
    let before = store.0.lock().unwrap().clone();
    for tenant in ["0", "t1"] {
        let value = svc
            .get_security_administrator(ctx("0", "u1", "s0"), tenant.into(), "u2".into())
            .unwrap();
        assert_eq!(value.tenant.id, tenant);
        assert_eq!(value.account.account_id, "u2");
        assert_eq!(
            value.role.kind,
            if tenant == "0" {
                RoleKind::SystemAdmin
            } else {
                RoleKind::TenantSecurityAdmin
            }
        );
        assert!(value.binding.is_none());
    }
    let data = store.0.lock().unwrap();
    assert_eq!(data.memberships, before.memberships);
    assert_eq!(data.audits, before.audits);
    drop(data);
    for actor in [ctx("t1", "u1", "s1"), ctx("t2", "u1", "s2")] {
        assert!(svc
            .get_security_administrator(actor, "t1".into(), "u2".into())
            .is_err());
    }
    store
        .0
        .lock()
        .unwrap()
        .permissions
        .get_mut(&key("idp.platform", "access.manage"))
        .unwrap()
        .enabled = false;
    assert_eq!(
        svc.get_security_administrator(ctx("0", "u1", "s0"), "0".into(), "u2".into()),
        Err(AccessError::Forbidden)
    );
}

#[test]
fn administrator_snapshot_tracks_appointment_and_removal_without_other_tenant_grants() {
    let (_, store) = security_service();
    let (svc, _) = service(store);
    svc.execute(
        ctx("0", "u1", "s0"),
        command(
            "t1",
            AccessAdminMutation::SetSecurityAdmin {
                subject_id: "u2".into(),
                appointed: true,
            },
        ),
    )
    .unwrap();
    let assigned = svc
        .get_security_administrator(ctx("0", "u1", "s0"), "t1".into(), "u2".into())
        .unwrap();
    assert_eq!(assigned.binding.unwrap().resource_type, "idp.tenant");
    assert!(svc
        .get_security_administrator(ctx("0", "u1", "s0"), "t2".into(), "u2".into())
        .unwrap()
        .binding
        .is_none());
    svc.execute(
        ctx("0", "u1", "s0"),
        command(
            "t1",
            AccessAdminMutation::SetSecurityAdmin {
                subject_id: "u2".into(),
                appointed: false,
            },
        ),
    )
    .unwrap();
    assert!(svc
        .get_security_administrator(ctx("0", "u1", "s0"), "t1".into(), "u2".into())
        .unwrap()
        .binding
        .is_none());
}

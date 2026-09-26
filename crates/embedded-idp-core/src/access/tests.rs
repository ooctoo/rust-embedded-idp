use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, UNIX_EPOCH},
};

use super::*;
use crate::{Account, AccountStatus, EmailVerificationCode, StoreError};

#[derive(Clone, Default)]
struct Data {
    accounts: BTreeMap<String, Account>,
    tenants: BTreeMap<String, Tenant>,
    memberships: Vec<TenantMembership>,
    roles: Vec<Role>,
    permissions: BTreeMap<PermissionKey, PermissionDefinition>,
    links: Vec<RolePermission>,
    bindings: Vec<RoleBinding>,
    verifications: Vec<EmailVerificationCode>,
    registrations: BTreeMap<String, String>,
    fail: bool,
    wrong_batch_length: bool,
    fail_registration: bool,
}

#[derive(Clone, Default)]
struct MemoryStore {
    data: Arc<Mutex<Data>>,
    checks: Arc<AtomicUsize>,
}

fn definition(resource_type: &str, action: &str) -> PermissionDefinition {
    PermissionDefinition {
        tenant_id: "0".into(),
        key: PermissionKey {
            resource_type: resource_type.into(),
            action: action.into(),
        },
        description: action.into(),
        category: PermissionCategory::Business,
        enabled: true,
        archived: false,
        version: 1,
        created_at: None,
    }
}

fn catalog() -> PermissionCatalog {
    PermissionCatalog::new(vec![
        definition("report", "read"),
        definition("report", "update"),
        definition("dataset", "read"),
    ])
    .unwrap()
}

fn account(id: &str) -> Account {
    Account {
        id: id.into(),
        email: format!("{id}@example.test"),
        password_hash: "test-hash".into(),
        display_name: None,
        status: AccountStatus::Active,
        created_at: UNIX_EPOCH,
    }
}

fn tenant(id: &str) -> Tenant {
    Tenant {
        id: id.into(),
        name: id.into(),
        status: TenantStatus::Active,
        allow_registration: true,
    }
}

fn membership(tenant_id: &str, subject_id: &str) -> TenantMembership {
    TenantMembership {
        tenant_id: tenant_id.into(),
        subject_id: subject_id.into(),
        status: MembershipStatus::Active,
        joined_at: UNIX_EPOCH,
        version: 1,
    }
}

fn grant(
    data: &mut Data,
    tenant: &str,
    subject: &str,
    role_id: &str,
    resource: &str,
    action: &str,
    scope: ResourceScope,
    kind: RoleKind,
) {
    if !data
        .roles
        .iter()
        .any(|r| r.tenant_id == tenant && r.id == role_id)
    {
        data.roles.push(Role {
            id: role_id.into(),
            tenant_id: tenant.into(),
            key: role_id.into(),
            name: role_id.into(),
            status: RoleStatus::Active,
            kind,
            version: 1,
            created_at: UNIX_EPOCH,
        });
    }
    let permission = PermissionKey {
        resource_type: resource.into(),
        action: action.into(),
    };
    let link = RolePermission {
        tenant_id: tenant.into(),
        role_id: role_id.into(),
        permission,
    };
    if !data.links.contains(&link) {
        data.links.push(link);
    }
    data.bindings.push(RoleBinding {
        id: format!("binding-{}", data.bindings.len()),
        tenant_id: tenant.into(),
        subject_id: subject.into(),
        role_id: role_id.into(),
        resource_type: resource.into(),
        scope,
        created_at: UNIX_EPOCH,
    });
}

fn setup(mode: TenancyMode) -> (CoreAccessService<MemoryStore>, MemoryStore) {
    let store = MemoryStore::default();
    {
        let mut d = store.data.lock().unwrap();
        d.permissions = catalog()
            .definitions()
            .map(|p| (p.key.clone(), p.clone()))
            .collect();
        for id in ["u1", "u2"] {
            d.accounts.insert(id.into(), account(id));
        }
        for id in ["0", "t1", "t2"] {
            d.tenants.insert(id.into(), tenant(id));
            d.memberships.push(membership(id, "u1"));
        }
        grant(
            &mut d,
            "t1",
            "u1",
            "reader",
            "report",
            "read",
            ResourceScope::Instance("r1".into()),
            RoleKind::Business,
        );
    }
    (
        CoreAccessService::new(mode, catalog(), store.clone()),
        store,
    )
}

fn q(text: &str) -> AccessQuery {
    text.parse().unwrap()
}

fn page_rows<T>(
    mut rows: Vec<T>,
    page: &AccessPageRequest,
    key: impl Fn(&T) -> Vec<String>,
) -> Vec<T> {
    rows.sort_by_key(&key);
    rows.retain(|r| page.cursor.as_ref().is_none_or(|c| key(r) > c.after));
    rows.truncate(page.fetch_limit());
    rows
}

impl AccessReadStore for MemoryStore {
    fn check_active_grants(&self, queries: &[AccessQuery]) -> Result<Vec<bool>, StoreError> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let d = self.data.lock().unwrap();
        if d.fail {
            return Err(StoreError::Backend("offline".into()));
        }
        if d.wrong_batch_length {
            return Ok(vec![]);
        }
        Ok(queries
            .iter()
            .map(|query| {
                let active = d
                    .accounts
                    .get(&query.subject_id)
                    .is_some_and(|a| a.status == AccountStatus::Active)
                    && d.tenants
                        .get(&query.tenant_id)
                        .is_some_and(|t| t.status == TenantStatus::Active)
                    && d.memberships.iter().any(|m| {
                        m.tenant_id == query.tenant_id
                            && m.subject_id == query.subject_id
                            && m.status == MembershipStatus::Active
                    });
                // Domain category is checked by CoreAccessService. The reference
                // grant predicate is additionally exercised for both possible modes.
                active
                    && d.bindings.iter().any(|binding| {
                        d.roles.iter().any(|role| {
                            d.links.iter().any(|link| {
                                d.permissions
                                    .get(&link.permission)
                                    .is_some_and(|permission| {
                                        [TenancyMode::Disabled, TenancyMode::Enabled].iter().any(
                                            |mode| {
                                                binding.grants(query, role, link, permission, *mode)
                                            },
                                        )
                                    })
                            })
                        })
                    })
            })
            .collect())
    }

    fn list_subject_roles(
        &self,
        tenant: &str,
        subject: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<Role>, StoreError> {
        let d = self.data.lock().unwrap();
        let ids: BTreeSet<_> = d
            .bindings
            .iter()
            .filter(|b| b.tenant_id == tenant && b.subject_id == subject)
            .map(|b| &b.role_id)
            .collect();
        Ok(page_rows(
            d.roles
                .iter()
                .filter(|r| r.tenant_id == tenant && ids.contains(&r.id))
                .cloned()
                .collect(),
            page,
            |r| vec![r.id.clone()],
        ))
    }

    fn list_role_permissions(
        &self,
        tenant: &str,
        role_id: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<PermissionDefinition>, StoreError> {
        let d = self.data.lock().unwrap();
        Ok(page_rows(
            d.links
                .iter()
                .filter(|l| l.tenant_id == tenant && l.role_id == role_id)
                .filter_map(|l| d.permissions.get(&l.permission).cloned())
                .map(|mut p| {
                    p.tenant_id = tenant.into();
                    p
                })
                .collect(),
            page,
            |p| vec![p.key.resource_type.clone(), p.key.action.clone()],
        ))
    }

    fn list_subject_tenants(
        &self,
        subject: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<SubjectTenant>, StoreError> {
        let d = self.data.lock().unwrap();
        Ok(page_rows(
            d.memberships
                .iter()
                .filter(|m| {
                    m.subject_id == subject
                        && m.tenant_id != "0"
                        && m.status != MembershipStatus::Removed
                })
                .filter_map(|m| {
                    d.tenants.get(&m.tenant_id).map(|t| SubjectTenant {
                        tenant: t.clone(),
                        membership: m.clone(),
                    })
                })
                .collect(),
            page,
            |r| vec![r.tenant.id.clone()],
        ))
    }
}

impl TenantRegistrationStore for MemoryStore {
    fn create_registered_account(
        &self,
        registration: &TenantRegistration,
    ) -> Result<(), StoreError> {
        let mut data = self.data.lock().unwrap();
        let tenant = data
            .tenants
            .get(registration.registration_tenant_id())
            .ok_or(StoreError::NotFound("tenant"))?;
        if tenant.status != TenantStatus::Active || !tenant.allow_registration {
            return Err(StoreError::Conflict("registration_closed"));
        }
        if data
            .accounts
            .values()
            .any(|a| a.id == registration.account().id || a.email == registration.account().email)
        {
            return Err(StoreError::Conflict("existing_account"));
        }
        // Test-only transaction: commit the copy only after every write succeeds.
        let mut pending = data.clone();
        pending.accounts.insert(
            registration.account().id.clone(),
            registration.account().clone(),
        );
        pending.memberships.push(registration.membership().clone());
        if data.fail_registration {
            return Err(StoreError::Backend("verification write failed".into()));
        }
        pending
            .verifications
            .push(registration.verification().clone());
        pending.registrations.insert(
            registration.account().id.clone(),
            registration.registration_tenant_id().into(),
        );
        *data = pending;
        Ok(())
    }
}

#[test]
fn descriptions_round_trip_and_only_empty_trailing_id_is_normalized() {
    for text in [
        "0/U1::report::read",
        "t-1/u.1::report.v2::read_one::r_1",
        "t1/u1::report::read::",
    ] {
        let query = q(text);
        assert_eq!(query.to_string(), text.strip_suffix("::").unwrap_or(text));
        assert_eq!(q(&query.to_string()), query);
    }
    let maximal = format!(
        "{}/{}::{}::{}::{}",
        "t".repeat(128),
        "u".repeat(128),
        "r".repeat(64),
        "a".repeat(64),
        "i".repeat(256)
    );
    assert_eq!(q(&maximal).to_string(), maximal);
    let mut structured = q("t1/u1::report::read");
    structured.resource_id = Some(String::new());
    assert!(structured.validate().is_err());
}

#[test]
fn malformed_descriptions_and_identifiers_are_rejected() {
    for text in [
        "",
        "t/u",
        "/u::r::a",
        "t/::r::a",
        "t/u/v::r::a",
        "t/u::::a",
        "t/u::r::",
        "t/u::R::a",
        "t/u::r::Read",
        "t/u::1r::a",
        "t/u::r::*",
        "t/u::r::a::*",
        "t/u::r::a::r::extra",
        "t/u::r::a::::",
        " t/u::r::a",
        "t/u::r::a ",
        "t/u::r::a::a%2Fb",
        "t/u::r::a::报告",
        "t/u::r::a::r\n",
    ] {
        assert!(text.parse::<AccessQuery>().is_err(), "accepted {text:?}");
    }
    for text in [
        format!("{}/u::r::a", "t".repeat(129)),
        format!("t/u::{}::a", "r".repeat(65)),
        format!("t/u::r::a::{}", "x".repeat(257)),
        "x".repeat(1025),
    ] {
        assert!(text.parse::<AccessQuery>().is_err());
    }
    assert!(ResourceScope::Instance(String::new()).validate().is_err());
}

#[test]
fn login_policy_keeps_reserved_domain_and_fixed_entries_separate() {
    let zero = LoginTenantPolicy::Fixed {
        tenant_id: "0".into(),
    };
    let fixed = LoginTenantPolicy::Fixed {
        tenant_id: "t1".into(),
    };
    let choose = LoginTenantPolicy::ChooseAfterAuthentication;
    assert!(zero.validate(TenancyMode::Disabled).is_ok());
    assert!(zero.validate(TenancyMode::Enabled).is_err());
    assert!(fixed.validate(TenancyMode::Disabled).is_err());
    assert!(choose.validate(TenancyMode::Disabled).is_err());
    assert!(fixed.validate_selection(TenancyMode::Enabled, "t1").is_ok());
    assert_eq!(
        fixed.validate_selection(TenancyMode::Enabled, "t2"),
        Err(AccessError::Forbidden)
    );
    assert!(choose
        .validate_selection(TenancyMode::Enabled, "t2")
        .is_ok());
    assert!(choose
        .validate_selection(TenancyMode::Enabled, "0")
        .is_err());
    assert!(choose.validate_selection(TenancyMode::Enabled, "").is_err());
}

#[test]
fn catalog_rejects_duplicates_reserved_prefix_and_category_conflicts() {
    assert!(PermissionCatalog::new(vec![
        definition("report", "read"),
        definition("report", "read")
    ])
    .is_err());
    assert!(PermissionCatalog::new(vec![definition("idp.custom", "read")]).is_err());
    assert!(PermissionCatalog::new(vec![definition("Report", "read")]).is_err());
    let mut conflict = definition("report", "update");
    conflict.category = PermissionCategory::Platform;
    assert!(PermissionCatalog::new(vec![definition("report", "read"), conflict]).is_err());
    assert_eq!(
        PermissionCatalog::new(vec![])
            .unwrap()
            .definitions()
            .count(),
        15
    );
}

#[test]
fn scopes_roles_and_tenants_follow_the_authorization_matrix() {
    let (service, store) = setup(TenancyMode::Enabled);
    for (text, decision) in [
        ("t1/u1::report::read::r1", AccessDecision::Allow),
        ("t1/u1::report::read::r2", AccessDecision::Deny),
        ("t1/u1::report::read", AccessDecision::Deny),
        ("t1/u1::report::update::r1", AccessDecision::Deny),
        ("t2/u1::report::read::r1", AccessDecision::Deny),
        ("t1/u2::report::read::r1", AccessDecision::Deny),
        ("0/u1::report::read::r1", AccessDecision::Deny),
        ("t1/u1::dataset::read::r1", AccessDecision::Deny),
        ("t1/u1::report::unknown::r1", AccessDecision::Deny),
    ] {
        assert_eq!(service.check(q(text)).unwrap(), decision, "{text}");
    }
    {
        let mut d = store.data.lock().unwrap();
        grant(
            &mut d,
            "t1",
            "u1",
            "editor",
            "report",
            "update",
            ResourceScope::Type,
            RoleKind::Business,
        );
    }
    assert_eq!(
        service
            .check(q("t1/u1::report::update::future-report"))
            .unwrap(),
        AccessDecision::Allow
    );
    assert_eq!(
        service.check(q("t1/u1::report::update")).unwrap(),
        AccessDecision::Allow
    );
    // Another type added to the role must not expand its existing report binding.
    store.data.lock().unwrap().links.push(RolePermission {
        tenant_id: "t1".into(),
        role_id: "editor".into(),
        permission: definition("dataset", "read").key,
    });
    assert_eq!(
        service.check(q("t1/u1::dataset::read::r1")).unwrap(),
        AccessDecision::Deny
    );
    store
        .data
        .lock()
        .unwrap()
        .bindings
        .retain(|b| b.role_id != "editor");
    assert_eq!(
        service.check(q("t1/u1::report::update::r1")).unwrap(),
        AccessDecision::Deny
    );
    assert_eq!(
        service.check(q("t1/u1::report::read::r1")).unwrap(),
        AccessDecision::Allow
    );
}

#[test]
fn all_status_changes_and_missing_relations_revoke_without_a_cache() {
    let (service, store) = setup(TenancyMode::Enabled);
    let original = store.data.lock().unwrap().clone();
    let cases: Vec<Box<dyn Fn(&mut Data)>> = vec![
        Box::new(|d| d.accounts.get_mut("u1").unwrap().status = AccountStatus::Disabled),
        Box::new(|d| d.accounts.get_mut("u1").unwrap().status = AccountStatus::PendingVerification),
        Box::new(|d| d.tenants.get_mut("t1").unwrap().status = TenantStatus::Suspended),
        Box::new(|d| d.tenants.get_mut("t1").unwrap().status = TenantStatus::Archived),
        Box::new(|d| {
            d.memberships
                .iter_mut()
                .find(|m| m.tenant_id == "t1")
                .unwrap()
                .status = MembershipStatus::Suspended
        }),
        Box::new(|d| {
            d.memberships
                .iter_mut()
                .find(|m| m.tenant_id == "t1")
                .unwrap()
                .status = MembershipStatus::Removed
        }),
        Box::new(|d| d.roles[0].status = RoleStatus::Disabled),
        Box::new(|d| d.roles[0].kind = RoleKind::SystemAdmin),
        Box::new(|d| {
            d.permissions
                .get_mut(&definition("report", "read").key)
                .unwrap()
                .enabled = false
        }),
        Box::new(|d| d.links.clear()),
        Box::new(|d| d.memberships.clear()),
        Box::new(|d| d.roles[0].tenant_id = "t2".into()),
        Box::new(|d| d.links[0].tenant_id = "t2".into()),
        Box::new(|d| d.bindings[0].tenant_id = "t2".into()),
        Box::new(|d| d.links[0].role_id = "other-role".into()),
        Box::new(|d| d.bindings[0].subject_id = "u2".into()),
    ];
    for mutate in cases {
        *store.data.lock().unwrap() = original.clone();
        assert_eq!(
            service.check(q("t1/u1::report::read::r1")).unwrap(),
            AccessDecision::Allow
        );
        mutate(&mut store.data.lock().unwrap());
        assert_eq!(
            service.check(q("t1/u1::report::read::r1")).unwrap(),
            AccessDecision::Deny
        );
    }
}

#[test]
fn disabled_domain_is_zero_and_platform_admin_is_not_a_business_bypass() {
    let (service, store) = setup(TenancyMode::Disabled);
    grant(
        &mut store.data.lock().unwrap(),
        "0",
        "u1",
        "reader0",
        "report",
        "read",
        ResourceScope::Type,
        RoleKind::Business,
    );
    assert_eq!(
        service.check(q("0/u1::report::read::r1")).unwrap(),
        AccessDecision::Allow
    );
    assert_eq!(
        service.check(q("t1/u1::report::read::r1")).unwrap(),
        AccessDecision::Deny
    );
    let enabled = CoreAccessService::new(TenancyMode::Enabled, catalog(), store.clone());
    grant(
        &mut store.data.lock().unwrap(),
        "0",
        "u1",
        "system",
        "idp.platform",
        "access.manage",
        ResourceScope::Type,
        RoleKind::SystemAdmin,
    );
    assert_eq!(
        enabled
            .check(q("0/u1::idp.platform::access.manage"))
            .unwrap(),
        AccessDecision::Allow
    );
    assert_eq!(
        enabled
            .check(q("0/u1::idp.platform::access.manage::t1"))
            .unwrap(),
        AccessDecision::Deny
    );
    assert_eq!(
        enabled.check(q("t2/u1::report::read::r1")).unwrap(),
        AccessDecision::Deny
    );
    assert_eq!(
        enabled.check(q("0/u1::report::read::r1")).unwrap(),
        AccessDecision::Deny
    );
}

#[test]
fn batches_preserve_order_and_duplicates_with_one_store_call() {
    let (service, store) = setup(TenancyMode::Enabled);
    let inputs = [
        "t1/u1::report::read::r1",
        "t1/u1::report::unknown",
        "t1/u1::report::read::r2",
        "t1/u1::report::read::r1",
    ];
    assert_eq!(
        service
            .check_many(BatchAccessQuery {
                queries: inputs.map(q).to_vec()
            })
            .unwrap(),
        vec![
            AccessDecision::Allow,
            AccessDecision::Deny,
            AccessDecision::Deny,
            AccessDecision::Allow
        ]
    );
    assert_eq!(store.checks.load(Ordering::SeqCst), 1);
    assert_eq!(
        service
            .check_many(BatchAccessQuery {
                queries: vec![q(inputs[0]); 100]
            })
            .unwrap()
            .len(),
        100
    );
    let before = store.checks.load(Ordering::SeqCst);
    for queries in [
        vec![],
        vec![q(inputs[0]); 101],
        vec![q(inputs[0]), q("t2/u1::report::read")],
        vec![q(inputs[0]), q("t1/u2::report::read")],
    ] {
        assert!(service.check_many(BatchAccessQuery { queries }).is_err());
    }
    assert_eq!(store.checks.load(Ordering::SeqCst), before);
}

#[test]
fn backend_failures_and_invalid_results_are_not_allow_or_normal_deny() {
    let (service, store) = setup(TenancyMode::Enabled);
    store.data.lock().unwrap().fail = true;
    assert!(matches!(
        service.check(q("t1/u1::report::read::r1")),
        Err(AccessError::Store(_))
    ));
    {
        let mut d = store.data.lock().unwrap();
        d.fail = false;
        d.wrong_batch_length = true;
    }
    assert_eq!(
        service.check(q("t1/u1::report::read::r1")),
        Err(AccessError::InvalidStoreResponse)
    );
}

#[test]
fn current_permission_status_is_read_from_the_store_not_startup_metadata() {
    let (_, store) = setup(TenancyMode::Enabled);
    let mut initially_disabled = definition("report", "read");
    initially_disabled.enabled = false;
    let service = CoreAccessService::new(
        TenancyMode::Enabled,
        PermissionCatalog::new(vec![initially_disabled]).unwrap(),
        store.clone(),
    );
    assert_eq!(
        service.check(q("t1/u1::report::read::r1")).unwrap(),
        AccessDecision::Allow
    );
    store
        .data
        .lock()
        .unwrap()
        .permissions
        .get_mut(&definition("report", "read").key)
        .unwrap()
        .enabled = false;
    assert_eq!(
        service.check(q("t1/u1::report::read::r1")).unwrap(),
        AccessDecision::Deny
    );
}

#[test]
fn role_pages_are_distinct_and_cursors_cannot_cross_subject_or_tenant() {
    let (service, store) = setup(TenancyMode::Enabled);
    {
        let mut d = store.data.lock().unwrap();
        grant(
            &mut d,
            "t1",
            "u1",
            "editor",
            "report",
            "update",
            ResourceScope::Type,
            RoleKind::Business,
        );
        grant(
            &mut d,
            "t1",
            "u1",
            "reader",
            "report",
            "read",
            ResourceScope::Instance("r2".into()),
            RoleKind::Business,
        );
    }
    let first = service
        .list_subject_roles(
            "t1",
            "u1",
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(first.items[0].id, "editor");
    assert!(first.has_more);
    let second_request = AccessPageRequest {
        limit: 1,
        cursor: first.next_cursor.clone(),
        sort_order: None,
    };
    let second = service
        .list_subject_roles("t1", "u1", second_request.clone())
        .unwrap();
    assert_eq!(second.items[0].id, "reader");
    assert!(!second.has_more);
    assert!(second.next_cursor.is_none());
    assert_eq!(
        service.list_subject_roles("t2", "u1", second_request.clone()),
        Err(AccessError::InvalidCursor)
    );
    assert_eq!(
        service.list_subject_roles("t1", "u2", second_request),
        Err(AccessError::InvalidCursor)
    );
    for limit in [0, 201] {
        assert!(service
            .list_subject_roles(
                "t1",
                "u1",
                AccessPageRequest {
                    limit,
                    cursor: None,
                    sort_order: None,
                }
            )
            .is_err());
    }
    let mut invalid = first.next_cursor.unwrap();
    invalid.version = 2;
    assert!(service
        .list_subject_roles(
            "t1",
            "u1",
            AccessPageRequest {
                limit: 1,
                cursor: Some(invalid),
                sort_order: None,
            }
        )
        .is_err());
}

#[test]
fn role_permissions_use_composite_cursor_and_keep_disabled_state_visible() {
    let (service, store) = setup(TenancyMode::Enabled);
    grant(
        &mut store.data.lock().unwrap(),
        "t1",
        "u1",
        "reader",
        "report",
        "update",
        ResourceScope::Type,
        RoleKind::Business,
    );
    store
        .data
        .lock()
        .unwrap()
        .permissions
        .get_mut(&definition("report", "update").key)
        .unwrap()
        .enabled = false;
    let first = service
        .list_role_permissions(
            "t1",
            "reader",
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(first.items[0].key.action, "read");
    let next = AccessPageRequest {
        limit: 1,
        cursor: first.next_cursor,
        sort_order: None,
    };
    let second = service
        .list_role_permissions("t1", "reader", next.clone())
        .unwrap();
    assert_eq!(second.items[0].key.action, "update");
    assert!(!second.items[0].enabled);
    assert!(service.list_role_permissions("t1", "other", next).is_err());
    assert_eq!(
        service.check(q("t1/u1::report::update::r1")).unwrap(),
        AccessDecision::Deny
    );
}

#[test]
fn tenant_lists_require_choose_policy_and_do_not_expose_system_or_removed_memberships() {
    let (service, store) = setup(TenancyMode::Enabled);
    let choose = LoginTenantPolicy::ChooseAfterAuthentication;
    let first = service
        .list_subject_tenants(
            "u1",
            &choose,
            AccessPageRequest {
                limit: 1,
                cursor: None,
                sort_order: None,
            },
        )
        .unwrap();
    assert_eq!(first.items[0].tenant.id, "t1");
    assert!(first.has_more);
    assert!(service
        .list_subject_tenants(
            "u2",
            &choose,
            AccessPageRequest {
                limit: 1,
                cursor: first.next_cursor,
                sort_order: None,
            }
        )
        .is_err());
    store
        .data
        .lock()
        .unwrap()
        .memberships
        .iter_mut()
        .find(|m| m.tenant_id == "t2")
        .unwrap()
        .status = MembershipStatus::Removed;
    let result = service
        .list_subject_tenants("u1", &choose, AccessPageRequest::default())
        .unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(
        service.list_subject_tenants(
            "u1",
            &LoginTenantPolicy::Fixed {
                tenant_id: "t1".into()
            },
            AccessPageRequest::default()
        ),
        Err(AccessError::FeatureDisabled)
    );
    let disabled = CoreAccessService::new(TenancyMode::Disabled, catalog(), store);
    assert!(disabled
        .list_subject_tenants("u1", &choose, AccessPageRequest::default())
        .is_err());
}

#[test]
fn lists_do_not_mix_tenants_or_subjects_even_when_role_ids_repeat() {
    let (service, store) = setup(TenancyMode::Enabled);
    assert!(service
        .list_subject_roles("t2", "u1", AccessPageRequest::default())
        .unwrap()
        .items
        .is_empty());
    assert!(service
        .list_role_permissions("t2", "reader", AccessPageRequest::default())
        .unwrap()
        .items
        .is_empty());
    {
        let mut d = store.data.lock().unwrap();
        d.memberships.push(membership("t2", "u2"));
        grant(
            &mut d,
            "t2",
            "u2",
            "reader",
            "report",
            "update",
            ResourceScope::Type,
            RoleKind::Business,
        );
    }
    assert!(service
        .list_subject_roles("t2", "u1", AccessPageRequest::default())
        .unwrap()
        .items
        .is_empty());
    let roles = service
        .list_subject_roles("t2", "u2", AccessPageRequest::default())
        .unwrap();
    assert_eq!(roles.items.len(), 1);
    assert_eq!(roles.items[0].tenant_id, "t2");
    let permissions = service
        .list_role_permissions("t2", "reader", AccessPageRequest::default())
        .unwrap();
    assert_eq!(permissions.items.len(), 1);
    assert_eq!(permissions.items[0].key.action, "update");
    let tenants = service
        .list_subject_tenants(
            "u2",
            &LoginTenantPolicy::ChooseAfterAuthentication,
            AccessPageRequest::default(),
        )
        .unwrap();
    assert_eq!(tenants.items.len(), 1);
    assert_eq!(tenants.items[0].tenant.id, "t2");
    assert_eq!(tenants.items[0].membership.subject_id, "u2");
}

#[test]
fn admin_preflight_uses_actor_domain_and_fixed_operation_permissions() {
    let (service, store) = setup(TenancyMode::Enabled);
    let actor = AccessActor {
        tenant_id: "t1".into(),
        subject_id: "u1".into(),
        session_id: "s1".into(),
    };
    assert_eq!(
        service.require_admin_access(&actor, "t1", AccessAdminOperation::ManageRoles),
        Err(AccessError::Forbidden)
    );
    grant(
        &mut store.data.lock().unwrap(),
        "t1",
        "u1",
        "security",
        "idp.tenant",
        "roles.manage",
        ResourceScope::Type,
        RoleKind::TenantSecurityAdmin,
    );
    assert!(service
        .require_admin_access(&actor, "t1", AccessAdminOperation::ManageRoles)
        .is_ok());
    assert_eq!(
        service.require_admin_access(&actor, "t2", AccessAdminOperation::ManageRoles),
        Err(AccessError::Forbidden)
    );
    assert_eq!(
        service.require_admin_access(&actor, "t1", AccessAdminOperation::BindUser),
        Err(AccessError::Forbidden)
    );
    let platform = AccessActor {
        tenant_id: "0".into(),
        ..actor
    };
    grant(
        &mut store.data.lock().unwrap(),
        "0",
        "u1",
        "system",
        "idp.platform",
        "users.bind",
        ResourceScope::Type,
        RoleKind::SystemAdmin,
    );
    assert!(service
        .require_admin_access(&platform, "t2", AccessAdminOperation::BindUser)
        .is_ok());
    assert_eq!(
        service.require_admin_access(&platform, "t2", AccessAdminOperation::ManageRoles),
        Err(AccessError::Forbidden)
    );
}

fn registration(tenant_id: &str) -> Result<TenantRegistration, AccessError> {
    let mut a = account("new-user");
    a.status = AccountStatus::PendingVerification;
    let verification = EmailVerificationCode {
        id: "v1".into(),
        account_id: a.id.clone(),
        email: a.email.clone(),
        code: "000000".into(),
        issued_at: UNIX_EPOCH,
        expires_at: UNIX_EPOCH + Duration::from_secs(900),
        consumed_at: None,
    };
    TenantRegistration::new(TenancyMode::Enabled, tenant_id.into(), a, verification)
}

#[test]
fn registration_contract_requires_a_tenant_and_cannot_create_a_bare_user() {
    assert!(registration("").is_err());
    assert!(registration("0").is_err());
    let prepared = registration("t1").unwrap();
    let mut wrong = prepared.verification().clone();
    wrong.account_id = "other".into();
    assert!(TenantRegistration::new(
        TenancyMode::Enabled,
        "t1".into(),
        prepared.account().clone(),
        wrong
    )
    .is_err());
    let (_, store) = setup(TenancyMode::Enabled);
    store
        .data
        .lock()
        .unwrap()
        .tenants
        .get_mut("t1")
        .unwrap()
        .allow_registration = false;
    assert!(store.create_registered_account(&prepared).is_err());
    assert!(!store.data.lock().unwrap().accounts.contains_key("new-user"));
    store
        .data
        .lock()
        .unwrap()
        .tenants
        .get_mut("t1")
        .unwrap()
        .allow_registration = true;
    store.data.lock().unwrap().fail_registration = true;
    assert!(store.create_registered_account(&prepared).is_err());
    {
        let d = store.data.lock().unwrap();
        assert!(!d.accounts.contains_key("new-user"));
        assert!(!d.memberships.iter().any(|m| m.subject_id == "new-user"));
        assert!(d.verifications.is_empty());
    }
    store.data.lock().unwrap().fail_registration = false;
    store.create_registered_account(&prepared).unwrap();
    assert_eq!(
        store
            .data
            .lock()
            .unwrap()
            .registrations
            .get("new-user")
            .unwrap(),
        "t1"
    );
    assert!(store
        .create_registered_account(&registration("t2").unwrap())
        .is_err());
    assert!(!store
        .data
        .lock()
        .unwrap()
        .memberships
        .iter()
        .any(|m| m.subject_id == "new-user" && m.tenant_id == "t2"));
}

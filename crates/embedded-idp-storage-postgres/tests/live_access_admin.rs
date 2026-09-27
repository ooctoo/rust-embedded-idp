//! Explicitly opt-in admin tests. Each test owns and removes its random schema.
use embedded_idp_core::access::*;
use embedded_idp_core::{Clock, IdGenerator};
use embedded_idp_storage_postgres::*;
use std::{
    env,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const NOW: u64 = 1_000;

fn catalog() -> PermissionCatalog {
    PermissionCatalog::new(
        [("report", "read"), ("report", "update")]
            .into_iter()
            .map(|(resource_type, action)| PermissionDefinition {
                tenant_id: "0".into(),
                key: PermissionKey {
                    business_id: "f_01".into(),
                    resource_type: resource_type.into(),
                    action: action.into(),
                },
                description: action.into(),
                category: PermissionCategory::Business,
                enabled: true,
                archived: false,
                version: 1,
                created_at: None,
            })
            .collect(),
    )
    .unwrap()
}

#[derive(Clone, Copy)]
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW)
    }
}

#[derive(Clone, Copy)]
struct UuidIds;
impl IdGenerator for UuidIds {
    fn next_id(&self, _: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(10_000);
        Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128).to_string()
    }
}

struct Db {
    adapter: PostgresStorageAdapter,
    mode: TenancyMode,
    actor: Uuid,
    owner: Uuid,
    member: Uuid,
    actor_session: Uuid,
    member_session: Uuid,
}

impl Db {
    fn new(mode: TenancyMode) -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_access_admin_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-access-admin-live-test".into(),
                max_connections: 8,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        adapter.initialize_access_schema(mode, &catalog()).unwrap();
        let db = Self {
            adapter,
            mode,
            actor: Uuid::now_v7(),
            owner: Uuid::now_v7(),
            member: Uuid::now_v7(),
            actor_session: Uuid::now_v7(),
            member_session: Uuid::now_v7(),
        };
        db.seed();
        db
    }

    fn schema(&self) -> &str {
        self.adapter.schema_name()
    }
    fn target(&self) -> &str {
        if self.mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        }
    }
    fn store(&self) -> PostgresAccessStore {
        PostgresAccessStore::new(self.adapter.clone(), self.mode).unwrap()
    }
    fn service(&self) -> CoreAccessAdminService<PostgresAccessStore, FixedClock, UuidIds> {
        CoreAccessAdminService::new(self.mode, catalog(), self.store(), FixedClock, UuidIds)
    }
    fn context(&self, session: impl Into<String>) -> AccessAdminContext {
        AccessAdminContext {
            actor: AccessActor {
                tenant_id: "0".into(),
                subject_id: self.actor.to_string(),
                session_id: session.into(),
            },
            authentication_source: "live_test".into(),
            request_id: Uuid::now_v7().to_string(),
        }
    }
    fn command(&self, mutation: AccessAdminMutation) -> AccessAdminCommand {
        AccessAdminCommand {
            tenant_id: self.target().into(),
            mutation,
        }
    }
    fn seed(&self) {
        let s = self.schema();
        let target = self.target();
        let mut client = self.adapter.connect().unwrap();
        let mut tx = client.transaction().unwrap();
        if self.mode == TenancyMode::Enabled {
            tx.execute(&format!("insert into {s}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values('t1','tenant','Tenant 1','active',true,$1),('t2','tenant','Tenant 2','active',true,$1)"), &[&(NOW as i64)]).unwrap();
            for tenant in ["t1", "t2"] {
                for permission in catalog()
                    .definitions()
                    .filter(|p| p.category != PermissionCategory::Platform)
                {
                    let category = if permission.category == PermissionCategory::Tenant {
                        "tenant"
                    } else {
                        "business"
                    };
                    tx.execute(&format!("insert into {s}.access_permissions(tenant_id,business_id,resource_type,action,category,description,enabled) values($1,$2,$3,$4,$5,$6,true)"), &[&tenant,&permission.key.business_id,&permission.key.resource_type,&permission.key.action,&category,&permission.description]).unwrap();
                }
            }
        }
        for (id, tenant, email) in [
            (self.actor, "0", "actor@example.test"),
            (self.owner, target, "owner@example.test"),
            (self.member, target, "member@example.test"),
        ] {
            tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,$2,$3,'fixture-hash','active',$4)"), &[&id, &tenant, &email, &(NOW as i64)]).unwrap();
            tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',$3)"), &[&tenant, &id, &(NOW as i64)]).unwrap();
        }
        if self.mode == TenancyMode::Enabled {
            tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('t2',$1,'active',$2)"), &[&self.member, &(NOW as i64)]).unwrap();
            tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('t2',$1,'active',$2)"), &[&self.owner, &(NOW as i64)]).unwrap();
        }
        let platform_role = Uuid::now_v7();
        tx.execute(&format!("insert into {s}.access_roles(tenant_id,business_id,id,key,name,status,kind,created_at_epoch) values('0','idp',$1,'idp_system_admin','IDP管理员','active','system_admin',$2)"), &[&platform_role, &(NOW as i64)]).unwrap();
        tx.execute(&format!("insert into {s}.access_role_permissions(tenant_id,business_id,role_id,resource_type,action) select '0','idp',$1,resource_type,action from {s}.access_permissions where tenant_id='0' and business_id='idp' and category='platform'"), &[&platform_role]).unwrap();
        tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,created_at_epoch,created_by) values($1,'0','idp',$2,$3,'type','idp.platform',$4,$2)"), &[&Uuid::now_v7(), &self.actor, &platform_role, &(NOW as i64)]).unwrap();
        if target != "0" {
            let target_role = Uuid::now_v7();
            tx.execute(&format!("insert into {s}.access_roles(tenant_id,business_id,id,key,name,status,kind,created_at_epoch) values($1,'idp',$2,'idp_tenant_security_admin','IDP租户管理员','active','tenant_security_admin',$3)"), &[&target, &target_role, &(NOW as i64)]).unwrap();
            tx.execute(&format!("insert into {s}.access_role_permissions(tenant_id,business_id,role_id,resource_type,action) select $1,'idp',$2,resource_type,action from {s}.access_permissions where tenant_id=$1 and business_id='idp' and category='tenant'"), &[&target, &target_role]).unwrap();
            tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,created_at_epoch,created_by) values($1,$2,'idp',$3,$4,'type','idp.tenant',$5,$3)"), &[&Uuid::now_v7(), &target, &self.owner, &target_role, &(NOW as i64)]).unwrap();
            let other_role = Uuid::now_v7();
            tx.execute(&format!("insert into {s}.access_roles(tenant_id,business_id,id,key,name,status,kind,created_at_epoch) values('t2','idp',$1,'idp_tenant_security_admin','IDP租户管理员','active','tenant_security_admin',$2)"), &[&other_role, &(NOW as i64)]).unwrap();
            tx.execute(&format!("insert into {s}.access_role_permissions(tenant_id,business_id,role_id,resource_type,action) select 't2','idp',$1,resource_type,action from {s}.access_permissions where tenant_id='t2' and business_id='idp' and category='tenant'"), &[&other_role]).unwrap();
            tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,created_at_epoch,created_by) values($1,'t2','idp',$2,$3,'type','idp.tenant',$4,$2)"), &[&Uuid::now_v7(), &self.owner, &other_role, &(NOW as i64)]).unwrap();
        }
        tx.execute(&format!("insert into {s}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values('live-admin-client','Live admin','[]','public_desktop',true,$1)"), &[&(NOW as i64)]).unwrap();
        tx.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','0',$1,$2,'live-admin-client','active',$3,$4,1,$3),('management',$5,$6,$7,'live-admin-client','active',$3,$4,1,$3)"), &[&self.actor_session, &self.actor, &(NOW as i64), &((NOW + 1_000) as i64), &target, &self.member_session, &self.member]).unwrap();
        tx.execute(
            &format!("update {s}.access_state set bootstrap_completed_at_epoch=$1"),
            &[&(NOW as i64)],
        )
        .unwrap();
        tx.commit().unwrap();
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        assert!(self.schema().starts_with("idp_access_admin_it_"));
        if let Ok(mut client) = self.adapter.connect() {
            let _ = client.batch_execute(&format!("drop schema {} cascade", self.schema()));
        }
    }
}

fn event_role_id(event: AccessAuditEvent) -> String {
    match event.change {
        AccessChange::Role {
            after: Some(record),
            ..
        } => record.role.id,
        _ => panic!("expected role mutation"),
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn admin_role_lifecycle_versions_and_domain_isolation_work_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let service = db.service();
        let role = event_role_id(
            service
                .execute(
                    db.context(db.actor_session.to_string()),
                    db.command(AccessAdminMutation::CreateRole {
                        business_id: "f_01".into(),
                        key: "reader".into(),
                        name: "Reader".into(),
                    }),
                )
                .unwrap(),
        );
        service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::ReplaceRolePermissions {
                    business_id: "f_01".into(),
                    role_id: role.clone(),
                    permissions: vec![PermissionKey {
                        business_id: "f_01".into(),
                        resource_type: "report".into(),
                        action: "read".into(),
                    }],
                    expected_version: 1,
                }),
            )
            .unwrap();
        let binding = service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::GrantRole {
                    business_id: "f_01".into(),
                    subject_id: db.member.to_string(),
                    role_id: role.clone(),
                    scope: RoleBindingScope::Resource {
                        resource_type: "report".into(),
                        scope: ResourceScope::Instance("report-1".into()),
                    },
                }),
            )
            .unwrap();
        let binding_id = match binding.change {
            AccessChange::Binding {
                after: Some(binding),
                ..
            } => binding.id,
            _ => panic!("expected binding"),
        };
        service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::ReplaceRolePermissions {
                    business_id: "f_01".into(),
                    role_id: role.clone(),
                    permissions: vec![],
                    expected_version: 2,
                }),
            )
            .unwrap();
        service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::ReplaceRolePermissions {
                    business_id: "f_01".into(),
                    role_id: role.clone(),
                    permissions: vec![PermissionKey {
                        business_id: "f_01".into(),
                        resource_type: "report".into(),
                        action: "read".into(),
                    }],
                    expected_version: 3,
                }),
            )
            .unwrap();
        let mut client = db.adapter.connect().unwrap();
        assert_eq!(
            client
                .query_one(
                    &format!(
                        "select count(*) from {}.access_role_bindings where id=$1",
                        db.schema()
                    ),
                    &[&Uuid::parse_str(&binding_id).unwrap()]
                )
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        let replacement = service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::GrantRole {
                    business_id: "f_01".into(),
                    subject_id: db.member.to_string(),
                    role_id: role.clone(),
                    scope: RoleBindingScope::Resource {
                        resource_type: "report".into(),
                        scope: ResourceScope::Instance("report-1".into()),
                    },
                }),
            )
            .unwrap();
        let replacement_id = match replacement.change {
            AccessChange::Binding {
                after: Some(binding),
                ..
            } => binding.id,
            _ => panic!("expected replacement binding"),
        };
        service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::UpdateRole {
                    business_id: "f_01".into(),
                    role_id: role.clone(),
                    name: "Reader v2".into(),
                    status: RoleStatus::Active,
                    expected_version: 4,
                }),
            )
            .unwrap();
        assert_eq!(
            service.execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::UpdateRole {
                    business_id: "f_01".into(),
                    role_id: role.clone(),
                    name: "stale".into(),
                    status: RoleStatus::Active,
                    expected_version: 4
                })
            ),
            Err(AccessError::Conflict("version"))
        );
        service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::RevokeRole {
                    business_id: "f_01".into(),
                    binding_id: replacement_id,
                }),
            )
            .unwrap();
        service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::DeleteRole {
                    business_id: "f_01".into(),
                    role_id: role.clone(),
                    expected_version: 5,
                }),
            )
            .unwrap();
        assert_eq!(
            client
                .query_one(
                    &format!(
                        "select count(*) from {}.access_roles where tenant_id=$1 and id=$2",
                        db.schema()
                    ),
                    &[&db.target(), &Uuid::parse_str(&role).unwrap()]
                )
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(client.query_one(&format!("select count(*) from {}.access_roles where tenant_id='t2' and key='reader'", db.schema()), &[]).unwrap().get::<_, i64>(0), 0);
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn removal_cleans_tenant_credentials_and_audit_or_actor_failure_rolls_back() {
    let db = Db::new(TenancyMode::Enabled);
    let service = db.service();
    let role = event_role_id(
        service
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::CreateRole {
                    business_id: "f_01".into(),
                    key: "reader".into(),
                    name: "Reader".into(),
                }),
            )
            .unwrap(),
    );
    service
        .execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::ReplaceRolePermissions {
                business_id: "f_01".into(),
                role_id: role.clone(),
                permissions: vec![PermissionKey {
                    business_id: "f_01".into(),
                    resource_type: "report".into(),
                    action: "read".into(),
                }],
                expected_version: 1,
            }),
        )
        .unwrap();
    service
        .execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::GrantRole {
                business_id: "f_01".into(),
                subject_id: db.member.to_string(),
                role_id: role,
                scope: RoleBindingScope::Resource {
                    resource_type: "report".into(),
                    scope: ResourceScope::Type,
                },
            }),
        )
        .unwrap();
    let t2_session = Uuid::now_v7();
    let t1_device = Uuid::now_v7();
    let t2_device = Uuid::now_v7();
    let t1_device_binding = Uuid::now_v7();
    let t2_device_binding = Uuid::now_v7();
    let t1_refresh = Uuid::now_v7();
    let t2_refresh = Uuid::now_v7();
    let s = db.schema();
    let mut client = db.adapter.connect().unwrap();
    client.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','t2',$1,$2,'live-admin-client','active',$3,$4,1,$3)"), &[&t2_session, &db.member, &(NOW as i64), &((NOW + 1_000) as i64)]).unwrap();
    client.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values('t1',$1,'live-admin-client','t1 device','active',$3),('t2',$2,'live-admin-client','t2 device','active',$3)"), &[&t1_device, &t2_device, &(NOW as i64)]).unwrap();
    client.execute(&format!("insert into {s}.account_device_bindings(tenant_id,id,account_id,device_id,status,bound_at_epoch) values('t1',$1,$2,$3,'active',$5),('t2',$4,$2,$6,'active',$5)"), &[&t1_device_binding, &db.member, &t1_device, &t2_device_binding, &(NOW as i64), &t2_device]).unwrap();
    client.execute(&format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values('t1',$1,$2,$3,1,$5,$6),('t2',$4,$7,$8,1,$5,$6)"), &[&t1_refresh, &db.member_session, &vec![1_u8; 32], &t2_refresh, &(NOW as i64), &((NOW + 1_000) as i64), &t2_session, &vec![2_u8; 32]]).unwrap();
    client.execute(&format!("insert into {s}.authorization_codes(tenant_id,code_digest,account_id,source_session_id,login_entry,client_id,redirect_uri,scope,created_at_epoch,expires_at_epoch) values('t1',$4,$1,$6,'test','live-admin-client','http://localhost','openid',$2,$3),('t2',$5,$1,$7,'test','live-admin-client','http://localhost','openid',$2,$3)"), &[&db.member, &(NOW as i64), &((NOW+1_000) as i64), &vec![10_u8;32], &vec![11_u8;32], &db.member_session, &t2_session]).unwrap();
    client.execute(&format!("insert into {s}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values('t1',$1,$2,'member@example.test','111111',$3,$4),('t2',$5,$2,'member@example.test','222222',$3,$4)"), &[&Uuid::now_v7(), &db.member, &(NOW as i64), &((NOW + 1_000) as i64), &Uuid::now_v7()]).unwrap();
    client.execute(&format!("insert into {s}.auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch,source_tenant_id,source_session_id) values($1,$2,$3,'live-admin-client','test','login',$4,$5,'t1',$6),($7,$8,$3,'live-admin-client','test','login',$4,$5,'t2',$9),($10,$11,$3,'live-admin-client','test','login',$4,$5,null,null)"), &[&Uuid::now_v7(), &vec![3_u8; 32], &db.member, &(NOW as i64), &((NOW + 1_000) as i64), &db.member_session, &Uuid::now_v7(), &vec![4_u8; 32], &t2_session, &Uuid::now_v7(), &vec![5_u8; 32]]).unwrap();
    service
        .execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::SetMemberStatus {
                subject_id: db.member.to_string(),
                status: MembershipStatus::Removed,
                expected_version: 1,
            }),
        )
        .unwrap();
    assert_eq!(client.query_one(&format!("select status from {}.access_memberships where tenant_id='t1' and account_id=$1", db.schema()), &[&db.member]).unwrap().get::<_, String>(0), "removed");
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select status from {}.auth_sessions where tenant_id='t1' and id=$1",
                    db.schema()
                ),
                &[&db.member_session]
            )
            .unwrap()
            .get::<_, String>(0),
        "revoked"
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select status from {}.auth_sessions where tenant_id='t2' and id=$1",
                    db.schema()
                ),
                &[&t2_session]
            )
            .unwrap()
            .get::<_, String>(0),
        "active"
    );
    assert_eq!(client.query_one(&format!("select revocation_reason from {}.refresh_tokens where tenant_id='t1' and id=$1", db.schema()), &[&t1_refresh]).unwrap().get::<_, Option<String>>(0).as_deref(), Some("administrative"));
    assert!(client.query_one(&format!("select revoked_at_epoch is null from {}.refresh_tokens where tenant_id='t2' and id=$1", db.schema()), &[&t2_refresh]).unwrap().get::<_, bool>(0));
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select count(*) from {}.authorization_codes where tenant_id='t1'",
                    db.schema()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select count(*) from {}.authorization_codes where tenant_id='t2'",
                    db.schema()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select count(*) from {}.email_verification_codes where tenant_id='t1'",
                    db.schema()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select count(*) from {}.email_verification_codes where tenant_id='t2'",
                    db.schema()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select status from {}.account_device_bindings where id=$1",
                    db.schema()
                ),
                &[&t1_device_binding]
            )
            .unwrap()
            .get::<_, String>(0),
        "unbound"
    );
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select status from {}.account_device_bindings where id=$1",
                    db.schema()
                ),
                &[&t2_device_binding]
            )
            .unwrap()
            .get::<_, String>(0),
        "active"
    );
    assert_eq!(client.query_one(&format!("select count(*) from {}.auth_tenant_selections where account_id=$1 and (source_tenant_id='t1' or source_tenant_id is null) and revoked_at_epoch is not null", db.schema()), &[&db.member]).unwrap().get::<_, i64>(0), 2);
    assert!(client.query_one(&format!("select revoked_at_epoch is null from {}.auth_tenant_selections where account_id=$1 and source_tenant_id='t2'", db.schema()), &[&db.member]).unwrap().get::<_, bool>(0));
    assert_eq!(client.query_one(&format!("select count(*) from {}.access_role_bindings where tenant_id='t1' and account_id=$1", db.schema()), &[&db.member]).unwrap().get::<_, i64>(0), 0);
    service
        .execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::BindMember {
                subject_id: db.member.to_string(),
            }),
        )
        .unwrap();
    assert_eq!(client.query_one(&format!("select count(*) from {}.access_role_bindings where tenant_id='t1' and account_id=$1", db.schema()), &[&db.member]).unwrap().get::<_, i64>(0), 0);
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select status from {}.auth_sessions where tenant_id='t1' and id=$1",
                    db.schema()
                ),
                &[&db.member_session]
            )
            .unwrap()
            .get::<_, String>(0),
        "revoked"
    );
    client.batch_execute(&format!("create function {0}.fail_audit() returns trigger language plpgsql as $$ begin raise exception 'audit blocked'; end $$; create trigger fail_audit before insert on {0}.access_audit_events for each row execute function {0}.fail_audit()", db.schema())).unwrap();
    assert!(service
        .execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::CreateRole {
                business_id: "f_01".into(),
                key: "audit-fails".into(),
                name: "Audit fails".into()
            })
        )
        .is_err());
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select count(*) from {}.access_roles where key='audit-fails'",
                    db.schema()
                ),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    client
        .batch_execute(&format!(
            "drop trigger fail_audit on {0}.access_audit_events; drop function {0}.fail_audit()",
            db.schema()
        ))
        .unwrap();
    assert_eq!(
        service.execute(
            db.context(Uuid::now_v7().to_string()),
            db.command(AccessAdminMutation::CreateRole {
                business_id: "f_01".into(),
                key: "invalid-session".into(),
                name: "Invalid session".into()
            })
        ),
        Err(AccessError::Forbidden)
    );
    client
        .execute(
            &format!(
                "update {}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'",
                db.schema()
            ),
            &[],
        )
        .unwrap();
    assert_eq!(
        service.execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::CreateRole {
                business_id: "f_01".into(),
                key: "directory-disabled".into(),
                name: "Directory disabled".into()
            })
        ),
        Err(AccessError::Forbidden)
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn admin_transaction_panic_rolls_back_and_returns_a_usable_connection() {
    let db = Db::new(TenancyMode::Enabled);
    let store = db.store();
    let role_id = Uuid::now_v7();
    let context = db.context(db.actor_session.to_string());
    let scope = AccessWriteScope {
        mode: TenancyMode::Enabled,
        exclusive_state: false,
        tenant_ids: vec!["0".into(), "t1".into()],
        subject_ids: vec![db.actor.to_string()],
    };
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = store.admin_transaction::<()>(|tx| {
            tx.lock_scope(&scope)?;
            assert!(tx.actor_is_active(&context.actor, FixedClock.now())?);
            tx.apply_change(
                &AccessChange::Role {
                    before: None,
                    after: Some(AccessRoleRecord {
                        role: Role {
                            id: role_id.to_string(),
                            tenant_id: "t1".into(),
                            business_id: "f_01".into(),
                            key: "panic-role".into(),
                            name: "Panic role".into(),
                            status: RoleStatus::Active,
                            kind: RoleKind::Business,
                            version: 1,
                            created_at: FixedClock.now(),
                        },
                        permissions: vec![],
                    }),
                },
                FixedClock.now(),
            )?;
            panic!("test transaction panic");
        });
    }));
    assert!(panic.is_err());
    let mut client = db.adapter.connect().unwrap();
    assert_eq!(
        client
            .query_one(
                &format!(
                    "select count(*) from {}.access_roles where id=$1",
                    db.schema()
                ),
                &[&role_id]
            )
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        client.query_one("select 1", &[]).unwrap().get::<_, i32>(0),
        1
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_last_tenant_security_admin_revocation_keeps_one_effective_admin() {
    let db = Db::new(TenancyMode::Enabled);
    let setup = db.service();
    setup
        .execute(
            db.context(db.actor_session.to_string()),
            db.command(AccessAdminMutation::SetSecurityAdmin {
                subject_id: db.member.to_string(),
                appointed: true,
            }),
        )
        .unwrap();
    let store_a = db.store();
    let store_b = db.store();
    let barrier = Arc::new(Barrier::new(3));
    let actor = db.actor.to_string();
    let actor_session = db.actor_session.to_string();
    let owner = db.owner.to_string();
    let member = db.member.to_string();
    let catalog_a = catalog();
    let catalog_b = catalog();
    let a_barrier = barrier.clone();
    let first_actor = actor.clone();
    let first_session = actor_session.clone();
    let first = thread::spawn(move || {
        let service = CoreAccessAdminService::new(
            TenancyMode::Enabled,
            catalog_a,
            store_a,
            FixedClock,
            UuidIds,
        );
        a_barrier.wait();
        service.execute(
            AccessAdminContext {
                actor: AccessActor {
                    tenant_id: "0".into(),
                    subject_id: first_actor,
                    session_id: first_session,
                },
                authentication_source: "live_test".into(),
                request_id: Uuid::now_v7().to_string(),
            },
            AccessAdminCommand {
                tenant_id: "t1".into(),
                mutation: AccessAdminMutation::SetSecurityAdmin {
                    subject_id: owner,
                    appointed: false,
                },
            },
        )
    });
    let b_barrier = barrier.clone();
    let second = thread::spawn(move || {
        let service = CoreAccessAdminService::new(
            TenancyMode::Enabled,
            catalog_b,
            store_b,
            FixedClock,
            UuidIds,
        );
        b_barrier.wait();
        service.execute(
            AccessAdminContext {
                actor: AccessActor {
                    tenant_id: "0".into(),
                    subject_id: actor,
                    session_id: actor_session,
                },
                authentication_source: "live_test".into(),
                request_id: Uuid::now_v7().to_string(),
            },
            AccessAdminCommand {
                tenant_id: "t1".into(),
                mutation: AccessAdminMutation::SetSecurityAdmin {
                    subject_id: member,
                    appointed: false,
                },
            },
        )
    });
    barrier.wait();
    let results = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results
        .iter()
        .any(|result| matches!(result, Err(AccessError::Conflict("last_security_admin")))));
    let mut client = db.adapter.connect().unwrap();
    assert_eq!(client.query_one(&format!("select count(*) from {}.access_role_bindings b join {}.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id where b.tenant_id='t1' and r.kind='tenant_security_admin'", db.schema(), db.schema()), &[]).unwrap().get::<_, i64>(0), 1);
}

#[path = "access_admin/devices.rs"]
mod devices;

#[path = "access_admin/sessions.rs"]
mod sessions;

#[path = "access_admin/clients.rs"]
mod clients;

#[path = "access_admin/accounts.rs"]
mod accounts;

#[path = "access_admin/account_security.rs"]
mod account_security;

#[path = "access_admin/tenants.rs"]
mod tenants;

#[path = "access_admin/roles.rs"]
mod roles;

#[path = "access_admin/role_bindings.rs"]
mod role_bindings;

#[path = "access_admin/permissions.rs"]
mod permissions;

#[path = "access_admin/diagnostic.rs"]
mod diagnostic;

#[path = "access_admin/security_admin.rs"]
mod security_admin;

#[path = "access_admin/audit.rs"]
mod audit;

#[path = "access_admin/list_order.rs"]
mod list_order;

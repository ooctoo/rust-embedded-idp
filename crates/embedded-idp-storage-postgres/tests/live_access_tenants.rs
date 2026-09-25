//! Explicit opt-in tests for tenant and permission-directory administration.
use embedded_idp_core::access::*;
use embedded_idp_core::{Account, AccountStatus, Clock, IdGenerator};
use embedded_idp_storage_postgres::*;
use std::{
    env,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const NOW: u64 = 1_000;

fn key(resource_type: &str, action: &str) -> PermissionKey {
    PermissionKey {
        resource_type: resource_type.into(),
        action: action.into(),
    }
}
fn catalog() -> PermissionCatalog {
    PermissionCatalog::new(
        [
            ("report", "read"),
            ("report", "update"),
            ("dataset", "read"),
        ]
        .into_iter()
        .map(|(resource_type, action)| PermissionDefinition {
            tenant_id: "0".into(),
            key: key(resource_type, action),
            description: format!("host {resource_type}/{action}"),
            category: PermissionCategory::Business,
            enabled: true,
            archived: false,
            version: 1,
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
        static NEXT: AtomicU64 = AtomicU64::new(50_000);
        Uuid::from_u128(NEXT.fetch_add(1, Ordering::Relaxed) as u128).to_string()
    }
}

struct Db {
    adapter: PostgresStorageAdapter,
    mode: TenancyMode,
    actor: Uuid,
    actor_session: Uuid,
    admin: Uuid,
    other: Uuid,
    disabled: Uuid,
}
impl Db {
    fn new(mode: TenancyMode) -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_access_tenants_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-access-tenants-live-test".into(),
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
            actor_session: Uuid::now_v7(),
            admin: Uuid::now_v7(),
            other: Uuid::now_v7(),
            disabled: Uuid::now_v7(),
        };
        CoreAccessBootstrapService::new(mode, db.adapter.clone(), FixedClock, UuidIds)
            .initialize(
                Account {
                    id: db.actor.to_string(),
                    email: "platform@example.test".into(),
                    password_hash: "fixture-hash".into(),
                    display_name: None,
                    status: AccountStatus::Active,
                    created_at: UNIX_EPOCH,
                },
                Uuid::now_v7().to_string(),
            )
            .unwrap();
        db.seed_accounts_and_session();
        db
    }
    fn schema(&self) -> &str {
        self.adapter.schema_name()
    }
    fn store(&self) -> PostgresAccessStore {
        PostgresAccessStore::new(self.adapter.clone(), self.mode).unwrap()
    }
    fn service(&self) -> CoreAccessAdminService<PostgresAccessStore, FixedClock, UuidIds> {
        CoreAccessAdminService::new(self.mode, catalog(), self.store(), FixedClock, UuidIds)
    }
    fn context(&self) -> AccessAdminContext {
        AccessAdminContext {
            actor: AccessActor {
                tenant_id: "0".into(),
                subject_id: self.actor.to_string(),
                session_id: self.actor_session.to_string(),
            },
            authentication_source: "live_test".into(),
            request_id: Uuid::now_v7().to_string(),
        }
    }
    fn command(&self, tenant: &str, mutation: AccessAdminMutation) -> AccessAdminCommand {
        AccessAdminCommand {
            tenant_id: tenant.into(),
            mutation,
        }
    }
    fn create(
        &self,
        service: &impl AccessAdminService,
        id: &str,
        administrator: Uuid,
    ) -> Result<AccessAuditEvent, AccessError> {
        service.execute(
            self.context(),
            self.command(
                id,
                AccessAdminMutation::CreateTenant {
                    name: format!("Tenant {id}"),
                    allow_registration: true,
                    administrator_subject_id: administrator.to_string(),
                },
            ),
        )
    }
    fn seed_accounts_and_session(&self) {
        let s = self.schema();
        let mut c = self.adapter.connect().unwrap();
        let mut tx = c.transaction().unwrap();
        for (id, email, status) in [
            (self.admin, "admin@example.test", "active"),
            (self.other, "other@example.test", "active"),
            (self.disabled, "disabled@example.test", "disabled"),
        ] {
            tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,'0',$2,'fixture-hash',$3,$4)"), &[&id,&email,&status,&(NOW as i64)]).unwrap();
            tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('0',$1,'active',$2)"), &[&id,&(NOW as i64)]).unwrap();
        }
        tx.execute(&format!("insert into {s}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values('tenant-test','Tenant test','[]','public_desktop',true,$1)"), &[&(NOW as i64)]).unwrap();
        tx.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','0',$1,$2,'tenant-test','active',$3,$4,1,$3)"), &[&self.actor_session,&self.actor,&(NOW as i64),&((NOW+1000) as i64)]).unwrap();
        tx.commit().unwrap();
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        assert!(self.schema().starts_with("idp_access_tenants_it_"));
        if let Ok(mut c) = self.adapter.connect() {
            let _ = c.batch_execute(&format!("drop schema {} cascade", self.schema()));
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_create_is_atomic_gated_and_unique() {
    let disabled = Db::new(TenancyMode::Disabled);
    let disabled_service = disabled.service();
    assert!(matches!(
        disabled.create(&disabled_service, "t1", disabled.admin),
        Err(AccessError::FeatureDisabled | AccessError::ModeMismatch)
    ));
    let db = Db::new(TenancyMode::Enabled);
    let service = db.service();
    assert!(db.create(&service, "bad", db.disabled).is_err());
    let mut c = db.adapter.connect().unwrap();
    assert_eq!(
        c.query_one(
            &format!(
                "select count(*) from {}.access_tenants where id='bad'",
                db.schema()
            ),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    db.create(&service, "t1", db.admin).unwrap();
    assert_eq!(
        c.query_one(
            &format!(
                "select status,version from {}.access_tenants where id='t1'",
                db.schema()
            ),
            &[]
        )
        .unwrap()
        .get::<_, String>(0),
        "active"
    );
    assert_eq!(c.query_one(&format!("select count(*) from {}.access_memberships where tenant_id='t1' and account_id=$1 and status='active'",db.schema()),&[&db.admin]).unwrap().get::<_,i64>(0),1);
    assert_eq!(c.query_one(&format!("select count(*) from {}.access_roles where tenant_id='t1' and kind='tenant_security_admin'",db.schema()),&[]).unwrap().get::<_,i64>(0),1);
    assert!(db.create(&service, "t1", db.other).is_err());
    let a = db.store();
    let b = db.store();
    let barrier = Arc::new(Barrier::new(3));
    let actor = db.actor.to_string();
    let session = db.actor_session.to_string();
    let first_admin = db.admin.to_string();
    let first_barrier = barrier.clone();
    let first = thread::spawn(move || {
        let service =
            CoreAccessAdminService::new(TenancyMode::Enabled, catalog(), a, FixedClock, UuidIds);
        first_barrier.wait();
        service.execute(
            AccessAdminContext {
                actor: AccessActor {
                    tenant_id: "0".into(),
                    subject_id: actor.clone(),
                    session_id: session.clone(),
                },
                authentication_source: "live_test".into(),
                request_id: Uuid::now_v7().to_string(),
            },
            AccessAdminCommand {
                tenant_id: "same".into(),
                mutation: AccessAdminMutation::CreateTenant {
                    name: "Same".into(),
                    allow_registration: true,
                    administrator_subject_id: first_admin,
                },
            },
        )
    });
    let second_barrier = barrier.clone();
    let other = db.other.to_string();
    let actor2 = db.actor.to_string();
    let session2 = db.actor_session.to_string();
    let second = thread::spawn(move || {
        let service =
            CoreAccessAdminService::new(TenancyMode::Enabled, catalog(), b, FixedClock, UuidIds);
        second_barrier.wait();
        service.execute(
            AccessAdminContext {
                actor: AccessActor {
                    tenant_id: "0".into(),
                    subject_id: actor2,
                    session_id: session2,
                },
                authentication_source: "live_test".into(),
                request_id: Uuid::now_v7().to_string(),
            },
            AccessAdminCommand {
                tenant_id: "same".into(),
                mutation: AccessAdminMutation::CreateTenant {
                    name: "Same".into(),
                    allow_registration: true,
                    administrator_subject_id: other,
                },
            },
        )
    });
    barrier.wait();
    let results = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        c.query_one(
            &format!(
                "select count(*) from {}.access_tenants where id='same'",
                db.schema()
            ),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        1
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn disabled_mode_keeps_directory_administration_in_system_domain() {
    let db = Db::new(TenancyMode::Disabled);
    let service = db.service();
    service
        .execute(
            db.context(),
            db.command(
                "0",
                AccessAdminMutation::SyncPermissions {
                    permissions: vec![key("report", "read")],
                },
            ),
        )
        .unwrap();
    service
        .execute(
            db.context(),
            db.command(
                "0",
                AccessAdminMutation::SetPermissionEnabled {
                    permission: key("report", "read"),
                    enabled: false,
                    expected_enabled: true,
                },
            ),
        )
        .unwrap();
    assert!(!db.adapter.connect().unwrap().query_one(&format!("select enabled from {}.access_permissions where resource_type='report' and action='read'",db.schema()),&[]).unwrap().get::<_,bool>(0));
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_state_version_cleanup_restore_and_audit_rollback() {
    let db = Db::new(TenancyMode::Enabled);
    let service = db.service();
    db.create(&service, "t1", db.admin).unwrap();
    db.create(&service, "t2", db.other).unwrap();
    let s = db.schema();
    let session = Uuid::now_v7();
    let t2_session = Uuid::now_v7();
    let device = Uuid::now_v7();
    let refresh = Uuid::now_v7();
    let mut c = db.adapter.connect().unwrap();
    c.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','t1',$1,$2,'tenant-test','active',$3,$4,1,$3)"), &[&session,&db.admin,&(NOW as i64),&((NOW+1000) as i64)]).unwrap();
    c.execute(&format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values('t1',$1,$2,$3,1,$4,$5)"), &[&refresh,&session,&vec![1_u8;32],&(NOW as i64),&((NOW+1000) as i64)]).unwrap();
    c.execute(&format!("insert into {s}.authorization_codes(tenant_id,code_digest,account_id,source_session_id,login_entry,client_id,redirect_uri,scope,created_at_epoch,expires_at_epoch) values('t1',$4,$1,$5,'test','tenant-test','http://localhost','openid',$2,$3)"), &[&db.admin,&(NOW as i64),&((NOW+1000) as i64), &vec![10_u8;32], &session]).unwrap();
    c.execute(&format!("insert into {s}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values('t1',$1,$2,'admin@example.test','111111',$3,$4)"), &[&Uuid::now_v7(),&db.admin,&(NOW as i64),&((NOW+1000) as i64)]).unwrap();
    c.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values('t1',$1,'tenant-test','device','active',$2)"), &[&device,&(NOW as i64)]).unwrap();
    c.execute(&format!("insert into {s}.device_nonces(tenant_id,id,device_id,purpose,challenge_digest,issued_at_epoch,expires_at_epoch) values('t1',$1,$2,'login',$3,$4,$5)"), &[&Uuid::now_v7(),&device,&vec![2_u8;32],&(NOW as i64),&((NOW+1000) as i64)]).unwrap();
    c.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','t2',$1,$2,'tenant-test','active',$3,$4,1,$3)"), &[&t2_session,&db.other,&(NOW as i64),&((NOW+1000) as i64)]).unwrap();
    c.execute(&format!("insert into {s}.auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch,source_tenant_id,source_session_id) values($1,$2,$3,'tenant-test','test','login',$4,$5,'t1',$6),($7,$8,$3,'tenant-test','test','login',$4,$5,null,null),($9,$10,$11,'tenant-test','test','login',$4,$5,'t2',$12)"), &[&Uuid::now_v7(),&vec![3_u8;32],&db.admin,&(NOW as i64),&((NOW+1000) as i64),&session,&Uuid::now_v7(),&vec![4_u8;32],&Uuid::now_v7(),&vec![5_u8;32],&db.other,&t2_session]).unwrap();
    service
        .execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::UpdateTenant {
                    name: "Suspended".into(),
                    status: TenantStatus::Suspended,
                    allow_registration: false,
                    expected_version: 1,
                },
            ),
        )
        .unwrap();
    assert_eq!(
        c.query_one(
            &format!("select status from {s}.auth_sessions where id=$1"),
            &[&session]
        )
        .unwrap()
        .get::<_, String>(0),
        "revoked"
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.authorization_codes where tenant_id='t1'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.email_verification_codes where tenant_id='t1'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.device_nonces where tenant_id='t1'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(c.query_one(&format!("select count(*) from {s}.auth_tenant_selections where account_id=$1 and (source_tenant_id='t1' or source_tenant_id is null) and revoked_at_epoch is not null"),&[&db.admin]).unwrap().get::<_,i64>(0),2);
    assert!(c.query_one(&format!("select revoked_at_epoch is null from {s}.auth_tenant_selections where account_id=$1 and source_tenant_id='t2'"),&[&db.other]).unwrap().get::<_,bool>(0));
    assert!(c
        .query_one(
            &format!("select revoked_at_epoch is not null from {s}.refresh_tokens where id=$1"),
            &[&refresh]
        )
        .unwrap()
        .get::<_, bool>(0));
    assert!(matches!(
        service.execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::UpdateTenant {
                    name: "stale".into(),
                    status: TenantStatus::Suspended,
                    allow_registration: false,
                    expected_version: 1
                }
            )
        ),
        Err(AccessError::Conflict("version"))
    ));
    service
        .execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::UpdateTenant {
                    name: "Restored".into(),
                    status: TenantStatus::Active,
                    allow_registration: true,
                    expected_version: 2,
                },
            ),
        )
        .unwrap();
    assert_eq!(
        c.query_one(
            &format!("select status from {s}.auth_sessions where id=$1"),
            &[&session]
        )
        .unwrap()
        .get::<_, String>(0),
        "revoked"
    );
    let rollback_session = Uuid::now_v7();
    c.execute(&format!("insert into {s}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','t1',$1,$2,'tenant-test','active',$3,$4,1,$3)"), &[&rollback_session,&db.admin,&(NOW as i64),&((NOW+1000) as i64)]).unwrap();
    c.batch_execute(&format!("create function {s}.fail_tenant_audit() returns trigger language plpgsql as $$ begin raise exception 'audit'; end $$; create trigger fail_tenant_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_tenant_audit()" )).unwrap();
    assert!(service
        .execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::UpdateTenant {
                    name: "Rollback suspend".into(),
                    status: TenantStatus::Suspended,
                    allow_registration: false,
                    expected_version: 3
                }
            )
        )
        .is_err());
    assert_eq!(
        c.query_one(
            &format!("select status from {s}.auth_sessions where id=$1"),
            &[&rollback_session]
        )
        .unwrap()
        .get::<_, String>(0),
        "active"
    );
    assert!(service
        .execute(
            db.context(),
            db.command(
                "rollback-tenant",
                AccessAdminMutation::CreateTenant {
                    name: "Rollback tenant".into(),
                    allow_registration: true,
                    administrator_subject_id: db.other.to_string()
                }
            )
        )
        .is_err());
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.access_tenants where id='rollback-tenant'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            &format!(
                "select count(*) from {s}.access_memberships where tenant_id='rollback-tenant'"
            ),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.access_roles where tenant_id='rollback-tenant'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert!(service
        .execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::UpdateTenant {
                    name: "Not committed".into(),
                    status: TenantStatus::Active,
                    allow_registration: false,
                    expected_version: 3
                }
            )
        )
        .is_err());
    assert_eq!(
        c.query_one(
            &format!("select name from {s}.access_tenants where id='t1'"),
            &[]
        )
        .unwrap()
        .get::<_, String>(0),
        "Restored"
    );
    c.batch_execute(&format!("drop trigger fail_tenant_audit on {s}.access_audit_events; drop function {s}.fail_tenant_audit(); delete from {s}.access_role_bindings where tenant_id='t1'" )).unwrap();
    assert!(matches!(
        service.execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::UpdateTenant {
                    name: "No admin".into(),
                    status: TenantStatus::Active,
                    allow_registration: true,
                    expected_version: 3
                }
            )
        ),
        Err(AccessError::Conflict("last_security_admin"))
    ));
    assert_eq!(
        c.query_one(
            &format!("select name from {s}.access_tenants where id='t1'"),
            &[]
        )
        .unwrap()
        .get::<_, String>(0),
        "Restored"
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn business_permissions_are_independent_per_tenant_and_archive_denies() {
    let db = Db::new(TenancyMode::Enabled);
    let service = db.service();
    db.create(&service, "t1", db.admin).unwrap();
    db.create(&service, "t2", db.other).unwrap();
    let permission = key("invoice", "read");
    for (tenant, subject, description) in [
        ("t1", db.admin, "Tenant one invoices"),
        ("t2", db.other, "Tenant two invoices"),
    ] {
        service
            .execute(
                db.context(),
                db.command(
                    tenant,
                    AccessAdminMutation::CreatePermission {
                        key: permission.clone(),
                        description: description.into(),
                    },
                ),
            )
            .unwrap();
        let role = service
            .execute(
                db.context(),
                db.command(
                    tenant,
                    AccessAdminMutation::CreateRole {
                        key: "reader".into(),
                        name: "Reader".into(),
                    },
                ),
            )
            .unwrap();
        let AccessChange::Role {
            after: Some(role), ..
        } = role.change
        else {
            panic!("expected role")
        };
        service
            .execute(
                db.context(),
                db.command(
                    tenant,
                    AccessAdminMutation::ReplaceRolePermissions {
                        role_id: role.role.id.clone(),
                        permissions: vec![permission.clone()],
                        expected_version: 1,
                    },
                ),
            )
            .unwrap();
        service
            .execute(
                db.context(),
                db.command(
                    tenant,
                    AccessAdminMutation::GrantRole {
                        subject_id: subject.to_string(),
                        role_id: role.role.id,
                        resource_type: "invoice".into(),
                        scope: ResourceScope::Type,
                    },
                ),
            )
            .unwrap();
    }
    let t1 = service
        .get_permission(db.context(), "t1".into(), permission.clone())
        .unwrap();
    let t2 = service
        .get_permission(db.context(), "t2".into(), permission.clone())
        .unwrap();
    assert_ne!(t1.description, t2.description);
    let checker = CoreAccessService::new(TenancyMode::Enabled, catalog(), db.store());
    let query = |tenant: &str, subject: Uuid| AccessQuery {
        tenant_id: tenant.into(),
        subject_id: subject.to_string(),
        resource_type: "invoice".into(),
        action: "read".into(),
        resource_id: None,
    };
    assert_eq!(
        checker.check(query("t1", db.admin)).unwrap(),
        AccessDecision::Allow
    );
    assert_eq!(
        checker.check(query("t2", db.other)).unwrap(),
        AccessDecision::Allow
    );
    service
        .execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::ArchivePermission {
                    key: permission.clone(),
                    expected_version: t1.version,
                },
            ),
        )
        .unwrap();
    assert_eq!(
        checker.check(query("t1", db.admin)).unwrap(),
        AccessDecision::Deny
    );
    assert_eq!(
        checker.check(query("t2", db.other)).unwrap(),
        AccessDecision::Allow
    );
    assert_eq!(
        service
            .get_permission(db.context(), "t2".into(), permission.clone())
            .unwrap()
            .description,
        t2.description
    );
    assert!(matches!(
        service.execute(
            db.context(),
            db.command(
                "t1",
                AccessAdminMutation::CreatePermission {
                    key: permission,
                    description: "Cannot reuse".into(),
                }
            )
        ),
        Err(AccessError::Conflict("permission_exists"))
    ));
}

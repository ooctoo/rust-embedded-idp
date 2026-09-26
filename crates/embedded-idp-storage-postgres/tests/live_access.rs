//! Explicitly opt-in tests. Every case owns a random schema and drops only that schema.
use embedded_idp_core::access::*;
use embedded_idp_core::{Account, AccountStatus, EmailVerificationCode};
use embedded_idp_storage_postgres::*;
use std::{
    env,
    sync::{Arc, Barrier},
    time::{Duration, UNIX_EPOCH},
};
use uuid::Uuid;

fn catalog() -> PermissionCatalog {
    PermissionCatalog::new(
        [
            ("report", "read"),
            ("report", "update"),
            ("dataset", "read"),
        ]
        .into_iter()
        .map(|(r, a)| PermissionDefinition {
            created_at: None,
            tenant_id: "0".into(),
            key: PermissionKey {
                resource_type: r.into(),
                action: a.into(),
            },
            description: a.into(),
            category: PermissionCategory::Business,
            enabled: true,
            archived: false,
            version: 1,
        })
        .collect(),
    )
    .unwrap()
}
struct Db {
    adapter: PostgresStorageAdapter,
    mode: TenancyMode,
    user: Uuid,
    role: Uuid,
}
impl Db {
    fn new(mode: TenancyMode) -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_access_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-access-live-test".into(),
                max_connections: 4,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        let facts = adapter
            .initialize_access_schema(mode, &catalog())
            .expect("initialize isolated access schema");
        assert!(!facts.bootstrap_completed);
        Self {
            adapter,
            mode,
            user: Uuid::now_v7(),
            role: Uuid::now_v7(),
        }
    }
    fn schema(&self) -> &str {
        self.adapter.schema_name()
    }
    fn seed(&self) {
        let s = self.schema();
        let mut client = self.adapter.connect().unwrap();
        let mut tx = client.transaction().unwrap();
        let tenant = if self.mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        };
        if self.mode == TenancyMode::Enabled {
            for t in ["t1", "t2"] {
                tx.execute(&format!("insert into {s}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values($1,'tenant',$1,'active',true,1)"),&[&t]).unwrap();
                for permission in catalog()
                    .definitions()
                    .filter(|p| p.category != PermissionCategory::Platform)
                {
                    let category = if permission.category == PermissionCategory::Tenant {
                        "tenant"
                    } else {
                        "business"
                    };
                    tx.execute(&format!("insert into {s}.access_permissions(tenant_id,resource_type,action,category,description,enabled) values($1,$2,$3,$4,$5,true)"), &[&t,&permission.key.resource_type,&permission.key.action,&category,&permission.description]).unwrap();
                }
            }
        }
        tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,$2,'fixture@example.test','fixture-only-hash','active',1)"),&[&self.user,&tenant]).unwrap();
        let tenants = if self.mode == TenancyMode::Enabled {
            vec!["0", "t1", "t2"]
        } else {
            vec!["0"]
        };
        for t in tenants {
            tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',1)"),&[&t,&self.user]).unwrap();
            let role = Uuid::now_v7();
            let (kind, resource, category) = if t == "0" {
                ("system_admin", "idp.platform", "platform")
            } else {
                ("tenant_security_admin", "idp.tenant", "tenant")
            };
            tx.execute(&format!("insert into {s}.access_roles(tenant_id,id,key,name,status,kind,created_at_epoch) values($1,$2,$3,$3,'active',$3,1)"),&[&t,&role,&kind]).unwrap();
            tx.execute(&format!("insert into {s}.access_role_permissions(tenant_id,role_id,resource_type,action) select $1,$2,resource_type,action from {s}.access_permissions where tenant_id=$1 and category=$3"),&[&t,&role,&category]).unwrap();
            tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,created_at_epoch,created_by) values($1,$2,$3,$4,$5,1,$3)"),&[&Uuid::now_v7(),&t,&self.user,&role,&resource]).unwrap();
        }
        tx.execute(&format!("insert into {s}.access_roles(tenant_id,id,key,name,status,kind,created_at_epoch) values($1,$2,'reader','Reader','active','business',1)"),&[&tenant,&self.role]).unwrap();
        tx.execute(&format!("insert into {s}.access_role_permissions(tenant_id,role_id,resource_type,action) values($1,$2,'report','read'),($1,$2,'dataset','read')"),&[&tenant,&self.role]).unwrap();
        tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,resource_id,created_at_epoch,created_by) values($1,$2,$3,$4,'report','r1',1,$3)"),&[&Uuid::now_v7(),&tenant,&self.user,&self.role]).unwrap();
        // Explicit TEST fixture bootstrap. Production bootstrap is a separate pending service.
        tx.execute(
            &format!("update {s}.access_state set bootstrap_completed_at_epoch=1"),
            &[],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    fn store(&self) -> PostgresAccessStore {
        PostgresAccessStore::new(self.adapter.clone(), self.mode).unwrap()
    }
    fn q(&self, tenant: &str, resource: &str, action: &str, id: Option<&str>) -> AccessQuery {
        AccessQuery {
            tenant_id: tenant.into(),
            subject_id: self.user.to_string(),
            resource_type: resource.into(),
            action: action.into(),
            resource_id: id.map(str::to_owned),
        }
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        assert!(self.schema().starts_with("idp_access_it_"));
        if let Ok(mut client) = self.adapter.connect() {
            let _ = client.batch_execute(&format!("drop schema {} cascade", self.schema()));
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn access_initialization_is_atomic_idempotent_and_allows_host_tables() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        assert!(PostgresAccessStore::new(db.adapter.clone(), mode).is_err());
        db.seed();
        db.adapter.connect().unwrap().execute(&format!("update {}.access_permissions set enabled=false where resource_type='report' and action='read'",db.schema()),&[]).unwrap();
        assert!(
            db.adapter
                .initialize_access_schema(mode, &catalog())
                .unwrap()
                .bootstrap_completed
        );
        let other = if mode == TenancyMode::Enabled {
            TenancyMode::Disabled
        } else {
            TenancyMode::Enabled
        };
        assert!(db
            .adapter
            .initialize_access_schema(other, &catalog())
            .is_err());
        for result in [
            db.adapter.apply_migrations(),
            db.adapter.apply_security_cutover(),
        ] {
            assert!(
                matches!(result, Err(embedded_idp_core::StoreError::Backend(message)) if message == "tenant access schema cannot use legacy migrations")
            );
        }
        let tenant = if mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        };
        assert!(!db.adapter.connect().unwrap().query_one(&format!("select enabled from {}.access_permissions where tenant_id=$1 and resource_type='report' and action='read'",db.schema()),&[&tenant]).unwrap().get::<_,bool>(0));
        assert!(db
            .adapter
            .connect()
            .unwrap()
            .execute(
                &format!("update {}.access_state set tenancy_mode=$1", db.schema()),
                &[&if mode == TenancyMode::Enabled {
                    "disabled"
                } else {
                    "enabled"
                }]
            )
            .is_err());
        if mode == TenancyMode::Disabled {
            assert!(db.adapter.connect().unwrap().execute(&format!("insert into {}.access_tenants(id,kind,name,status,created_at_epoch) values('t1','tenant','Tenant','active',1)",db.schema()),&[]).is_err());
        }
    }
    let db = Db::new(TenancyMode::Enabled);
    // A host-owned table may coexist with IdP tables in the same schema.
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!("drop schema {0} cascade; create schema {0}; create table {0}.legacy_data(id int); insert into {0}.legacy_data values(7)",db.schema())).unwrap();
    let facts = db
        .adapter
        .initialize_access_schema(TenancyMode::Enabled, &catalog())
        .unwrap();
    assert!(!facts.bootstrap_completed);
    assert_eq!(
        c.query_one(&format!("select id from {}.legacy_data", db.schema()), &[])
            .unwrap()
            .get::<_, i32>(0),
        7
    );
    // A conflicting IdP table must fail before creating any of the others.
    c.batch_execute(&format!("drop schema {0} cascade; create schema {0}; create table {0}.legacy_data(id int); create table {0}.accounts(id int)",db.schema())).unwrap();
    assert!(matches!(
        db.adapter
            .initialize_access_schema(TenancyMode::Enabled, &catalog()),
        Err(embedded_idp_core::StoreError::Conflict(
            "access.schema_object_conflict"
        ))
    ));
    assert!(c
        .query_one(
            "select to_regclass($1) is null",
            &[&format!("{}.access_tenants", db.schema())]
        )
        .unwrap()
        .get::<_, bool>(0));
    assert!(c
        .query_one(
            &format!("select count(*) from {}.accounts", db.schema()),
            &[]
        )
        .is_ok());
    // Non-table name collisions are also rolled back by PostgreSQL.
    c.batch_execute(&format!("drop schema {0} cascade; create schema {0}; create table {0}.legacy_data(id int); create index access_memberships_by_account on {0}.legacy_data(id)",db.schema())).unwrap();
    assert!(matches!(
        db.adapter
            .initialize_access_schema(TenancyMode::Enabled, &catalog()),
        Err(embedded_idp_core::StoreError::Conflict(
            "access.schema_object_conflict"
        ))
    ));
    assert!(c
        .query_one(
            "select to_regclass($1) is null",
            &[&format!("{}.access_state", db.schema())]
        )
        .unwrap()
        .get::<_, bool>(0));
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn access_sql_checks_exact_scopes_status_revocation_and_batch_order_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.seed();
        let t = if mode == TenancyMode::Enabled {
            "t1"
        } else {
            "0"
        };
        let service = CoreAccessService::new(mode, catalog(), db.store());
        let q = db.q(t, "report", "read", Some("r1"));
        assert_eq!(service.check(q.clone()).unwrap(), AccessDecision::Allow);
        let queries = vec![
            q.clone(),
            db.q(t, "report", "read", Some("r2")),
            db.q(t, "report", "read", None),
            db.q(t, "dataset", "read", Some("r1")),
            q.clone(),
        ];
        assert_eq!(
            service.check_many(BatchAccessQuery { queries }).unwrap(),
            vec![
                AccessDecision::Allow,
                AccessDecision::Deny,
                AccessDecision::Deny,
                AccessDecision::Deny,
                AccessDecision::Allow
            ]
        );
        assert_eq!(
            service
                .check_many(BatchAccessQuery {
                    queries: vec![q.clone(); 100]
                })
                .unwrap(),
            vec![AccessDecision::Allow; 100]
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                service
                    .check(db.q("t2", "report", "read", Some("r1")))
                    .unwrap(),
                AccessDecision::Deny
            );
        }
        let mut c = db.adapter.connect().unwrap();
        let s = db.schema();
        for (table, filter, column, off, on) in [
            ("accounts", "id=$1", "status", "disabled", "active"),
            (
                "access_memberships",
                "account_id=$1 and tenant_id=$2",
                "status",
                "suspended",
                "active",
            ),
            (
                "access_roles",
                "id=$1 and tenant_id=$2",
                "status",
                "disabled",
                "active",
            ),
        ] {
            let id = if table == "access_roles" {
                db.role
            } else {
                db.user
            };
            let sql = format!(
                "update {s}.{table} set {column}=$3 where {filter} and $2::text is not null"
            );
            c.execute(&sql, &[&id, &t, &off]).unwrap();
            assert_eq!(service.check(q.clone()).unwrap(), AccessDecision::Deny);
            c.execute(&sql, &[&id, &t, &on]).unwrap();
            assert_eq!(service.check(q.clone()).unwrap(), AccessDecision::Allow);
        }
        c.execute(&format!("update {s}.access_permissions set enabled=false where resource_type='report' and action='read'"),&[]).unwrap();
        assert_eq!(service.check(q.clone()).unwrap(), AccessDecision::Deny);
        c.execute(&format!("update {s}.access_permissions set enabled=true where resource_type='report' and action='read'"),&[]).unwrap();
        c.execute(&format!("update {s}.access_role_bindings set resource_id=null where tenant_id=$1 and role_id=$2"),&[&t,&db.role]).unwrap();
        assert_eq!(
            service
                .check(db.q(t, "report", "read", Some("future-report")))
                .unwrap(),
            AccessDecision::Allow
        );
        assert_eq!(
            service.check(db.q(t, "report", "read", None)).unwrap(),
            AccessDecision::Allow
        );
        c.execute(
            &format!("delete from {s}.access_role_bindings where tenant_id=$1 and role_id=$2"),
            &[&t, &db.role],
        )
        .unwrap();
        assert_eq!(service.check(q).unwrap(), AccessDecision::Deny);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn access_lists_page_without_cross_tenant_or_subject_data() {
    let db = Db::new(TenancyMode::Enabled);
    db.seed();
    let service = CoreAccessService::new(TenancyMode::Enabled, catalog(), db.store());
    let mut page = AccessPageRequest {
        sort_order: None,
        limit: 1,
        cursor: None,
    };
    let mut roles = vec![];
    loop {
        let result = service
            .list_subject_roles("t1", &db.user.to_string(), page.clone())
            .unwrap();
        roles.extend(result.items);
        if !result.has_more {
            break;
        }
        page.cursor = result.next_cursor;
    }
    assert_eq!(roles.len(), 2);
    assert!(roles.iter().all(|r| r.tenant_id == "t1"));
    assert!(service
        .list_subject_roles(
            "t1",
            &Uuid::now_v7().to_string(),
            AccessPageRequest::default()
        )
        .unwrap()
        .items
        .is_empty());
    assert!(service
        .list_role_permissions("t2", &db.role.to_string(), AccessPageRequest::default())
        .unwrap()
        .items
        .is_empty());
    let first = service
        .list_role_permissions(
            "t1",
            &db.role.to_string(),
            AccessPageRequest {
                sort_order: None,
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(first.items[0].key.resource_type, "dataset");
    let second = service
        .list_role_permissions(
            "t1",
            &db.role.to_string(),
            AccessPageRequest {
                sort_order: None,
                limit: 1,
                cursor: first.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(second.items[0].key.resource_type, "report");
    assert!(!second.has_more);
    let tenants = service
        .list_subject_tenants(
            &db.user.to_string(),
            &LoginTenantPolicy::ChooseAfterAuthentication,
            AccessPageRequest::default(),
        )
        .unwrap();
    assert_eq!(
        tenants
            .items
            .iter()
            .map(|t| t.tenant.id.as_str())
            .collect::<Vec<_>>(),
        vec!["t1", "t2"]
    );
}

fn registration(
    tenant: &str,
    account: Uuid,
    verification: Uuid,
    email: &str,
) -> TenantRegistration {
    TenantRegistration::new(
        TenancyMode::Enabled,
        tenant.into(),
        Account {
            id: account.to_string(),
            email: email.into(),
            password_hash: "test-only-hash".into(),
            display_name: None,
            status: AccountStatus::PendingVerification,
            created_at: UNIX_EPOCH + Duration::from_secs(100),
        },
        EmailVerificationCode {
            id: verification.to_string(),
            account_id: account.to_string(),
            email: email.into(),
            code: "test-only-code".into(),
            issued_at: UNIX_EPOCH + Duration::from_secs(100),
            expires_at: UNIX_EPOCH + Duration::from_secs(200),
            consumed_at: None,
        },
    )
    .unwrap()
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn access_registration_and_database_constraints_keep_membership_atomic() {
    let db = Db::new(TenancyMode::Enabled);
    db.seed();
    let store = db.store();
    let user = Uuid::now_v7();
    let verification = Uuid::now_v7();
    store
        .create_registered_account(&registration("t1", user, verification, "new@example.test"))
        .unwrap();
    assert!(store
        .create_registered_account(&registration(
            "t2",
            Uuid::now_v7(),
            Uuid::now_v7(),
            "new@example.test"
        ))
        .is_err());
    let rolled_back = Uuid::now_v7();
    assert!(store
        .create_registered_account(&registration(
            "t1",
            rolled_back,
            verification,
            "rollback@example.test"
        ))
        .is_err());
    let mut c = db.adapter.connect().unwrap();
    let s = db.schema();
    assert!(!c
        .query_one(
            &format!("select exists(select 1 from {s}.accounts where id=$1)"),
            &[&rolled_back]
        )
        .unwrap()
        .get::<_, bool>(0));
    assert!(c.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,'t1','bare@example.test','test-hash','active',1)"),&[&Uuid::now_v7()]).is_err());
    assert!(c.execute(&format!("update {s}.access_memberships set status='removed',removed_at_epoch=200 where account_id=$1"),&[&user]).is_err());
    // Cross-tenant role and a blank resource scope must be rejected by constraints.
    assert!(c.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,resource_id,created_at_epoch,created_by) values($1,'t2',$2,$3,'report','r1',1,$2)"),&[&Uuid::now_v7(),&db.user,&db.role]).is_err());
    assert!(c
        .execute(
            &format!("update {s}.access_role_bindings set resource_id='' where role_id=$1"),
            &[&db.role]
        )
        .is_err());
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn database_serializes_concurrent_last_membership_removals() {
    let db = Db::new(TenancyMode::Enabled);
    db.seed();
    let user = Uuid::now_v7();
    db.store()
        .create_registered_account(&registration(
            "t1",
            user,
            Uuid::now_v7(),
            "race@example.test",
        ))
        .unwrap();
    db.adapter.connect().unwrap().execute(&format!("insert into {}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('t2',$1,'active',100)",db.schema()),&[&user]).unwrap();
    for isolation in ["read committed", "repeatable read"] {
        db.adapter.connect().unwrap().execute(&format!("update {}.access_memberships set status='active',removed_at_epoch=null where account_id=$1",db.schema()),&[&user]).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|threads| {
            let handles:Vec<_>=["t1","t2"].into_iter().map(|tenant| { let adapter=db.adapter.clone(); let barrier=barrier.clone(); threads.spawn(move || {
                let mut c=adapter.connect().unwrap(); let mut tx=c.transaction().unwrap();
                tx.batch_execute(&format!("set transaction isolation level {isolation}; set local statement_timeout='5s'; set local lock_timeout='3s'")).unwrap();
                tx.execute(&format!("update {}.access_memberships set status='removed',removed_at_epoch=200 where tenant_id=$1 and account_id=$2",adapter.schema_name()),&[&tenant,&user]).unwrap();
                barrier.wait(); tx.commit().is_ok()
            }) }).collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results.iter().filter(|ok| **ok).count(),
            1,
            "exactly one removal commits"
        );
        assert_eq!(db.adapter.connect().unwrap().query_one(&format!("select count(*) from {}.access_memberships where account_id=$1 and status<>'removed'",db.schema()),&[&user]).unwrap().get::<_,i64>(0),1);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn device_credentials_stay_in_their_tenant_and_layout_damage_is_rejected() {
    let db = Db::new(TenancyMode::Enabled);
    db.seed();
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!(
        "insert into {s}.oidc_clients values('test','Test','[]','public_desktop',true,null,1)"
    ))
    .unwrap();
    let devices = [Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7()];
    for (tenant, device) in [("t1", devices[0]), ("t2", devices[1]), ("t1", devices[2])] {
        c.execute(&format!("insert into {s}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values($1,$2,'test','Test','pending',1)"), &[&tenant,&device]).unwrap();
    }
    let key = "k".repeat(43);
    let key_sql = format!("insert into {s}.device_proof_keys(tenant_id,key_id,device_id,algorithm,public_jwk,version,status,registered_at_epoch) values('t1',$1,$2,'ed25519','test-only-jwk',1,'active',1)");
    assert!(c.execute(&key_sql, &[&key, &devices[1]]).is_err());
    c.execute(&key_sql, &[&key, &devices[0]]).unwrap();
    let current_key_sql = format!("update {s}.devices set proof_key_id=$1 where id=$2");
    for wrong_device in [devices[1], devices[2]] {
        assert!(c.execute(&current_key_sql, &[&key, &wrong_device]).is_err());
    }
    c.execute(&current_key_sql, &[&key, &devices[0]]).unwrap();
    let session = Uuid::now_v7();
    let session_sql = format!("insert into {s}.auth_sessions(tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('t2',$1,$2,'test',$3,'active',1,100,1,1)");
    assert!(c
        .execute(&session_sql, &[&session, &db.user, &devices[0]])
        .is_err());
    c.execute(&session_sql, &[&session, &db.user, &devices[1]])
        .unwrap();
    let digest = vec![0u8; 32];
    let refresh_sql = format!("insert into {s}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch,revoked_at_epoch,revocation_reason) values($1,$2,$3,$4,1,1,100,2,$5)");
    let token = Uuid::now_v7();
    assert!(c
        .execute(&refresh_sql, &[&"t1", &token, &session, &digest, &"logout"])
        .is_err());
    assert!(c
        .execute(
            &refresh_sql,
            &[&"t2", &token, &session, &digest, &None::<&str>]
        )
        .is_err());
    c.execute(&refresh_sql, &[&"t2", &token, &session, &digest, &"logout"])
        .unwrap();
    c.batch_execute(&format!(
        "alter table {s}.access_memberships disable trigger membership_requires_membership"
    ))
    .unwrap();
    assert!(db
        .adapter
        .inspect_access_schema(TenancyMode::Enabled)
        .is_err());
    assert!(db
        .adapter
        .initialize_access_schema(TenancyMode::Enabled, &catalog())
        .is_err());
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn list_time_upgrade_preserves_unknown_history_and_is_repeatable() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    let mut client = db.adapter.connect().unwrap();
    client
        .batch_execute(&format!(
            "alter table {s}.access_permissions drop column created_at_epoch cascade"
        ))
        .unwrap();
    assert!(matches!(
        db.adapter.inspect_access_schema(db.mode),
        Err(embedded_idp_core::StoreError::Conflict(
            "access.list_time_migration_required"
        ))
    ));
    let migration = include_str!("../../../scripts/migrate_list_time_desc.sql")
        .lines()
        .filter(|line| !line.starts_with('\\'))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(":\"schema\"", s);
    for _ in 0..2 {
        client.batch_execute(&migration).unwrap();
        db.adapter.inspect_access_schema(db.mode).unwrap();
    }
    let unknown: i64 = client
        .query_one(
            &format!("select count(*) from {s}.access_permissions where created_at_epoch is null"),
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        unknown as usize,
        catalog()
            .definitions()
            .filter(|p| p.category != PermissionCategory::Business)
            .count()
    );
    client.batch_execute(&format!("insert into {s}.access_permissions(tenant_id,resource_type,action,category,description,enabled) values('0','new','read','business','new permission',true)")).unwrap();
    let created: Option<i64> = client
        .query_one(
            &format!(
                "select created_at_epoch from {s}.access_permissions where resource_type='new'"
            ),
            &[],
        )
        .unwrap()
        .get(0);
    assert!(created.is_some_and(|t| t > 0));
}

//! Explicit opt-in tests for the offline access bootstrap transaction.
//! Each case owns a random schema and drops only that schema.
use embedded_idp_core::access::*;
use embedded_idp_core::{Account, AccountStatus, Clock, IdGenerator, StoreError};
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

const NOW: u64 = 1_700_000_000;

#[derive(Clone, Copy)]
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW)
    }
}

#[derive(Clone, Copy)]
struct FixedIds;
impl IdGenerator for FixedIds {
    fn next_id(&self, prefix: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(10_000);
        let value = NEXT.fetch_add(1, Ordering::Relaxed);
        let _ = prefix;
        Uuid::from_u128(value as u128).to_string()
    }
}

fn catalog() -> PermissionCatalog {
    PermissionCatalog::new(vec![PermissionDefinition {
        created_at: None,
        tenant_id: "0".into(),
        key: PermissionKey {
            business_id: "f_01".into(),
            resource_type: "report".into(),
            action: "read".into(),
        },
        description: "read reports".into(),
        category: PermissionCategory::Business,
        enabled: true,
        archived: false,
        version: 1,
    }])
    .unwrap()
}

fn account(id: Uuid, hash: &str) -> Account {
    Account {
        id: id.to_string(),
        email: format!("{}@example.test", id.simple()),
        password_hash: hash.into(),
        display_name: Some("Bootstrap administrator".into()),
        status: AccountStatus::Active,
        created_at: UNIX_EPOCH,
    }
}

struct Db {
    adapter: PostgresStorageAdapter,
    mode: TenancyMode,
}

impl Db {
    fn new(mode: TenancyMode) -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_access_bootstrap_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-access-bootstrap-live-test".into(),
                max_connections: 4,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        let facts = adapter.initialize_access_schema(mode, &catalog()).unwrap();
        assert!(!facts.bootstrap_completed);
        Self { adapter, mode }
    }

    fn schema(&self) -> &str {
        self.adapter.schema_name()
    }

    fn service(&self) -> CoreAccessBootstrapService<PostgresStorageAdapter, FixedClock, FixedIds> {
        CoreAccessBootstrapService::new(self.mode, self.adapter.clone(), FixedClock, FixedIds)
    }

    fn count(&self, table: &str) -> i64 {
        self.adapter
            .connect()
            .unwrap()
            .query_one(
                &format!("select count(*) from {}.{}", self.schema(), table),
                &[],
            )
            .unwrap()
            .get(0)
    }

    fn bootstrap_completed(&self) -> bool {
        self.adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select bootstrap_completed_at_epoch is not null from {}.access_state",
                    self.schema()
                ),
                &[],
            )
            .unwrap()
            .get(0)
    }

    fn readiness_snapshot(&self) -> (i64, i64, i64, i64, i64, bool, bool) {
        let row = self.adapter
            .connect()
            .unwrap()
            .query_one(
                &format!(
                    "select \
                        (select count(*) from {0}.accounts), \
                        (select count(*) from {0}.access_memberships), \
                        (select count(*) from {0}.access_roles), \
                        (select count(*) from {0}.access_role_bindings), \
                        (select count(*) from {0}.access_audit_events), \
                        (select bootstrap_completed_at_epoch is not null from {0}.access_state), \
                        coalesce((select enabled from {0}.access_permissions where tenant_id='0' and resource_type='report' and action='read'), false)",
                    self.schema()
                ),
                &[],
            )
            .unwrap();
        (
            row.get(0),
            row.get(1),
            row.get(2),
            row.get(3),
            row.get(4),
            row.get(5),
            row.get(6),
        )
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        assert!(self.schema().starts_with("idp_access_bootstrap_it_"));
        if let Ok(mut client) = self.adapter.connect() {
            let _ = client.batch_execute(&format!("drop schema {} cascade", self.schema()));
        }
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn bootstrap_initializes_both_modes_and_is_idempotent() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let first_id = Uuid::from_u128(1);
        assert_eq!(
            db.service()
                .initialize(account(first_id, "hash-one"), "request-one".into())
                .unwrap(),
            AccessBootstrapResult::Initialized
        );
        assert_eq!(db.count("accounts"), 1);
        assert_eq!(db.count("access_memberships"), 1);
        assert_eq!(db.count("access_roles"), 1);
        assert_eq!(db.count("access_role_bindings"), 1);
        assert_eq!(db.count("access_audit_events"), 1);
        assert!(db.bootstrap_completed());

        assert_eq!(
            db.service()
                .initialize(
                    account(Uuid::from_u128(2), "hash-two"),
                    "request-two".into()
                )
                .unwrap(),
            AccessBootstrapResult::AlreadyInitialized
        );
        assert_eq!(db.count("accounts"), 1);
        assert_eq!(
            db.adapter
                .connect()
                .unwrap()
                .query_one(
                    &format!("select password_hash from {}.accounts", db.schema()),
                    &[]
                )
                .unwrap()
                .get::<_, String>(0),
            "hash-one"
        );
        assert_eq!(db.count("access_audit_events"), 1);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn bootstrap_concurrent_first_call_initializes_once() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Arc::new(Db::new(mode));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for n in 0..2 {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                db.service().initialize(
                    account(Uuid::from_u128(100 + n), "concurrent-hash"),
                    format!("concurrent-{n}"),
                )
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == AccessBootstrapResult::Initialized)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| **r == AccessBootstrapResult::AlreadyInitialized)
                .count(),
            1
        );
        assert_eq!(db.count("accounts"), 1);
        assert_eq!(db.count("access_audit_events"), 1);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn bootstrap_rolls_back_directory_and_audit_failures() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        db.adapter.connect().unwrap().execute(
            &format!("update {}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'", db.schema()), &[]).unwrap();
        assert!(db
            .service()
            .initialize(
                account(Uuid::from_u128(3), "hash"),
                "directory-failure".into()
            )
            .is_err());
        assert_eq!(db.count("accounts"), 0);
        assert!(!db.bootstrap_completed());

        let db = Db::new(mode);
        let s = db.schema();
        db.adapter.connect().unwrap().batch_execute(&format!(
            "create function {s}.fail_bootstrap_audit() returns trigger language plpgsql as $$ begin raise exception 'test audit failure'; end $$; create trigger fail_bootstrap_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_bootstrap_audit()"
        )).unwrap();
        assert!(db
            .service()
            .initialize(account(Uuid::from_u128(4), "hash"), "audit-failure".into())
            .is_err());
        assert_eq!(db.count("accounts"), 0);
        assert_eq!(db.count("access_roles"), 0);
        assert!(!db.bootstrap_completed());
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn bootstrap_refuses_to_repair_last_security_admin() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let id = Uuid::from_u128(5);
        db.service()
            .initialize(account(id, "hash"), "first".into())
            .unwrap();
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("delete from {}.access_role_bindings", db.schema()),
                &[],
            )
            .unwrap();
        assert!(db
            .service()
            .initialize(account(Uuid::from_u128(6), "new-hash"), "repair".into())
            .is_err());
        assert_eq!(db.count("accounts"), 1);
        assert!(db.bootstrap_completed());
        assert_eq!(db.count("access_role_bindings"), 0);
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn readiness_requires_prepared_catalog_and_effective_admin_without_mutating_state() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        assert!(matches!(
            PostgresAccessStore::new(db.adapter.clone(), mode),
            Err(StoreError::Conflict("access.bootstrap_required"))
        ));
        db.service()
            .initialize(account(Uuid::from_u128(7), "hash"), "ready".into())
            .unwrap();
        let store = PostgresAccessStore::new(db.adapter.clone(), mode).unwrap();
        let before = db.readiness_snapshot();
        store.check_readiness(&catalog()).unwrap();
        assert_eq!(db.readiness_snapshot(), before);

        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "insert into {}.access_permissions(tenant_id,business_id,resource_type,action,category,description,enabled) values('0','readiness_test','idp.platform','access.manage','business','duplicate key outside the catalog',true)",
                    db.schema()
                ),
                &[],
            )
            .unwrap();
        store.check_readiness(&catalog()).unwrap();

        db.adapter.connect().unwrap().execute(
            &format!("update {}.access_permissions set enabled=false where resource_type='report' and action='read'", db.schema()),
            &[],
        ).unwrap();
        let before = db.readiness_snapshot();
        store.check_readiness(&catalog()).unwrap();
        assert_eq!(db.readiness_snapshot(), before);

        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!("delete from {}.access_role_bindings", db.schema()),
                &[],
            )
            .unwrap();
        let before = db.readiness_snapshot();
        assert!(matches!(
            store.check_readiness(&catalog()),
            Err(StoreError::Conflict("access.last_security_admin"))
        ));
        assert_eq!(db.readiness_snapshot(), before);
    }

    let disabled = Db::new(TenancyMode::Disabled);
    disabled
        .service()
        .initialize(account(Uuid::from_u128(8), "hash"), "disabled".into())
        .unwrap();
    let store = PostgresAccessStore::new(disabled.adapter.clone(), TenancyMode::Disabled).unwrap();
    disabled.adapter.connect().unwrap().execute(
        &format!("update {}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'", disabled.schema()),
        &[],
    ).unwrap();
    let before = disabled.readiness_snapshot();
    assert!(matches!(
        store.check_readiness(&catalog()),
        Err(StoreError::Conflict("access.readiness_catalog"))
    ));
    assert_eq!(disabled.readiness_snapshot(), before);

    let disabled_admin = Db::new(TenancyMode::Disabled);
    disabled_admin
        .service()
        .initialize(account(Uuid::from_u128(9), "hash"), "disabled-admin".into())
        .unwrap();
    let store =
        PostgresAccessStore::new(disabled_admin.adapter.clone(), TenancyMode::Disabled).unwrap();
    disabled_admin
        .adapter
        .connect()
        .unwrap()
        .execute(
            &format!(
                "update {}.access_roles set status='disabled' where kind='system_admin'",
                disabled_admin.schema()
            ),
            &[],
        )
        .unwrap();
    let before = disabled_admin.readiness_snapshot();
    assert!(matches!(
        store.check_readiness(&catalog()),
        Err(StoreError::Conflict("access.last_security_admin"))
    ));
    assert_eq!(disabled_admin.readiness_snapshot(), before);

    let enabled = Db::new(TenancyMode::Enabled);
    enabled
        .service()
        .initialize(account(Uuid::from_u128(10), "hash"), "mode".into())
        .unwrap();
    assert!(matches!(
        PostgresAccessStore::new(enabled.adapter.clone(), TenancyMode::Disabled),
        Err(StoreError::Conflict("access.schema_mode_or_version"))
    ));
}

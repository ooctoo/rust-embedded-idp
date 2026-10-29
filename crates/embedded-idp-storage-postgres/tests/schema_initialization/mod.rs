//! Requires a disposable PostgreSQL instance with explicit role-management access.
use super::catalog;
use embedded_idp_core::access::*;
use embedded_idp_core::{Account, AccountStatus, StoreError, SystemClock, UuidV7IdGenerator};
use embedded_idp_storage_postgres::*;
use postgres::{Client, NoTls};
use std::{
    env,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    thread,
    time::{Duration, Instant, SystemTime},
};
use uuid::Uuid;

struct Fixture {
    admin: Client,
    uri: String,
    schema: String,
    schemas: Vec<String>,
    roles: Vec<String>,
    database_grants: Vec<String>,
}

impl Fixture {
    fn new() -> Self {
        let uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
            .expect("explicit disposable test connection required");
        let mut admin = Client::connect(&uri, NoTls).expect("connect to disposable test database");
        assert!(admin.query_one(
            "select (rolsuper or rolcreaterole) and has_database_privilege(current_database(),'CREATE') from pg_roles where rolname=current_user", &[],
        ).unwrap().get::<_, bool>(0), "schema initialization tests require role management and database CREATE in a disposable instance");
        Self {
            admin,
            uri,
            schema: format!("idp_schema_{}", Uuid::now_v7().simple()),
            schemas: vec![],
            roles: vec![],
            database_grants: vec![],
        }
    }

    fn prepare(&mut self) -> String {
        let schema = self.schema.clone();
        self.schemas.push(schema.clone());
        self.admin.batch_execute(&format!(
            "create schema {schema}; create table {schema}.host_data(id int primary key); insert into {schema}.host_data values(7)"
        )).unwrap();
        let uri = self.role();
        self.admin
            .batch_execute(&format!(
                "grant usage,create on schema {schema} to {}",
                self.roles[0]
            ))
            .unwrap();
        uri
    }

    fn role(&mut self) -> String {
        let role = format!("idp_init_{}", Uuid::now_v7().simple());
        // Generated test-only alphanumeric values; never print credentials or URIs.
        let password = Uuid::now_v7().simple().to_string();
        self.admin.batch_execute(&format!(
            "create role {role} login password '{password}' nosuperuser nocreatedb nocreaterole noinherit nobypassrls"
        )).expect("create isolated test role");
        self.roles.push(role.clone());
        let separator = if self.uri.contains('?') { '&' } else { '?' };
        // postgres parses query credentials after authority credentials. Both new
        // values contain only generated ASCII letters, digits and underscores.
        format!("{}{separator}user={role}&password={password}", self.uri)
    }

    fn adapter(&self, uri: &str) -> PostgresStorageAdapter {
        PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: uri.into(),
                schema_name: self.schema.clone(),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: self.schema.clone(),
                max_connections: 1,
                connect_timeout_secs: 3,
            },
        })
        .unwrap()
    }

    fn restricted(&mut self, adapter: &PostgresStorageAdapter) {
        let mut c = adapter.connect().unwrap();
        let row = c.query_one(
            "select current_user::text, session_user::text, not (rolsuper or rolcreatedb or rolcreaterole or rolbypassrls), has_database_privilege(current_database(),'CREATE'), has_schema_privilege($1,'USAGE'), has_schema_privilege($1,'CREATE'), (select nspowner<>r.oid from pg_namespace where nspname=$1) and (select datdba<>r.oid from pg_database where datname=current_database()) from pg_roles r where rolname=current_user",
            &[&self.schema],
        ).unwrap();
        assert_eq!(row.get::<_, String>(0), self.roles[0]);
        assert_eq!(row.get::<_, String>(1), self.roles[0]);
        assert!(row.get::<_, bool>(2));
        assert!(
            !row.get::<_, bool>(3),
            "effective database CREATE must be absent"
        );
        assert!(row.get::<_, bool>(4) && row.get::<_, bool>(5) && row.get::<_, bool>(6));
        assert_eq!(c.query_one("select count(*) from pg_auth_members where member=(select oid from pg_roles where rolname=current_user)", &[]).unwrap().get::<_, i64>(0), 0);
        assert!(!c
            .query_one(
                "select has_table_privilege($1,'SELECT')",
                &[&format!("{}.host_data", self.schema)]
            )
            .unwrap()
            .get::<_, bool>(0));
    }

    /// Includes identities, owners, ACLs, definitions and implicit types, not just access_state.
    fn snapshot(&mut self) -> String {
        self.admin.query_one(
            "with ns as materialized (select oid,nspowner,nspacl from pg_namespace where nspname=$1),
             relations as materialized (select c.oid,relname,relkind,relowner,relacl from pg_class c join ns on c.relnamespace=ns.oid),
             functions as materialized (select p.oid,proowner,proacl from pg_proc p join ns on p.pronamespace=ns.oid),
             constraints as materialized (select c.oid,conname,conrelid,convalidated from pg_constraint c join ns on c.connamespace=ns.oid)
             select jsonb_build_object(
               'schema',(select jsonb_agg(to_jsonb(ns) order by oid) from ns),
               'relations',(select jsonb_agg(to_jsonb(r) order by oid) from relations r),
               'columns',(select jsonb_agg(jsonb_build_array(a.attrelid,a.attname,a.atttypid,a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) order by a.attrelid,a.attnum) from pg_attribute a join relations r on a.attrelid=r.oid left join pg_attrdef d on d.adrelid=a.attrelid and d.adnum=a.attnum where a.attnum>0 and not a.attisdropped),
               'constraints',(select jsonb_agg(jsonb_build_array(c.oid,c.conname,c.conrelid,c.convalidated,pg_get_constraintdef(c.oid)) order by c.oid) from constraints c),
               'indexes',(select jsonb_agg(pg_get_indexdef(oid) order by oid) from relations where relkind='i'),
               'functions',(select jsonb_agg(jsonb_build_array(oid,proowner,proacl,pg_get_functiondef(oid)) order by oid) from functions),
               'types',(select jsonb_agg(jsonb_build_array(t.oid,typname,typowner,typacl) order by t.oid) from pg_type t join ns on t.typnamespace=ns.oid),
               'triggers',(select jsonb_agg(jsonb_build_array(g.oid,g.tgenabled,pg_get_triggerdef(g.oid)) order by g.oid) from pg_trigger g join relations r on g.tgrelid=r.oid)
             )::text", &[&self.schema],
        ).unwrap().get(0)
    }

    fn data(&mut self) -> String {
        let s = &self.schema;
        self.admin.query_one(&format!(
            "select jsonb_build_object('state',(select jsonb_agg(to_jsonb(t)) from {s}.access_state t),'permissions',(select jsonb_agg(to_jsonb(t) order by tenant_id,business_id,resource_type,action) from {s}.access_permissions t),'accounts',(select jsonb_agg(to_jsonb(t) order by id) from {s}.accounts t),'roles',(select jsonb_agg(to_jsonb(t) order by id) from {s}.access_roles t),'audit',(select jsonb_agg(to_jsonb(t) order by id) from {s}.access_audit_events t))::text"
        ), &[]).unwrap().get(0)
    }

    fn assert_host(&mut self) {
        assert_eq!(
            self.admin
                .query_one(&format!("select id from {}.host_data", self.schema), &[])
                .unwrap()
                .get::<_, i32>(0),
            7
        );
    }

    fn host_metadata(&mut self) -> String {
        self.admin.query_one(
            "select jsonb_build_array(c.oid,c.relowner,c.relacl,i.oid,i.relowner,i.relacl,pg_get_indexdef(i.oid),pg_get_constraintdef(k.oid),a.attname,a.atttypid,a.attnotnull)::text from pg_class c join pg_attribute a on a.attrelid=c.oid and a.attnum=1 join pg_constraint k on k.conrelid=c.oid and k.contype='p' join pg_class i on i.oid=k.conindid where c.oid=to_regclass($1)",
            &[&format!("{}.host_data", self.schema)],
        ).unwrap().get(0)
    }

    fn cleanup(&mut self) {
        for schema in &self.schemas {
            self.admin
                .batch_execute(&format!("drop schema if exists {schema} cascade"))
                .expect("remove owned random test schema");
            assert!(!self
                .admin
                .query_one(
                    "select exists(select 1 from pg_namespace where nspname=$1)",
                    &[schema]
                )
                .unwrap()
                .get::<_, bool>(0));
        }
        let database: String = self
            .admin
            .query_one("select current_database()", &[])
            .unwrap()
            .get(0);
        let database = database.replace('"', "\"\"");
        for role in &self.roles {
            // Only revoke grants this fixture actually made, avoiding needless
            // concurrent updates of the shared pg_database ACL row.
            if self.database_grants.contains(role) {
                self.admin
                    .batch_execute(&format!(
                        "revoke create on database \"{database}\" from {role}"
                    ))
                    .expect("revoke owned database CREATE grant");
            }
            self.admin
                .batch_execute(&format!("drop role {role}"))
                .expect("remove owned random test role");
            assert!(!self
                .admin
                .query_one(
                    "select exists(select 1 from pg_roles where rolname=$1)",
                    &[role]
                )
                .unwrap()
                .get::<_, bool>(0));
        }
    }
}

fn fixture(test: impl FnOnce(&mut Fixture, String)) {
    let mut f = Fixture::new();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let uri = f.prepare();
        test(&mut f, uri);
    }));
    // Unwinding drops test adapters and pooled connections before role removal.
    f.cleanup();
    if let Err(error) = result {
        resume_unwind(error);
    }
}

fn bootstrap(adapter: &PostgresStorageAdapter, mode: TenancyMode) -> Uuid {
    let subject = Uuid::now_v7();
    let result =
        CoreAccessBootstrapService::new(mode, adapter.clone(), SystemClock, UuidV7IdGenerator)
            .initialize(
                Account {
                    id: subject.to_string(),
                    email: format!("{subject}@example.test"),
                    password_hash: "synthetic-bootstrap-hash".into(),
                    display_name: None,
                    status: AccountStatus::Active,
                    created_at: SystemTime::UNIX_EPOCH,
                },
                Uuid::now_v7().to_string(),
            )
            .unwrap();
    assert_eq!(result, AccessBootstrapResult::Initialized);
    PostgresAccessStore::new(adapter.clone(), mode)
        .unwrap()
        .check_readiness(&catalog())
        .unwrap();
    subject
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn precreated_schema_initializes_with_only_schema_privileges_and_preserves_data() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        fixture(|f, uri| {
            let adapter = f.adapter(&uri);
            f.restricted(&adapter);
            let host_metadata = f.host_metadata();
            let host_before = f.admin.query_one("select oid::text,nspowner::text,nspacl::text from pg_namespace where nspname=$1", &[&f.schema]).unwrap();
            let facts = adapter.initialize_access_schema(mode, &catalog()).unwrap();
            assert_eq!(facts.version, "tenant_v6");
            assert!(!facts.bootstrap_completed);
            assert_eq!(adapter.inspect_access_schema(mode).unwrap(), facts);
            let host_after = f.admin.query_one("select oid::text,nspowner::text,nspacl::text from pg_namespace where nspname=$1", &[&f.schema]).unwrap();
            for column in 0..3 {
                assert_eq!(
                    host_before.get::<_, String>(column),
                    host_after.get::<_, String>(column)
                );
            }
            assert!(f.admin.query_one("select bool_and(c.relowner=(select oid from pg_roles where rolname=$2)) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname<>'host_data' and c.relname<>'host_data_pkey'", &[&f.schema,&f.roles[0]]).unwrap().get::<_, bool>(0));
            f.assert_host();
            assert!(
                host_metadata == f.host_metadata(),
                "host definition/identity/ACL changed"
            );
            assert!(!adapter
                .connect()
                .unwrap()
                .query_one(
                    "select has_table_privilege($1,'SELECT')",
                    &[&format!("{}.host_data", f.schema)]
                )
                .unwrap()
                .get::<_, bool>(0));
            for bootstrapped in [false, true] {
                if bootstrapped {
                    bootstrap(&adapter, mode);
                }
                f.admin
                    .batch_execute(&format!(
                        "revoke create on schema {} from {}",
                        f.schema, f.roles[0]
                    ))
                    .unwrap();
                let before = f.snapshot();
                let data = f.data();
                // Discarding the previous success result models an unconfirmed caller retry.
                let repeated = adapter.initialize_access_schema(mode, &catalog()).unwrap();
                assert_eq!(repeated.bootstrap_completed, bootstrapped);
                assert!(
                    before == f.snapshot(),
                    "repeat changed object identity/definition/ACL"
                );
                assert!(data == f.data(), "repeat changed persisted data");
            }
            f.restricted_read_denied(&adapter, mode);
        });
    }
}

impl Fixture {
    fn restricted_read_denied(&mut self, owner: &PostgresStorageAdapter, mode: TenancyMode) {
        let uri = self.role();
        let role = self.roles.last().unwrap();
        self.admin
            .batch_execute(&format!("grant usage on schema {} to {role}", self.schema))
            .unwrap();
        let adapter = self.adapter(&uri);
        let before = self.snapshot();
        let data = self.data();
        assert!(adapter.initialize_access_schema(mode, &catalog()).is_err());
        assert!(before == self.snapshot() && data == self.data());
        owner.inspect_access_schema(mode).unwrap();
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn precreated_schema_rejects_missing_usage_or_create_without_partial_objects() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for privilege in ["usage", "create"] {
            fixture(|f, uri| {
                let adapter = f.adapter(&uri);
                f.restricted(&adapter);
                f.admin
                    .batch_execute(&format!(
                        "revoke {privilege} on schema {} from {}",
                        f.schema, f.roles[0]
                    ))
                    .unwrap();
                assert!(!adapter
                    .connect()
                    .unwrap()
                    .query_one(
                        "select has_schema_privilege($1,$2)",
                        &[&f.schema, &privilege.to_uppercase()]
                    )
                    .unwrap()
                    .get::<_, bool>(0));
                let before = f.snapshot();
                assert!(adapter.initialize_access_schema(mode, &catalog()).is_err());
                assert!(
                    before == f.snapshot(),
                    "failed permission check left objects behind"
                );
                f.assert_host();
            });
        }
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn absent_schema_requires_database_create_and_retains_legacy_creation_path() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        fixture(|f, uri| {
            let adapter = f.adapter(&uri);
            f.restricted(&adapter);
            f.admin
                .batch_execute(&format!("drop schema {} cascade", f.schema))
                .unwrap();
            assert!(adapter.initialize_access_schema(mode, &catalog()).is_err());
            assert!(!f
                .admin
                .query_one(
                    "select exists(select 1 from pg_namespace where nspname=$1)",
                    &[&f.schema]
                )
                .unwrap()
                .get::<_, bool>(0));
            let database: String = f
                .admin
                .query_one("select current_database()", &[])
                .unwrap()
                .get(0);
            f.admin
                .batch_execute(&format!(
                    "grant create on database \"{}\" to {}",
                    database.replace('"', "\"\""),
                    f.roles[0]
                ))
                .unwrap();
            f.database_grants.push(f.roles[0].clone());
            // Force a table-creation error after the missing schema was created,
            // without changing global privileges or adding a failure-injection hook.
            f.admin
                .batch_execute(&format!(
                    "alter role {} set default_tablespace=pg_global",
                    f.roles[0]
                ))
                .unwrap();
            let failing = f.adapter(&uri);
            assert_eq!(
                failing
                    .connect()
                    .unwrap()
                    .query_one("show default_tablespace", &[])
                    .unwrap()
                    .get::<_, String>(0),
                "pg_global"
            );
            let absent = f.snapshot();
            assert!(failing.initialize_access_schema(mode, &catalog()).is_err());
            assert!(
                absent == f.snapshot(),
                "failed DDL retained an auto-created schema"
            );
            drop(failing);
            f.admin
                .batch_execute(&format!(
                    "alter role {} reset default_tablespace",
                    f.roles[0]
                ))
                .unwrap();
            adapter.initialize_access_schema(mode, &catalog()).unwrap();
            adapter.inspect_access_schema(mode).unwrap();
        });
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn object_conflicts_roll_back_catalogs_and_release_pooled_transaction_and_lock() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for conflict in [
            "create table __S__.accounts(id int)",
            "create view __S__.access_state as select 1 as singleton",
            "create index access_memberships_by_account on __S__.host_data(id)",
            "create domain __S__.accounts as text",
            "create function __S__.access_validate_binding() returns trigger language plpgsql as $$ begin return new; end $$",
            "create index devices_tenant_id_id_client_id_key on __S__.host_data(id)",
        ] {
            fixture(|f, uri| {
                let adapter = f.adapter(&uri);
                f.restricted(&adapter);
                f.admin
                    .batch_execute(&conflict.replace("__S__", &f.schema))
                    .unwrap();
                let before = f.snapshot();
                let pid: i32 = adapter
                    .connect()
                    .unwrap()
                    .query_one("select pg_backend_pid()", &[])
                    .unwrap()
                    .get(0);
                assert!(
                    adapter.initialize_access_schema(mode, &catalog()).is_err(),
                    "conflict was accepted: {conflict}"
                );
                assert!(
                    before == f.snapshot(),
                    "rollback changed pre-existing catalog: {conflict}"
                );
                f.assert_host();
                let mut reused = adapter.connect().unwrap();
                assert_eq!(
                    reused
                        .query_one("select pg_backend_pid()", &[])
                        .unwrap()
                        .get::<_, i32>(0),
                    pid
                );
                assert!(!reused.query_one("select exists(select 1 from pg_locks where locktype='advisory' and pid=pg_backend_pid())", &[]).unwrap().get::<_, bool>(0));
                drop(reused);
                let mut tx = f.admin.transaction().unwrap();
                assert!(
                    tx.query_one(
                        "select pg_try_advisory_xact_lock(hashtext($1))",
                        &[&format!("{}:embedded-idp-migration", f.schema)]
                    )
                    .unwrap()
                    .get::<_, bool>(0)
                );
                tx.rollback().unwrap();
                // Explicit fixture repair, followed by the same initialization request.
                f.admin.batch_execute(&format!("drop schema {} cascade; create schema {}; grant usage,create on schema {} to {}", f.schema,f.schema,f.schema,f.roles[0])).unwrap();
                adapter.initialize_access_schema(mode, &catalog()).unwrap();
                adapter.inspect_access_schema(mode).unwrap();
            });
        }
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn automatic_constraint_names_must_pass_layout_validation_before_commit() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        fixture(|f, _| {
            // Privileged baseline bypasses the separate CREATE SCHEMA permission
            // defect, so this regression exposes the missing final layout check.
            let adapter = f.adapter(&f.uri);
            f.admin
                .batch_execute(&format!(
                    "create index devices_tenant_id_id_client_id_key on {}.host_data(id)",
                    f.schema
                ))
                .unwrap();
            let before = f.snapshot();
            assert!(
                adapter.initialize_access_schema(mode, &catalog()).is_err(),
                "initialization accepted automatically renamed required constraint"
            );
            assert!(
                before == f.snapshot(),
                "late validation did not roll back DDL"
            );
            f.assert_host();
        });
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn initialized_schema_rejects_wrong_mode_and_detected_damage_without_repair() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for damage in [
            "alter table __S__.accounts disable trigger account_requires_membership",
            "drop table __S__.scan_login_origin_closures",
        ] {
            fixture(|f, uri| {
                let adapter = f.adapter(&uri);
                adapter.initialize_access_schema(mode, &catalog()).unwrap();
                let other = if mode == TenancyMode::Disabled {
                    TenancyMode::Enabled
                } else {
                    TenancyMode::Disabled
                };
                let before = f.snapshot();
                assert!(matches!(
                    adapter.initialize_access_schema(other, &catalog()),
                    Err(StoreError::Conflict("access.schema_mode_or_version"))
                ));
                assert!(before == f.snapshot());
                f.admin
                    .batch_execute(&damage.replace("__S__", &f.schema))
                    .unwrap();
                let damaged = f.snapshot();
                assert!(adapter.initialize_access_schema(mode, &catalog()).is_err());
                assert!(
                    damaged == f.snapshot(),
                    "initialization repaired detected damage"
                );
            });
        }
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn historical_access_layouts_are_rejected_without_migration() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for (version, ddl) in [
            ("tenant_v2", include_str!("../../src/sql/tenant_v2.sql")),
            ("tenant_v3", include_str!("../../src/sql/tenant_v3.sql")),
            ("tenant_v4", include_str!("../../src/sql/tenant_v4.sql")),
            ("tenant_v5", include_str!("../../src/sql/tenant_v5.sql")),
        ] {
            fixture(|f, _| {
                f.admin
                    .batch_execute(&ddl.replace("__SCHEMA__", &f.schema))
                    .unwrap();
                let mode_name = if mode == TenancyMode::Disabled {
                    "disabled"
                } else {
                    "enabled"
                };
                f.admin.execute(&format!("insert into {}.access_state(singleton,tenancy_mode,module_version) values(true,$1,$2)",f.schema), &[&mode_name,&version]).unwrap();
                let before = f.snapshot();
                let adapter = f.adapter(&f.uri);
                assert!(
                    adapter.initialize_access_schema(mode, &catalog()).is_err(),
                    "accepted {version}"
                );
                assert!(before == f.snapshot(), "rewrote {version} objects");
                assert_eq!(
                    f.admin
                        .query_one(
                            &format!("select module_version from {}.access_state", f.schema),
                            &[]
                        )
                        .unwrap()
                        .get::<_, String>(0),
                    version
                );
                f.assert_host();
            });
        }
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn initialization_after_lock_wait_uses_current_committed_state() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        for isolation in ["read committed", "repeatable read"] {
            fixture(|f, uri| {
                f.admin
                    .batch_execute(&format!(
                        "alter role {} set default_transaction_isolation='{isolation}'",
                        f.roles[0]
                    ))
                    .unwrap();
                let adapters = [f.adapter(&uri), f.adapter(&uri)];
                for adapter in &adapters {
                    f.restricted(adapter);
                    assert_eq!(
                        adapter
                            .connect()
                            .unwrap()
                            .query_one("show default_transaction_isolation", &[])
                            .unwrap()
                            .get::<_, String>(0),
                        isolation
                    );
                }
                let mut observer = Client::connect(&f.uri, NoTls).unwrap();
                let mut blocker = f.admin.transaction().unwrap();
                blocker
                    .query_one(
                        "select pg_advisory_xact_lock(hashtext($1))",
                        &[&format!("{}:embedded-idp-migration", f.schema)],
                    )
                    .unwrap();
                let handles = adapters.map(|adapter| {
                    thread::spawn(move || {
                        let result = adapter.initialize_access_schema(mode, &catalog());
                        (adapter, result)
                    })
                });
                let deadline = Instant::now() + Duration::from_secs(10);
                let waiting = loop {
                    let count: i64 = observer.query_one("select count(*) from pg_stat_activity where application_name=$1 and wait_event='advisory'", &[&f.schema]).unwrap().get(0);
                    if count == 2 {
                        break true;
                    }
                    if Instant::now() >= deadline {
                        break false;
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                blocker.rollback().unwrap();
                let results = handles.map(|h| h.join().expect("initialization worker panicked"));
                assert!(
                    waiting,
                    "both initializers must actually wait on the migration lock"
                );
                for (adapter, result) in results {
                    result.unwrap();
                    adapter.inspect_access_schema(mode).unwrap();
                    assert_eq!(
                        adapter
                            .connect()
                            .unwrap()
                            .query_one("show default_transaction_isolation", &[])
                            .unwrap()
                            .get::<_, String>(0),
                        isolation
                    );
                }
            });
        }
    }
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn trusted_search_path_and_nonconflicting_overloads_keep_the_explicit_target() {
    fixture(|f, uri| {
        let noise = format!("{}_noise", f.schema);
        f.schemas.push(noise.clone());
        f.admin.batch_execute(&format!("create schema {noise}; create table {noise}.accounts(id int); grant usage on schema {noise} to {}; alter role {} set search_path=pg_catalog,{noise}; create function {}.access_validate_binding(text) returns text language sql as $$ select $1 $$; create function {}.host_trigger() returns trigger language plpgsql as $$ begin return new; end $$; create trigger role_binding_guard before insert on {}.host_data for each row execute function {}.host_trigger()",f.roles[0],f.roles[0],f.schema,f.schema,f.schema,f.schema)).unwrap();
        let adapter = f.adapter(&uri);
        f.restricted(&adapter);
        adapter
            .initialize_access_schema(TenancyMode::Disabled, &catalog())
            .unwrap();
        adapter
            .inspect_access_schema(TenancyMode::Disabled)
            .unwrap();
        f.assert_host();
        assert_eq!(
            f.admin
                .query_one(&format!("select count(*) from {noise}.accounts"), &[])
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        assert!(f
            .admin
            .query_one(
                "select to_regprocedure($1) is not null",
                &[&format!("{}.access_validate_binding(text)", f.schema)]
            )
            .unwrap()
            .get::<_, bool>(0));
    });
}

#[test]
#[ignore = "requires disposable EMBEDDED_IDP_TEST_PG_CONNECTION_URI with role management"]
fn separate_runtime_role_needs_object_grants_and_can_execute_real_admin_writes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        fixture(|f, uri| {
            let initializer = f.adapter(&uri);
            f.restricted(&initializer);
            initializer
                .initialize_access_schema(mode, &catalog())
                .unwrap();
            let subject = bootstrap(&initializer, mode);
            let session = Uuid::now_v7();
            let mut c = initializer.connect().unwrap();
            c.batch_execute(&format!("insert into {}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values('schema-test','Schema test','[]','public_desktop',true,1)",f.schema)).unwrap();
            c.execute(&format!("insert into {}.auth_sessions(purpose,tenant_id,id,account_id,client_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,authenticated_at_epoch) values('management','0',$1,$2,'schema-test','active',1,4102444800,1,1)",f.schema), &[&session,&subject]).unwrap();
            drop(c);
            let runtime_uri = f.role();
            let role = f.roles.last().unwrap().clone();
            f.admin
                .batch_execute(&format!("grant usage on schema {} to {role}", f.schema))
                .unwrap();
            // Grant only the exact tables created by the initializer, not host_data.
            let tables: Vec<String> = f.admin.query("select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relkind='r' and c.relowner=(select oid from pg_roles where rolname=$2)", &[&f.schema,&f.roles[0]]).unwrap().into_iter().map(|r| r.get(0)).collect();
            for table in &tables {
                f.admin
                    .batch_execute(&format!("grant select on {}.{table} to {role}", f.schema))
                    .unwrap();
            }
            let runtime = f.adapter(&runtime_uri);
            assert!(!runtime
                .connect()
                .unwrap()
                .query_one(
                    "select has_schema_privilege($1,'CREATE') or has_table_privilege($2,'SELECT')",
                    &[&f.schema, &format!("{}.host_data", f.schema)]
                )
                .unwrap()
                .get::<_, bool>(0));
            let store = PostgresAccessStore::new(runtime.clone(), mode).unwrap();
            store.check_readiness(&catalog()).unwrap();
            let service =
                CoreAccessAdminService::new(mode, catalog(), store, SystemClock, UuidV7IdGenerator);
            let context = || AccessAdminContext {
                actor: AccessActor {
                    tenant_id: "0".into(),
                    subject_id: subject.to_string(),
                    session_id: session.to_string(),
                },
                authentication_source: "schema_test".into(),
                request_id: Uuid::now_v7().to_string(),
            };
            let command = || AccessAdminCommand {
                tenant_id: "schema_tenant".into(),
                mutation: AccessAdminMutation::CreateTenant {
                    name: "Schema test tenant".into(),
                    allow_registration: true,
                    administrator_subject_id: subject.to_string(),
                },
            };
            // Enabled uses tenant creation; Disabled uses a business role in domain 0.
            let command = || {
                if mode == TenancyMode::Enabled {
                    command()
                } else {
                    AccessAdminCommand {
                        tenant_id: "0".into(),
                        mutation: AccessAdminMutation::CreateRole {
                            business_id: "f_01".into(),
                            key: "schema_reader".into(),
                            name: "Schema reader".into(),
                        },
                    }
                }
            };
            assert!(
                matches!(
                    service.execute(context(), command()),
                    Err(AccessError::Store(StoreError::Backend(_)))
                ),
                "readiness is not write authority"
            );
            for table in &tables {
                f.admin
                    .batch_execute(&format!(
                        "grant insert,update,delete on {}.{table} to {role}",
                        f.schema
                    ))
                    .unwrap();
            }
            service.execute(context(), command()).unwrap();
            f.assert_host();
        });
    }
}

#[test]
fn reserved_schema_initialization_is_rejected_before_connecting() {
    for schema in ["pg_catalog", "pg_temp", "pg_idp_test"] {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: "postgres://127.0.0.1:1/unused".into(),
                schema_name: schema.into(),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "reserved-schema-offline-test".into(),
                max_connections: 1,
                connect_timeout_secs: 1,
            },
        })
        .unwrap();
        assert!(
            matches!(adapter.initialize_access_schema(TenancyMode::Disabled,&catalog()),Err(StoreError::Backend(message)) if message=="reserved postgres schema cannot be initialized")
        );
    }
}

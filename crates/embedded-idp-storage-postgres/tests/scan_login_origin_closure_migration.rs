use embedded_idp_core::access::TenancyMode;
use embedded_idp_storage_postgres::*;
use std::env;
use uuid::Uuid;

struct V5Db {
    adapter: PostgresStorageAdapter,
}
impl V5Db {
    fn new() -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_scan_closure_migration_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-scan-closure-migration-test".into(),
                max_connections: 2,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        let schema = adapter.schema_name().to_owned();
        let mut client = adapter.connect().unwrap();
        client
            .batch_execute(&format!("create schema {schema}"))
            .unwrap();
        client
            .batch_execute(&include_str!("../src/sql/tenant_v5.sql").replace("__SCHEMA__", &schema))
            .unwrap();
        client.batch_execute(&format!("insert into {schema}.access_state(singleton,tenancy_mode,module_version) values(true,'enabled','tenant_v5'); insert into {schema}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values('0','system','System','active',false,1)")).unwrap();
        Self { adapter }
    }
}
impl Drop for V5Db {
    fn drop(&mut self) {
        assert!(self
            .adapter
            .schema_name()
            .starts_with("idp_scan_closure_migration_it_"));
        if let Ok(mut client) = self.adapter.connect() {
            let _ = client.batch_execute(&format!(
                "drop schema {} cascade",
                self.adapter.schema_name()
            ));
        }
    }
}
fn migration_do() -> String {
    let sql = include_str!("../../../scripts/migrate_scan_login_origin_closures.sql");
    let start = sql.find("do $$\ndeclare n text").unwrap();
    let end = sql[start..].find("end $$;").unwrap() + start + "end $$;".len();
    sql[start..end].to_owned()
}
fn apply(client: &mut postgres::Client, schema: &str, body: &str) -> Result<(), postgres::Error> {
    let mut transaction = client.transaction()?;
    transaction.execute(
        "select set_config('embedded_idp.scan_origin_closure_schema',$1,true)",
        &[&schema],
    )?;
    transaction.batch_execute(body)?;
    transaction.commit()
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn scan_origin_closure_do_migrates_v5_idempotently_and_rolls_back_on_version_write_failure() {
    let db = V5Db::new();
    let body = migration_do();
    let mut client = db.adapter.connect().unwrap();
    apply(&mut client, db.adapter.schema_name(), &body).unwrap();
    assert_eq!(
        db.adapter
            .inspect_access_schema(TenancyMode::Enabled)
            .unwrap()
            .version,
        "tenant_v6"
    );
    apply(&mut client, db.adapter.schema_name(), &body).unwrap();
    let columns: i64 = client.query_one(&format!("select count(*) from information_schema.columns where table_schema=$1 and table_name='scan_login_origin_closures'"), &[&db.adapter.schema_name()]).unwrap().get(0);
    assert_eq!(columns, 10);
    let failed = V5Db::new();
    let schema = failed.adapter.schema_name().to_owned();
    let mut failing = failed.adapter.connect().unwrap();
    failing.batch_execute(&format!("create function {schema}.fail_version() returns trigger language plpgsql as $$ begin raise exception 'test'; end $$; create trigger fail_version before update on {schema}.access_state for each row execute function {schema}.fail_version()")).unwrap();
    assert!(apply(&mut failing, &schema, &body).is_err());
    let version: String = failing
        .query_one(
            &format!("select module_version from {schema}.access_state"),
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(version, "tenant_v5");
    let closures: i64 = failing.query_one("select count(*) from information_schema.tables where table_schema=$1 and table_name='scan_login_origin_closures'", &[&schema]).unwrap().get(0);
    assert_eq!(closures, 0);
}

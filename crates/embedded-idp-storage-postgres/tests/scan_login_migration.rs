use embedded_idp_core::access::TenancyMode;
use embedded_idp_storage_postgres::*;
use std::env;
use uuid::Uuid;

struct LegacyDb {
    adapter: PostgresStorageAdapter,
}
impl LegacyDb {
    fn new() -> Self {
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
                    .expect("explicit test connection required"),
                schema_name: format!("idp_scan_migration_it_{}", Uuid::now_v7().simple()),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-scan-migration-test".into(),
                max_connections: 2,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        let s = adapter.schema_name().to_owned();
        let mut c = adapter.connect().unwrap();
        c.batch_execute(&format!("create schema {s}")).unwrap();
        c.batch_execute(&include_str!("../src/sql/tenant_v4.sql").replace("__SCHEMA__", &s))
            .unwrap();
        c.batch_execute(&format!("insert into {s}.access_state(singleton,tenancy_mode,module_version) values(true,'enabled','tenant_v4'); insert into {s}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values('0','system','System','active',false,1)" )).unwrap();
        Self { adapter }
    }
    fn schema(&self) -> &str {
        self.adapter.schema_name()
    }
}
impl Drop for LegacyDb {
    fn drop(&mut self) {
        assert!(self.schema().starts_with("idp_scan_migration_it_"));
        if let Ok(mut c) = self.adapter.connect() {
            let _ = c.batch_execute(&format!("drop schema {} cascade", self.schema()));
        }
    }
}
fn migration_do(sql: &str) -> String {
    let start = sql.find("do $$\ndeclare n text").unwrap();
    let end = sql[start..].find("end $$;").unwrap() + start + "end $$;".len();
    sql[start..end].to_owned()
}
fn apply(
    c: &mut postgres::Client,
    schema: &str,
    body: &str,
    setting: &str,
) -> Result<(), postgres::Error> {
    let mut tx = c.transaction()?;
    tx.execute("select set_config($1,$2,true)", &[&setting, &schema])?;
    tx.batch_execute(body)?;
    tx.commit()
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn scan_login_do_migrates_v4_idempotently_and_rolls_back_on_version_write_failure() {
    let db = LegacyDb::new();
    let body = migration_do(include_str!("../../../scripts/migrate_scan_login.sql"));
    let mut c = db.adapter.connect().unwrap();
    apply(&mut c, db.schema(), &body, "embedded_idp.scan_schema").unwrap();
    assert_eq!(
        c.query_one(
            &format!("select module_version from {}.access_state", db.schema()),
            &[]
        )
        .unwrap()
        .get::<_, String>(0),
        "tenant_v5"
    );
    apply(&mut c, db.schema(), &body, "embedded_idp.scan_schema").unwrap();
    let tables:i64=c.query_one(&format!("select count(*) from information_schema.tables where table_schema=$1 and table_name like 'scan_login_%'"),&[&db.schema()]).unwrap().get(0);
    assert_eq!(tables, 4);
    // The current adapter requires v6; historical v4->v5 stays unchanged.
    assert!(db
        .adapter
        .inspect_access_schema(TenancyMode::Enabled)
        .is_err());
    let closure_body = migration_do(include_str!(
        "../../../scripts/migrate_scan_login_origin_closures.sql"
    ));
    apply(
        &mut c,
        db.schema(),
        &closure_body,
        "embedded_idp.scan_origin_closure_schema",
    )
    .unwrap();
    assert_eq!(
        db.adapter
            .inspect_access_schema(TenancyMode::Enabled)
            .unwrap()
            .version,
        "tenant_v6"
    );
    let failed = LegacyDb::new();
    let mut f = failed.adapter.connect().unwrap();
    let s = failed.schema().to_owned();
    f.batch_execute(&format!("create function {s}.fail_version() returns trigger language plpgsql as $$ begin raise exception 'test'; end $$; create trigger fail_version before update on {s}.access_state for each row execute function {s}.fail_version()" )).unwrap();
    assert!(apply(&mut f, &s, &body, "embedded_idp.scan_schema").is_err());
    let version: String = f
        .query_one(&format!("select module_version from {s}.access_state"), &[])
        .unwrap()
        .get(0);
    assert_eq!(version, "tenant_v4");
    let scans:i64=f.query_one("select count(*) from information_schema.tables where table_schema=$1 and table_name like 'scan_login_%'",&[&s]).unwrap().get(0);
    assert_eq!(scans, 0);
}

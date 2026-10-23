use std::{env, time::Instant};

use embedded_idp_core::StoreError;
use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresStorageAdapter,
};
use uuid::Uuid;

fn adapter(schema_name: String) -> PostgresStorageAdapter {
    let connection_uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
        .expect("EMBEDDED_IDP_TEST_PG_CONNECTION_URI is required for live pool tests");
    PostgresStorageAdapter::new(PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri,
            schema_name,
            tls_mode: PgTlsMode::Disable,
            tls_ca_cert_path: None,
        },
        pool: DbPoolConfig {
            application_name: "embedded-idp-pool-test".to_string(),
            max_connections: 1,
            connect_timeout_secs: 1,
        },
    })
    .expect("pool test config should be valid")
}

#[test]
#[ignore = "requires EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn cloned_adapters_share_bounded_capacity_and_open_fresh_connections() {
    let adapter = adapter("embedded_idp_pool_test".to_string());
    let clone = adapter.clone();
    let mut first = adapter
        .connect()
        .expect("first pooled connection should open");
    let first_backend_pid: i32 = first
        .query_one("select pg_backend_pid()", &[])
        .expect("read first backend id")
        .get(0);

    let started = Instant::now();
    let exhaustion = clone.connect();
    assert!(started.elapsed() >= std::time::Duration::from_millis(9500));
    assert!(started.elapsed() < std::time::Duration::from_secs(11));
    assert!(matches!(exhaustion, Err(StoreError::Backend(_))));

    drop(first);
    let mut reused = clone
        .connect()
        .expect("released pooled connection should be reusable");
    reused
        .query_one("select 1", &[])
        .expect("reused connection should remain usable");
    let reused_backend_pid: i32 = reused
        .query_one("select pg_backend_pid()", &[])
        .expect("read reused backend id")
        .get(0);
    assert_ne!(reused_backend_pid, first_backend_pid);
}

#[test]
#[ignore = "requires EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn failed_legacy_cutover_releases_transaction_and_advisory_locks() {
    let schema_name = format!("pool_cutover_{}", Uuid::now_v7().simple());
    let adapter = adapter(schema_name);
    let mut first = adapter
        .connect()
        .expect("first pooled connection should open");
    let first_backend_pid: i32 = first
        .query_one("select pg_backend_pid()", &[])
        .expect("read first backend id")
        .get(0);
    drop(first);

    assert!(matches!(
        adapter.apply_security_cutover(),
        Err(StoreError::Backend(_))
    ));

    let mut reused = adapter
        .connect()
        .expect("online pool should remain usable after failed initialization");
    let reused_backend_pid: i32 = reused
        .query_one("select pg_backend_pid()", &[])
        .expect("read reused backend id")
        .get(0);
    assert_ne!(reused_backend_pid, first_backend_pid);
    let no_advisory_locks: bool = reused
        .query_one(
            "select not exists (select 1 from pg_locks where locktype = 'advisory' and pid = pg_backend_pid())",
            &[],
        )
        .expect("inspect advisory locks")
        .get(0);
    assert!(no_advisory_locks);
    let lock_key = format!("{}:embedded-idp-migration", adapter.schema_name());
    assert!(reused
        .query_one("select pg_try_advisory_lock(hashtext($1))", &[&lock_key])
        .unwrap()
        .get::<_, bool>(0));
    reused
        .query_one("select pg_advisory_unlock(hashtext($1))", &[&lock_key])
        .unwrap();
}

#[test]
#[ignore = "requires EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn generic_transport_preserves_stricter_host_readonly_probe_limits() {
    let mut config = adapter("embedded_idp_pool_test".into()).config().clone();
    config.connection.connection_uri.push_str("&options=-c%20default_transaction_read_only%3Don%20-c%20statement_timeout%3D1000%20-c%20lock_timeout%3D500");
    let adapter = PostgresStorageAdapter::new(config).unwrap();
    let mut client = adapter.connect().unwrap();
    let protected: bool = client.query_one(
        "select current_setting('default_transaction_read_only')='on' and current_setting('statement_timeout')::interval=interval '1 second' and current_setting('lock_timeout')::interval=interval '500 milliseconds'", &[]
    ).unwrap().get(0);
    assert!(
        protected,
        "generic defaults must preserve stricter trusted Host options"
    );
}

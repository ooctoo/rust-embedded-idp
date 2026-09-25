//! Explicit local PostgreSQL opt-in; runs the real CLI against disposable schemas.
use embedded_idp_core::access::{PermissionCatalog, TenancyMode};
use embedded_idp_core::{IdGenerator, UuidV7IdGenerator};
use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresAccessStore,
    PostgresStorageAdapter,
};
use std::{
    env,
    io::Write,
    process::{Command, Output, Stdio},
};
struct Db {
    adapter: PostgresStorageAdapter,
    uri: String,
    mode: TenancyMode,
}
impl Db {
    fn new(mode: TenancyMode) -> Self {
        let uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
            .expect("explicit test database required");
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: uri.clone(),
                schema_name: format!(
                    "idp_bootstrap_cli_it_{}",
                    UuidV7IdGenerator.next_id("schema").replace('-', "")
                ),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "idp-bootstrap-cli-test".into(),
                max_connections: 2,
                connect_timeout_secs: 3,
            },
        })
        .unwrap();
        adapter
            .initialize_access_schema(mode, &PermissionCatalog::new(vec![]).unwrap())
            .unwrap();
        Self { adapter, uri, mode }
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_embedded-idp-app"));
        for (key, _) in env::vars().filter(|(k, _)| k.starts_with("EMBEDDED_IDP_")) {
            cmd.env_remove(key);
        }
        cmd.env("EMBEDDED_IDP_APP_PG_URI", &self.uri)
            .env("EMBEDDED_IDP_APP_PG_SCHEMA", self.adapter.schema_name())
            .env(
                "EMBEDDED_IDP_APP_TENANCY_MODE",
                if self.mode == TenancyMode::Enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            )
            .env("EMBEDDED_IDP_APP_PG_TLS_MODE", "disable");
        cmd
    }
    fn initialize(&self, email: &str, password: &str) -> Output {
        let mut cmd = self.command();
        cmd.args(["bootstrap-admin", "--email", email, "--password-stdin"]);
        run(cmd, password)
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        assert!(self
            .adapter
            .schema_name()
            .starts_with("idp_bootstrap_cli_it_"));
        if let Ok(mut c) = self.adapter.connect() {
            let _ = c.batch_execute(&format!(
                "drop schema {} cascade",
                self.adapter.schema_name()
            ));
        }
    }
}
fn run(mut command: Command, password: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(password.as_bytes());
    let output = child.wait_with_output().unwrap();
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains(password.trim_end()));
    }
    output
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn cli_bootstrap_initializes_both_modes_and_never_resets_existing_credentials() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let s = db.adapter.schema_name();
        let bad = db.initialize("invalid-address", "FixtureAdmin123\n");
        assert!(!bad.status.success());
        let mut c = db.adapter.connect().unwrap();
        assert_eq!(
            c.query_one(&format!("select count(*) from {s}.accounts"), &[])
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        let mut policy = db.command();
        policy
            .env("EMBEDDED_IDP_APP_PASSWORD_MIN_LENGTH", "32")
            .args([
                "bootstrap-admin",
                "--email",
                "first@example.test",
                "--password-stdin",
            ]);
        assert!(!run(policy, "FixtureAdmin123\n").status.success());
        let first = db.initialize("first@example.test", "FixtureAdmin123\n");
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&first.stdout).trim(),
            "administrator bootstrap initialized"
        );
        let row = c
            .query_one(
                &format!("select id::text,email,password_hash from {s}.accounts"),
                &[],
            )
            .unwrap();
        let id: String = row.get(0);
        let hash: String = row.get(2);
        assert_eq!(row.get::<_, String>(1), "first@example.test");
        assert!(hash.starts_with("$argon2id$"));
        assert!(PostgresAccessStore::new(db.adapter.clone(), mode).is_ok());
        assert_eq!(c.query_one(&format!("select count(*) from {s}.access_memberships where tenant_id='0' and status='active'"),&[]).unwrap().get::<_,i64>(0),1);
        assert_eq!(c.query_one(&format!("select count(*) from {s}.access_role_bindings where tenant_id='0' and resource_type='idp.platform' and resource_id is null"),&[]).unwrap().get::<_,i64>(0),1);
        assert_eq!(
            c.query_one(&format!("select count(*) from {s}.auth_sessions"), &[])
                .unwrap()
                .get::<_, i64>(0),
            0
        );
        let audit:String=c.query_one(&format!("select change_json::text from {s}.access_audit_events where operation='access.bootstrap'"),&[]).unwrap().get(0);
        assert!(!audit.contains("FixtureAdmin123"));
        assert!(!audit.contains("password"));
        let repeated = db.initialize("different@example.test", "DifferentAdmin456\n");
        assert!(repeated.status.success());
        assert!(String::from_utf8_lossy(&repeated.stdout).contains("already initialized"));
        let row = c
            .query_one(
                &format!("select id::text,email,password_hash from {s}.accounts"),
                &[],
            )
            .unwrap();
        assert_eq!(row.get::<_, String>(0), id);
        assert_eq!(row.get::<_, String>(1), "first@example.test");
        assert_eq!(row.get::<_, String>(2), hash);
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.access_audit_events"),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        c.batch_execute(&format!("update {s}.accounts set status='disabled'"))
            .unwrap();
        let refused = db.initialize("repair@example.test", "RepairAdmin789\n");
        assert!(!refused.status.success());
        assert_eq!(
            c.query_one(&format!("select status from {s}.accounts"), &[])
                .unwrap()
                .get::<_, String>(0),
            "disabled"
        );
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn cli_bootstrap_rolls_back_failure_requires_explicit_target_and_online_signing_key() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let s = db.adapter.schema_name();
        let mut c = db.adapter.connect().unwrap();
        for missing in [
            "EMBEDDED_IDP_APP_TENANCY_MODE",
            "EMBEDDED_IDP_APP_PG_URI",
            "EMBEDDED_IDP_APP_PG_SCHEMA",
        ] {
            let mut command = db.command();
            command.env_remove(missing).args([
                "bootstrap-admin",
                "--email",
                "admin@example.test",
                "--password-stdin",
            ]);
            assert!(!run(command, "FixtureAdmin123\n").status.success());
        }
        let mut wrong_mode = db.command();
        wrong_mode
            .env(
                "EMBEDDED_IDP_APP_TENANCY_MODE",
                if mode == TenancyMode::Enabled {
                    "disabled"
                } else {
                    "enabled"
                },
            )
            .args([
                "bootstrap-admin",
                "--email",
                "admin@example.test",
                "--password-stdin",
            ]);
        assert!(!run(wrong_mode, "FixtureAdmin123\n").status.success());
        c.batch_execute(&format!("create function {s}.fail_cli_audit() returns trigger language plpgsql as $$ begin raise exception 'injected bootstrap audit failure'; end $$; create trigger fail_cli_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_cli_audit()")).unwrap();
        assert!(!db
            .initialize("admin@example.test", "FixtureAdmin123\n")
            .status
            .success());
        for table in [
            "accounts",
            "access_roles",
            "access_role_bindings",
            "access_memberships",
            "access_audit_events",
        ] {
            assert_eq!(
                c.query_one(&format!("select count(*) from {s}.{table}"), &[])
                    .unwrap()
                    .get::<_, i64>(0),
                0
            );
        }
        assert!(!c
            .query_one(
                &format!("select bootstrap_completed_at_epoch is not null from {s}.access_state"),
                &[]
            )
            .unwrap()
            .get::<_, bool>(0));
        c.batch_execute(&format!(
            "drop trigger fail_cli_audit on {s}.access_audit_events"
        ))
        .unwrap();
        assert!(db
            .initialize("admin@example.test", "FixtureAdmin123\n")
            .status
            .success());
        let online = db
            .command()
            .env(
                "EMBEDDED_IDP_APP_SIGNING_KEY_FILE",
                "/nonexistent/idp-test-key.der",
            )
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!online.status.success());
        assert!(String::from_utf8_lossy(&online.stderr).contains("cannot open signing key"));
        assert_eq!(
            c.query_one(&format!("select count(*) from {s}.accounts"), &[])
                .unwrap()
                .get::<_, i64>(0),
            1
        );
    }
}

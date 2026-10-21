use super::registration_email_support::*;
use embedded_idp_core::access::{
    PreparedRegistrationEmail, RegistrationEmailPolicy, RegistrationEmailScope, TenancyMode,
};
use embedded_idp_core::SecretString;
use embedded_idp_security::RingRegistrationEmailCrypto;
use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresRegistrationEmailStore,
    PostgresStorageAdapter,
};
use std::{
    env,
    process::{Command, Output, Stdio},
    sync::Arc,
};
use uuid::Uuid;

const CHILD_SCHEMA_ENV: &str = "SUT_I1_CHILD_SCHEMA";
const CHILD_OPERATION_ENV: &str = "SUT_I1_CHILD_OPERATION";
const CHILD_TEST_NAME: &str = "cases_process::two_processes_same_operation_are_idempotent";
const CHILD_EMAIL: &str = "two-process@example.test";
const CHILD_PASSWORD: &str = "TwoProcessPassword123";

#[test]
#[ignore = "requires fresh loopback sut_idp3_test with explicit confirmation"]
fn two_processes_same_operation_are_idempotent() {
    match (
        env::var(CHILD_SCHEMA_ENV).ok(),
        env::var(CHILD_OPERATION_ENV).ok(),
    ) {
        (Some(schema), Some(operation)) => {
            child_register(&schema, &operation);
            return;
        }
        (None, None) => {}
        _ => panic!("child schema and operation must be provided together"),
    }

    let fixture = Fixture::new();
    let account_count = fixture.count("accounts");
    let membership_count = fixture.count("access_memberships");
    let operation = Uuid::now_v7();
    let operation_text = operation.to_string();
    let mut children = Vec::with_capacity(2);
    for _ in 0..2 {
        let mut command = Command::new(env::current_exe().expect("current test executable"));
        command
            .args(["--ignored", "--exact", CHILD_TEST_NAME, "--nocapture"])
            .env(CHILD_SCHEMA_ENV, &fixture.schema)
            .env(CHILD_OPERATION_ENV, &operation_text)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        children.push(command.spawn().expect("spawn registration child"));
    }

    let outputs: Vec<Output> = children
        .into_iter()
        .map(|child| child.wait_with_output().expect("wait registration child"))
        .collect();
    for (index, output) in outputs.iter().enumerate() {
        assert_child_success(index, output);
    }

    assert_eq!(fixture.count("registration_email_contexts"), 1);
    assert_eq!(fixture.count("registration_email_intents"), 1);
    assert_eq!(fixture.count("registration_email_operations"), 1);
    assert_eq!(send_history_lengths(&fixture), (1, 1));
    assert_eq!(fixture.count("accounts"), account_count);
    assert_eq!(fixture.count("access_memberships"), membership_count);
}

fn child_register(schema: &str, operation: &str) {
    assert!(schema.starts_with("reg_email_foundation_i1_"));
    let operation = Uuid::parse_str(operation).expect("child operation UUID");
    let uri = isolated_uri();
    let adapter = PostgresStorageAdapter::new(PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri: uri,
            schema_name: schema.to_string(),
            tls_mode: PgTlsMode::Disable,
            tls_ca_cert_path: None,
        },
        pool: DbPoolConfig {
            application_name: "registration-email-process-child".to_string(),
            max_connections: 4,
            connect_timeout_secs: 5,
        },
    })
    .expect("child adapter config");
    let scope = RegistrationEmailScope::new(AUTHORITY, PRODUCT, TENANT, TenancyMode::Enabled)
        .expect("child registration scope");
    let crypto = Arc::new(
        RingRegistrationEmailCrypto::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32])
            .expect("child test crypto"),
    );
    let store = PostgresRegistrationEmailStore::new(
        adapter,
        scope.clone(),
        RegistrationEmailPolicy::default(),
        crypto.clone(),
    )
    .expect("child registration store");
    let prepared = PreparedRegistrationEmail::prepare(
        &scope,
        crypto.as_ref(),
        operation,
        CHILD_EMAIL,
        &SecretString::new(CHILD_PASSWORD),
        None,
    )
    .expect("child prepared registration");
    store
        .register(&prepared)
        .expect("child registration accepted");
}

fn isolated_uri() -> String {
    assert_eq!(
        env::var("SUT_ISOLATED_ENV_CONFIRMED").as_deref(),
        Ok("fresh-test-instance")
    );
    let uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
        .expect("isolated PostgreSQL URI is required");
    assert_eq!(
        uri,
        "postgres://postgres@127.0.0.1:51412/sut_idp3_test?sslmode=disable"
    );
    uri
}

fn assert_child_success(index: usize, output: &Output) {
    assert!(
        output.status.success(),
        "registration child {index} failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

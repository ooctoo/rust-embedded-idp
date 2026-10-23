mod relay;

use crate::registration_email_support::Fixture;
use embedded_idp_core::access::{
    RegistrationEmailError, RegistrationEmailPolicy, RegistrationEmailScope,
    RegistrationEmailService,
};
use embedded_idp_security::RingRegistrationEmailCrypto;
use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresRegistrationEmailStore,
    PostgresStorageAdapter,
};
use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub use relay::{Cut, Relay};

pub const READONLY_DEADLINE: Duration = Duration::from_secs(6);
pub const IDENTITY_DEADLINE: Duration = Duration::from_secs(11);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub contexts: i64,
    pub attached: i64,
    pub intents: i64,
}

#[derive(Debug)]
pub struct CallEvidence {
    pub result: Option<bool>,
    pub elapsed_ms: u128,
    pub physical_eof: bool,
    pub thread_joined: bool,
    pub hit: bool,
    pub relay_open: bool,
}

pub fn database() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 51412))
}

pub fn install_runtime_and_resume(fixture: &Fixture) {
    let plan = fixture
        .adapter
        .registration_email_runtime_migration_plan(&fixture.scope)
        .expect("runtime plan");
    fixture
        .adapter
        .apply_registration_email_runtime(&plan, &fixture.scope)
        .expect("runtime apply");
    let store = fixture.store();
    RegistrationEmailService::resume_registration(&store).expect("runtime resume");
}

pub fn relay_adapter(fixture: &Fixture, relay: &Relay) -> PostgresStorageAdapter {
    let mut config = fixture.adapter.config().clone();
    config.connection.connection_uri = config
        .connection
        .connection_uri
        .replace("127.0.0.1:51412", &format!("127.0.0.1:{}", relay.port));
    config.pool = DbPoolConfig {
        application_name: "registration-email-physical-live".to_string(),
        max_connections: 4,
        connect_timeout_secs: 1,
    };
    PostgresStorageAdapter::new(PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri: config.connection.connection_uri,
            schema_name: config.connection.schema_name,
            tls_mode: PgTlsMode::Disable,
            tls_ca_cert_path: None,
        },
        pool: config.pool,
    })
    .expect("relay adapter")
}

pub type RegistrationStore = PostgresRegistrationEmailStore<RingRegistrationEmailCrypto>;

pub fn relay_store(fixture: &Fixture, relay: &Relay) -> RegistrationStore {
    PostgresRegistrationEmailStore::new(
        relay_adapter(fixture, relay),
        fixture.scope.clone(),
        RegistrationEmailPolicy::default(),
        fixture.crypto.clone(),
    )
    .expect("relay registration store")
}

pub fn tls_store(
    fixture: &Fixture,
    port: u16,
    host: &str,
    ca_path: Option<&Path>,
) -> Result<RegistrationStore, RegistrationEmailError> {
    tls_store_parts(
        fixture.uri.clone(),
        fixture.schema.clone(),
        fixture.scope.clone(),
        fixture.crypto.clone(),
        port,
        host,
        ca_path,
    )
}

pub fn tls_store_parts(
    base_uri: String,
    schema_name: String,
    scope: RegistrationEmailScope,
    crypto: Arc<RingRegistrationEmailCrypto>,
    port: u16,
    host: &str,
    ca_path: Option<&Path>,
) -> Result<RegistrationStore, RegistrationEmailError> {
    let authority = base_uri
        .replace("127.0.0.1:51412", &format!("{host}:{port}"))
        .split('?')
        .next()
        .expect("fixture URI authority")
        .to_string();
    let adapter = PostgresStorageAdapter::new(PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri: format!("{authority}?sslmode=require&hostaddr=127.0.0.1"),
            schema_name,
            tls_mode: PgTlsMode::Require,
            tls_ca_cert_path: ca_path.map(|path| path.to_string_lossy().into_owned()),
        },
        pool: DbPoolConfig {
            application_name: "registration-email-physical-tls".to_string(),
            max_connections: 4,
            connect_timeout_secs: 1,
        },
    })
    .map_err(|_| RegistrationEmailError::Unavailable)?;
    PostgresRegistrationEmailStore::new(adapter, scope, RegistrationEmailPolicy::default(), crypto)
}

pub fn confirmed_ca_path() -> PathBuf {
    assert_eq!(
        env::var("SUT_ISOLATED_ENV_CONFIRMED").as_deref(),
        Ok("fresh-test-instance")
    );
    let raw = env::var("SUT_INGRESS_TEST_CA_PATH").expect("explicit isolated ingress test CA path");
    let candidate = PathBuf::from(raw);
    assert!(
        candidate.is_absolute(),
        "isolated ingress CA path must be absolute"
    );
    let canonical = candidate
        .canonicalize()
        .expect("isolated ingress test CA path must exist");
    let temp_root = env::temp_dir()
        .canonicalize()
        .expect("system temp directory must exist");
    assert!(
        canonical.starts_with(&temp_root),
        "isolated ingress CA path must be below the system temp directory"
    );
    assert_eq!(
        canonical.file_name().and_then(|name| name.to_str()),
        Some("ca.pem"),
        "isolated ingress CA file must be named ca.pem"
    );
    assert!(
        fs::metadata(&canonical)
            .expect("isolated ingress CA metadata")
            .is_file(),
        "isolated ingress CA path must be a regular file"
    );
    canonical
}

pub fn finish_call(
    relay: &mut Relay,
    hit_eof_before: usize,
    timeout: Duration,
    call: impl FnOnce() -> bool + Send + 'static,
) -> CallEvidence {
    let (sender, receiver) = mpsc::channel();
    let call_started = Instant::now();
    let worker = thread::spawn(move || {
        let result = call();
        let _ = sender.send(result);
    });
    let hit = relay.wait_for_hits(1);
    let result = if hit {
        receiver.recv_timeout(timeout).ok()
    } else {
        None
    };
    let elapsed_ms = call_started.elapsed().as_millis();
    let physical_eof = result.is_some() && hit && relay.wait_for_hit_peer_eof(hit_eof_before + 1);
    let (thread_joined, relay_open) = if result.is_some() && physical_eof {
        let joined = worker.join().is_ok();
        if joined {
            relay.disarm();
            (true, true)
        } else {
            relay.close();
            (false, false)
        }
    } else {
        relay.close();
        (worker.join().is_ok(), false)
    };
    CallEvidence {
        result,
        elapsed_ms,
        physical_eof,
        thread_joined,
        hit,
        relay_open,
    }
}

pub fn counts(fixture: &Fixture) -> Counts {
    let mut client = fixture.adapter.connect().expect("count connection");
    Counts {
        contexts: client
            .query_one(
                &format!(
                    "select count(*) from {}.registration_email_contexts",
                    fixture.schema
                ),
                &[],
            )
            .expect("context count")
            .get(0),
        attached: client
            .query_one(
                &format!(
                    "select count(*) from {}.registration_email_operations where phase='attached'",
                    fixture.schema
                ),
                &[],
            )
            .expect("attached count")
            .get(0),
        intents: client
            .query_one(
                &format!(
                    "select count(*) from {}.registration_email_intents",
                    fixture.schema
                ),
                &[],
            )
            .expect("intent count")
            .get(0),
    }
}

pub fn operation_count(fixture: &Fixture) -> i64 {
    fixture
        .adapter
        .connect()
        .expect("operation count connection")
        .query_one(
            &format!(
                "select count(*) from {}.registration_email_operations",
                fixture.schema
            ),
            &[],
        )
        .expect("operation count")
        .get(0)
}

pub fn only_context(fixture: &Fixture) -> Uuid {
    fixture
        .adapter
        .connect()
        .expect("context connection")
        .query_one(
            &format!(
                "select id from {}.registration_email_contexts order by id",
                fixture.schema
            ),
            &[],
        )
        .expect("context row")
        .get(0)
}

pub fn print_marker(
    stage: u8,
    evidence: &CallEvidence,
    recovered: bool,
    counts: Counts,
    replay_no_extra: bool,
) {
    println!(
        "SUT_IDP_PHYSICAL {{\"stage\":{},\"elapsed_ms\":{},\"physical_eof\":{},\"thread_joined\":{},\"recovered\":{},\"contexts\":{},\"attached\":{},\"intents\":{},\"replay_no_extra\":{}}}",
        stage,
        evidence.elapsed_ms,
        evidence.physical_eof,
        evidence.thread_joined,
        recovered,
        counts.contexts,
        counts.attached,
        counts.intents,
        replay_no_extra,
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyFacts {
    pub accounts: i64,
    pub active_accounts: i64,
    pub memberships: i64,
    pub active_memberships: i64,
    pub consumed_codes: i64,
    pub completed_contexts: i64,
    pub verify_attached: i64,
}

pub fn verify_facts(fixture: &Fixture, email: &str, context: Uuid, operation: Uuid) -> VerifyFacts {
    let mut client = fixture.adapter.connect().expect("verify facts connection");
    let row = client
        .query_one(
            &format!(
                "select (select count(*) from {schema}.accounts where email=$1), (select count(*) from {schema}.accounts where email=$1 and status='active'), (select count(*) from {schema}.access_memberships m join {schema}.accounts a on a.id=m.account_id where a.email=$1), (select count(*) from {schema}.access_memberships m join {schema}.accounts a on a.id=m.account_id where a.email=$1 and m.status='active'), (select count(*) from {schema}.registration_email_codes where context_id=$2 and seq=1 and consumed_at is not null), (select count(*) from {schema}.registration_email_contexts where id=$2 and completed_operation=$3), (select count(*) from {schema}.registration_email_operations where kind='verify' and operation_id=$3 and phase='attached' and result='verified')",
                schema = fixture.schema
            ),
            &[&email, &context, &operation],
        )
        .expect("verify facts");
    VerifyFacts {
        accounts: row.get(0),
        active_accounts: row.get(1),
        memberships: row.get(2),
        active_memberships: row.get(3),
        consumed_codes: row.get(4),
        completed_contexts: row.get(5),
        verify_attached: row.get(6),
    }
}

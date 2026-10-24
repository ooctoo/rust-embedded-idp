use embedded_idp_core::access::*;
use embedded_idp_core::{
    AuthConfig, Clock, SecretString, UuidV7IdGenerator, VerificationCodeGenerator,
};
use embedded_idp_security::RingRegistrationEmailCrypto;
use embedded_idp_storage_postgres::*;
use std::{
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const TENANT: &str = "t1";
pub const AUTHORITY: &str = "sut";
pub const PRODUCT: &str = "online";
pub const EXISTING_EMAIL: &str = "existing@example.test";
pub const EXISTING_PASSWORD: &str = "ExistingPass123";

#[derive(Clone, Copy)]
pub struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
}

struct FixedCodes;
impl VerificationCodeGenerator for FixedCodes {
    fn generate_code(&self) -> String {
        "123456".to_string()
    }
}

fn test_uri() -> String {
    assert_eq!(
        env::var("SUT_ISOLATED_ENV_CONFIRMED").as_deref(),
        Ok("fresh-test-instance")
    );
    let uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
        .expect("the isolated PostgreSQL URI is required");
    assert_eq!(
        uri,
        "postgres://postgres@127.0.0.1:51412/sut_idp3_test?sslmode=disable"
    );
    uri
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        allow_local_registration: true,
        access_token_ttl_secs: 60,
        refresh_token_ttl_secs: 600,
        session_ttl_secs: 600,
        verification_code_ttl_secs: 60,
        password_min_length: 8,
        password_max_length: 128,
    }
}

pub struct Fixture {
    pub uri: String,
    pub adapter: PostgresStorageAdapter,
    pub schema: String,
    pub scope: RegistrationEmailScope,
    pub crypto: Arc<RingRegistrationEmailCrypto>,
}

impl Fixture {
    pub fn new() -> Self {
        Self::build_mode(false, TenancyMode::Enabled)
    }

    pub fn with_existing_account() -> Self {
        Self::build_mode(true, TenancyMode::Enabled)
    }

    pub fn with_disabled_mode() -> Self {
        Self::build_mode(false, TenancyMode::Disabled)
    }

    fn build_mode(existing_account: bool, mode: TenancyMode) -> Self {
        let uri = test_uri();
        let schema = format!("reg_email_foundation_i1_{}", Uuid::now_v7().simple());
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: uri.clone(),
                schema_name: schema.clone(),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "registration-email-foundation-live".to_string(),
                max_connections: 8,
                connect_timeout_secs: 5,
            },
        })
        .expect("fixture config");
        adapter
            .initialize_access_schema(mode, &PermissionCatalog::new(vec![]).unwrap())
            .expect("tenant_v6 schema");
        CoreAccessBootstrapService::new(mode, adapter.clone(), FixedClock, UuidV7IdGenerator)
            .initialize_administrator(
                &auth_config(),
                BootstrapAdministrator {
                    email: "admin@example.test".to_string(),
                    display_name: Some("Fixture administrator".to_string()),
                    password: SecretString::new("AdminPass123"),
                    request_id: "registration-email-foundation".to_string(),
                },
            )
            .expect("bootstrap administrator");
        let mut client = adapter.connect().expect("fixture connection");
        if mode == TenancyMode::Enabled {
            client
                .execute(
                    &format!(
                        "insert into {schema}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values($1,'tenant','Tenant 1','active',true,$2)"
                    ),
                    &[&TENANT, &1_i64],
                )
                .expect("tenant binding seed");
        }
        if existing_account {
            let store = PostgresAccessStore::new(adapter.clone(), TenancyMode::Enabled)
                .expect("access store");
            CoreTenantRegistrationService::new(
                TenancyMode::Enabled,
                auth_config(),
                store,
                FixedClock,
                UuidV7IdGenerator,
                FixedCodes,
            )
            .expect("legacy registration service")
            .register_account(RegisterTenantAccountCommand {
                tenant_id: TENANT.to_string(),
                email: EXISTING_EMAIL.to_string(),
                password: SecretString::new(EXISTING_PASSWORD),
                display_name: Some("Existing user".to_string()),
            })
            .expect("seed pending account");
        }
        let plan = adapter
            .registration_email_migration_plan(mode)
            .expect("foundation plan");
        adapter
            .apply_registration_email_foundation(&plan, AUTHORITY, mode)
            .expect("foundation apply");
        let tenant = if mode == TenancyMode::Disabled {
            "0"
        } else {
            TENANT
        };
        let scope = RegistrationEmailScope::new(AUTHORITY, PRODUCT, tenant, mode)
            .expect("registration scope");
        adapter
            .bind_registration_email_product(&scope)
            .expect("registration product binding");
        client
            .execute(
                &format!(
                    "insert into {schema}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,created_at_epoch) values('web','Web','[\"https://example.test/callback\"]','public_desktop',true,$1)"
                ),
                &[&1_i64],
            )
            .expect("OIDC client seed");
        let crypto = Arc::new(
            RingRegistrationEmailCrypto::new([1; 32], [2; 32], [3; 32], [4; 32], [5; 32])
                .expect("test crypto"),
        );
        Self {
            uri,
            adapter,
            schema,
            scope,
            crypto,
        }
    }

    pub fn store(&self) -> PostgresRegistrationEmailStore<RingRegistrationEmailCrypto> {
        PostgresRegistrationEmailStore::new(
            self.adapter.clone(),
            self.scope.clone(),
            RegistrationEmailPolicy::default(),
            self.crypto.clone(),
        )
        .expect("registration store")
    }

    pub fn prepared(
        &self,
        operation: Uuid,
        email: &str,
        password: &str,
        display_name: Option<&str>,
    ) -> PreparedRegistrationEmail {
        PreparedRegistrationEmail::prepare(
            &self.scope,
            self.crypto.as_ref(),
            operation,
            email,
            &SecretString::new(password),
            display_name,
        )
        .expect("prepared registration")
    }

    pub fn context_id(&self, token: &SecretString) -> Uuid {
        self.context_id_str(token.expose_secret())
    }

    pub fn context_id_str(&self, token: &str) -> Uuid {
        let digest = self.crypto.context_digest(token);
        self.adapter
            .connect()
            .expect("fixture connection")
            .query_one(
                &format!(
                    "select id from {}.registration_email_contexts where lookup_digest=$1",
                    self.schema
                ),
                &[&digest.as_slice()],
            )
            .expect("registration context")
            .get(0)
    }

    pub fn count(&self, table: &str) -> i64 {
        self.adapter
            .connect()
            .expect("fixture connection")
            .query_one(
                &format!("select count(*) from {}.{table}", self.schema),
                &[],
            )
            .expect("count query")
            .get(0)
    }

    pub fn now(&self) -> i64 {
        self.adapter
            .connect()
            .expect("fixture connection")
            .query_one(
                "select floor(extract(epoch from clock_timestamp()))::bigint",
                &[],
            )
            .expect("database clock")
            .get(0)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.schema.starts_with("reg_email_foundation_i1_"));
        let started = std::time::Instant::now();
        let result = self
            .adapter
            .connect()
            .map_err(|_| "connect_error".to_owned())
            .and_then(|mut client| {
                client
                    .batch_execute(&format!("drop schema {} cascade", self.schema))
                    .map_err(|e| {
                        e.code()
                            .map(|c| c.code())
                            .unwrap_or("unavailable")
                            .to_owned()
                    })
            });
        eprintln!(
            "SUT_IDP_FIXTURE_CLEANUP {}",
            serde_json::json!({
                "fixture":self.schema.trim_start_matches("reg_email_foundation_i1_"),
                "test":std::thread::current().name().unwrap_or("unnamed"),
                "elapsed_ms":started.elapsed().as_millis(),
                "sqlstate":result.as_ref().err().map(String::as_str).unwrap_or("00000")
            })
        );
        if !std::thread::panicking() {
            assert!(
                result.is_ok(),
                "owning fixture cleanup failed; sqlstate={}",
                result.unwrap_err()
            );
        }
    }
}

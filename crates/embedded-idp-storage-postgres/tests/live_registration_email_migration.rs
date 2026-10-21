use std::env;

use embedded_idp_core::access::{RegistrationEmailScope, TenancyMode};
use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresStorageAdapter,
};
use postgres::{config::Host, Client, Config, NoTls};
use uuid::Uuid;

fn isolated_uri() -> String {
    let marker = env::var("SUT_ISOLATED_ENV_CONFIRMED")
        .expect("SUT_ISOLATED_ENV_CONFIRMED is required; .env is never read");
    assert_eq!(marker, "fresh-test-instance");
    let uri = env::var("EMBEDDED_IDP_TEST_PG_CONNECTION_URI")
        .expect("EMBEDDED_IDP_TEST_PG_CONNECTION_URI is required");
    assert_eq!(
        uri,
        "postgres://postgres@127.0.0.1:51412/sut_idp3_test?sslmode=disable"
    );
    let config: Config = uri.parse().expect("test URI must parse");
    assert_eq!(config.get_dbname(), Some("sut_idp3_test"));
    assert!(config.get_hosts().iter().all(|host| match host {
        Host::Tcp(value) => value == "127.0.0.1" || value == "::1",
        Host::Unix(_) => false,
    }));
    let query = uri.split_once('?').map(|(_, query)| query).unwrap_or("");
    assert!(query.split('&').any(|part| part == "sslmode=disable"));
    let authority = uri
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|rest| rest.rsplit('@').next())
        .unwrap_or("");
    let explicit_port = if authority.starts_with('[') {
        authority.rsplit_once("]:").is_some()
    } else {
        authority
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    };
    assert!(explicit_port || query.split('&').any(|part| part.starts_with("port=")));
    uri
}

struct Fixture {
    uri: String,
    schema: String,
    adapter: PostgresStorageAdapter,
    account_id: Uuid,
    code_id: Uuid,
}

impl Fixture {
    fn new(collision: bool) -> Self {
        let uri = isolated_uri();
        let schema = format!("registration_email_i1_{}", Uuid::now_v7().simple());
        let adapter = PostgresStorageAdapter::new(PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: uri.clone(),
                schema_name: schema.clone(),
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "registration-email-live-test".to_string(),
                max_connections: 4,
                connect_timeout_secs: 5,
            },
        })
        .expect("fixture config");
        let mut client = adapter.connect().expect("connect fixture");
        client
            .batch_execute(&format!("create schema {schema}"))
            .expect("create random schema");
        client
            .batch_execute(&include_str!("../src/sql/tenant_v6.sql").replace("__SCHEMA__", &schema))
            .expect("install tenant_v6 fixture");
        client
            .batch_execute(&format!(
                "insert into {schema}.access_state(singleton,tenancy_mode,module_version) values(true,'enabled','tenant_v6');\
                 insert into {schema}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values\
                 ('0','system','System','active',false,1700000000),('t1','tenant','Tenant','active',true,1700000000)"
            ))
            .expect("seed access state");
        let account_id = Uuid::now_v7();
        seed_account(&mut client, &schema, account_id, " User@EXAMPLE.COM ");
        if collision {
            let second = Uuid::now_v7();
            seed_account(&mut client, &schema, second, "User@example.com");
        }
        let code_id = Uuid::now_v7();
        client
            .execute(
                &format!(
                    "insert into {schema}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7)"
                ),
                &[
                    &"t1",
                    &code_id,
                    &account_id,
                    &" User@EXAMPLE.COM ",
                    &"123456",
                    &1_700_000_000_i64,
                    &1_700_000_900_i64,
                ],
            )
            .expect("seed legacy code");
        Self {
            uri,
            schema,
            adapter,
            account_id,
            code_id,
        }
    }

    fn scope(&self) -> RegistrationEmailScope {
        RegistrationEmailScope {
            authority: "sut".to_string(),
            product: "online".to_string(),
            tenant: "t1".to_string(),
            mode: TenancyMode::Enabled,
        }
    }

    fn plan(&self) -> embedded_idp_storage_postgres::RegistrationEmailMigrationPlan {
        self.adapter
            .registration_email_migration_plan(TenancyMode::Enabled)
            .expect("inventory plan")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        assert!(self.schema.starts_with("registration_email_i1_"));
        if let Ok(mut client) = Client::connect(&self.uri, NoTls) {
            let _ = client.batch_execute(&format!("drop schema {} cascade", self.schema));
        }
    }
}

fn seed_account(client: &mut postgres::Client, schema: &str, id: Uuid, email: &str) {
    let mut tx = client.transaction().expect("seed transaction");
    tx.execute(
        &format!(
            "insert into {schema}.accounts(id,registration_tenant_id,email,password_hash,display_name,status,created_at_epoch) values($1,'t1',$2,'$argon2id$v=19$test','Test','pending_verification',1700000000)"
        ),
        &[&id, &email],
    )
    .expect("seed account");
    tx.execute(
        &format!(
            "insert into {schema}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch) values('t1',$1,'active',1,1700000000)"
        ),
        &[&id],
    )
    .expect("seed membership");
    tx.commit().expect("commit seed transaction");
}

#[path = "registration_email_migration_support/case_1.rs"]
mod case_1;
#[path = "registration_email_migration_support/case_2.rs"]
mod case_2;
#[path = "registration_email_migration_support/case_3.rs"]
mod case_3;
#[path = "registration_email_migration_support/case_4.rs"]
mod case_4;
#[path = "registration_email_migration_support/case_5.rs"]
mod case_5;
#[path = "registration_email_migration_support/case_6.rs"]
mod case_6;
#[path = "registration_email_migration_support/case_7.rs"]
mod case_7;

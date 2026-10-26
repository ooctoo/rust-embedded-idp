use std::{
    io::{self, Read},
    time::Duration,
};

use embedded_idp_core::access::*;
use embedded_idp_core::{
    access::{
        AccessBootstrapResult, BootstrapAdministrator, CoreAccessBootstrapService,
        CoreManagementClientPreparationService, PrepareManagementClient, TenancyMode,
    },
    IdGenerator, SecretString, SystemClock, UuidV7IdGenerator,
};
use embedded_idp_storage_postgres::PostgresStorageAdapter;
use postgres::{Client, NoTls};

use crate::config::{valid_schema, Config};

const MARKER: &str = "tenant-host";
const VERSION: i32 = 1;

fn connection(uri: &str) -> Result<Client, String> {
    let mut pg: postgres::Config = uri.parse().map_err(|_| "invalid business database URI")?;
    pg.connect_timeout(Duration::from_secs(5));
    pg.connect(NoTls)
        .map_err(|_| "business database unavailable".into())
}

fn connect(config: &Config) -> Result<Client, String> {
    connection(&config.business_uri)
}

fn qualified(schema: &str, table: &str) -> String {
    format!("\"{schema}\".\"{table}\"")
}

fn validate_config(config: &Config) -> Result<(), String> {
    let idp_schema = &config.idp.connection.schema_name;
    if !valid_schema(idp_schema)
        || !valid_schema(&config.business_schema)
        || idp_schema == &config.business_schema
    {
        return Err("use distinct a05_ prefixed IdP and business schemas".into());
    }
    Ok(())
}

/// Initialize only an absent business schema. Existing unmarked schemas are never adopted.
fn db_init(config: &Config) -> Result<(), String> {
    validate_config(config)?;
    let mut identity = connection(&config.idp.connection.connection_uri)?;
    identity
        .query_one(
            "select pg_advisory_lock(hashtext($1))",
            &[&format!("a05-init:{}", config.idp.connection.schema_name)],
        )
        .map_err(|_| "cannot lock identity preparation")?;
    let mut client = connect(config)?;
    let mut tx = client
        .transaction()
        .map_err(|_| "cannot begin business schema transaction")?;
    tx.query_one(
        "select pg_advisory_xact_lock(hashtext($1))",
        &[&config.business_schema],
    )
    .map_err(|_| "cannot lock business schema initialization")?;
    let exists: bool = tx
        .query_one(
            "select exists(select 1 from pg_namespace where nspname=$1)",
            &[&config.business_schema],
        )
        .map_err(|_| "cannot inspect business schema")?
        .get(0);
    if exists {
        verify_marker_tx(&mut tx, config)?;
        tx.commit()
            .map_err(|_| "cannot finish marker verification")?;
        return initialize_idp(config);
    }
    let identity_exists: bool = identity
        .query_one(
            "select exists(select 1 from pg_namespace where nspname=$1)",
            &[&config.idp.connection.schema_name],
        )
        .map_err(|_| "cannot inspect identity schema")?
        .get(0);
    if identity_exists {
        return Err(
            "refusing to adopt an existing identity schema without this example marker".into(),
        );
    }
    tx.batch_execute(&format!(
        "create schema {}",
        qualified(&config.business_schema, "").trim_end_matches(".\"\"")
    ))
    .map_err(|_| "cannot create business schema")?;
    tx.batch_execute(&format!(
        "create table {} (id text primary key, version integer not null, idp_schema text not null);\
         create table {} (tenant_id text not null, report_id text not null, title text not null, body text not null, primary key(tenant_id, report_id));",
        qualified(&config.business_schema, "example_schema_marker"), qualified(&config.business_schema, "reports")
    )).map_err(|_| "cannot create business tables")?;
    tx.execute(
        &format!(
            "insert into {} (id,version,idp_schema) values ($1,$2,$3)",
            qualified(&config.business_schema, "example_schema_marker")
        ),
        &[&MARKER, &VERSION, &config.idp.connection.schema_name],
    )
    .map_err(|_| "cannot write business schema marker")?;
    tx.commit()
        .map_err(|_| "cannot commit business schema initialization".to_string())?;
    initialize_idp(config)
}

fn verify_marker_tx(tx: &mut postgres::Transaction<'_>, config: &Config) -> Result<(), String> {
    let marker_table = qualified(&config.business_schema, "example_schema_marker");
    let rows = tx
        .query(
            &format!("select id,version,idp_schema from {marker_table}"),
            &[],
        )
        .map_err(|_| "business schema is unmarked or marker table is incompatible")?;
    if rows.len() != 1
        || rows[0].get::<_, String>(0) != MARKER
        || rows[0].get::<_, i32>(1) != VERSION
        || rows[0].get::<_, String>(2) != config.idp.connection.schema_name
    {
        return Err("business schema marker mismatch".into());
    }
    tx.query(
        &format!(
            "select tenant_id,report_id,title,body from {} limit 0",
            qualified(&config.business_schema, "reports")
        ),
        &[],
    )
    .map_err(|_| "business report table is missing or incompatible")?;
    Ok(())
}

/// Verify the example-owned marker and report table without changing the database.
pub fn verify_marker(config: &Config) -> Result<(), String> {
    validate_config(config)?;
    let mut client = connect(config)?;
    let mut tx = client
        .transaction()
        .map_err(|_| "cannot begin business schema verification")?;
    verify_marker_tx(&mut tx, config)?;
    tx.commit()
        .map_err(|_| "cannot finish business schema verification".to_string())
}

fn read_stdin(max: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read password input")?;
    if bytes.len() > max {
        return Err("password input is too large".into());
    }
    Ok(bytes)
}
fn read_password() -> Result<SecretString, String> {
    let mut value = read_stdin(4096)?;
    if value.ends_with(b"\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with(b"\n") {
        value.pop();
    }
    let value = String::from_utf8(value).map_err(|_| "password input must be UTF-8")?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("password input is empty or contains control characters".into());
    }
    Ok(SecretString::new(value))
}

fn prepare_clients(config: &Config) -> Result<(), String> {
    validate_config(config)?;
    verify_marker(config)?;
    let adapter = config.adapter()?;
    adapter
        .prepare_management_client_audit_schema(TenancyMode::Enabled)
        .map_err(|_| "cannot prepare management-client audit schema")?;
    let preparation = CoreManagementClientPreparationService::new(
        TenancyMode::Enabled,
        adapter.clone(),
        SystemClock,
        UuidV7IdGenerator,
    );
    let result = preparation
        .prepare(PrepareManagementClient {
            client_id: "tenant-host-management".into(),
            client_name: "Tenant Host Management".into(),
            redirect_uris: vec![format!("{}/management-callback", config.browser_origin)],
            request_id: UuidV7IdGenerator.next_id("request"),
        })
        .map_err(|_| "management client preparation failed or conflicts")?;
    if matches!(
        result,
        embedded_idp_core::access::ManagementClientPreparationResult::Conflict
    ) {
        return Err("management client definition conflicts with tenant-host profile".into());
    }
    verify_marker(config)?;
    config
        .store()?
        .check_readiness(&PermissionCatalog::new(vec![]).unwrap())
        .map_err(|_| "IdP not ready")?;
    let mut client = connection(&config.idp.connection.connection_uri)?;
    for (id, name) in [
        ("tenant-host-fixed", "Tenant Host Fixed"),
        ("tenant-host-choose", "Tenant Host Choose"),
    ] {
        let mut tx = client
            .transaction()
            .map_err(|_| "cannot begin business-client transaction")?;
        tx.query_one("select pg_advisory_xact_lock(hashtext($1))", &[&id])
            .map_err(|_| "cannot lock business-client preparation")?;
        let table = qualified(&config.idp.connection.schema_name, "oidc_clients");
        let redirects = vec![format!("{}/{id}-callback", config.browser_origin)];
        let redirects_json = serde_json::to_string(&redirects).map_err(|_| "invalid redirects")?;
        tx.execute(&format!("insert into {table}(client_id,client_name,redirect_uris_json,client_type,pkce_required,client_secret_hash,created_at_epoch) values($1,$2,$3,'public_desktop',true,null,floor(extract(epoch from clock_timestamp()))::bigint) on conflict(client_id) do nothing"), &[&id,&name,&redirects_json])
            .map_err(|_| "cannot insert business client")?;
        let row = tx.query_one(&format!("select client_name,redirect_uris_json,client_type,pkce_required,client_secret_hash from {table} where client_id=$1 for update"), &[&id])
            .map_err(|_| "cannot read prepared business client")?;
        let stored_redirects: String = row.get(1);
        let parsed: Vec<String> = serde_json::from_str(&stored_redirects)
            .map_err(|_| "business client redirect definition is invalid")?;
        if row.get::<_, String>(0) != name
            || parsed != redirects
            || row.get::<_, String>(2) != "public_desktop"
            || !row.get::<_, bool>(3)
            || row.get::<_, Option<String>>(4).is_some()
        {
            return Err(format!(
                "business client {id} conflicts with tenant-host profile"
            ));
        }
        tx.commit()
            .map_err(|_| "cannot commit business-client preparation")?;
    }
    Ok(())
}

fn bootstrap_admin(config: &Config, args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: bootstrap-admin <email> (password via stdin)".into());
    }
    verify_marker(config)?;
    let adapter: PostgresStorageAdapter = config.adapter()?;
    let bootstrap = CoreAccessBootstrapService::new(
        TenancyMode::Enabled,
        adapter,
        SystemClock,
        UuidV7IdGenerator,
    );
    let result = bootstrap
        .initialize_administrator(
            &config.auth(),
            BootstrapAdministrator {
                email: args[0].clone(),
                display_name: None,
                password: read_password()?,
                request_id: "a05-bootstrap-admin".into(),
            },
        )
        .map_err(|_| {
            "administrator bootstrap failed; inspect existing IdP bootstrap state".to_string()
        })?;
    match result {
        AccessBootstrapResult::Initialized => println!("administrator initialized"),
        AccessBootstrapResult::AlreadyInitialized => println!("administrator already initialized"),
    }
    Ok(())
}

pub fn run(config: &Config, action: &str, args: &[String]) -> Result<(), String> {
    match action {
        "db-init" if args.is_empty() => db_init(config),
        "bootstrap-admin" => bootstrap_admin(config,args),
        "prepare-clients" if args.is_empty() => prepare_clients(config),
        "seed-fixtures" => seed_fixtures(config,args),
        _ => Err("usage: db-init | bootstrap-admin <email> | prepare-clients | seed-fixtures <admin-email>".into()),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedPasswords {
    admin_password: String,
    fixture_password: String,
}
fn seed_fixtures(config: &Config, args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("usage: seed-fixtures <admin-email> (JSON passwords via stdin)".into());
    }
    verify_marker(config)?;
    let passwords: SeedPasswords = serde_json::from_slice(&read_stdin(8192)?)
        .map_err(|_| "expected stdin JSON admin_password and fixture_password")?;
    let store = config.store()?;
    let key = crate::load_key(config)?;
    let auth = crate::management_auth(config, &store, &key)?;
    let session = match auth
        .login(TenantPasswordLogin {
            email: args[0].clone(),
            password: SecretString::new(passwords.admin_password),
        })
        .map_err(|_| "fixture administrator login failed")?
    {
        TenantLoginOutcome::Authenticated(s) => s,
        _ => return Err("fixture administrator must authenticate in platform domain".into()),
    };
    let context = auth
        .authenticate(
            session.tokens.access_token.clone(),
            UuidV7IdGenerator.next_id("request"),
        )
        .map_err(|_| "fixture administrator authentication failed")?;
    let result: Result<(), String> = (|| {
        let mut db = connection(&config.idp.connection.connection_uri)?;
        // Session lock serializes this example's multi-transaction fixture commands only.
        db.query_one(
            "select pg_advisory_lock(hashtext($1))",
            &[&format!(
                "a05-fixtures:{}",
                config.idp.connection.schema_name
            )],
        )
        .map_err(|_| "fixture lock failed")?;
        let schema = &config.idp.connection.schema_name;
        let conflict=db.query_one(&format!("select exists(select 1 from {schema}.access_tenants where id in ('tenant-a','tenant-b'))"),&[]).map_err(|_| "cannot inspect fixture tenants")?.get::<_,bool>(0);
        if conflict {
            return Err("fixture tenants already exist; refusing to overwrite or resume partial seed; inspect the isolated schemas".into());
        }
        let admin = || {
            CoreAccessAdminService::new(
                TenancyMode::Enabled,
                PermissionCatalog::new(vec![]).unwrap(),
                store.clone(),
                SystemClock,
                UuidV7IdGenerator,
            )
        };
        let accounts = CoreAccountSecurityService::new(admin(), config.auth())
            .map_err(|_| "invalid account configuration")?;
        let ctx = || AccessAdminContext {
            request_id: UuidV7IdGenerator.next_id("request"),
            ..context.clone()
        };
        for tenant in ["tenant-a", "tenant-b"] {
            accounts
                .create_tenant(
                    ctx(),
                    AdminCreateTenant {
                        tenant_id: tenant.into(),
                        name: format!("Example {tenant}"),
                        allow_registration: false,
                        administrator: InitialTenantAdministrator::Existing {
                            subject_id: context.actor.subject_id.clone(),
                        },
                    },
                )
                .map_err(|e| {
                    format!("fixture tenant creation failed: {e:?}; partial seed retained")
                })?;
        }
        let create = |email: &str| -> Result<String, String> {
            match accounts
                .create_account(
                    ctx(),
                    AdminCreateAccount {
                        tenant_id: "tenant-a".into(),
                        email: email.into(),
                        password: SecretString::new(passwords.fixture_password.clone()),
                        display_name: Some(email.into()),
                    },
                )
                .map_err(|e| format!("fixture account creation failed: {e:?}"))?
                .change
            {
                AccessChange::AccountCreated { after } => Ok(after.account_id),
                _ => Err("unexpected account result".into()),
            }
        };
        let both = create("both@example.test")?;
        let only = create("only-a@example.test")?;
        let mutate = |tenant: &str, mutation| {
            admin()
                .execute(
                    ctx(),
                    AccessAdminCommand {
                        tenant_id: tenant.into(),
                        mutation,
                    },
                )
                .map_err(|e| format!("fixture permission/membership preparation failed: {e:?}"))
        };
        mutate(
            "tenant-b",
            AccessAdminMutation::BindMember {
                subject_id: both.clone(),
            },
        )?;
        for tenant in ["tenant-a", "tenant-b"] {
            let permission = PermissionKey {
                business_id: "reports".into(),
                resource_type: "report".into(),
                action: "read".into(),
            };
            mutate(
                tenant,
                AccessAdminMutation::CreatePermission {
                    key: permission.clone(),
                    description: "Read example reports".into(),
                },
            )?;
            let role = match mutate(
                tenant,
                AccessAdminMutation::CreateRole {
                    business_id: "reports".into(),
                    key: "reader".into(),
                    name: "Example report reader".into(),
                },
            )?
            .change
            {
                AccessChange::Role { after: Some(r), .. } => r,
                _ => return Err("unexpected role result".into()),
            };
            mutate(
                tenant,
                AccessAdminMutation::ReplaceRolePermissions {
                    business_id: "reports".into(),
                    role_id: role.role.id.clone(),
                    permissions: vec![permission],
                    expected_version: role.role.version,
                },
            )?;
            for account in if tenant == "tenant-a" {
                vec![&both, &only]
            } else {
                vec![&both]
            } {
                for report in ["r001", "missing"] {
                    mutate(
                        tenant,
                        AccessAdminMutation::GrantRole {
                            business_id: "reports".into(),
                            subject_id: account.clone(),
                            role_id: role.role.id.clone(),
                            scope: RoleBindingScope::Resource {
                                resource_type: "report".into(),
                                scope: ResourceScope::Instance(report.into()),
                            },
                        },
                    )?;
                }
            }
        }
        let mut business = connect(config)?;
        let mut tx = business
            .transaction()
            .map_err(|_| "cannot begin report fixture transaction")?;
        verify_marker_tx(&mut tx, config)?;
        for tenant in ["tenant-a", "tenant-b"] {
            for n in 0..=50 {
                let id = format!("r{n:03}");
                let title = format!("{tenant} report {id}");
                let body = format!("Isolated example content owned by {tenant}");
                tx.execute(
                    &format!(
                        "insert into {}(tenant_id,report_id,title,body) values($1,$2,$3,$4)",
                        qualified(&config.business_schema, "reports")
                    ),
                    &[&tenant, &id, &title, &body],
                )
                .map_err(|_| "report fixtures conflict; partial IdP seed retained")?;
            }
        }
        tx.commit().map_err(|_| "report fixture commit failed")?;
        Ok(())
    })();
    let logout = auth.logout(session.tokens.access_token);
    result?;
    logout.map_err(|_| "fixtures prepared but fixture administrator logout failed")?;
    println!(
        "prepared tenant-a/tenant-b, both@example.test, only-a@example.test and isolated reports"
    );
    Ok(())
}

fn initialize_idp(config: &Config) -> Result<(), String> {
    config
        .adapter()?
        .initialize_access_schema(
            TenancyMode::Enabled,
            &PermissionCatalog::new(vec![]).unwrap(),
        )
        .map_err(|_| "IdP initialization failed; existing business marker is retained")?;
    Ok(())
}

use embedded_idp_core::access::{PermissionCatalog, TenancyMode};
use std::env;

use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresStorageAdapter,
};
use postgres::Client;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1).peekable();
    let schema_only = args.peek().is_some_and(|value| value == "--schema-only");
    let access_schema = args.peek().is_some_and(|value| value == "--access-schema");
    if schema_only || access_schema {
        args.next();
    }
    let connection_uri = args
        .next()
        .or_else(|| env::var("EMBEDDED_IDP_APP_PG_URI").ok())
        .ok_or_else(|| usage("missing connection URI argument or EMBEDDED_IDP_APP_PG_URI"))?;
    let schema_name = args
        .next()
        .or_else(|| env::var("EMBEDDED_IDP_APP_PG_SCHEMA").ok())
        .unwrap_or_else(|| "embedded_idp".to_string());
    let client_id = args.next().unwrap_or_else(|| "desktop-app".to_string());

    if args.next().is_some() {
        return Err(usage("received unexpected extra arguments"));
    }

    let tls_mode = match env::var("EMBEDDED_IDP_APP_PG_TLS_MODE").as_deref() {
        Ok("require") => PgTlsMode::Require,
        Ok("prefer") => PgTlsMode::Prefer,
        Ok("disable") | Err(env::VarError::NotPresent) => PgTlsMode::Disable,
        _ => return Err("invalid EMBEDDED_IDP_APP_PG_TLS_MODE".to_string()),
    };
    let adapter = PostgresStorageAdapter::new(PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri,
            schema_name: schema_name.clone(),
            tls_mode,
            tls_ca_cert_path: env::var("EMBEDDED_IDP_APP_PG_TLS_CA_CERT_PATH").ok(),
        },
        pool: DbPoolConfig {
            application_name: "embedded-idp-bootstrap".to_string(),
            max_connections: 4,
            connect_timeout_secs: 5,
        },
    })
    .map_err(|error| format!("invalid postgres config: {error:?}"))?;

    if access_schema {
        let mode = match env::var("EMBEDDED_IDP_APP_TENANCY_MODE").as_deref() {
            Ok("disabled") => TenancyMode::Disabled,
            Ok("enabled") => TenancyMode::Enabled,
            _ => return Err("explicit EMBEDDED_IDP_APP_TENANCY_MODE is required".into()),
        };
        let catalog = PermissionCatalog::new(vec![]).map_err(|_| "invalid permission catalog")?;
        let facts = adapter
            .initialize_access_schema(mode, &catalog)
            .map_err(|error| format!("access schema initialization failed: {error:?}"))?;
        println!(
            "prepared {schema_name} version {}; administrator bootstrap complete: {}",
            facts.version, facts.bootstrap_completed
        );
        return Ok(());
    }
    if schema_only {
        adapter
            .connect()
            .map_err(|error| format!("postgres connection failed: {error:?}"))?
            .batch_execute(&format!("create schema if not exists \"{schema_name}\""))
            .map_err(|error| format!("failed to prepare schema: {error}"))?;
        println!("prepared schema {schema_name}; no application tables or seed data created");
        return Ok(());
    }
    adapter
        .apply_migrations()
        .map_err(|error| format!("legacy initialization failed: {error:?}"))?;
    let mut client = adapter
        .connect()
        .map_err(|error| format!("postgres connection failed: {error:?}"))?;

    seed_default_desktop_client(&mut client, &schema_name, &client_id)?;

    println!("bootstrapped embedded idp postgres schema");
    println!("  schema: {schema_name}");
    println!("  desktop client: {client_id}");
    Ok(())
}

fn seed_default_desktop_client(
    client: &mut Client,
    schema_name: &str,
    client_id: &str,
) -> Result<(), String> {
    let sql = format!(
        "insert into {}.oidc_clients \
         (client_id, client_name, redirect_uris_json, client_type, pkce_required, client_secret_hash, created_at_epoch) \
         values ($1, $2, $3, $4, $5, $6, $7) \
         on conflict (client_id) do update set \
           client_name = excluded.client_name, \
           redirect_uris_json = excluded.redirect_uris_json, \
           client_type = excluded.client_type, \
           pkce_required = excluded.pkce_required, \
           client_secret_hash = excluded.client_secret_hash",
        schema_name
    );
    let redirect_uris = serde_json::to_string(&vec!["http://127.0.0.1:49152/callback"])
        .map_err(|error| format!("failed to serialize default redirect uris: {error}"))?;

    client
        .execute(
            &sql,
            &[
                &client_id,
                &"Desktop App",
                &redirect_uris,
                &"public_desktop",
                &true,
                &Option::<String>::None,
                &1_700_000_000_i64,
            ],
        )
        .map_err(|error| format!("failed to seed default desktop client: {error}"))?;

    Ok(())
}

fn usage(reason: &str) -> String {
    format!(
        "{reason}\nusage: cargo run -p embedded-idp-storage-postgres --example bootstrap_local_postgres -- [--schema-only|--access-schema] [postgres-connection-uri] [schema-name] [client-id]\nConnection URI and schema may also come from EMBEDDED_IDP_APP_PG_URI and EMBEDDED_IDP_APP_PG_SCHEMA."
    )
}

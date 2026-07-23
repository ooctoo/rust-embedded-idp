use std::env;

use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresStorageAdapter,
};
use postgres::{Client, NoTls};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let connection_uri = args
        .next()
        .ok_or_else(|| usage("missing <postgres-connection-uri> argument"))?;
    let schema_name = args.next().unwrap_or_else(|| "embedded_idp".to_string());
    let client_id = args.next().unwrap_or_else(|| "desktop-app".to_string());

    if args.next().is_some() {
        return Err(usage("received unexpected extra arguments"));
    }

    let adapter = PostgresStorageAdapter::new(PgStorageConfig {
        connection: PgConnectionConfig {
            connection_uri: connection_uri.clone(),
            schema_name: schema_name.clone(),
            tls_mode: PgTlsMode::Disable,
            tls_ca_cert_path: None,
        },
        pool: DbPoolConfig {
            application_name: "embedded-idp-bootstrap".to_string(),
            max_connections: 4,
            connect_timeout_secs: 5,
        },
    })
    .map_err(|error| format!("invalid postgres config: {error:?}"))?;

    let mut client = Client::connect(&connection_uri, NoTls)
        .map_err(|error| format!("failed to connect postgres bootstrap client: {error:?}"))?;
    for step in adapter.migration_plan().steps {
        client
            .batch_execute(&step.sql)
            .map_err(|error| format!("failed to apply migration {}: {error:?}", step.version))?;
    }

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
        "{reason}\nusage: cargo run -p embedded-idp-storage-postgres --example bootstrap_local_postgres -- <postgres-connection-uri> [schema-name] [client-id]"
    )
}

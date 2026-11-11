use embedded_idp_core::{access::TenancyMode, AuthConfig};
use embedded_idp_storage_postgres::{
    DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode, PostgresAccessStore,
    PostgresStorageAdapter,
};
use std::{env, net::SocketAddr};

pub struct Config {
    pub bind_addr: SocketAddr,
    pub browser_origin: String,
    pub issuer: String,
    pub idp: PgStorageConfig,
    pub business_uri: String,
    pub business_schema: String,
    pub signing_key_file: String,
    pub management_enabled: bool,
    auth: AuthConfig,
}
pub fn valid_schema(s: &str) -> bool {
    s.starts_with("a05_")
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn local_database(uri: &str) -> Result<(), String> {
    let pg: postgres::Config = uri.parse().map_err(|_| "invalid database URI")?;
    if pg.get_hosts().is_empty() || !pg.get_hosts().iter().all(|h| matches!(h, postgres::config::Host::Tcp(host) if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()))) {
        return Err("this isolated example requires explicit loopback database hosts".into());
    }
    if pg.get_ssl_mode() == postgres::config::SslMode::Require {
        return Err(
            "this local-only example uses NoTls; do not point it at a TLS-required service".into(),
        );
    }
    Ok(())
}
impl Config {
    pub fn from_env() -> Result<Self, String> {
        let value = |name: &str, default: &str| env::var(name).unwrap_or_else(|_| default.into());
        let bind_addr: SocketAddr = value("TENANT_HOST_BIND_ADDR", "127.0.0.1:9400")
            .parse()
            .map_err(|_| "invalid bind address")?;
        if !bind_addr.ip().is_loopback() {
            return Err("tenant-host is a loopback-only example".into());
        }
        let uri = env::var("TENANT_HOST_PG_URI").map_err(|_| "set TENANT_HOST_PG_URI")?;
        let business_uri = value("TENANT_HOST_BUSINESS_PG_URI", &uri);
        local_database(&uri)?;
        local_database(&business_uri)?;
        let schema = value("TENANT_HOST_PG_SCHEMA", "a05_identity");
        let business_schema = value("TENANT_HOST_BUSINESS_SCHEMA", "a05_reports");
        if !valid_schema(&schema) || !valid_schema(&business_schema) || schema == business_schema {
            return Err("use distinct a05_ prefixed schemas".into());
        }
        let browser_origin = value("TENANT_HOST_BROWSER_ORIGIN", &format!("http://{bind_addr}"));
        // Delegate exact origin and transport validation to the existing public adapter.
        embedded_idp_axum::BrowserSessionHttpConfig::new(
            &browser_origin,
            "a05_validation",
            "/fixed/auth/browser",
            embedded_idp_core::AccessTokenPurpose::Business,
        )
        .map_err(str::to_owned)?;
        let idp = PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: uri,
                schema_name: schema,
                tls_mode: PgTlsMode::Disable,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "tenant-host".into(),
                max_connections: 8,
                connect_timeout_secs: 5,
            },
        };
        idp.validate()
            .map_err(|_| "invalid IdP database configuration")?;
        let management_enabled = match value("TENANT_HOST_MANAGEMENT", "true").as_str() {
            "true" => true,
            "false" => false,
            _ => return Err("TENANT_HOST_MANAGEMENT must be true or false".into()),
        };
        let auth = auth_config(&value("TENANT_HOST_ACCESS_TOKEN_TTL_SECS", "900"))?;
        Ok(Self {
            bind_addr,
            issuer: value("TENANT_HOST_ISSUER", "http://localhost/tenant-host"),
            browser_origin,
            idp,
            business_uri,
            business_schema,
            management_enabled,
            auth,
            signing_key_file: value(
                "TENANT_HOST_SIGNING_KEY_FILE",
                "examples/tenant-host/.local/signing-key.der",
            ),
        })
    }
    pub fn auth(&self) -> AuthConfig {
        self.auth.clone()
    }
    pub fn adapter(&self) -> Result<PostgresStorageAdapter, String> {
        PostgresStorageAdapter::new(self.idp.clone())
            .map_err(|_| "invalid database configuration".into())
    }
    pub fn store(&self) -> Result<PostgresAccessStore, String> {
        PostgresAccessStore::new(self.adapter()?, TenancyMode::Enabled)
            .map_err(|_| "IdP schema is not ready".into())
    }
}
fn auth_config(access_ttl: &str) -> Result<AuthConfig, String> {
    let access_token_ttl_secs = access_ttl
        .parse::<u64>()
        .map_err(|_| "TENANT_HOST_ACCESS_TOKEN_TTL_SECS must be an integer")?;
    let config = AuthConfig {
        allow_local_registration: false,
        access_token_ttl_secs,
        refresh_token_ttl_secs: 86400,
        session_ttl_secs: 604800,
        verification_code_ttl_secs: 900,
        password_min_length: 12,
        password_max_length: 128,
    };
    if config.access_token_ttl_secs == 0
        || config.access_token_ttl_secs >= config.refresh_token_ttl_secs
    {
        return Err("TENANT_HOST_ACCESS_TOKEN_TTL_SECS must be 1..86399".into());
    }
    Ok(config)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn access_ttl_accepts_shorter_and_longer_host_values_and_rejects_invalid_values() {
        for secs in [1, 300, 900, 1800, 86399] {
            let auth = auth_config(&secs.to_string()).unwrap();
            assert_eq!(auth.access_token_ttl_secs, secs);
            assert!(auth.access_token_ttl_secs < auth.refresh_token_ttl_secs);
            assert!(auth.refresh_token_ttl_secs <= auth.session_ttl_secs);
        }
        for value in ["", "0", "-1", "300.5", "86400", "18446744073709551616"] {
            assert!(auth_config(value).is_err(), "{value}");
        }
    }
    #[test]
    fn isolation_configuration_rejects_remote_and_unsafe_scopes() {
        for s in ["", "public", "a05_a;drop", "a05_X", "a05_a.b"] {
            assert!(!valid_schema(s));
        }
        assert!(valid_schema("a05_test_123"));
        assert!(local_database("postgres://localhost/db").is_ok());
        for uri in [
            "postgres://db.example/db",
            "postgres:///db",
            "postgres://127.0.0.1/db?sslmode=require",
        ] {
            assert!(local_database(uri).is_err());
        }
    }
}

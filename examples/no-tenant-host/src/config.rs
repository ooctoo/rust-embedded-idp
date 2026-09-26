use std::{env, net::SocketAddr};

use embedded_idp_core::{
    access::{LoginTenantPolicy, TenancyMode},
    AuthConfig, OidcConfig,
};
use embedded_idp_storage_postgres::{DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode};

pub struct Config {
    pub mode: TenancyMode,
    pub bind_addr: SocketAddr,
    pub browser_origin: String,
    pub issuer: String,
    pub idp: PgStorageConfig,
    pub business_uri: String,
    pub business_schema: String,
    pub signing_key_file: String,
    pub client_id: String,
    pub login_policy: LoginTenantPolicy,
    pub auth: AuthConfig,
    pub oidc: OidcConfig,
    pub proof_ttl_secs: u64,
    pub proof_skew_secs: u64,
}

fn value(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.into())
}

fn number(name: &str, default: u64) -> Result<u64, String> {
    value(name, &default.to_string())
        .parse::<u64>()
        .map_err(|_| format!("invalid {name}"))
}

fn flag(name: &str, default: bool) -> Result<bool, String> {
    match value(name, if default { "true" } else { "false" }).as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("invalid {name}")),
    }
}

pub fn valid_schema(name: &str) -> bool {
    name.len() <= 63
        && name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || *b == b'_')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        if env::var("EMBEDDED_IDP_APP_TENANCY_MODE").as_deref() != Ok("disabled") {
            return Err("this example requires EMBEDDED_IDP_APP_TENANCY_MODE=disabled".into());
        }
        let mode = TenancyMode::Disabled;
        let bind_addr = value("NO_TENANT_HOST_BIND_ADDR", "127.0.0.1:9300")
            .parse()
            .map_err(|_| "invalid NO_TENANT_HOST_BIND_ADDR")?;
        let issuer = env::var("EMBEDDED_IDP_APP_ISSUER")
            .map_err(|_| "set EMBEDDED_IDP_APP_ISSUER to the shared IdP issuer")?;
        let client_id = value("EMBEDDED_IDP_APP_PUBLIC_CLIENT_ID", "desktop-app");
        let idp_uri =
            env::var("EMBEDDED_IDP_APP_PG_URI").map_err(|_| "set EMBEDDED_IDP_APP_PG_URI")?;
        let idp_schema =
            env::var("EMBEDDED_IDP_APP_PG_SCHEMA").map_err(|_| "set EMBEDDED_IDP_APP_PG_SCHEMA")?;
        let business_uri = value("NO_TENANT_HOST_BUSINESS_PG_URI", &idp_uri);
        let business_schema = value("NO_TENANT_HOST_BUSINESS_SCHEMA", "no_tenant_host_business");
        if !valid_schema(&business_schema) {
            return Err("NO_TENANT_HOST_BUSINESS_SCHEMA must be a valid schema".into());
        }
        let tls_mode = match value("EMBEDDED_IDP_APP_PG_TLS_MODE", "prefer").as_str() {
            "disable" => PgTlsMode::Disable,
            "prefer" => PgTlsMode::Prefer,
            "require" => PgTlsMode::Require,
            _ => return Err("invalid EMBEDDED_IDP_APP_PG_TLS_MODE".into()),
        };
        let idp = PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: idp_uri,
                schema_name: idp_schema,
                tls_mode,
                tls_ca_cert_path: env::var("EMBEDDED_IDP_APP_PG_TLS_CA_CERT_PATH").ok(),
            },
            pool: DbPoolConfig {
                application_name: "no-tenant-host-idp".into(),
                max_connections: number("EMBEDDED_IDP_APP_PG_MAX_CONNECTIONS", 10)?
                    .try_into()
                    .map_err(|_| "invalid EMBEDDED_IDP_APP_PG_MAX_CONNECTIONS")?,
                connect_timeout_secs: number("EMBEDDED_IDP_APP_PG_CONNECT_TIMEOUT_SECS", 5)?,
            },
        };
        idp.validate()
            .map_err(|_| "invalid IdP Postgres configuration")?;
        let login_policy = LoginTenantPolicy::Fixed {
            tenant_id: "0".into(),
        };
        login_policy
            .validate(mode)
            .map_err(|_| "invalid login tenant policy")?;
        let auth = AuthConfig {
            allow_local_registration: flag("EMBEDDED_IDP_APP_ALLOW_LOCAL_REGISTRATION", true)?,
            access_token_ttl_secs: number("EMBEDDED_IDP_APP_ACCESS_TOKEN_TTL_SECS", 900)?,
            refresh_token_ttl_secs: number("EMBEDDED_IDP_APP_REFRESH_TOKEN_TTL_SECS", 86_400)?,
            session_ttl_secs: number("EMBEDDED_IDP_APP_SESSION_TTL_SECS", 604_800)?,
            verification_code_ttl_secs: number("EMBEDDED_IDP_APP_VERIFICATION_CODE_TTL_SECS", 900)?,
            password_min_length: number("EMBEDDED_IDP_APP_PASSWORD_MIN_LENGTH", 8)?
                .try_into()
                .map_err(|_| "invalid EMBEDDED_IDP_APP_PASSWORD_MIN_LENGTH")?,
            password_max_length: number("EMBEDDED_IDP_APP_PASSWORD_MAX_LENGTH", 128)?
                .try_into()
                .map_err(|_| "invalid EMBEDDED_IDP_APP_PASSWORD_MAX_LENGTH")?,
        };
        let oidc = OidcConfig {
            authorization_code_ttl_secs: number(
                "EMBEDDED_IDP_APP_AUTHORIZATION_CODE_TTL_SECS",
                300,
            )?,
            require_pkce_for_public_clients: flag(
                "EMBEDDED_IDP_APP_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS",
                true,
            )?,
        };
        Ok(Self {
            mode,
            browser_origin: value(
                "NO_TENANT_HOST_BROWSER_ORIGIN",
                &format!("http://{bind_addr}"),
            ),
            bind_addr,
            issuer,
            idp,
            business_uri,
            business_schema,
            signing_key_file: value(
                "EMBEDDED_IDP_APP_SIGNING_KEY_FILE",
                "examples/no-tenant-host/.local/idp-signing-key.der",
            ),
            client_id,
            login_policy,
            auth,
            oidc,
            proof_ttl_secs: number("EMBEDDED_IDP_APP_DEVICE_NONCE_TTL_SECS", 300)?,
            proof_skew_secs: number("EMBEDDED_IDP_APP_DEVICE_PROOF_CLOCK_SKEW_SECS", 30)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::valid_schema;

    #[test]
    fn business_schema_cannot_escape_its_identifier() {
        assert!(valid_schema("no_tenant_host_business"));
        for value in ["", "Idp", "a-b", "a;drop schema idp", "a.b", "a/../b"] {
            assert!(!valid_schema(value));
        }
    }
}

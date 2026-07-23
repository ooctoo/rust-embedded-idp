use std::env;
use std::net::SocketAddr;

use embedded_idp_core::{
    AuthConfig, ConfigValidationError, DeviceConfig, EmbeddedIdpConfig, OidcConfig,
};
use embedded_idp_storage_postgres::{DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgTlsMode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedIdpAppConfig {
    pub bind_addr: SocketAddr,
    pub embedded_idp: EmbeddedIdpConfig,
    pub admin_ui_base_path: String,
    pub postgres: PgStorageConfig,
    pub email_delivery: EmailDeliveryConfig,
    pub public_client: SeedClientConfig,
    pub confidential_client: Option<SeedConfidentialClientConfig>,
    pub dev_subject_header: String,
    pub admin_api_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedClientConfig {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedConfidentialClientConfig {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailDeliveryConfig {
    pub mode: EmailDeliveryMode,
    pub sendmail_command: String,
    pub smtp: SmtpEmailDeliveryConfig,
    pub from_email: String,
    pub from_name: Option<String>,
    pub subject: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailDeliveryMode {
    Log,
    Sendmail,
    Smtp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpEmailDeliveryConfig {
    pub host: String,
    pub port: u16,
    pub tls_mode: SmtpTlsMode,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTlsMode {
    StartTls,
    ImplicitTls,
    Plain,
}

impl EmbeddedIdpAppConfig {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = env_var("EMBEDDED_IDP_APP_BIND_ADDR", "127.0.0.1:9100")
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid EMBEDDED_IDP_APP_BIND_ADDR: {error}"))?;
        let issuer = env_var("EMBEDDED_IDP_APP_ISSUER", &format!("http://{bind_addr}"));
        let admin_ui_base_path = match env::var("EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH") {
            Ok(value) => normalize_admin_ui_base_path(&value)?,
            Err(env::VarError::NotPresent) => "/".to_string(),
            Err(error) => {
                return Err(format!(
                    "invalid EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH: {error}"
                ))
            }
        };
        let embedded_idp = EmbeddedIdpConfig {
            issuer,
            auth: AuthConfig {
                allow_local_registration: env_flag(
                    "EMBEDDED_IDP_APP_ALLOW_LOCAL_REGISTRATION",
                    true,
                )?,
                access_token_ttl_secs: env_u64("EMBEDDED_IDP_APP_ACCESS_TOKEN_TTL_SECS", 900)?,
                refresh_token_ttl_secs: env_u64("EMBEDDED_IDP_APP_REFRESH_TOKEN_TTL_SECS", 86_400)?,
                session_ttl_secs: env_u64("EMBEDDED_IDP_APP_SESSION_TTL_SECS", 604_800)?,
                verification_code_ttl_secs: env_u64(
                    "EMBEDDED_IDP_APP_VERIFICATION_CODE_TTL_SECS",
                    900,
                )?,
                password_min_length: env_usize("EMBEDDED_IDP_APP_PASSWORD_MIN_LENGTH", 8)?,
                password_max_length: env_usize("EMBEDDED_IDP_APP_PASSWORD_MAX_LENGTH", 128)?,
            },
            device: DeviceConfig {
                nonce_ttl_secs: env_u64("EMBEDDED_IDP_APP_DEVICE_NONCE_TTL_SECS", 300)?,
                proof_clock_skew_secs: env_u64(
                    "EMBEDDED_IDP_APP_DEVICE_PROOF_CLOCK_SKEW_SECS",
                    30,
                )?,
                heartbeat_grace_period_secs: env_u64(
                    "EMBEDDED_IDP_APP_DEVICE_HEARTBEAT_GRACE_PERIOD_SECS",
                    60,
                )?,
            },
            oidc: OidcConfig {
                authorization_code_ttl_secs: env_u64(
                    "EMBEDDED_IDP_APP_AUTHORIZATION_CODE_TTL_SECS",
                    300,
                )?,
                require_pkce_for_public_clients: env_flag(
                    "EMBEDDED_IDP_APP_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS",
                    true,
                )?,
            },
        };
        embedded_idp
            .validate()
            .map_err(|error| format_embedded_idp_config_error(&embedded_idp, error))?;

        let postgres = PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: env_var(
                    "EMBEDDED_IDP_APP_PG_URI",
                    "postgres://127.0.0.1:5432/postgres",
                ),
                schema_name: env_var("EMBEDDED_IDP_APP_PG_SCHEMA", "embedded_idp"),
                tls_mode: env_tls_mode("EMBEDDED_IDP_APP_PG_TLS_MODE")?,
                tls_ca_cert_path: env::var("EMBEDDED_IDP_APP_PG_TLS_CA_CERT_PATH").ok(),
            },
            pool: DbPoolConfig {
                application_name: env_var("EMBEDDED_IDP_APP_PG_APP_NAME", "embedded-idp-app"),
                max_connections: env_u32("EMBEDDED_IDP_APP_PG_MAX_CONNECTIONS", 10)?,
                connect_timeout_secs: env_u64("EMBEDDED_IDP_APP_PG_CONNECT_TIMEOUT_SECS", 5)?,
            },
        };
        postgres
            .validate()
            .map_err(|error| format!("invalid postgres config: {error:?}"))?;
        let email_delivery = EmailDeliveryConfig {
            mode: env_email_delivery_mode("EMBEDDED_IDP_APP_EMAIL_DELIVERY_MODE")?,
            sendmail_command: env_var(
                "EMBEDDED_IDP_APP_EMAIL_SENDMAIL_COMMAND",
                "/usr/sbin/sendmail",
            ),
            smtp: SmtpEmailDeliveryConfig {
                host: env_var("EMBEDDED_IDP_APP_EMAIL_SMTP_HOST", "localhost"),
                port: env_u16("EMBEDDED_IDP_APP_EMAIL_SMTP_PORT", 587)?,
                tls_mode: env_smtp_tls_mode("EMBEDDED_IDP_APP_EMAIL_SMTP_TLS_MODE")?,
                username: env::var("EMBEDDED_IDP_APP_EMAIL_SMTP_USERNAME").ok(),
                password: env::var("EMBEDDED_IDP_APP_EMAIL_SMTP_PASSWORD").ok(),
            },
            from_email: env_var(
                "EMBEDDED_IDP_APP_EMAIL_FROM",
                "embedded-idp@localhost.localdomain",
            ),
            from_name: env::var("EMBEDDED_IDP_APP_EMAIL_FROM_NAME").ok(),
            subject: env_var(
                "EMBEDDED_IDP_APP_EMAIL_VERIFICATION_SUBJECT",
                "Your embedded IDP verification code",
            ),
        };

        let public_client = SeedClientConfig {
            client_id: env_var("EMBEDDED_IDP_APP_PUBLIC_CLIENT_ID", "desktop-app"),
            client_name: env_var(
                "EMBEDDED_IDP_APP_PUBLIC_CLIENT_NAME",
                "Embedded IdP Desktop App",
            ),
            redirect_uri: env_var(
                "EMBEDDED_IDP_APP_PUBLIC_REDIRECT_URI",
                "http://127.0.0.1:43821/callback",
            ),
        };

        let confidential_client_id = env::var("EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_ID").ok();
        let confidential_client_secret =
            env::var("EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_SECRET").ok();
        let confidential_client = match (confidential_client_id, confidential_client_secret) {
            (Some(client_id), Some(client_secret)) => Some(SeedConfidentialClientConfig {
                client_id,
                client_name: env_var(
                    "EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_NAME",
                    "Embedded IdP Web App",
                ),
                redirect_uri: env_var(
                    "EMBEDDED_IDP_APP_CONFIDENTIAL_REDIRECT_URI",
                    "https://example.com/callback",
                ),
                client_secret,
            }),
            (None, None) => None,
            _ => {
                return Err(
                    "EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_ID and EMBEDDED_IDP_APP_CONFIDENTIAL_CLIENT_SECRET must be set together"
                        .to_string(),
                )
            }
        };

        Ok(Self {
            bind_addr,
            embedded_idp,
            admin_ui_base_path,
            postgres,
            email_delivery,
            public_client,
            confidential_client,
            dev_subject_header: env_var(
                "EMBEDDED_IDP_APP_DEV_SUBJECT_HEADER",
                "x-embedded-idp-account-id",
            ),
            admin_api_key: env::var("EMBEDDED_IDP_APP_ADMIN_API_KEY").ok(),
        })
    }
}

fn env_var(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_u64(name: &str, default: u64) -> Result<u64, String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()?
        .map_or(Ok(default), Ok)
}

fn env_u32(name: &str, default: u32) -> Result<u32, String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()?
        .map_or(Ok(default), Ok)
}

fn env_u16(name: &str, default: u16) -> Result<u16, String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()?
        .map_or(Ok(default), Ok)
}

fn env_usize(name: &str, default: usize) -> Result<usize, String> {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()?
        .map_or(Ok(default), Ok)
}

fn env_flag(name: &str, default: bool) -> Result<bool, String> {
    env::var(name)
        .ok()
        .map(|value| match value.as_str() {
            "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
            "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
            _ => Err(format!("invalid {name}: expected boolean-like value")),
        })
        .transpose()?
        .map_or(Ok(default), Ok)
}

fn env_tls_mode(name: &str) -> Result<PgTlsMode, String> {
    match env::var(name).ok().as_deref() {
        None | Some("prefer") | Some("PREFER") => Ok(PgTlsMode::Prefer),
        Some("disable") | Some("DISABLE") => Ok(PgTlsMode::Disable),
        Some("require") | Some("REQUIRE") => Ok(PgTlsMode::Require),
        Some(_) => Err(format!("invalid {name}: expected disable|prefer|require")),
    }
}

fn env_email_delivery_mode(name: &str) -> Result<EmailDeliveryMode, String> {
    match env::var(name).ok().as_deref() {
        None | Some("log") | Some("LOG") => Ok(EmailDeliveryMode::Log),
        Some("sendmail") | Some("SENDMAIL") => Ok(EmailDeliveryMode::Sendmail),
        Some("smtp") | Some("SMTP") => Ok(EmailDeliveryMode::Smtp),
        Some(_) => Err(format!("invalid {name}: expected log|sendmail|smtp")),
    }
}

fn env_smtp_tls_mode(name: &str) -> Result<SmtpTlsMode, String> {
    match env::var(name).ok().as_deref() {
        None | Some("starttls") | Some("STARTTLS") => Ok(SmtpTlsMode::StartTls),
        Some("implicit_tls") | Some("IMPLICIT_TLS") => Ok(SmtpTlsMode::ImplicitTls),
        Some("plain") | Some("PLAIN") => Ok(SmtpTlsMode::Plain),
        Some(_) => Err(format!(
            "invalid {name}: expected starttls|implicit_tls|plain"
        )),
    }
}

fn format_embedded_idp_config_error(
    config: &EmbeddedIdpConfig,
    error: ConfigValidationError,
) -> String {
    match error {
        ConfigValidationError::InvalidIssuer => format!(
            "invalid embedded idp config: EMBEDDED_IDP_APP_ISSUER must start with https://, http://localhost, or http://127.0.0.1; 0.0.0.0 is only valid for EMBEDDED_IDP_APP_BIND_ADDR. current value: {}",
            config.issuer
        ),
        other => format!("invalid embedded idp config: {other:?}"),
    }
}

fn normalize_admin_ui_base_path(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(
            "invalid EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH: value cannot be empty".to_string(),
        );
    }
    if !trimmed.starts_with('/') {
        return Err(
            "invalid EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH: value must start with /".to_string(),
        );
    }
    if trimmed == "/" {
        return Ok("/".to_string());
    }

    Ok(trimmed.trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use std::env;

    use embedded_idp_core::{
        AuthConfig, ConfigValidationError, DeviceConfig, EmbeddedIdpConfig, OidcConfig,
    };

    use super::{
        format_embedded_idp_config_error, normalize_admin_ui_base_path, EmbeddedIdpAppConfig,
    };

    #[test]
    fn config_uses_defaults() {
        env::remove_var("EMBEDDED_IDP_APP_BIND_ADDR");
        env::remove_var("EMBEDDED_IDP_APP_ADMIN_UI_BASE_PATH");
        env::remove_var("EMBEDDED_IDP_APP_PUBLIC_CLIENT_ID");
        env::remove_var("EMBEDDED_IDP_APP_PASSWORD_MIN_LENGTH");

        let config = EmbeddedIdpAppConfig::from_env().expect("config should load");

        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:9100");
        assert_eq!(config.admin_ui_base_path, "/");
        assert_eq!(config.public_client.client_id, "desktop-app");
        assert_eq!(config.embedded_idp.auth.password_min_length, 8);
    }

    #[test]
    fn invalid_issuer_error_explains_supported_values() {
        let message = format_embedded_idp_config_error(
            &EmbeddedIdpConfig {
                issuer: "http://0.0.0.0:8080".to_string(),
                auth: AuthConfig {
                    allow_local_registration: true,
                    access_token_ttl_secs: 900,
                    refresh_token_ttl_secs: 86_400,
                    session_ttl_secs: 604_800,
                    verification_code_ttl_secs: 900,
                    password_min_length: 8,
                    password_max_length: 128,
                },
                device: DeviceConfig {
                    nonce_ttl_secs: 300,
                    proof_clock_skew_secs: 30,
                    heartbeat_grace_period_secs: 60,
                },
                oidc: OidcConfig {
                    authorization_code_ttl_secs: 300,
                    require_pkce_for_public_clients: true,
                },
            },
            ConfigValidationError::InvalidIssuer,
        );

        assert!(message.contains("EMBEDDED_IDP_APP_ISSUER"));
        assert!(message.contains("0.0.0.0 is only valid for EMBEDDED_IDP_APP_BIND_ADDR"));
        assert!(message.contains("http://0.0.0.0:8080"));
    }

    #[test]
    fn admin_ui_base_path_trims_trailing_slash() {
        assert_eq!(
            normalize_admin_ui_base_path("/admin-console/"),
            Ok("/admin-console".to_string())
        );
    }
}

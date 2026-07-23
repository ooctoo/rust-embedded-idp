#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgStorageConfig {
    pub connection: PgConnectionConfig,
    pub pool: DbPoolConfig,
}

impl PgStorageConfig {
    pub fn validate(&self) -> Result<(), PgStorageConfigError> {
        self.connection.validate()?;
        self.pool.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgConnectionConfig {
    pub connection_uri: String,
    pub schema_name: String,
    pub tls_mode: PgTlsMode,
    pub tls_ca_cert_path: Option<String>,
}

impl PgConnectionConfig {
    fn validate(&self) -> Result<(), PgStorageConfigError> {
        if !self.connection_uri.starts_with("postgres://")
            && !self.connection_uri.starts_with("postgresql://")
        {
            return Err(PgStorageConfigError::InvalidConnectionUri);
        }

        if self.schema_name.trim().is_empty() {
            return Err(PgStorageConfigError::MissingSchemaName);
        }
        if !is_valid_schema_name(&self.schema_name) {
            return Err(PgStorageConfigError::InvalidSchemaName);
        }
        if self
            .tls_ca_cert_path
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(PgStorageConfigError::InvalidTlsCaCertPath);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbPoolConfig {
    pub application_name: String,
    pub max_connections: u32,
    pub connect_timeout_secs: u64,
}

impl DbPoolConfig {
    fn validate(&self) -> Result<(), PgStorageConfigError> {
        if self.application_name.trim().is_empty() {
            return Err(PgStorageConfigError::MissingApplicationName);
        }

        if self.max_connections == 0 {
            return Err(PgStorageConfigError::MaxConnectionsMustBePositive);
        }

        if self.connect_timeout_secs == 0 {
            return Err(PgStorageConfigError::ConnectTimeoutMustBePositive);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgTlsMode {
    Disable,
    Prefer,
    Require,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgStorageConfigError {
    InvalidConnectionUri,
    MissingSchemaName,
    InvalidSchemaName,
    InvalidTlsCaCertPath,
    MissingApplicationName,
    MaxConnectionsMustBePositive,
    ConnectTimeoutMustBePositive,
}

fn is_valid_schema_name(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::{
        DbPoolConfig, PgConnectionConfig, PgStorageConfig, PgStorageConfigError, PgTlsMode,
    };

    fn valid_config() -> PgStorageConfig {
        PgStorageConfig {
            connection: PgConnectionConfig {
                connection_uri: "postgres://localhost:5432/embedded_idp".to_string(),
                schema_name: "embedded_idp".to_string(),
                tls_mode: PgTlsMode::Prefer,
                tls_ca_cert_path: None,
            },
            pool: DbPoolConfig {
                application_name: "embedded-idp-host".to_string(),
                max_connections: 10,
                connect_timeout_secs: 5,
            },
        }
    }

    #[test]
    fn config_accepts_postgres_uri() {
        assert_eq!(valid_config().validate(), Ok(()));
    }

    #[test]
    fn config_rejects_non_postgres_uri() {
        let mut config = valid_config();
        config.connection.connection_uri = "mysql://localhost:3306/idp".to_string();

        assert_eq!(
            config.validate(),
            Err(PgStorageConfigError::InvalidConnectionUri)
        );
    }

    #[test]
    fn config_rejects_zero_pool_size() {
        let mut config = valid_config();
        config.pool.max_connections = 0;

        assert_eq!(
            config.validate(),
            Err(PgStorageConfigError::MaxConnectionsMustBePositive)
        );
    }

    #[test]
    fn config_rejects_missing_schema_name() {
        let mut config = valid_config();
        config.connection.schema_name = String::new();

        assert_eq!(
            config.validate(),
            Err(PgStorageConfigError::MissingSchemaName)
        );
    }

    #[test]
    fn config_rejects_invalid_schema_identifier() {
        let mut config = valid_config();
        config.connection.schema_name = "tenant-a".to_string();

        assert_eq!(
            config.validate(),
            Err(PgStorageConfigError::InvalidSchemaName)
        );
    }

    #[test]
    fn config_rejects_blank_tls_ca_cert_path() {
        let mut config = valid_config();
        config.connection.tls_ca_cert_path = Some("   ".to_string());

        assert_eq!(
            config.validate(),
            Err(PgStorageConfigError::InvalidTlsCaCertPath)
        );
    }
}

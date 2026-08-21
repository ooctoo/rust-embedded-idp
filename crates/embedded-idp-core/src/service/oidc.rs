use crate::IssuedTokenBundle;

use super::{ContractValidationError, ServiceError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAuthorizationCommand {
    pub subject_account_id: String,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

impl StartAuthorizationCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.subject_account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingSubjectAccountId);
        }

        if self.response_type.trim().is_empty() {
            return Err(ContractValidationError::MissingResponseType);
        }

        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        if self.redirect_uri.trim().is_empty() {
            return Err(ContractValidationError::MissingRedirectUri);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAuthorizationResult {
    pub authorization_code: String,
    pub redirect_uri: String,
    pub state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeAuthorizationCodeCommand {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

impl ExchangeAuthorizationCodeCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.grant_type.trim().is_empty() {
            return Err(ContractValidationError::MissingGrantType);
        }

        if self.code.trim().is_empty() {
            return Err(ContractValidationError::MissingAuthorizationCode);
        }

        if self.redirect_uri.trim().is_empty() {
            return Err(ContractValidationError::MissingRedirectUri);
        }

        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeAuthorizationCodeResult {
    pub subject_account_id: String,
    pub tokens: IssuedTokenBundle,
    pub id_token: Option<crate::SecretString>,
    pub scope: Option<String>,
    pub token_type: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeTokenCommand {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub revoked_at: std::time::SystemTime,
}

impl RevokeTokenCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.token.trim().is_empty() {
            return Err(ContractValidationError::MissingToken);
        }

        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeTokenResult {
    pub revoked: bool,
    pub revoked_session_id: Option<String>,
    pub revoked_token_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetUserInfoCommand {
    pub access_token: String,
    pub observed_at: std::time::SystemTime,
}

impl GetUserInfoCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.access_token.trim().is_empty() {
            return Err(ContractValidationError::MissingToken);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetUserInfoResult {
    pub subject_account_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub client_id: String,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectTokenCommand {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub observed_at: std::time::SystemTime,
}

impl IntrospectTokenCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.token.trim().is_empty() {
            return Err(ContractValidationError::MissingToken);
        }

        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntrospectTokenResult {
    pub active: bool,
    pub subject_account_id: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub token_type: Option<&'static str>,
    pub session_id: Option<String>,
    pub expires_at: Option<std::time::SystemTime>,
    pub issued_at: Option<std::time::SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwksDocument {
    pub keys: Vec<JsonWebKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonWebKey {
    pub key_id: String,
    pub key_type: String,
    pub algorithm: String,
    pub public_key_use: String,
    pub curve: Option<String>,
    pub modulus: Option<String>,
    pub exponent: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

pub trait OidcAuthorizationService: Send + Sync {
    fn start_authorization(
        &self,
        command: StartAuthorizationCommand,
    ) -> Result<StartAuthorizationResult, ServiceError>;

    fn exchange_authorization_code(
        &self,
        command: ExchangeAuthorizationCodeCommand,
    ) -> Result<ExchangeAuthorizationCodeResult, ServiceError>;
}

pub trait OidcMetadataService: Send + Sync {
    fn jwks_document(&self) -> Result<JwksDocument, ServiceError>;

    fn jwks_etag(&self) -> Option<String> {
        None
    }
}

pub trait TokenManagementService: Send + Sync {
    fn revoke_token(&self, command: RevokeTokenCommand) -> Result<RevokeTokenResult, ServiceError>;
}

pub trait UserInfoService: Send + Sync {
    fn get_user_info(&self, command: GetUserInfoCommand)
        -> Result<GetUserInfoResult, ServiceError>;
}

pub trait TokenIntrospectionService: Send + Sync {
    fn introspect_token(
        &self,
        command: IntrospectTokenCommand,
    ) -> Result<IntrospectTokenResult, ServiceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticOidcMetadataService {
    jwks: JwksDocument,
}

impl StaticOidcMetadataService {
    pub fn new(jwks: JwksDocument) -> Self {
        Self { jwks }
    }
}

impl OidcMetadataService for StaticOidcMetadataService {
    fn jwks_document(&self) -> Result<JwksDocument, ServiceError> {
        Ok(self.jwks.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::IssuedTokenBundle;

    use super::{
        ContractValidationError, ExchangeAuthorizationCodeCommand, ExchangeAuthorizationCodeResult,
        GetUserInfoCommand, GetUserInfoResult, IntrospectTokenCommand, IntrospectTokenResult,
        JsonWebKey, JwksDocument, OidcMetadataService, RevokeTokenCommand, RevokeTokenResult,
        StartAuthorizationCommand, StartAuthorizationResult, StaticOidcMetadataService,
    };

    #[test]
    fn authorize_command_requires_response_type_and_redirect_uri() {
        let command = StartAuthorizationCommand {
            subject_account_id: String::new(),
            response_type: String::new(),
            client_id: "desktop-app".to_string(),
            redirect_uri: String::new(),
            scope: Some("openid profile".to_string()),
            state: Some("state-1".to_string()),
            code_challenge: Some("challenge".to_string()),
            code_challenge_method: Some("S256".to_string()),
            nonce: Some("nonce-1".to_string()),
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingSubjectAccountId)
        );
    }

    #[test]
    fn token_exchange_requires_grant_type_and_code() {
        let command = ExchangeAuthorizationCodeCommand {
            grant_type: String::new(),
            code: String::new(),
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            client_id: "desktop-app".to_string(),
            client_secret: None,
            code_verifier: Some("verifier".to_string()),
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingGrantType)
        );
    }

    #[test]
    fn oidc_result_models_are_cloneable() {
        let authorize = StartAuthorizationResult {
            authorization_code: "code-1".to_string(),
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            state: Some("state-1".to_string()),
        };
        let token = ExchangeAuthorizationCodeResult {
            subject_account_id: "acct-1".to_string(),
            tokens: IssuedTokenBundle {
                access_token: crate::SecretString::new("access"),
                refresh_token: crate::SecretString::new("refresh"),
                access_expires_at: std::time::SystemTime::UNIX_EPOCH,
                refresh_expires_at: std::time::SystemTime::UNIX_EPOCH,
                refresh_token_version: 0,
            },
            id_token: Some(crate::SecretString::new("id-token")),
            scope: Some("openid profile".to_string()),
            token_type: "Bearer",
        };
        let jwks = JwksDocument {
            keys: vec![JsonWebKey {
                key_id: "kid-1".to_string(),
                key_type: "EC".to_string(),
                algorithm: "ES256".to_string(),
                public_key_use: "sig".to_string(),
                curve: Some("P-256".to_string()),
                modulus: None,
                exponent: None,
                x: Some("x".to_string()),
                y: Some("y".to_string()),
            }],
        };
        let revoke = RevokeTokenResult {
            revoked: true,
            revoked_session_id: Some("sess-1".to_string()),
            revoked_token_version: Some(1),
        };
        let user_info = GetUserInfoResult {
            subject_account_id: "acct-1".to_string(),
            email: "user@example.com".to_string(),
            display_name: Some("User".to_string()),
            client_id: "desktop-app".to_string(),
            scope: Some("openid profile".to_string()),
        };
        let introspection = IntrospectTokenResult {
            active: true,
            subject_account_id: Some("acct-1".to_string()),
            client_id: Some("desktop-app".to_string()),
            scope: Some("openid profile".to_string()),
            token_type: Some("access_token"),
            session_id: Some("sess-1".to_string()),
            expires_at: Some(std::time::SystemTime::UNIX_EPOCH),
            issued_at: Some(std::time::SystemTime::UNIX_EPOCH),
        };

        assert_eq!(authorize.clone(), authorize);
        assert_eq!(token.clone(), token);
        assert_eq!(jwks.clone(), jwks);
        assert_eq!(revoke.clone(), revoke);
        assert_eq!(user_info.clone(), user_info);
        assert_eq!(introspection.clone(), introspection);
    }

    #[test]
    fn static_metadata_service_returns_cloned_jwks() {
        let service = StaticOidcMetadataService::new(JwksDocument {
            keys: vec![JsonWebKey {
                key_id: "kid-1".to_string(),
                key_type: "EC".to_string(),
                algorithm: "ES256".to_string(),
                public_key_use: "sig".to_string(),
                curve: Some("P-256".to_string()),
                modulus: None,
                exponent: None,
                x: Some("x".to_string()),
                y: Some("y".to_string()),
            }],
        });

        let jwks = service.jwks_document().expect("jwks should clone");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].key_id, "kid-1");
    }

    #[test]
    fn revoke_command_requires_token_and_client_id() {
        let command = RevokeTokenCommand {
            token: String::new(),
            token_type_hint: Some("refresh_token".to_string()),
            client_id: String::new(),
            client_secret: None,
            revoked_at: std::time::SystemTime::UNIX_EPOCH,
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingToken)
        );
    }

    #[test]
    fn user_info_command_requires_access_token() {
        let command = GetUserInfoCommand {
            access_token: String::new(),
            observed_at: std::time::SystemTime::UNIX_EPOCH,
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingToken)
        );
    }

    #[test]
    fn introspection_command_requires_token_and_client_id() {
        let command = IntrospectTokenCommand {
            token: String::new(),
            token_type_hint: Some("access_token".to_string()),
            client_id: String::new(),
            client_secret: None,
            observed_at: std::time::SystemTime::UNIX_EPOCH,
        };

        assert_eq!(
            command.validate(),
            Err(ContractValidationError::MissingToken)
        );
    }
}

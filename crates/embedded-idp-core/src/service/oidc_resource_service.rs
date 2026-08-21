use crate::{
    AccessTokenValidator, AccountStatus, AccountStore, AuthSession, ClientSecretVerifier,
    GetUserInfoCommand, GetUserInfoResult, IntrospectTokenCommand, IntrospectTokenResult,
    RefreshTokenRecord, RefreshTokenStore, ServiceError, SessionStatus, SessionStore, StoreError,
    StoreTransactionRunner, TokenIntrospectionService, UserInfoService, ValidatedAccessToken,
};

use super::auth_support::{map_account_status_conflict, require_active_account_status};
use super::{auth, client_auth};

pub struct CoreOidcResourceService<S, V, C> {
    store_runner: S,
    access_token_validator: V,
    client_secret_verifier: C,
}

impl<S, V, C> CoreOidcResourceService<S, V, C> {
    pub fn new(store_runner: S, access_token_validator: V, client_secret_verifier: C) -> Self {
        Self {
            store_runner,
            access_token_validator,
            client_secret_verifier,
        }
    }
}

impl<S, V, C> UserInfoService for CoreOidcResourceService<S, V, C>
where
    S: StoreTransactionRunner + Send + Sync,
    V: AccessTokenValidator + Send + Sync,
    C: ClientSecretVerifier + Send + Sync,
{
    fn get_user_info(
        &self,
        command: GetUserInfoCommand,
    ) -> Result<GetUserInfoResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        let Some(token) = self
            .access_token_validator
            .validate_access_token(&command.access_token, command.observed_at)
            .map_err(ServiceError::Token)?
            .filter(|value| value.expires_at > command.observed_at)
        else {
            return Err(ServiceError::InvalidToken);
        };

        self.store_runner
            .transaction(|tx| {
                let session = tx
                    .find_session(&token.session_id)?
                    .ok_or(StoreError::NotFound("auth_session.id"))?;
                if !access_token_is_active(&token, &session, command.observed_at) {
                    return Err(StoreError::Conflict("access_token.inactive"));
                }

                let account = tx
                    .find_account(&token.subject_account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                require_active_account_status(&account.status)?;

                Ok(GetUserInfoResult {
                    subject_account_id: account.id,
                    email: account.email,
                    display_name: account.display_name,
                    client_id: token.client_id.clone(),
                    scope: token.scope.clone(),
                })
            })
            .map_err(map_user_info_store_error)
    }
}

impl<S, V, C> TokenIntrospectionService for CoreOidcResourceService<S, V, C>
where
    S: StoreTransactionRunner + Send + Sync,
    V: AccessTokenValidator + Send + Sync,
    C: ClientSecretVerifier + Send + Sync,
{
    fn introspect_token(
        &self,
        command: IntrospectTokenCommand,
    ) -> Result<IntrospectTokenResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        match command.token_type_hint.as_deref() {
            Some("refresh_token") => self.introspect_refresh_token(&command),
            Some("access_token") => self.introspect_access_token(&command),
            _ => match self.introspect_refresh_token_if_present(&command)? {
                Some(result) => Ok(result),
                None => self.introspect_access_token(&command),
            },
        }
    }
}

impl<S, V, C> CoreOidcResourceService<S, V, C>
where
    S: StoreTransactionRunner + Send + Sync,
    V: AccessTokenValidator + Send + Sync,
    C: ClientSecretVerifier + Send + Sync,
{
    fn introspect_refresh_token(
        &self,
        command: &IntrospectTokenCommand,
    ) -> Result<IntrospectTokenResult, ServiceError> {
        Ok(self
            .introspect_refresh_token_if_present(command)?
            .unwrap_or_else(inactive_token_result))
    }

    fn introspect_refresh_token_if_present(
        &self,
        command: &IntrospectTokenCommand,
    ) -> Result<Option<IntrospectTokenResult>, ServiceError> {
        self.store_runner
            .transaction(|tx| {
                let client = auth::resolve_client(tx, &command.client_id)?;
                client_auth::authenticate_client(
                    &client,
                    command.client_secret.as_deref(),
                    &self.client_secret_verifier,
                )?;
                let token_digest = crate::digest_refresh_token(&command.token);
                let Some(refresh_token) = tx.find_refresh_token(&token_digest)? else {
                    return Ok(None);
                };

                let session = match tx.find_session(&refresh_token.session_id)? {
                    Some(session) => session,
                    None => return Ok(Some(inactive_token_result())),
                };
                if session.client_id != client.client_id {
                    return Err(StoreError::Conflict("oidc_client.authentication"));
                }

                let account = match tx.find_account(&session.account_id)? {
                    Some(account) => account,
                    None => return Ok(Some(inactive_token_result())),
                };

                if !refresh_token_is_active(
                    &refresh_token,
                    &session,
                    account.status,
                    command.observed_at,
                ) {
                    return Ok(Some(inactive_token_result()));
                }

                Ok(Some(IntrospectTokenResult {
                    active: true,
                    subject_account_id: Some(session.account_id.clone()),
                    client_id: Some(session.client_id.clone()),
                    scope: None,
                    token_type: Some("refresh_token"),
                    session_id: Some(session.id),
                    expires_at: Some(refresh_token.expires_at),
                    issued_at: Some(refresh_token.issued_at),
                }))
            })
            .map_err(map_introspection_store_error)
    }

    fn introspect_access_token(
        &self,
        command: &IntrospectTokenCommand,
    ) -> Result<IntrospectTokenResult, ServiceError> {
        let Some(token) = self
            .access_token_validator
            .validate_access_token(&command.token, command.observed_at)
            .map_err(ServiceError::Token)?
        else {
            return Ok(inactive_token_result());
        };

        if token.client_id != command.client_id {
            return Err(ServiceError::InvalidClientAuthentication);
        }

        if token.expires_at <= command.observed_at {
            return Ok(inactive_token_result());
        }

        self.store_runner
            .transaction(|tx| {
                let client = auth::resolve_client(tx, &command.client_id)?;
                client_auth::authenticate_client(
                    &client,
                    command.client_secret.as_deref(),
                    &self.client_secret_verifier,
                )?;
                let session = match tx.find_session(&token.session_id)? {
                    Some(session) => session,
                    None => return Ok(inactive_token_result()),
                };
                let account = match tx.find_account(&token.subject_account_id)? {
                    Some(account) => account,
                    None => return Ok(inactive_token_result()),
                };

                if !access_token_is_active(&token, &session, command.observed_at)
                    || account.status != AccountStatus::Active
                {
                    return Ok(inactive_token_result());
                }

                Ok(IntrospectTokenResult {
                    active: true,
                    subject_account_id: Some(token.subject_account_id),
                    client_id: Some(token.client_id),
                    scope: token.scope,
                    token_type: Some("access_token"),
                    session_id: Some(token.session_id),
                    expires_at: Some(token.expires_at),
                    issued_at: Some(token.issued_at),
                })
            })
            .map_err(map_introspection_store_error)
    }
}

fn access_token_is_active(
    token: &ValidatedAccessToken,
    session: &AuthSession,
    observed_at: std::time::SystemTime,
) -> bool {
    token.subject_account_id == session.account_id
        && token.client_id == session.client_id
        && session.status == SessionStatus::Active
        && session.expires_at > observed_at
        && token.expires_at > observed_at
}

fn refresh_token_is_active(
    token: &RefreshTokenRecord,
    session: &AuthSession,
    account_status: AccountStatus,
    observed_at: std::time::SystemTime,
) -> bool {
    token.revoked_at.is_none()
        && token.expires_at > observed_at
        && session.status == SessionStatus::Active
        && session.expires_at > observed_at
        && account_status == AccountStatus::Active
}

fn inactive_token_result() -> IntrospectTokenResult {
    IntrospectTokenResult {
        active: false,
        subject_account_id: None,
        client_id: None,
        scope: None,
        token_type: None,
        session_id: None,
        expires_at: None,
        issued_at: None,
    }
}

fn map_user_info_store_error(error: StoreError) -> ServiceError {
    if let Some(error) = map_account_status_conflict(&error) {
        return error;
    }

    match error {
        StoreError::NotFound("account.id") => ServiceError::AccountNotFound,
        StoreError::NotFound("auth_session.id") | StoreError::Conflict("access_token.inactive") => {
            ServiceError::InvalidToken
        }
        StoreError::Backend(message) if message.starts_with("token:") => {
            ServiceError::Token(auth::parse_token_error(&message))
        }
        other => ServiceError::Store(other),
    }
}

fn map_introspection_store_error(error: StoreError) -> ServiceError {
    match error {
        StoreError::NotFound("oidc_client.id") => ServiceError::ClientNotFound,
        StoreError::Conflict("oidc_client.client_secret") => {
            ServiceError::ClientAuthenticationRequired
        }
        StoreError::Conflict("oidc_client.authentication") => {
            ServiceError::InvalidClientAuthentication
        }
        StoreError::Backend(message) if message.starts_with("token:") => {
            ServiceError::Token(auth::parse_token_error(&message))
        }
        other => ServiceError::Store(other),
    }
}

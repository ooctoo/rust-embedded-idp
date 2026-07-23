use std::time::SystemTime;

use crate::{
    Account, AccountStatus, AuthSession, OidcClientType, PageMetadata, PageRequest, SessionStatus,
    TimePageCursor, MAX_PAGE_LIMIT,
};

use super::ContractValidationError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListAccountsCommand {
    pub status: Option<AccountStatus>,
    pub email: Option<String>,
    pub created_after: Option<SystemTime>,
    pub created_before: Option<SystemTime>,
    pub cursor: Option<TimePageCursor>,
    pub page: PageRequest,
}

impl ListAccountsCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self
            .email
            .as_deref()
            .is_some_and(|email| email.trim().is_empty())
        {
            return Err(ContractValidationError::MissingEmail);
        }

        validate_cursor(&self.cursor, &self.page)?;
        validate_page_request(&self.page)?;
        validate_time_range(self.created_after, self.created_before)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListAccountsResult {
    pub accounts: Vec<Account>,
    pub page: PageMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAccountCommand {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

impl CreateAccountCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.email.trim().is_empty() {
            return Err(ContractValidationError::MissingEmail);
        }

        if self.password.trim().is_empty() {
            return Err(ContractValidationError::MissingPassword);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAccountResult {
    pub account: Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAccountCommand {
    pub account_id: String,
}

impl GetAccountCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingAccountId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAccountResult {
    pub account: Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateAccountCommand {
    pub account_id: String,
}

impl ActivateAccountCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingAccountId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateAccountResult {
    pub account: Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisableAccountCommand {
    pub account_id: String,
}

impl DisableAccountCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingAccountId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisableAccountResult {
    pub account: Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAccountPasswordCommand {
    pub account_id: String,
    pub new_password: String,
}

impl SetAccountPasswordCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingAccountId);
        }

        if self.new_password.trim().is_empty() {
            return Err(ContractValidationError::MissingPassword);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAccountPasswordResult {
    pub account: Account,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAccountSessionsCommand {
    pub account_id: String,
    pub revoked_at: SystemTime,
}

impl RevokeAccountSessionsCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.account_id.trim().is_empty() {
            return Err(ContractValidationError::MissingAccountId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAccountSessionsResult {
    pub sessions: Vec<AuthSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListSessionsCommand {
    pub account_id: Option<String>,
    pub status: Option<SessionStatus>,
    pub client_id: Option<String>,
    pub device_id: Option<String>,
    pub created_after: Option<SystemTime>,
    pub created_before: Option<SystemTime>,
    pub cursor: Option<TimePageCursor>,
    pub page: PageRequest,
}

impl ListSessionsCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self
            .account_id
            .as_deref()
            .is_some_and(|account_id| account_id.trim().is_empty())
        {
            return Err(ContractValidationError::MissingAccountId);
        }

        if self
            .client_id
            .as_deref()
            .is_some_and(|client_id| client_id.trim().is_empty())
        {
            return Err(ContractValidationError::MissingClientId);
        }

        if self
            .device_id
            .as_deref()
            .is_some_and(|device_id| device_id.trim().is_empty())
        {
            return Err(ContractValidationError::MissingDeviceId);
        }

        validate_cursor(&self.cursor, &self.page)?;
        validate_page_request(&self.page)?;
        validate_time_range(self.created_after, self.created_before)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSessionsResult {
    pub sessions: Vec<AuthSession>,
    pub page: PageMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSessionCommand {
    pub session_id: String,
}

impl GetSessionCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.session_id.trim().is_empty() {
            return Err(ContractValidationError::MissingSessionId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSessionResult {
    pub session: AuthSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeSessionCommand {
    pub session_id: String,
    pub revoked_at: SystemTime,
}

impl RevokeSessionCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.session_id.trim().is_empty() {
            return Err(ContractValidationError::MissingSessionId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeSessionResult {
    pub session: AuthSession,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminClientRecord {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub client_type: OidcClientType,
    pub pkce_required: bool,
    pub client_secret_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListClientsCommand {
    pub client_type: Option<OidcClientType>,
    pub pkce_required: Option<bool>,
    pub page: PageRequest,
}

impl ListClientsCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        validate_page_request(&self.page)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListClientsResult {
    pub clients: Vec<AdminClientRecord>,
    pub page: PageMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetClientCommand {
    pub client_id: String,
}

impl GetClientCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetClientResult {
    pub client: AdminClientRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsertClientCommand {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub client_type: OidcClientType,
    pub pkce_required: bool,
    pub client_secret: Option<String>,
}

impl UpsertClientCommand {
    pub fn validate(&self) -> Result<(), ContractValidationError> {
        if self.client_id.trim().is_empty() {
            return Err(ContractValidationError::MissingClientId);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsertClientResult {
    pub client: AdminClientRecord,
}

fn validate_page_request(page: &PageRequest) -> Result<(), ContractValidationError> {
    if page.limit == 0 || page.limit > MAX_PAGE_LIMIT {
        return Err(ContractValidationError::InvalidPageLimit {
            max_limit: MAX_PAGE_LIMIT,
        });
    }

    Ok(())
}

fn validate_time_range(
    after: Option<SystemTime>,
    before: Option<SystemTime>,
) -> Result<(), ContractValidationError> {
    if matches!((after, before), (Some(after), Some(before)) if after > before) {
        return Err(ContractValidationError::InvalidTimeRange);
    }

    Ok(())
}

fn validate_cursor(
    cursor: &Option<TimePageCursor>,
    page: &PageRequest,
) -> Result<(), ContractValidationError> {
    let Some(cursor) = cursor else {
        return Ok(());
    };

    if cursor.entity_id.trim().is_empty() {
        return Err(ContractValidationError::MissingCursorId);
    }

    if page.offset != 0 {
        return Err(ContractValidationError::CursorWithOffsetUnsupported);
    }

    Ok(())
}

pub trait AdminService: Send + Sync {
    fn create_account(
        &self,
        command: CreateAccountCommand,
    ) -> Result<CreateAccountResult, super::ServiceError>;

    fn list_accounts(
        &self,
        command: ListAccountsCommand,
    ) -> Result<ListAccountsResult, super::ServiceError>;

    fn get_account(
        &self,
        command: GetAccountCommand,
    ) -> Result<GetAccountResult, super::ServiceError>;

    fn activate_account(
        &self,
        command: ActivateAccountCommand,
    ) -> Result<ActivateAccountResult, super::ServiceError>;

    fn disable_account(
        &self,
        command: DisableAccountCommand,
    ) -> Result<DisableAccountResult, super::ServiceError>;

    fn set_account_password(
        &self,
        command: SetAccountPasswordCommand,
    ) -> Result<SetAccountPasswordResult, super::ServiceError>;

    fn revoke_account_sessions(
        &self,
        command: RevokeAccountSessionsCommand,
    ) -> Result<RevokeAccountSessionsResult, super::ServiceError>;

    fn list_sessions(
        &self,
        command: ListSessionsCommand,
    ) -> Result<ListSessionsResult, super::ServiceError>;

    fn get_session(
        &self,
        command: GetSessionCommand,
    ) -> Result<GetSessionResult, super::ServiceError>;

    fn revoke_session(
        &self,
        command: RevokeSessionCommand,
    ) -> Result<RevokeSessionResult, super::ServiceError>;

    fn list_clients(
        &self,
        command: ListClientsCommand,
    ) -> Result<ListClientsResult, super::ServiceError>;

    fn get_client(&self, command: GetClientCommand)
        -> Result<GetClientResult, super::ServiceError>;

    fn upsert_client(
        &self,
        command: UpsertClientCommand,
    ) -> Result<UpsertClientResult, super::ServiceError>;
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{
        ActivateAccountCommand, DisableAccountCommand, GetAccountCommand, GetClientCommand,
        GetSessionCommand, ListAccountsCommand, ListSessionsCommand, RevokeAccountSessionsCommand,
        RevokeSessionCommand, SetAccountPasswordCommand, UpsertClientCommand,
    };
    use crate::{ContractValidationError, OidcClientType, TimePageCursor};

    #[test]
    fn account_admin_commands_require_account_id() {
        assert_eq!(
            GetAccountCommand {
                account_id: String::new(),
            }
            .validate(),
            Err(ContractValidationError::MissingAccountId)
        );
        assert_eq!(
            ActivateAccountCommand {
                account_id: String::new(),
            }
            .validate(),
            Err(ContractValidationError::MissingAccountId)
        );
        assert_eq!(
            DisableAccountCommand {
                account_id: String::new(),
            }
            .validate(),
            Err(ContractValidationError::MissingAccountId)
        );
        assert_eq!(
            RevokeAccountSessionsCommand {
                account_id: String::new(),
                revoked_at: SystemTime::UNIX_EPOCH,
            }
            .validate(),
            Err(ContractValidationError::MissingAccountId)
        );
    }

    #[test]
    fn password_and_session_admin_commands_validate_identifiers() {
        assert_eq!(
            SetAccountPasswordCommand {
                account_id: "acct-1".to_string(),
                new_password: String::new(),
            }
            .validate(),
            Err(ContractValidationError::MissingPassword)
        );
        assert_eq!(
            GetSessionCommand {
                session_id: String::new(),
            }
            .validate(),
            Err(ContractValidationError::MissingSessionId)
        );
        assert_eq!(
            RevokeSessionCommand {
                session_id: String::new(),
                revoked_at: SystemTime::UNIX_EPOCH,
            }
            .validate(),
            Err(ContractValidationError::MissingSessionId)
        );
        assert_eq!(
            ListSessionsCommand {
                account_id: Some(String::new()),
                ..Default::default()
            }
            .validate(),
            Err(ContractValidationError::MissingAccountId)
        );
        assert_eq!(
            GetClientCommand {
                client_id: String::new(),
            }
            .validate(),
            Err(ContractValidationError::MissingClientId)
        );
        assert_eq!(
            UpsertClientCommand {
                client_id: String::new(),
                client_name: "Client".to_string(),
                redirect_uris: vec!["http://127.0.0.1:49152/callback".to_string()],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret: None,
            }
            .validate(),
            Err(ContractValidationError::MissingClientId)
        );
    }

    #[test]
    fn list_admin_commands_validate_page_and_time_ranges() {
        assert_eq!(
            ListAccountsCommand {
                page: crate::PageRequest {
                    limit: 0,
                    offset: 0,
                },
                ..Default::default()
            }
            .validate(),
            Err(ContractValidationError::InvalidPageLimit {
                max_limit: crate::MAX_PAGE_LIMIT,
            })
        );
        assert_eq!(
            ListSessionsCommand {
                created_after: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10)),
                created_before: Some(SystemTime::UNIX_EPOCH),
                ..Default::default()
            }
            .validate(),
            Err(ContractValidationError::InvalidTimeRange)
        );
        assert_eq!(
            ListAccountsCommand {
                cursor: Some(TimePageCursor {
                    sort_time: SystemTime::UNIX_EPOCH,
                    entity_id: String::new(),
                }),
                ..Default::default()
            }
            .validate(),
            Err(ContractValidationError::MissingCursorId)
        );
        assert_eq!(
            ListSessionsCommand {
                cursor: Some(TimePageCursor {
                    sort_time: SystemTime::UNIX_EPOCH,
                    entity_id: "sess-1".to_string(),
                }),
                page: crate::PageRequest {
                    limit: 10,
                    offset: 1,
                },
                ..Default::default()
            }
            .validate(),
            Err(ContractValidationError::CursorWithOffsetUnsupported)
        );
    }
}

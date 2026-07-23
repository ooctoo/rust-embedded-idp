use std::time::SystemTime;

use crate::{
    Account, AccountDeviceBinding, AccountStatus, AuthSession, AuthorizationCodeRecord,
    DeviceNonceRecord, DeviceRecord, DeviceStatus, EmailVerificationCode, OidcClient,
    OidcClientType, PageRequest, RefreshTokenRecord, SessionStatus, TimePageCursor,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Conflict(&'static str),
    NotFound(&'static str),
    Backend(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountListQuery {
    pub status: Option<AccountStatus>,
    pub email: Option<String>,
    pub created_after: Option<SystemTime>,
    pub created_before: Option<SystemTime>,
    pub cursor: Option<TimePageCursor>,
    pub page: PageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListQuery {
    pub account_id: Option<String>,
    pub status: Option<SessionStatus>,
    pub client_id: Option<String>,
    pub device_id: Option<String>,
    pub created_after: Option<SystemTime>,
    pub created_before: Option<SystemTime>,
    pub cursor: Option<TimePageCursor>,
    pub page: PageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListQuery {
    pub account_id: Option<String>,
    pub client_id: Option<String>,
    pub status: Option<DeviceStatus>,
    pub registered_after: Option<SystemTime>,
    pub registered_before: Option<SystemTime>,
    pub cursor: Option<TimePageCursor>,
    pub page: PageRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientListQuery {
    pub client_type: Option<OidcClientType>,
    pub pkce_required: Option<bool>,
    pub page: PageRequest,
}

pub trait AccountStore {
    fn find_account(&mut self, account_id: &str) -> Result<Option<Account>, StoreError>;
    fn list_accounts(&mut self) -> Result<Vec<Account>, StoreError>;
    fn list_accounts_by_query(
        &mut self,
        query: &AccountListQuery,
    ) -> Result<Vec<Account>, StoreError>;
    fn count_accounts_by_query(&mut self, query: &AccountListQuery) -> Result<u64, StoreError>;
    fn find_by_email(&mut self, email: &str) -> Result<Option<Account>, StoreError>;
    fn insert_account(&mut self, account: Account) -> Result<Account, StoreError>;
    fn update_account(&mut self, account: Account) -> Result<Account, StoreError>;
}

pub trait SessionStore {
    fn find_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError>;
    fn list_sessions(&mut self, account_id: Option<&str>) -> Result<Vec<AuthSession>, StoreError>;
    fn list_sessions_by_query(
        &mut self,
        query: &SessionListQuery,
    ) -> Result<Vec<AuthSession>, StoreError>;
    fn count_sessions_by_query(&mut self, query: &SessionListQuery) -> Result<u64, StoreError>;
    fn insert_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError>;
    fn update_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError>;
}

pub trait DeviceStore {
    fn find_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError>;
    fn list_devices(&mut self) -> Result<Vec<DeviceRecord>, StoreError>;
    fn list_devices_by_query(
        &mut self,
        query: &DeviceListQuery,
    ) -> Result<Vec<DeviceRecord>, StoreError>;
    fn count_devices_by_query(&mut self, query: &DeviceListQuery) -> Result<u64, StoreError>;
    fn find_device_by_proof_key_id(
        &mut self,
        proof_key_id: &str,
    ) -> Result<Option<DeviceRecord>, StoreError>;
    fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError>;
    fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError>;
}

pub trait AccountDeviceBindingStore {
    fn find_active_account_device_binding(
        &mut self,
        account_id: &str,
        device_id: &str,
    ) -> Result<Option<AccountDeviceBinding>, StoreError>;

    fn list_account_device_bindings_by_device(
        &mut self,
        device_id: &str,
    ) -> Result<Vec<AccountDeviceBinding>, StoreError>;

    fn list_active_account_device_bindings_by_account(
        &mut self,
        account_id: &str,
    ) -> Result<Vec<AccountDeviceBinding>, StoreError>;

    fn insert_account_device_binding(
        &mut self,
        binding: AccountDeviceBinding,
    ) -> Result<AccountDeviceBinding, StoreError>;

    fn update_account_device_binding(
        &mut self,
        binding: AccountDeviceBinding,
    ) -> Result<AccountDeviceBinding, StoreError>;
}

pub trait DeviceNonceStore {
    fn find_device_nonce(
        &mut self,
        challenge: &str,
    ) -> Result<Option<DeviceNonceRecord>, StoreError>;

    fn insert_device_nonce(
        &mut self,
        nonce: DeviceNonceRecord,
    ) -> Result<DeviceNonceRecord, StoreError>;

    fn consume_device_nonce(
        &mut self,
        challenge: &str,
        consumed_at: SystemTime,
    ) -> Result<Option<DeviceNonceRecord>, StoreError>;
}

pub trait ClientStore {
    fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError>;
    fn list_clients(&mut self) -> Result<Vec<OidcClient>, StoreError>;
    fn list_clients_by_query(
        &mut self,
        query: &ClientListQuery,
    ) -> Result<Vec<OidcClient>, StoreError>;
    fn count_clients_by_query(&mut self, query: &ClientListQuery) -> Result<u64, StoreError>;
    fn upsert_client(&mut self, client: OidcClient) -> Result<OidcClient, StoreError>;
}

pub trait AuthorizationCodeStore {
    fn find_authorization_code(
        &mut self,
        code: &str,
    ) -> Result<Option<AuthorizationCodeRecord>, StoreError>;

    fn insert_authorization_code(
        &mut self,
        code: AuthorizationCodeRecord,
    ) -> Result<AuthorizationCodeRecord, StoreError>;

    fn consume_authorization_code(
        &mut self,
        code: &str,
        consumed_at: SystemTime,
    ) -> Result<Option<AuthorizationCodeRecord>, StoreError>;
}

pub trait EmailVerificationStore {
    fn find_email_verification_code(
        &mut self,
        email: &str,
        code: &str,
    ) -> Result<Option<EmailVerificationCode>, StoreError>;

    fn insert_email_verification_code(
        &mut self,
        verification: EmailVerificationCode,
    ) -> Result<EmailVerificationCode, StoreError>;

    fn consume_email_verification_code(
        &mut self,
        verification_id: &str,
        consumed_at: SystemTime,
    ) -> Result<Option<EmailVerificationCode>, StoreError>;

    fn consume_email_verification_codes_for_account(
        &mut self,
        account_id: &str,
        consumed_at: SystemTime,
    ) -> Result<Vec<EmailVerificationCode>, StoreError>;
}

pub trait RefreshTokenStore {
    fn find_refresh_token(
        &mut self,
        token_value: &str,
    ) -> Result<Option<RefreshTokenRecord>, StoreError>;

    fn insert_refresh_token(
        &mut self,
        token: RefreshTokenRecord,
    ) -> Result<RefreshTokenRecord, StoreError>;

    fn revoke_refresh_token(
        &mut self,
        token_value: &str,
        revoked_at: SystemTime,
    ) -> Result<Option<RefreshTokenRecord>, StoreError>;

    fn revoke_refresh_tokens_for_session(
        &mut self,
        session_id: &str,
        revoked_at: SystemTime,
    ) -> Result<Vec<RefreshTokenRecord>, StoreError>;
}

pub trait StoreTransaction:
    AccountStore
    + SessionStore
    + DeviceStore
    + AccountDeviceBindingStore
    + DeviceNonceStore
    + ClientStore
    + AuthorizationCodeStore
    + EmailVerificationStore
    + RefreshTokenStore
{
}

impl<T> StoreTransaction for T where
    T: AccountStore
        + SessionStore
        + DeviceStore
        + AccountDeviceBindingStore
        + DeviceNonceStore
        + ClientStore
        + AuthorizationCodeStore
        + EmailVerificationStore
        + RefreshTokenStore
{
}

pub trait StoreTransactionRunner {
    type Transaction<'a>: StoreTransaction
    where
        Self: 'a;

    fn transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError>;
}

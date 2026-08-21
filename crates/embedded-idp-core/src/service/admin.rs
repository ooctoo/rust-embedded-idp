use crate::{
    finalize_page, AccountListQuery, AccountStatus, AccountStore, AuthConfig, ClientListQuery,
    ClientSecretHasher, ClientStore, OidcClient, OidcClientType, RefreshTokenStore,
    SessionListQuery, SessionStatus, SessionStore, StoreError, StoreTransactionRunner,
    UuidV7IdGenerator,
};

use super::{
    password, ActivateAccountCommand, ActivateAccountResult, AdminService, CreateAccountCommand,
    CreateAccountResult, DisableAccountCommand, DisableAccountResult, GetAccountCommand,
    GetAccountResult, GetClientCommand, GetClientResult, GetSessionCommand, GetSessionResult,
    ListAccountsCommand, ListAccountsResult, ListClientsCommand, ListClientsResult,
    ListSessionsCommand, ListSessionsResult, RevokeAccountSessionsCommand,
    RevokeAccountSessionsResult, RevokeSessionCommand, RevokeSessionResult, ServiceError,
    SetAccountPasswordCommand, SetAccountPasswordResult, UpsertClientCommand, UpsertClientResult,
};
use crate::IdGenerator;

pub struct CoreAdminService<S, H> {
    auth_config: AuthConfig,
    store_runner: S,
    client_secret_hasher: H,
}

impl<S, H> CoreAdminService<S, H> {
    pub fn new(auth_config: AuthConfig, store_runner: S, client_secret_hasher: H) -> Self {
        Self {
            auth_config,
            store_runner,
            client_secret_hasher,
        }
    }
}

impl<S, H> AdminService for CoreAdminService<S, H>
where
    S: StoreTransactionRunner + Send + Sync,
    H: ClientSecretHasher + Send + Sync,
{
    fn create_account(
        &self,
        command: CreateAccountCommand,
    ) -> Result<CreateAccountResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;
        password::validate_registration_password(&self.auth_config, &command.password)
            .map_err(ServiceError::InvalidContract)?;
        let password_hash =
            password::hash_password(&command.password).map_err(ServiceError::Store)?;
        let created_at = std::time::SystemTime::now();
        let id_generator = UuidV7IdGenerator;

        self.store_runner
            .transaction(|tx| {
                if tx.find_by_email(&command.email)?.is_some() {
                    return Err(StoreError::Conflict("account.email"));
                }

                let account = tx.insert_account(crate::Account {
                    id: id_generator.next_id("acct"),
                    email: command.email,
                    password_hash,
                    display_name: command.display_name,
                    status: AccountStatus::Active,
                    created_at,
                })?;
                Ok(CreateAccountResult { account })
            })
            .map_err(map_store_error)
    }

    fn list_accounts(
        &self,
        command: ListAccountsCommand,
    ) -> Result<ListAccountsResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;
        let query = account_list_query(&command);

        self.store_runner
            .transaction(|tx| {
                let total = tx.count_accounts_by_query(&query)?;
                let (accounts, page) =
                    finalize_page(tx.list_accounts_by_query(&query)?, query.page, total);
                Ok(ListAccountsResult { accounts, page })
            })
            .map_err(map_store_error)
    }

    fn get_account(&self, command: GetAccountCommand) -> Result<GetAccountResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let account = tx
                    .find_account(&command.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                Ok(GetAccountResult { account })
            })
            .map_err(map_store_error)
    }

    fn activate_account(
        &self,
        command: ActivateAccountCommand,
    ) -> Result<ActivateAccountResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let mut account = tx
                    .find_account(&command.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                account.status = AccountStatus::Active;
                let account = tx.update_account(account)?;
                Ok(ActivateAccountResult { account })
            })
            .map_err(map_store_error)
    }

    fn disable_account(
        &self,
        command: DisableAccountCommand,
    ) -> Result<DisableAccountResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let mut account = tx
                    .find_account(&command.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                account.status = AccountStatus::Disabled;
                let account = tx.update_account(account)?;
                Ok(DisableAccountResult { account })
            })
            .map_err(map_store_error)
    }

    fn set_account_password(
        &self,
        command: SetAccountPasswordCommand,
    ) -> Result<SetAccountPasswordResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;
        password::validate_registration_password(&self.auth_config, &command.new_password)
            .map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let mut account = tx
                    .find_account(&command.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                account.password_hash = password::hash_password(&command.new_password)?;
                let account = tx.update_account(account)?;
                Ok(SetAccountPasswordResult { account })
            })
            .map_err(map_store_error)
    }

    fn revoke_account_sessions(
        &self,
        command: RevokeAccountSessionsCommand,
    ) -> Result<RevokeAccountSessionsResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                tx.find_account(&command.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                let sessions = tx.list_sessions(Some(&command.account_id))?;
                let mut revoked = Vec::with_capacity(sessions.len());

                for session in sessions {
                    let session = revoke_session_record(tx, session, command.revoked_at)?;
                    revoked.push(session);
                }

                Ok(RevokeAccountSessionsResult { sessions: revoked })
            })
            .map_err(map_store_error)
    }

    fn list_sessions(
        &self,
        command: ListSessionsCommand,
    ) -> Result<ListSessionsResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let query = session_list_query(&command);
                let total = tx.count_sessions_by_query(&query)?;
                let (sessions, page) =
                    finalize_page(tx.list_sessions_by_query(&query)?, query.page, total);
                Ok(ListSessionsResult { sessions, page })
            })
            .map_err(map_store_error)
    }

    fn get_session(&self, command: GetSessionCommand) -> Result<GetSessionResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let session = tx
                    .find_session(&command.session_id)?
                    .ok_or(StoreError::NotFound("auth_session.id"))?;
                Ok(GetSessionResult { session })
            })
            .map_err(map_store_error)
    }

    fn revoke_session(
        &self,
        command: RevokeSessionCommand,
    ) -> Result<RevokeSessionResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let session = tx
                    .find_session(&command.session_id)?
                    .ok_or(StoreError::NotFound("auth_session.id"))?;
                let session = revoke_session_record(tx, session, command.revoked_at)?;
                Ok(RevokeSessionResult { session })
            })
            .map_err(map_store_error)
    }

    fn list_clients(&self, command: ListClientsCommand) -> Result<ListClientsResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;
        let query = client_list_query(&command);

        self.store_runner
            .transaction(|tx| {
                let total = tx.count_clients_by_query(&query)?;
                let (clients, page) =
                    finalize_page(tx.list_clients_by_query(&query)?, query.page, total);
                Ok(ListClientsResult {
                    clients: clients.into_iter().map(admin_client_record).collect(),
                    page,
                })
            })
            .map_err(map_store_error)
    }

    fn get_client(&self, command: GetClientCommand) -> Result<GetClientResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let client = tx
                    .find_client(&command.client_id)?
                    .ok_or(StoreError::NotFound("oidc_client.id"))?;
                Ok(GetClientResult {
                    client: admin_client_record(client),
                })
            })
            .map_err(map_store_error)
    }

    fn upsert_client(
        &self,
        command: UpsertClientCommand,
    ) -> Result<UpsertClientResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let existing = tx.find_client(&command.client_id)?;
                let client =
                    build_client_for_upsert(existing, command, &self.client_secret_hasher)?;
                let client = tx.upsert_client(client)?;
                Ok(UpsertClientResult {
                    client: admin_client_record(client),
                })
            })
            .map_err(map_store_error)
    }
}

fn revoke_session_record(
    tx: &mut impl AdminStore,
    mut session: crate::AuthSession,
    revoked_at: std::time::SystemTime,
) -> Result<crate::AuthSession, StoreError> {
    if session.status != SessionStatus::Revoked {
        session.status = SessionStatus::Revoked;
        session = tx.update_session(session)?;
    }
    tx.revoke_refresh_tokens_for_session(
        &session.id,
        crate::RefreshTokenRevocationReason::Administrative,
        revoked_at,
    )?;
    Ok(session)
}

fn build_client_for_upsert(
    existing: Option<OidcClient>,
    command: UpsertClientCommand,
    client_secret_hasher: &impl ClientSecretHasher,
) -> Result<OidcClient, StoreError> {
    let client_secret_hash = match command.client_type {
        OidcClientType::PublicDesktop => None,
        OidcClientType::ConfidentialWeb => match command
            .client_secret
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(raw_secret) => Some(
                client_secret_hasher
                    .hash_client_secret(raw_secret)
                    .map_err(|error| StoreError::Backend(format!("client_secret:{error:?}")))?,
            ),
            None => existing.and_then(|client| client.client_secret_hash),
        },
    };

    let client = OidcClient {
        client_id: command.client_id,
        client_name: command.client_name,
        redirect_uris: command.redirect_uris,
        client_type: command.client_type,
        pkce_required: command.pkce_required,
        client_secret_hash,
    };
    client
        .validate()
        .map_err(|error| StoreError::Backend(format!("invalid client config: {error:?}")))?;
    Ok(client)
}

fn account_list_query(command: &ListAccountsCommand) -> AccountListQuery {
    AccountListQuery {
        status: command.status.clone(),
        email: command.email.clone(),
        created_after: command.created_after,
        created_before: command.created_before,
        cursor: command.cursor.clone(),
        page: command.page,
    }
}

fn session_list_query(command: &ListSessionsCommand) -> SessionListQuery {
    SessionListQuery {
        account_id: command.account_id.clone(),
        status: command.status.clone(),
        client_id: command.client_id.clone(),
        device_id: command.device_id.clone(),
        created_after: command.created_after,
        created_before: command.created_before,
        cursor: command.cursor.clone(),
        page: command.page,
    }
}

fn client_list_query(command: &ListClientsCommand) -> ClientListQuery {
    ClientListQuery {
        client_type: command.client_type,
        pkce_required: command.pkce_required,
        page: command.page,
    }
}

fn admin_client_record(client: OidcClient) -> super::AdminClientRecord {
    super::AdminClientRecord {
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
        client_type: client.client_type,
        pkce_required: client.pkce_required,
        client_secret_configured: client
            .client_secret_hash
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
    }
}

fn map_store_error(error: StoreError) -> ServiceError {
    match error {
        StoreError::Conflict("account.email") => ServiceError::EmailAlreadyExists,
        StoreError::NotFound("account.id") => ServiceError::AccountNotFound,
        StoreError::NotFound("auth_session.id") => ServiceError::SessionNotFound,
        StoreError::NotFound("oidc_client.id") => ServiceError::ClientNotFound,
        StoreError::Backend(message) if message.starts_with("invalid client config:") => {
            ServiceError::InvalidClientConfig(super::auth::parse_client_error(&message))
        }
        other => ServiceError::Store(other),
    }
}

trait AdminStore: AccountStore + SessionStore + RefreshTokenStore + ClientStore {}

impl<T> AdminStore for T where T: AccountStore + SessionStore + RefreshTokenStore + ClientStore {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use std::time::SystemTime;

    use super::*;
    use crate::{
        digest_refresh_token, Account, AccountDeviceBinding, AccountDeviceBindingStore,
        AuthSession, AuthorizationCodeRecord, AuthorizationCodeStore, ClientSecretError,
        ClientSecretHasher, ClientStore, DeviceNonceRecord, DeviceNonceStore, DeviceRecord,
        DeviceStore, EmailVerificationCode, EmailVerificationStore, OidcClient, OidcClientType,
        PageRequest, RefreshTokenRecord, RefreshTokenRevocationReason,
    };

    #[derive(Default)]
    struct TestStoreState {
        accounts: HashMap<String, Account>,
        sessions: HashMap<String, AuthSession>,
        refresh_tokens: HashMap<[u8; 32], RefreshTokenRecord>,
        clients: HashMap<String, OidcClient>,
    }

    #[derive(Default)]
    struct TestStoreRunner {
        state: Mutex<TestStoreState>,
    }

    struct TestStoreTx<'a> {
        state: MutexGuard<'a, TestStoreState>,
    }

    impl StoreTransactionRunner for TestStoreRunner {
        type Transaction<'a>
            = TestStoreTx<'a>
        where
            Self: 'a;

        fn transaction<R>(
            &self,
            run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, StoreError>,
        ) -> Result<R, StoreError> {
            let mut tx = TestStoreTx {
                state: self.state.lock().expect("lock store"),
            };
            run(&mut tx)
        }
    }

    impl AccountStore for TestStoreTx<'_> {
        fn find_account(&mut self, account_id: &str) -> Result<Option<Account>, StoreError> {
            Ok(self.state.accounts.get(account_id).cloned())
        }

        fn list_accounts(&mut self) -> Result<Vec<Account>, StoreError> {
            Ok(self.state.accounts.values().cloned().collect())
        }

        fn list_accounts_by_query(
            &mut self,
            query: &AccountListQuery,
        ) -> Result<Vec<Account>, StoreError> {
            let mut accounts: Vec<_> = self
                .state
                .accounts
                .values()
                .filter(|account| {
                    query
                        .status
                        .as_ref()
                        .is_none_or(|status| &account.status == status)
                })
                .filter(|account| {
                    query
                        .email
                        .as_deref()
                        .is_none_or(|email| account.email.contains(email))
                })
                .filter(|account| {
                    query
                        .created_after
                        .is_none_or(|created_after| account.created_at >= created_after)
                })
                .filter(|account| {
                    query
                        .created_before
                        .is_none_or(|created_before| account.created_at <= created_before)
                })
                .cloned()
                .collect();
            accounts.sort_by(|left, right| {
                right
                    .created_at
                    .cmp(&left.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            Ok(slice_page(accounts, query.page))
        }

        fn count_accounts_by_query(&mut self, query: &AccountListQuery) -> Result<u64, StoreError> {
            Ok(self
                .state
                .accounts
                .values()
                .filter(|account| {
                    query
                        .status
                        .as_ref()
                        .is_none_or(|status| &account.status == status)
                })
                .filter(|account| {
                    query
                        .email
                        .as_deref()
                        .is_none_or(|email| account.email.contains(email))
                })
                .filter(|account| {
                    query
                        .created_after
                        .is_none_or(|created_after| account.created_at >= created_after)
                })
                .filter(|account| {
                    query
                        .created_before
                        .is_none_or(|created_before| account.created_at <= created_before)
                })
                .count() as u64)
        }

        fn find_by_email(&mut self, email: &str) -> Result<Option<Account>, StoreError> {
            Ok(self
                .state
                .accounts
                .values()
                .find(|account| account.email == email)
                .cloned())
        }

        fn insert_account(&mut self, account: Account) -> Result<Account, StoreError> {
            self.state
                .accounts
                .insert(account.id.clone(), account.clone());
            Ok(account)
        }

        fn update_account(&mut self, account: Account) -> Result<Account, StoreError> {
            self.state
                .accounts
                .insert(account.id.clone(), account.clone());
            Ok(account)
        }
    }

    impl SessionStore for TestStoreTx<'_> {
        fn find_session(&mut self, session_id: &str) -> Result<Option<AuthSession>, StoreError> {
            Ok(self.state.sessions.get(session_id).cloned())
        }

        fn list_sessions(
            &mut self,
            account_id: Option<&str>,
        ) -> Result<Vec<AuthSession>, StoreError> {
            Ok(self
                .state
                .sessions
                .values()
                .filter(|session| {
                    account_id.is_none_or(|account_id| session.account_id == account_id)
                })
                .cloned()
                .collect())
        }

        fn list_sessions_by_query(
            &mut self,
            query: &SessionListQuery,
        ) -> Result<Vec<AuthSession>, StoreError> {
            let mut sessions: Vec<_> = self
                .state
                .sessions
                .values()
                .filter(|session| {
                    query
                        .account_id
                        .as_deref()
                        .is_none_or(|account_id| session.account_id == account_id)
                })
                .filter(|session| {
                    query
                        .status
                        .as_ref()
                        .is_none_or(|status| &session.status == status)
                })
                .filter(|session| {
                    query
                        .client_id
                        .as_deref()
                        .is_none_or(|client_id| session.client_id == client_id)
                })
                .filter(|session| {
                    query
                        .device_id
                        .as_deref()
                        .is_none_or(|device_id| session.device_id.as_deref() == Some(device_id))
                })
                .filter(|session| {
                    query
                        .created_after
                        .is_none_or(|created_after| session.created_at >= created_after)
                })
                .filter(|session| {
                    query
                        .created_before
                        .is_none_or(|created_before| session.created_at <= created_before)
                })
                .cloned()
                .collect();
            sessions.sort_by(|left, right| {
                right
                    .created_at
                    .cmp(&left.created_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            Ok(slice_page(sessions, query.page))
        }

        fn count_sessions_by_query(&mut self, query: &SessionListQuery) -> Result<u64, StoreError> {
            Ok(self
                .state
                .sessions
                .values()
                .filter(|session| {
                    query
                        .account_id
                        .as_deref()
                        .is_none_or(|account_id| session.account_id == account_id)
                })
                .filter(|session| {
                    query
                        .status
                        .as_ref()
                        .is_none_or(|status| &session.status == status)
                })
                .filter(|session| {
                    query
                        .client_id
                        .as_deref()
                        .is_none_or(|client_id| session.client_id == client_id)
                })
                .filter(|session| {
                    query
                        .device_id
                        .as_deref()
                        .is_none_or(|device_id| session.device_id.as_deref() == Some(device_id))
                })
                .filter(|session| {
                    query
                        .created_after
                        .is_none_or(|created_after| session.created_at >= created_after)
                })
                .filter(|session| {
                    query
                        .created_before
                        .is_none_or(|created_before| session.created_at <= created_before)
                })
                .count() as u64)
        }

        fn insert_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
            self.state
                .sessions
                .insert(session.id.clone(), session.clone());
            Ok(session)
        }

        fn update_session(&mut self, session: AuthSession) -> Result<AuthSession, StoreError> {
            self.state
                .sessions
                .insert(session.id.clone(), session.clone());
            Ok(session)
        }
    }

    impl RefreshTokenStore for TestStoreTx<'_> {
        fn find_refresh_token(
            &mut self,
            token_digest: &[u8; 32],
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(self.state.refresh_tokens.get(token_digest).cloned())
        }

        fn insert_refresh_token(
            &mut self,
            token: RefreshTokenRecord,
        ) -> Result<RefreshTokenRecord, StoreError> {
            self.state
                .refresh_tokens
                .insert(token.token_digest, token.clone());
            Ok(token)
        }

        fn revoke_refresh_token(
            &mut self,
            token_digest: &[u8; 32],
            reason: RefreshTokenRevocationReason,
            revoked_at: SystemTime,
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            let Some(token) = self.state.refresh_tokens.get_mut(token_digest) else {
                return Ok(None);
            };
            token.revoked_at = Some(revoked_at);
            token.revocation_reason = Some(reason);
            Ok(Some(token.clone()))
        }

        fn revoke_refresh_tokens_for_session(
            &mut self,
            session_id: &str,
            reason: RefreshTokenRevocationReason,
            revoked_at: SystemTime,
        ) -> Result<Vec<RefreshTokenRecord>, StoreError> {
            let mut revoked = Vec::new();
            for token in self.state.refresh_tokens.values_mut() {
                if token.session_id == session_id {
                    token.revoked_at = Some(revoked_at);
                    token.revocation_reason = Some(reason);
                    revoked.push(token.clone());
                }
            }
            Ok(revoked)
        }
    }

    impl DeviceStore for TestStoreTx<'_> {
        fn find_device(&mut self, _device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(None)
        }
        fn list_devices(&mut self) -> Result<Vec<DeviceRecord>, StoreError> {
            Ok(Vec::new())
        }
        fn list_devices_by_query(
            &mut self,
            _query: &crate::DeviceListQuery,
        ) -> Result<Vec<DeviceRecord>, StoreError> {
            Ok(Vec::new())
        }
        fn count_devices_by_query(
            &mut self,
            _query: &crate::DeviceListQuery,
        ) -> Result<u64, StoreError> {
            Ok(0)
        }
        fn find_device_by_proof_key_id(
            &mut self,
            _proof_key_id: &str,
        ) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(None)
        }
        fn insert_device(&mut self, _device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            unreachable!()
        }
        fn update_device(&mut self, _device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            unreachable!()
        }
    }

    impl AccountDeviceBindingStore for TestStoreTx<'_> {
        fn find_active_account_device_binding(
            &mut self,
            _account_id: &str,
            _device_id: &str,
        ) -> Result<Option<AccountDeviceBinding>, StoreError> {
            Ok(None)
        }
        fn list_account_device_bindings_by_device(
            &mut self,
            _device_id: &str,
        ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
            Ok(Vec::new())
        }
        fn list_active_account_device_bindings_by_account(
            &mut self,
            _account_id: &str,
        ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
            Ok(Vec::new())
        }
        fn insert_account_device_binding(
            &mut self,
            _binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            unreachable!()
        }
        fn update_account_device_binding(
            &mut self,
            _binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            unreachable!()
        }
    }

    impl DeviceNonceStore for TestStoreTx<'_> {
        fn find_device_nonce(
            &mut self,
            _challenge: &str,
        ) -> Result<Option<DeviceNonceRecord>, StoreError> {
            Ok(None)
        }
        fn insert_device_nonce(
            &mut self,
            _nonce: DeviceNonceRecord,
        ) -> Result<DeviceNonceRecord, StoreError> {
            unreachable!()
        }
        fn consume_device_nonce(
            &mut self,
            _challenge: &str,
            _consumed_at: SystemTime,
        ) -> Result<Option<DeviceNonceRecord>, StoreError> {
            Ok(None)
        }
    }

    impl ClientStore for TestStoreTx<'_> {
        fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
            Ok(self.state.clients.get(client_id).cloned())
        }

        fn list_clients(&mut self) -> Result<Vec<OidcClient>, StoreError> {
            Ok(self.state.clients.values().cloned().collect())
        }

        fn list_clients_by_query(
            &mut self,
            query: &ClientListQuery,
        ) -> Result<Vec<OidcClient>, StoreError> {
            let mut clients: Vec<_> = self
                .state
                .clients
                .values()
                .filter(|client| {
                    query
                        .client_type
                        .as_ref()
                        .is_none_or(|client_type| &client.client_type == client_type)
                })
                .filter(|client| {
                    query
                        .pkce_required
                        .is_none_or(|pkce_required| client.pkce_required == pkce_required)
                })
                .cloned()
                .collect();
            clients.sort_by(|left, right| left.client_id.cmp(&right.client_id));
            Ok(slice_page(clients, query.page))
        }

        fn count_clients_by_query(&mut self, query: &ClientListQuery) -> Result<u64, StoreError> {
            Ok(self
                .state
                .clients
                .values()
                .filter(|client| {
                    query
                        .client_type
                        .as_ref()
                        .is_none_or(|client_type| &client.client_type == client_type)
                })
                .filter(|client| {
                    query
                        .pkce_required
                        .is_none_or(|pkce_required| client.pkce_required == pkce_required)
                })
                .count() as u64)
        }

        fn upsert_client(&mut self, client: OidcClient) -> Result<OidcClient, StoreError> {
            self.state
                .clients
                .insert(client.client_id.clone(), client.clone());
            Ok(client)
        }
    }

    impl AuthorizationCodeStore for TestStoreTx<'_> {
        fn find_authorization_code(
            &mut self,
            _code: &str,
        ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
            Ok(None)
        }
        fn insert_authorization_code(
            &mut self,
            _code: AuthorizationCodeRecord,
        ) -> Result<AuthorizationCodeRecord, StoreError> {
            unreachable!()
        }
        fn consume_authorization_code(
            &mut self,
            _code: &str,
            _consumed_at: SystemTime,
        ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
            Ok(None)
        }
    }

    impl EmailVerificationStore for TestStoreTx<'_> {
        fn find_email_verification_code(
            &mut self,
            _email: &str,
            _code: &str,
        ) -> Result<Option<EmailVerificationCode>, StoreError> {
            Ok(None)
        }

        fn insert_email_verification_code(
            &mut self,
            verification: EmailVerificationCode,
        ) -> Result<EmailVerificationCode, StoreError> {
            Ok(verification)
        }

        fn consume_email_verification_code(
            &mut self,
            _verification_id: &str,
            _consumed_at: SystemTime,
        ) -> Result<Option<EmailVerificationCode>, StoreError> {
            Ok(None)
        }

        fn consume_email_verification_codes_for_account(
            &mut self,
            _account_id: &str,
            _consumed_at: SystemTime,
        ) -> Result<Vec<EmailVerificationCode>, StoreError> {
            Ok(Vec::new())
        }
    }

    fn auth_config() -> AuthConfig {
        AuthConfig {
            allow_local_registration: true,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 86_400,
            session_ttl_secs: 604_800,
            verification_code_ttl_secs: 900,
            password_min_length: 8,
            password_max_length: 128,
        }
    }

    fn account() -> Account {
        Account {
            id: "acct-1".to_string(),
            email: "user@example.com".to_string(),
            password_hash: "$argon2id$demo".to_string(),
            display_name: Some("User".to_string()),
            status: AccountStatus::Active,
            created_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn session() -> AuthSession {
        AuthSession {
            id: "sess-1".to_string(),
            account_id: "acct-1".to_string(),
            client_id: "desktop-app".to_string(),
            device_id: None,
            status: SessionStatus::Active,
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: SystemTime::UNIX_EPOCH,
            refresh_token_version: 0,
        }
    }

    fn older_account() -> Account {
        Account {
            id: "acct-2".to_string(),
            email: "disabled@example.com".to_string(),
            password_hash: "$argon2id$demo-2".to_string(),
            display_name: Some("Disabled".to_string()),
            status: AccountStatus::Disabled,
            created_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn web_client() -> OidcClient {
        OidcClient {
            client_id: "web-app".to_string(),
            client_name: "Web App".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            client_type: OidcClientType::ConfidentialWeb,
            pkce_required: false,
            client_secret_hash: Some("hash:top-secret".to_string()),
        }
    }

    struct TestClientSecretHasher;

    impl ClientSecretHasher for TestClientSecretHasher {
        fn hash_client_secret(&self, raw_secret: &str) -> Result<String, ClientSecretError> {
            Ok(format!("hash:{raw_secret}"))
        }
    }

    fn slice_page<T>(mut items: Vec<T>, page: PageRequest) -> Vec<T> {
        if page.offset as usize >= items.len() {
            return Vec::new();
        }
        items.drain(0..page.offset as usize);
        items.truncate(page.fetch_limit() as usize);
        items
    }

    fn service() -> CoreAdminService<TestStoreRunner, TestClientSecretHasher> {
        let runner = TestStoreRunner::default();
        {
            let mut state = runner.state.lock().expect("lock state");
            state.accounts.insert("acct-1".to_string(), account());
            state.accounts.insert("acct-2".to_string(), older_account());
            state.sessions.insert("sess-1".to_string(), session());
            state.refresh_tokens.insert(
                digest_refresh_token("refresh-1"),
                RefreshTokenRecord {
                    id: "rtok-1".to_string(),
                    session_id: "sess-1".to_string(),
                    token_digest: digest_refresh_token("refresh-1"),
                    token_version: 0,
                    issued_at: SystemTime::UNIX_EPOCH,
                    expires_at: SystemTime::UNIX_EPOCH,
                    revoked_at: None,
                    revocation_reason: None,
                },
            );
            state.clients.insert(
                "desktop-app".to_string(),
                OidcClient {
                    client_id: "desktop-app".to_string(),
                    client_name: "Desktop App".to_string(),
                    redirect_uris: vec!["http://127.0.0.1:49152/callback".to_string()],
                    client_type: OidcClientType::PublicDesktop,
                    pkce_required: true,
                    client_secret_hash: None,
                },
            );
            state.clients.insert("web-app".to_string(), web_client());
        }

        CoreAdminService::new(auth_config(), runner, TestClientSecretHasher)
    }

    #[test]
    fn disabling_and_activating_account_updates_status() {
        let service = service();

        let disabled = service
            .disable_account(DisableAccountCommand {
                account_id: "acct-1".to_string(),
            })
            .expect("disable account");
        assert_eq!(disabled.account.status, AccountStatus::Disabled);

        let activated = service
            .activate_account(ActivateAccountCommand {
                account_id: "acct-1".to_string(),
            })
            .expect("activate account");
        assert_eq!(activated.account.status, AccountStatus::Active);
    }

    #[test]
    fn set_account_password_rehashes_password() {
        let service = service();

        let result = service
            .set_account_password(SetAccountPasswordCommand {
                account_id: "acct-1".to_string(),
                new_password: "new-password-1".to_string(),
            })
            .expect("set password");

        assert_ne!(result.account.password_hash, "$argon2id$demo");
        assert!(result.account.password_hash.starts_with("$argon2id$"));
    }

    #[test]
    fn create_account_inserts_active_account() {
        let service = service();

        let result = service
            .create_account(CreateAccountCommand {
                email: "new-user@example.com".to_string(),
                password: "new-password-1".to_string(),
                display_name: Some("New User".to_string()),
            })
            .expect("create account");

        assert_eq!(result.account.email, "new-user@example.com");
        assert_eq!(result.account.status, AccountStatus::Active);
        assert_eq!(result.account.display_name.as_deref(), Some("New User"));
        assert!(result.account.password_hash.starts_with("$argon2id$"));
    }

    #[test]
    fn create_account_rejects_duplicate_email() {
        let service = service();

        assert_eq!(
            service.create_account(CreateAccountCommand {
                email: "user@example.com".to_string(),
                password: "new-password-1".to_string(),
                display_name: None,
            }),
            Err(ServiceError::EmailAlreadyExists)
        );
    }

    #[test]
    fn revoke_session_updates_status_and_refresh_tokens() {
        let service = service();

        let result = service
            .revoke_session(RevokeSessionCommand {
                session_id: "sess-1".to_string(),
                revoked_at: SystemTime::UNIX_EPOCH,
            })
            .expect("revoke session");

        assert_eq!(result.session.status, SessionStatus::Revoked);
    }

    #[test]
    fn revoke_account_sessions_updates_all_matching_sessions() {
        let service = service();

        let result = service
            .revoke_account_sessions(RevokeAccountSessionsCommand {
                account_id: "acct-1".to_string(),
                revoked_at: SystemTime::UNIX_EPOCH,
            })
            .expect("revoke account sessions");

        assert_eq!(result.sessions.len(), 1);
        assert_eq!(result.sessions[0].status, SessionStatus::Revoked);
    }

    #[test]
    fn upsert_client_hashes_confidential_secret() {
        let service = service();

        let result = service
            .upsert_client(UpsertClientCommand {
                client_id: "web-app".to_string(),
                client_name: "Web App".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                client_type: OidcClientType::ConfidentialWeb,
                pkce_required: false,
                client_secret: Some("top-secret".to_string()),
            })
            .expect("upsert client");

        assert_eq!(result.client.client_id, "web-app");
        assert!(result.client.client_secret_configured);
    }

    #[test]
    fn get_client_rejects_missing_client() {
        let service = service();

        assert_eq!(
            service.get_client(GetClientCommand {
                client_id: "missing-client".to_string(),
            }),
            Err(ServiceError::ClientNotFound)
        );
    }

    #[test]
    fn list_accounts_applies_status_email_and_page_filters() {
        let service = service();

        let result = service
            .list_accounts(ListAccountsCommand {
                status: Some(AccountStatus::Active),
                email: Some("user@".to_string()),
                page: PageRequest {
                    limit: 1,
                    offset: 0,
                },
                ..Default::default()
            })
            .expect("list accounts");

        assert_eq!(result.accounts.len(), 1);
        assert_eq!(result.accounts[0].id, "acct-1");
        assert_eq!(result.page.limit, 1);
        assert_eq!(result.page.returned, 1);
        assert_eq!(result.page.total, 1);
        assert!(!result.page.has_more);
    }

    #[test]
    fn list_clients_reports_has_more_when_page_is_truncated() {
        let service = service();

        let result = service
            .list_clients(ListClientsCommand {
                page: PageRequest {
                    limit: 1,
                    offset: 0,
                },
                ..Default::default()
            })
            .expect("list clients");

        assert_eq!(result.clients.len(), 1);
        assert_eq!(result.page.limit, 1);
        assert_eq!(result.page.returned, 1);
        assert_eq!(result.page.total, 2);
        assert!(result.page.has_more);
    }
}

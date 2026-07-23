use std::time::Duration;

use crate::{
    finalize_page, AccountDeviceBinding, AccountDeviceBindingStatus, AccountDeviceBindingStore,
    AccountStore, BindDeviceToAccountCommand, BindDeviceToAccountResult, ClientStore,
    CompleteDeviceRegistrationCommand, CompleteDeviceRegistrationResult, DeviceConfig,
    DeviceHeartbeatCommand, DeviceHeartbeatResult, DeviceListQuery, DeviceNonceRecord,
    DeviceNonceStore, DeviceProofError, DeviceProofVerifier, DeviceRecord, DeviceService,
    DeviceStatus, DeviceStore, DisableDeviceCommand, DisableDeviceResult, GetDeviceCommand,
    GetDeviceResult, IdGenerator, ListDevicesCommand, ListDevicesResult, OidcClient,
    ProvisionDeviceCommand, ProvisionDeviceResult, RevokeDeviceCommand, RevokeDeviceResult,
    StoreError, StoreTransactionRunner, UnbindDeviceFromAccountCommand,
    UnbindDeviceFromAccountResult,
};

use super::auth_support::{map_account_status_conflict, require_active_account_status};
use super::{auth, ServiceError};

pub struct CoreDeviceService<S, P, I> {
    config: DeviceConfig,
    store_runner: S,
    proof_verifier: P,
    id_generator: I,
}

impl<S, P, I> CoreDeviceService<S, P, I> {
    pub fn new(config: DeviceConfig, store_runner: S, proof_verifier: P, id_generator: I) -> Self {
        Self {
            config,
            store_runner,
            proof_verifier,
            id_generator,
        }
    }
}

impl<S, P, I> DeviceService for CoreDeviceService<S, P, I>
where
    S: StoreTransactionRunner + Send + Sync,
    P: DeviceProofVerifier + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn provision_device(
        &self,
        command: ProvisionDeviceCommand,
    ) -> Result<ProvisionDeviceResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let client = resolve_client(tx, &command.client_id)?;
                let device = tx.insert_device(DeviceRecord {
                    id: self.id_generator.next_id("dev"),
                    client_id: client.client_id,
                    device_name: command.device_name,
                    proof_key_id: None,
                    status: DeviceStatus::Pending,
                    registered_at: command.requested_at,
                    last_seen_at: None,
                })?;
                let nonce = tx.insert_device_nonce(DeviceNonceRecord {
                    id: self.id_generator.next_id("dnonce"),
                    device_id: device.id.clone(),
                    challenge: self.id_generator.next_id("dchallenge"),
                    issued_at: command.requested_at,
                    expires_at: command.requested_at
                        + Duration::from_secs(self.config.nonce_ttl_secs),
                    consumed_at: None,
                })?;

                Ok(ProvisionDeviceResult { device, nonce })
            })
            .map_err(map_store_error)
    }

    fn complete_device_registration(
        &self,
        command: CompleteDeviceRegistrationCommand,
    ) -> Result<CompleteDeviceRegistrationResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        let allowed_skew_secs = self.config.proof_clock_skew_secs;

        self.store_runner
            .transaction(|tx| {
                let mut device = tx
                    .find_device(&command.device_id)?
                    .ok_or(StoreError::NotFound("device.id"))?;
                ensure_device_is_pending(&device)?;
                ensure_proof_key_available(tx, &command.proof.key_id, Some(&device.id))?;

                let nonce = tx
                    .find_device_nonce(&command.proof.challenge)?
                    .ok_or(StoreError::Conflict("device.challenge"))?;
                ensure_nonce_matches_device(&nonce, &device, command.completed_at)?;

                self.proof_verifier
                    .verify(&command.proof, command.completed_at, allowed_skew_secs)
                    .map_err(StoreError::from_device_proof)?;
                tx.consume_device_nonce(&command.proof.challenge, command.completed_at)?
                    .ok_or(StoreError::Conflict("device.challenge"))?;

                device.proof_key_id = Some(command.proof.key_id);
                device.status = DeviceStatus::Active;
                device.last_seen_at = Some(command.completed_at);
                let device = tx.update_device(device)?;

                Ok(CompleteDeviceRegistrationResult { device })
            })
            .map_err(map_store_error)
    }

    fn bind_device_to_account(
        &self,
        command: BindDeviceToAccountCommand,
    ) -> Result<BindDeviceToAccountResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let account = tx
                    .find_account(&command.account_id)?
                    .ok_or(StoreError::NotFound("account.id"))?;
                require_active_account_status(&account.status)?;

                let device = tx
                    .find_device(&command.device_id)?
                    .ok_or(StoreError::NotFound("device.id"))?;
                ensure_device_is_active(&device)?;

                if let Some(binding) =
                    tx.find_active_account_device_binding(&command.account_id, &command.device_id)?
                {
                    return Ok(BindDeviceToAccountResult { binding });
                }

                let binding = tx.insert_account_device_binding(AccountDeviceBinding {
                    id: self.id_generator.next_id("dbind"),
                    account_id: command.account_id,
                    device_id: command.device_id,
                    status: AccountDeviceBindingStatus::Active,
                    bound_at: command.bound_at,
                    unbound_at: None,
                    last_authenticated_at: Some(command.bound_at),
                })?;

                Ok(BindDeviceToAccountResult { binding })
            })
            .map_err(map_store_error)
    }

    fn get_device(&self, command: GetDeviceCommand) -> Result<GetDeviceResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let device = tx
                    .find_device(&command.device_id)?
                    .ok_or(StoreError::NotFound("device.id"))?;
                let bindings = tx.list_account_device_bindings_by_device(&command.device_id)?;

                Ok(GetDeviceResult { device, bindings })
            })
            .map_err(map_store_error)
    }

    fn list_devices(&self, command: ListDevicesCommand) -> Result<ListDevicesResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;
        let query = DeviceListQuery {
            account_id: command.account_id,
            client_id: command.client_id,
            status: command.status,
            registered_after: command.registered_after,
            registered_before: command.registered_before,
            cursor: command.cursor,
            page: command.page,
        };

        self.store_runner
            .transaction(|tx| {
                let total = tx.count_devices_by_query(&query)?;
                let (devices, page) =
                    finalize_page(tx.list_devices_by_query(&query)?, query.page, total);

                Ok(ListDevicesResult { devices, page })
            })
            .map_err(map_store_error)
    }

    fn unbind_device_from_account(
        &self,
        command: UnbindDeviceFromAccountCommand,
    ) -> Result<UnbindDeviceFromAccountResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let mut binding = tx
                    .find_active_account_device_binding(&command.account_id, &command.device_id)?
                    .ok_or(StoreError::NotFound("account_device_binding.active"))?;

                binding.status = AccountDeviceBindingStatus::Unbound;
                binding.unbound_at = Some(command.unbound_at);
                let binding = tx.update_account_device_binding(binding)?;

                Ok(UnbindDeviceFromAccountResult { binding })
            })
            .map_err(map_store_error)
    }

    fn disable_device(
        &self,
        command: DisableDeviceCommand,
    ) -> Result<DisableDeviceResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let mut device = tx
                    .find_device(&command.device_id)?
                    .ok_or(StoreError::NotFound("device.id"))?;

                if device.status == DeviceStatus::Revoked {
                    return Err(StoreError::Conflict("device.status"));
                }

                device.status = DeviceStatus::Disabled;
                let device = tx.update_device(device)?;

                Ok(DisableDeviceResult { device })
            })
            .map_err(map_store_error)
    }

    fn revoke_device(
        &self,
        command: RevokeDeviceCommand,
    ) -> Result<RevokeDeviceResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let mut device = tx
                    .find_device(&command.device_id)?
                    .ok_or(StoreError::NotFound("device.id"))?;

                device.status = DeviceStatus::Revoked;
                let device = tx.update_device(device)?;

                Ok(RevokeDeviceResult { device })
            })
            .map_err(map_store_error)
    }

    fn heartbeat(
        &self,
        command: DeviceHeartbeatCommand,
    ) -> Result<DeviceHeartbeatResult, ServiceError> {
        command.validate().map_err(ServiceError::InvalidContract)?;

        self.store_runner
            .transaction(|tx| {
                let mut device = tx
                    .find_device(&command.device_id)?
                    .ok_or(StoreError::NotFound("device.id"))?;
                ensure_device_is_active(&device)?;

                device.last_seen_at = Some(command.observed_at);
                let device = tx.update_device(device)?;

                Ok(DeviceHeartbeatResult { device })
            })
            .map_err(map_store_error)
    }
}

fn resolve_client(store: &mut impl ClientStore, client_id: &str) -> Result<OidcClient, StoreError> {
    let client = store
        .find_client(client_id)?
        .ok_or(StoreError::NotFound("oidc_client.id"))?;
    client
        .validate()
        .map_err(|error| StoreError::Backend(format!("invalid client config: {error:?}")))?;
    Ok(client)
}

fn ensure_device_is_pending(device: &DeviceRecord) -> Result<(), StoreError> {
    match device.status {
        DeviceStatus::Pending => Ok(()),
        DeviceStatus::Disabled | DeviceStatus::Revoked => {
            Err(StoreError::Conflict("device.status"))
        }
        DeviceStatus::Active => Err(StoreError::Conflict("device.registration_state")),
    }
}

fn ensure_device_is_active(device: &DeviceRecord) -> Result<(), StoreError> {
    match device.status {
        DeviceStatus::Active => Ok(()),
        DeviceStatus::Disabled | DeviceStatus::Revoked => {
            Err(StoreError::Conflict("device.status"))
        }
        DeviceStatus::Pending => Err(StoreError::Conflict("device.registration_state")),
    }
}

fn ensure_nonce_matches_device(
    nonce: &DeviceNonceRecord,
    device: &DeviceRecord,
    observed_at: std::time::SystemTime,
) -> Result<(), StoreError> {
    if nonce.device_id != device.id
        || nonce.consumed_at.is_some()
        || nonce.expires_at <= observed_at
    {
        return Err(StoreError::Conflict("device.challenge"));
    }

    Ok(())
}

fn ensure_proof_key_available(
    store: &mut impl DeviceStore,
    proof_key_id: &str,
    device_id: Option<&str>,
) -> Result<(), StoreError> {
    let Some(existing) = store.find_device_by_proof_key_id(proof_key_id)? else {
        return Ok(());
    };

    if device_id.is_some_and(|device_id| existing.id == device_id) {
        return Ok(());
    }

    Err(StoreError::Conflict("device.proof_key_id"))
}

fn map_store_error(error: StoreError) -> ServiceError {
    if let Some(error) = map_account_status_conflict(&error) {
        return error;
    }

    match error {
        StoreError::NotFound("account.id") => ServiceError::AccountNotFound,
        StoreError::NotFound("oidc_client.id") => ServiceError::ClientNotFound,
        StoreError::NotFound("device.id") => ServiceError::DeviceNotFound,
        StoreError::NotFound("account_device_binding.active") => {
            ServiceError::DeviceBindingNotFound
        }
        StoreError::Conflict("device.status") => ServiceError::DeviceDisabled,
        StoreError::Conflict("device.challenge") => ServiceError::InvalidDeviceChallenge,
        StoreError::Conflict("device.registration_state")
        | StoreError::Conflict("device.proof_key_id") => {
            ServiceError::DeviceRegistrationStateInvalid
        }
        StoreError::Backend(message) if message.starts_with("invalid client config:") => {
            ServiceError::InvalidClientConfig(auth::parse_client_error(&message))
        }
        StoreError::Backend(message) if message.starts_with("device_proof:") => {
            ServiceError::DeviceProofRejected(parse_device_proof_error(&message))
        }
        other => ServiceError::Store(other),
    }
}

fn parse_device_proof_error(message: &str) -> DeviceProofError {
    if message.contains("MissingKeyId") {
        return DeviceProofError::MissingKeyId;
    }
    if message.contains("MissingChallenge") {
        return DeviceProofError::MissingChallenge;
    }
    if message.contains("MissingSignature") {
        return DeviceProofError::MissingSignature;
    }
    if message.contains("ProofExpired") {
        return DeviceProofError::ProofExpired;
    }
    DeviceProofError::VerifierRejected
}

impl StoreError {
    fn from_device_proof(error: DeviceProofError) -> Self {
        StoreError::Backend(format!("device_proof:{error:?}"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};
    use std::time::SystemTime;

    use super::*;
    use crate::{
        Account, AccountStore, AuthSession, AuthorizationCodeRecord, AuthorizationCodeStore,
        ClientStore, DeviceNonceStore, DeviceProof, EmailVerificationCode, EmailVerificationStore,
        OidcClientType, RefreshTokenRecord, RefreshTokenStore, SessionStore,
    };

    struct TestIds;
    impl IdGenerator for TestIds {
        fn next_id(&self, prefix: &str) -> String {
            format!("{prefix}-1")
        }
    }

    struct TestVerifier;
    impl DeviceProofVerifier for TestVerifier {
        fn verify(
            &self,
            proof: &DeviceProof,
            _observed_at: SystemTime,
            _allowed_skew_secs: u64,
        ) -> Result<(), DeviceProofError> {
            if proof.signature == "reject" {
                return Err(DeviceProofError::VerifierRejected);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestStoreState {
        accounts: HashMap<String, Account>,
        devices: HashMap<String, DeviceRecord>,
        bindings: HashMap<String, AccountDeviceBinding>,
        nonces: HashMap<String, DeviceNonceRecord>,
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
                state: self.state.lock().unwrap(),
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
            _query: &crate::AccountListQuery,
        ) -> Result<Vec<Account>, StoreError> {
            self.list_accounts()
        }

        fn count_accounts_by_query(
            &mut self,
            _query: &crate::AccountListQuery,
        ) -> Result<u64, StoreError> {
            Ok(self.state.accounts.len() as u64)
        }

        fn find_by_email(&mut self, _email: &str) -> Result<Option<Account>, StoreError> {
            Ok(None)
        }

        fn insert_account(&mut self, _account: Account) -> Result<Account, StoreError> {
            unreachable!("not needed in device service tests")
        }

        fn update_account(&mut self, _account: Account) -> Result<Account, StoreError> {
            unreachable!("not needed in device service tests")
        }
    }

    impl SessionStore for TestStoreTx<'_> {
        fn find_session(&mut self, _session_id: &str) -> Result<Option<AuthSession>, StoreError> {
            Ok(None)
        }

        fn list_sessions(
            &mut self,
            _account_id: Option<&str>,
        ) -> Result<Vec<AuthSession>, StoreError> {
            Ok(Vec::new())
        }

        fn list_sessions_by_query(
            &mut self,
            _query: &crate::SessionListQuery,
        ) -> Result<Vec<AuthSession>, StoreError> {
            Ok(Vec::new())
        }

        fn count_sessions_by_query(
            &mut self,
            _query: &crate::SessionListQuery,
        ) -> Result<u64, StoreError> {
            Ok(0)
        }

        fn insert_session(&mut self, _session: AuthSession) -> Result<AuthSession, StoreError> {
            unreachable!("not needed in device service tests")
        }

        fn update_session(&mut self, _session: AuthSession) -> Result<AuthSession, StoreError> {
            unreachable!("not needed in device service tests")
        }
    }

    impl DeviceStore for TestStoreTx<'_> {
        fn find_device(&mut self, device_id: &str) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(self.state.devices.get(device_id).cloned())
        }

        fn list_devices(&mut self) -> Result<Vec<DeviceRecord>, StoreError> {
            Ok(self.state.devices.values().cloned().collect())
        }

        fn list_devices_by_query(
            &mut self,
            query: &crate::DeviceListQuery,
        ) -> Result<Vec<DeviceRecord>, StoreError> {
            let mut devices: Vec<_> = self
                .state
                .devices
                .values()
                .filter(|device| {
                    query.account_id.as_deref().is_none_or(|account_id| {
                        self.state.bindings.values().any(|binding| {
                            binding.account_id == account_id
                                && binding.device_id == device.id
                                && binding.status == AccountDeviceBindingStatus::Active
                        })
                    })
                })
                .filter(|device| {
                    query
                        .client_id
                        .as_deref()
                        .is_none_or(|client_id| device.client_id == client_id)
                })
                .filter(|device| {
                    query
                        .status
                        .as_ref()
                        .is_none_or(|status| &device.status == status)
                })
                .filter(|device| {
                    query
                        .registered_after
                        .is_none_or(|after| device.registered_at >= after)
                })
                .filter(|device| {
                    query
                        .registered_before
                        .is_none_or(|before| device.registered_at <= before)
                })
                .cloned()
                .collect();
            devices.sort_by(|left, right| {
                right
                    .registered_at
                    .cmp(&left.registered_at)
                    .then_with(|| left.id.cmp(&right.id))
            });
            if query.page.offset as usize >= devices.len() {
                return Ok(Vec::new());
            }
            devices.drain(0..query.page.offset as usize);
            devices.truncate(query.page.limit as usize);
            Ok(devices)
        }

        fn count_devices_by_query(
            &mut self,
            query: &crate::DeviceListQuery,
        ) -> Result<u64, StoreError> {
            Ok(self
                .state
                .devices
                .values()
                .filter(|device| {
                    query.account_id.as_deref().is_none_or(|account_id| {
                        self.state.bindings.values().any(|binding| {
                            binding.account_id == account_id
                                && binding.device_id == device.id
                                && binding.status == AccountDeviceBindingStatus::Active
                        })
                    })
                })
                .filter(|device| {
                    query
                        .client_id
                        .as_deref()
                        .is_none_or(|client_id| device.client_id == client_id)
                })
                .filter(|device| {
                    query
                        .status
                        .as_ref()
                        .is_none_or(|status| &device.status == status)
                })
                .filter(|device| {
                    query
                        .registered_after
                        .is_none_or(|after| device.registered_at >= after)
                })
                .filter(|device| {
                    query
                        .registered_before
                        .is_none_or(|before| device.registered_at <= before)
                })
                .count() as u64)
        }

        fn find_device_by_proof_key_id(
            &mut self,
            proof_key_id: &str,
        ) -> Result<Option<DeviceRecord>, StoreError> {
            Ok(self
                .state
                .devices
                .values()
                .find(|device| device.proof_key_id.as_deref() == Some(proof_key_id))
                .cloned())
        }

        fn insert_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            self.state.devices.insert(device.id.clone(), device.clone());
            Ok(device)
        }

        fn update_device(&mut self, device: DeviceRecord) -> Result<DeviceRecord, StoreError> {
            self.state.devices.insert(device.id.clone(), device.clone());
            Ok(device)
        }
    }

    impl crate::AccountDeviceBindingStore for TestStoreTx<'_> {
        fn find_active_account_device_binding(
            &mut self,
            account_id: &str,
            device_id: &str,
        ) -> Result<Option<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .values()
                .find(|binding| {
                    binding.account_id == account_id
                        && binding.device_id == device_id
                        && binding.status == AccountDeviceBindingStatus::Active
                })
                .cloned())
        }

        fn list_account_device_bindings_by_device(
            &mut self,
            device_id: &str,
        ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .values()
                .filter(|binding| binding.device_id == device_id)
                .cloned()
                .collect())
        }

        fn list_active_account_device_bindings_by_account(
            &mut self,
            account_id: &str,
        ) -> Result<Vec<AccountDeviceBinding>, StoreError> {
            Ok(self
                .state
                .bindings
                .values()
                .filter(|binding| {
                    binding.account_id == account_id
                        && binding.status == AccountDeviceBindingStatus::Active
                })
                .cloned()
                .collect())
        }

        fn insert_account_device_binding(
            &mut self,
            binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            self.state
                .bindings
                .insert(binding.id.clone(), binding.clone());
            Ok(binding)
        }

        fn update_account_device_binding(
            &mut self,
            binding: AccountDeviceBinding,
        ) -> Result<AccountDeviceBinding, StoreError> {
            self.state
                .bindings
                .insert(binding.id.clone(), binding.clone());
            Ok(binding)
        }
    }

    impl DeviceNonceStore for TestStoreTx<'_> {
        fn find_device_nonce(
            &mut self,
            challenge: &str,
        ) -> Result<Option<DeviceNonceRecord>, StoreError> {
            Ok(self.state.nonces.get(challenge).cloned())
        }

        fn insert_device_nonce(
            &mut self,
            nonce: DeviceNonceRecord,
        ) -> Result<DeviceNonceRecord, StoreError> {
            self.state
                .nonces
                .insert(nonce.challenge.clone(), nonce.clone());
            Ok(nonce)
        }

        fn consume_device_nonce(
            &mut self,
            challenge: &str,
            consumed_at: SystemTime,
        ) -> Result<Option<DeviceNonceRecord>, StoreError> {
            let Some(nonce) = self.state.nonces.get_mut(challenge) else {
                return Ok(None);
            };
            if nonce.consumed_at.is_some() {
                return Ok(None);
            }
            nonce.consumed_at = Some(consumed_at);
            Ok(Some(nonce.clone()))
        }
    }

    impl ClientStore for TestStoreTx<'_> {
        fn find_client(&mut self, client_id: &str) -> Result<Option<OidcClient>, StoreError> {
            Ok(Some(OidcClient {
                client_id: client_id.to_string(),
                client_name: "Desktop".to_string(),
                redirect_uris: vec!["http://127.0.0.1:8080/callback".to_string()],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret_hash: None,
            }))
        }

        fn list_clients(&mut self) -> Result<Vec<OidcClient>, StoreError> {
            Ok(vec![OidcClient {
                client_id: "desktop-app".to_string(),
                client_name: "Desktop".to_string(),
                redirect_uris: vec!["http://127.0.0.1:8080/callback".to_string()],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret_hash: None,
            }])
        }

        fn list_clients_by_query(
            &mut self,
            _query: &crate::ClientListQuery,
        ) -> Result<Vec<OidcClient>, StoreError> {
            self.list_clients()
        }

        fn count_clients_by_query(
            &mut self,
            _query: &crate::ClientListQuery,
        ) -> Result<u64, StoreError> {
            Ok(1)
        }

        fn upsert_client(&mut self, client: OidcClient) -> Result<OidcClient, StoreError> {
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
            unreachable!("not needed in device service tests")
        }

        fn consume_authorization_code(
            &mut self,
            _code: &str,
            _consumed_at: SystemTime,
        ) -> Result<Option<AuthorizationCodeRecord>, StoreError> {
            unreachable!("not needed in device service tests")
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

    impl RefreshTokenStore for TestStoreTx<'_> {
        fn find_refresh_token(
            &mut self,
            _token_value: &str,
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(None)
        }

        fn insert_refresh_token(
            &mut self,
            _token: RefreshTokenRecord,
        ) -> Result<RefreshTokenRecord, StoreError> {
            unreachable!("not needed in device service tests")
        }

        fn revoke_refresh_token(
            &mut self,
            _token_value: &str,
            _revoked_at: SystemTime,
        ) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(None)
        }

        fn revoke_refresh_tokens_for_session(
            &mut self,
            _session_id: &str,
            _revoked_at: SystemTime,
        ) -> Result<Vec<RefreshTokenRecord>, StoreError> {
            Ok(Vec::new())
        }
    }

    fn service() -> CoreDeviceService<TestStoreRunner, TestVerifier, TestIds> {
        let runner = TestStoreRunner::default();
        runner.state.lock().unwrap().accounts.insert(
            "acct-1".to_string(),
            Account {
                id: "acct-1".to_string(),
                email: "user@example.com".to_string(),
                password_hash: "$argon2id$demo".to_string(),
                display_name: Some("User".to_string()),
                status: crate::AccountStatus::Active,
                created_at: SystemTime::UNIX_EPOCH,
            },
        );

        CoreDeviceService::new(
            DeviceConfig {
                nonce_ttl_secs: 300,
                proof_clock_skew_secs: 30,
                heartbeat_grace_period_secs: 60,
            },
            runner,
            TestVerifier,
            TestIds,
        )
    }

    #[test]
    fn provision_device_creates_pending_device_and_nonce() {
        let service = service();

        let result = service
            .provision_device(ProvisionDeviceCommand {
                client_id: "desktop-app".to_string(),
                device_name: "Shared Kiosk".to_string(),
                requested_at: SystemTime::UNIX_EPOCH,
            })
            .expect("provision should succeed");

        assert_eq!(result.device.status, DeviceStatus::Pending);
        assert_eq!(result.device.proof_key_id, None);
        assert_eq!(result.nonce.device_id, result.device.id);
    }

    #[test]
    fn complete_device_registration_consumes_challenge_and_activates_device() {
        let service = service();
        let provisioned = service
            .provision_device(ProvisionDeviceCommand {
                client_id: "desktop-app".to_string(),
                device_name: "Shared Kiosk".to_string(),
                requested_at: SystemTime::UNIX_EPOCH,
            })
            .expect("provision should succeed");

        let result = service
            .complete_device_registration(CompleteDeviceRegistrationCommand {
                device_id: provisioned.device.id,
                proof: DeviceProof {
                    key_id: "key-1".to_string(),
                    challenge: provisioned.nonce.challenge,
                    signature: "ok".to_string(),
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                completed_at: SystemTime::UNIX_EPOCH,
            })
            .expect("completion should succeed");

        assert_eq!(result.device.status, DeviceStatus::Active);
        assert_eq!(result.device.proof_key_id.as_deref(), Some("key-1"));
    }

    #[test]
    fn bind_device_to_account_creates_binding_for_active_device() {
        let service = service();
        let registered = complete_device(&service);

        let result = service
            .bind_device_to_account(BindDeviceToAccountCommand {
                account_id: "acct-1".to_string(),
                device_id: registered.id,
                bound_at: SystemTime::UNIX_EPOCH,
            })
            .expect("binding should succeed");

        assert_eq!(result.binding.account_id, "acct-1");
        assert_eq!(result.binding.status, AccountDeviceBindingStatus::Active);
    }

    #[test]
    fn heartbeat_updates_last_seen_for_active_device() {
        let service = service();
        let registered = complete_device(&service);

        let heartbeat = service
            .heartbeat(DeviceHeartbeatCommand {
                device_id: registered.id,
                observed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            })
            .expect("heartbeat should succeed");

        assert_eq!(
            heartbeat.device.last_seen_at,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10))
        );
    }

    #[test]
    fn get_and_list_devices_return_registered_records() {
        let service = service();
        let registered = complete_and_bind_device(&service);

        let fetched = service
            .get_device(GetDeviceCommand {
                device_id: registered.id.clone(),
            })
            .expect("get should succeed");
        assert_eq!(fetched.device.id, registered.id);
        assert_eq!(fetched.bindings.len(), 1);

        let listed = service
            .list_devices(ListDevicesCommand {
                account_id: Some("acct-1".to_string()),
                ..Default::default()
            })
            .expect("list should succeed");
        assert_eq!(listed.devices.len(), 1);
        assert_eq!(listed.devices[0].id, registered.id);
    }

    #[test]
    fn unbind_disable_and_revoke_update_management_state() {
        let service = service();
        let registered = complete_and_bind_device(&service);

        let unbound = service
            .unbind_device_from_account(UnbindDeviceFromAccountCommand {
                account_id: "acct-1".to_string(),
                device_id: registered.id.clone(),
                unbound_at: SystemTime::UNIX_EPOCH,
            })
            .expect("unbind should succeed");
        assert_eq!(unbound.binding.status, AccountDeviceBindingStatus::Unbound);

        let disabled = service
            .disable_device(DisableDeviceCommand {
                device_id: registered.id.clone(),
            })
            .expect("disable should succeed");
        assert_eq!(disabled.device.status, DeviceStatus::Disabled);

        let revoked = service
            .revoke_device(RevokeDeviceCommand {
                device_id: registered.id,
            })
            .expect("revoke should succeed");
        assert_eq!(revoked.device.status, DeviceStatus::Revoked);
    }

    #[test]
    fn complete_device_registration_rejects_invalid_nonce() {
        let service = service();
        let provisioned = service
            .provision_device(ProvisionDeviceCommand {
                client_id: "desktop-app".to_string(),
                device_name: "Shared Kiosk".to_string(),
                requested_at: SystemTime::UNIX_EPOCH,
            })
            .expect("provision should succeed");

        let error = service
            .complete_device_registration(CompleteDeviceRegistrationCommand {
                device_id: provisioned.device.id,
                proof: DeviceProof {
                    key_id: "key-1".to_string(),
                    challenge: "wrong-challenge".to_string(),
                    signature: "ok".to_string(),
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                completed_at: SystemTime::UNIX_EPOCH,
            })
            .expect_err("completion should fail");

        assert_eq!(error, ServiceError::InvalidDeviceChallenge);
    }

    #[test]
    fn register_device_rejects_invalid_proof() {
        let service = service();
        let provisioned = service
            .provision_device(ProvisionDeviceCommand {
                client_id: "desktop-app".to_string(),
                device_name: "MacBook".to_string(),
                requested_at: SystemTime::UNIX_EPOCH,
            })
            .expect("provision should succeed");

        let error = service
            .complete_device_registration(CompleteDeviceRegistrationCommand {
                device_id: provisioned.device.id,
                proof: DeviceProof {
                    key_id: "key-1".to_string(),
                    challenge: provisioned.nonce.challenge,
                    signature: "reject".to_string(),
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                completed_at: SystemTime::UNIX_EPOCH,
            })
            .expect_err("register should reject invalid proof");

        assert_eq!(
            error,
            ServiceError::DeviceProofRejected(DeviceProofError::VerifierRejected)
        );
    }

    fn complete_device(
        service: &CoreDeviceService<TestStoreRunner, TestVerifier, TestIds>,
    ) -> DeviceRecord {
        let provisioned = service
            .provision_device(ProvisionDeviceCommand {
                client_id: "desktop-app".to_string(),
                device_name: "MacBook".to_string(),
                requested_at: SystemTime::UNIX_EPOCH,
            })
            .expect("provision should succeed");

        service
            .complete_device_registration(CompleteDeviceRegistrationCommand {
                device_id: provisioned.device.id,
                proof: DeviceProof {
                    key_id: "key-1".to_string(),
                    challenge: provisioned.nonce.challenge,
                    signature: "ok".to_string(),
                    signed_at: SystemTime::UNIX_EPOCH,
                },
                completed_at: SystemTime::UNIX_EPOCH,
            })
            .expect("completion should succeed")
            .device
    }

    fn complete_and_bind_device(
        service: &CoreDeviceService<TestStoreRunner, TestVerifier, TestIds>,
    ) -> DeviceRecord {
        let device = complete_device(service);
        service
            .bind_device_to_account(BindDeviceToAccountCommand {
                account_id: "acct-1".to_string(),
                device_id: device.id.clone(),
                bound_at: SystemTime::UNIX_EPOCH,
            })
            .expect("binding should succeed");
        device
    }
}

use super::*;

pub const TENANT_DEVICE_HEARTBEAT_PURPOSE: &str = "heartbeat";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSubjectDevice {
    pub device: TenantProofDevice,
    pub binding_id: String,
    pub binding_version: u64,
    pub name: String,
    pub registered_at: SystemTime,
    pub last_seen_at: Option<SystemTime>,
    pub binding_status: AccountDeviceBindingStatus,
}
pub trait TenantDeviceManagementTransaction: TenantDeviceLifecycleTransaction {
    fn self_device_operation(
        &mut self,
        actor: &AccessActor,
        operation_id: &str,
    ) -> Result<Option<([u8; 32], DeviceOperationReceipt)>, StoreError>;
    fn append_self_unbind_audit(
        &mut self,
        actor: &AccessActor,
        receipt: &DeviceOperationReceipt,
        digest: &[u8; 32],
        request_id: &str,
    ) -> Result<(), StoreError>;
    /// Bounded, ordered by device ID; only this account's non-unbound bindings.
    fn subject_devices(
        &mut self,
        actor: &AccessActor,
        client: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<TenantSubjectDevice>, StoreError>;
    fn subject_device(
        &mut self,
        actor: &AccessActor,
        client: &str,
        device: &str,
    ) -> Result<Option<TenantSubjectDevice>, StoreError>;
    fn record_heartbeat(
        &mut self,
        tenant: &str,
        device: &str,
        now: SystemTime,
    ) -> Result<(), StoreError>;
    /// Only this account/device in this tenant. Revoke every associated session
    /// and refresh credential atomically; never change the device's other users.
    fn unbind_subject_device(
        &mut self,
        actor: &AccessActor,
        device: &str,
        binding_id: &str,
        expected_version: u64,
        now: SystemTime,
    ) -> Result<(), StoreError>;
}
impl<S, J, V, G, C, I> CoreTenantDeviceProofService<S, J, V, G, C, I>
where
    S: TenantAuthStore,
    for<'a> S::Transaction<'a>: TenantDeviceManagementTransaction,
    J: DevicePublicJwkValidator,
    V: DeviceSignatureVerifier,
    G: DeviceChallengeGenerator,
    C: Clock,
    I: IdGenerator,
{
    pub fn list_subject_devices(
        &self,
        actor: AccessActor,
        page: AccessPageRequest,
    ) -> Result<AccessPage<TenantSubjectDevice>, TenantAuthError> {
        self.mode.validate_business_tenant(&actor.tenant_id)?;
        let scope = AccessListScope::SubjectDevices {
            tenant_id: actor.tenant_id.clone(),
            subject_id: actor.subject_id.clone(),
            client_id: self.config.client_id.clone(),
        };
        page.validate(&scope)?;
        if page.cursor.as_ref().is_some_and(|c| {
            uuid::Uuid::parse_str(&c.after[0]).map_or(true, |id| id.to_string() != c.after[0])
        }) {
            return Err(AccessError::InvalidCursor.into());
        }

        self.store.auth_transaction(self.mode, |tx| {
            self.lock_actor(tx, &actor)?;
            let rows = tx.subject_devices(&actor, &self.config.client_id, &page)?;
            for row in &rows {
                self.check_subject_device(&actor, row)?;
            }
            Ok(super::super::service::finish_page(
                rows,
                page,
                scope,
                |r| vec![r.device.id.clone()],
            )?)
        })
    }
    pub fn get_subject_device(
        &self,
        actor: AccessActor,
        device: &str,
    ) -> Result<TenantSubjectDevice, TenantAuthError> {
        self.mode.validate_business_tenant(&actor.tenant_id)?;
        super::super::query::validate_id(device, 128, "device_id")?;
        self.store.auth_transaction(self.mode, |tx| {
            self.lock_actor(tx, &actor)?;
            let row = tx
                .subject_device(&actor, &self.config.client_id, device)?
                .ok_or(AccessError::Forbidden)?;
            self.check_subject_device(&actor, &row)?;
            if row.device.id != device {
                return Err(AccessError::InvalidStoreResponse.into());
            }
            Ok(row)
        })
    }
    pub fn subject_device_key_metadata(
        &self,
        actor: AccessActor,
        device: &str,
        key: &str,
    ) -> Result<DeviceKeyMetadata, TenantAuthError> {
        self.mode.validate_business_tenant(&actor.tenant_id)?;
        super::super::query::validate_id(device, 128, "device_id")?;
        super::super::query::validate_id(key, 128, "key_id")?;
        self.store.auth_transaction(self.mode, |tx| {
            self.lock_actor(tx, &actor)?;
            let row = tx
                .subject_device(&actor, &self.config.client_id, device)?
                .ok_or(AccessError::Forbidden)?;
            self.check_subject_device(&actor, &row)?;
            if row.device.status != DeviceStatus::Active
                || row.binding_status != AccountDeviceBindingStatus::Active
            {
                return Err(AccessError::Forbidden.into());
            }
            let current_id = row
                .device
                .proof_key_id
                .as_deref()
                .ok_or(AccessError::Forbidden)?;
            let current = tx
                .key_metadata(&actor.tenant_id, device, current_id)?
                .ok_or(AccessError::Forbidden)?;
            if current.status != DeviceProofKeyStatus::Active || current.device_id != device {
                return Err(AccessError::Forbidden.into());
            }
            let metadata = tx
                .key_metadata(&actor.tenant_id, device, key)?
                .ok_or(AccessError::NotFound("device_key"))?;
            if metadata.tenant_id != actor.tenant_id
                || metadata.device_id != device
                || metadata.key_id != key
            {
                return Err(AccessError::InvalidStoreResponse.into());
            }
            Ok(metadata)
        })
    }
    pub fn unbind_subject_device(
        &self,
        actor: AccessActor,
        device: &str,
        binding_id: &str,
        expected_version: u64,
        operation_id: &str,
    ) -> Result<DeviceOperationReceipt, TenantAuthError> {
        self.mode.validate_business_tenant(&actor.tenant_id)?;
        super::super::query::validate_id(device, 128, "device_id")?;
        if uuid::Uuid::parse_str(binding_id).map_or(true, |id| id.to_string() != binding_id) {
            return Err(AccessError::InvalidInput("binding_id").into());
        }
        if expected_version == 0 || i64::try_from(expected_version).is_err() {
            return Err(AccessError::InvalidInput("expected_version").into());
        }
        validate_device_operation_id(operation_id)?;
        let digest = device_command_digest(
            "device.binding.unbind.self",
            &actor.tenant_id,
            device,
            Some(binding_id),
            Some(&actor.subject_id),
            expected_version,
            "self_service",
        );
        self.store.auth_transaction(self.mode, |tx| {
            self.lock_actor(tx, &actor)?;
            if let Some((stored_digest, receipt)) =
                tx.self_device_operation(&actor, operation_id)?
            {
                if stored_digest != digest {
                    return Err(AccessError::Conflict("device_operation_conflict").into());
                }
                return Ok(receipt);
            }
            let row = tx
                .subject_device(&actor, &self.config.client_id, device)?
                .ok_or(AccessError::Forbidden)?;
            self.check_subject_device(&actor, &row)?;
            if row.device.id != device {
                return Err(AccessError::InvalidStoreResponse.into());
            }
            if row.binding_id != binding_id || row.binding_version != expected_version {
                return Err(AccessError::Conflict("device_binding_version").into());
            }
            if row.binding_status != AccountDeviceBindingStatus::Active {
                return Err(AccessError::Forbidden.into());
            }
            let now = self.clock.now();
            tx.unbind_subject_device(&actor, device, binding_id, expected_version, now)
                .map_err(AccessError::from)?;
            let receipt = DeviceOperationReceipt {
                operation_id: operation_id.into(),
                audit_id: self.ids.next_id("audit"),
                device_id: device.into(),
                binding_id: Some(binding_id.into()),
                operation: "device.binding.unbind.self",
                occurred_at: now,
                result_version: expected_version + 1,
                result_status: "unbound".into(),
            };
            tx.append_self_unbind_audit(&actor, &receipt, &digest, &self.ids.next_id("request"))?;
            Ok(receipt)
        })
    }
    pub fn self_device_operation_result(
        &self,
        actor: AccessActor,
        operation_id: &str,
    ) -> Result<DeviceOperationReceipt, TenantAuthError> {
        self.mode.validate_business_tenant(&actor.tenant_id)?;
        validate_device_operation_id(operation_id)?;
        self.store.auth_transaction(self.mode, |tx| {
            self.lock_actor(tx, &actor)?;
            tx.self_device_operation(&actor, operation_id)?
                .map(|(_, receipt)| receipt)
                .ok_or(AccessError::NotFound("device_operation").into())
        })
    }
    pub fn heartbeat(
        &self,
        command: VerifyTenantDeviceRequest,
    ) -> Result<VerifiedDeviceRequest, TenantAuthError> {
        self.mode
            .validate_business_tenant(&command.actor.tenant_id)?;
        let purpose = DeviceProofPurpose::new(TENANT_DEVICE_HEARTBEAT_PURPOSE)
            .map_err(TenantAuthError::Security)?;
        self.require_purpose(&purpose)?;
        if command.expected_purpose != purpose {
            return Err(invalid_proof());
        }
        self.store.auth_transaction(self.mode, |tx| {
            let actor = &command.actor;
            let session = self.lock_actor(tx, actor)?;
            if session
                .device_id
                .as_ref()
                .is_some_and(|d| d != &command.proof.device_id)
            {
                return Err(TenantAuthError::InvalidSession);
            }
            let (verified, _) = self.verify_in_transaction(
                tx,
                &actor.tenant_id,
                &actor.subject_id,
                &purpose,
                &command.proof,
                &command.binding,
                None,
                false,
            )?;
            if session.created_at > verified.verified_at
                || session.expires_at <= verified.verified_at
            {
                return Err(TenantAuthError::InvalidSession);
            }
            tx.record_heartbeat(&actor.tenant_id, &verified.device_id, verified.verified_at)?;
            Ok(verified)
        })
    }
    fn check_subject_device(
        &self,
        actor: &AccessActor,
        row: &TenantSubjectDevice,
    ) -> Result<(), TenantAuthError> {
        if row.device.tenant_id != actor.tenant_id
            || row.device.client_id != self.config.client_id
            || uuid::Uuid::parse_str(&row.binding_id)
                .map_or(true, |id| id.to_string() != row.binding_id)
            || row.binding_version == 0
            || row.binding_status == AccountDeviceBindingStatus::Unbound
        {
            return Err(AccessError::InvalidStoreResponse.into());
        }
        Ok(())
    }
}

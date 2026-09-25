use super::*;

pub const TENANT_DEVICE_HEARTBEAT_PURPOSE: &str = "heartbeat";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSubjectDevice {
    pub device: TenantProofDevice,
    pub name: String,
    pub registered_at: SystemTime,
    pub last_seen_at: Option<SystemTime>,
    pub binding_status: AccountDeviceBindingStatus,
}
pub trait TenantDeviceManagementTransaction: TenantDeviceLifecycleTransaction {
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
    pub fn unbind_subject_device(
        &self,
        actor: AccessActor,
        device: &str,
    ) -> Result<(), TenantAuthError> {
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
            tx.unbind_subject_device(&actor, device, self.clock.now())?;
            Ok(())
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
            || row.binding_status == AccountDeviceBindingStatus::Unbound
        {
            return Err(AccessError::InvalidStoreResponse.into());
        }
        Ok(())
    }
}

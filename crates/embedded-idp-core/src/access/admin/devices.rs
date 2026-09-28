use super::*;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest, TenantProofDevice,
};
use crate::AccountDeviceBindingStatus;

/// Management projection; never includes JWKs, account credentials or bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDeviceRecord {
    pub device: TenantProofDevice,
    pub name: String,
    pub registered_at: SystemTime,
    pub last_seen_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDeviceBindingRecord {
    pub tenant_id: String,
    pub id: String,
    pub device_id: String,
    pub account_id: String,
    pub status: AccountDeviceBindingStatus,
    pub version: u64,
    pub bound_at: SystemTime,
    pub unbound_at: Option<SystemTime>,
    pub last_authenticated_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminDeviceFilter {
    /// Only active account-device bindings in the target tenant match.
    pub account_id: Option<String>,
    pub client_id: Option<String>,
    pub status: Option<DeviceStatus>,
    pub registered_after: Option<SystemTime>,
    pub registered_before: Option<SystemTime>,
}
impl AdminDeviceFilter {
    pub fn validate(&self) -> Result<(), AccessError> {
        for (value, field) in [
            (&self.account_id, "account_id"),
            (&self.client_id, "client_id"),
        ] {
            if let Some(value) = value {
                validate_id(value, 128, field)?;
            }
        }
        validate_created_range(self.registered_after, self.registered_before).map_err(|e| match e {
            AccessError::InvalidInput("created_time_range") => {
                AccessError::InvalidInput("registered_time_range")
            }
            _ => AccessError::InvalidInput("registered_time"),
        })
    }

    /// Checks metadata only; the store must enforce the account-binding predicate.
    pub fn matches_metadata(&self, r: &AccessDeviceRecord) -> bool {
        self.client_id
            .as_ref()
            .is_none_or(|id| id == &r.device.client_id)
            && self
                .status
                .as_ref()
                .is_none_or(|status| status == &r.device.status)
            && self.registered_after.is_none_or(|t| r.registered_at >= t)
            && self.registered_before.is_none_or(|t| r.registered_at <= t)
    }
}

pub trait TenantDeviceAdminService: AccessAdminService {
    fn list_devices(
        &self,
        context: AccessAdminContext,
        tenant: String,
        filter: AdminDeviceFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessDeviceRecord>, AccessError>;
    fn get_device(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
    ) -> Result<AccessDeviceRecord, AccessError>;
    fn get_device_key_metadata(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        key: String,
    ) -> Result<super::super::DeviceKeyMetadata, AccessError>;
    fn get_device_binding(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        binding_id: String,
    ) -> Result<AccessDeviceBindingRecord, AccessError>;
    fn list_device_bindings(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        status: Option<AccountDeviceBindingStatus>,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessDeviceBindingRecord>, AccessError>;
    fn unbind_device_binding(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        binding_id: String,
        expected_version: u64,
        operation_id: String,
        reason: String,
    ) -> Result<AccessAuditEvent, AccessError>;
    fn device_operation_result(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        operation_id: String,
    ) -> Result<super::super::DeviceOperationReceipt, AccessError>;
}

impl<S, C, I> TenantDeviceAdminService for CoreAccessAdminService<S, C, I>
where
    S: AccessAdminStore,
    C: Clock + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn list_devices(
        &self,
        context: AccessAdminContext,
        tenant: String,
        filter: AdminDeviceFilter,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessDeviceRecord>, AccessError> {
        filter.validate()?;
        let scope = AccessListScope::AdminDevices {
            tenant_id: tenant.clone(),
            filter: filter.clone(),
        };
        page.validate(&scope)?;
        if page.cursor.as_ref().is_some_and(|c| {
            uuid::Uuid::parse_str(&c.after[1]).map_or(true, |id| id.to_string() != c.after[1])
        }) {
            return Err(AccessError::InvalidCursor);
        }
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageDevices,
            )?;
            let rows = tx.admin_devices(&tenant, &filter, &page)?;
            if rows
                .iter()
                .any(|r| r.device.tenant_id != tenant || !filter.matches_metadata(r))
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |r| {
                time_page_key(r.registered_at, r.device.id.clone())
            })
        })
    }
    fn get_device(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
    ) -> Result<AccessDeviceRecord, AccessError> {
        validate_id(&device, 128, "device_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageDevices,
            )?;
            let row = tx
                .admin_device(&tenant, &device)?
                .ok_or(AccessError::NotFound("device"))?;
            if row.device.tenant_id != tenant || row.device.id != device {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(row)
        })
    }
    fn get_device_key_metadata(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        key: String,
    ) -> Result<super::super::DeviceKeyMetadata, AccessError> {
        validate_id(&device, 128, "device_id")?;
        validate_id(&key, 128, "key_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageDevices,
            )?;
            if tx.admin_device(&tenant, &device)?.is_none() {
                return Err(AccessError::NotFound("device"));
            }
            let metadata = tx
                .admin_device_key_metadata(&tenant, &device, &key)?
                .ok_or(AccessError::NotFound("device_key"))?;
            if metadata.tenant_id != tenant
                || metadata.device_id != device
                || metadata.key_id != key
            {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(metadata)
        })
    }
    fn get_device_binding(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        binding_id: String,
    ) -> Result<AccessDeviceBindingRecord, AccessError> {
        for (value, field) in [(&device, "device_id"), (&binding_id, "binding_id")] {
            if uuid::Uuid::parse_str(value).map_or(true, |id| id.to_string() != *value) {
                return Err(AccessError::InvalidInput(field));
            }
        }
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageDevices,
            )?;
            let row = tx
                .admin_device_binding(&tenant, &device, &binding_id)?
                .ok_or(AccessError::NotFound("device_binding"))?;
            if row.tenant_id != tenant || row.device_id != device || row.id != binding_id {
                return Err(AccessError::InvalidStoreResponse);
            }
            Ok(row)
        })
    }
    fn list_device_bindings(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        status: Option<AccountDeviceBindingStatus>,
        page: AccessPageRequest,
    ) -> Result<AccessPage<AccessDeviceBindingRecord>, AccessError> {
        if uuid::Uuid::parse_str(&device).map_or(true, |id| id.to_string() != device) {
            return Err(AccessError::InvalidInput("device_id"));
        }
        let scope = AccessListScope::AdminDeviceBindings {
            tenant_id: tenant.clone(),
            device_id: device.clone(),
            status: status.clone(),
        };
        page.validate(&scope)?;
        if page.cursor.as_ref().is_some_and(|c| {
            uuid::Uuid::parse_str(&c.after[1]).map_or(true, |id| id.to_string() != c.after[1])
        }) {
            return Err(AccessError::InvalidCursor);
        }
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageDevices,
            )?;
            if tx.admin_device(&tenant, &device)?.is_none() {
                return Err(AccessError::NotFound("device"));
            }
            let rows = tx.admin_device_bindings(&tenant, &device, status.as_ref(), &page)?;
            if rows.iter().any(|r| {
                r.tenant_id != tenant
                    || r.device_id != device
                    || status.as_ref().is_some_and(|s| s != &r.status)
            }) {
                return Err(AccessError::InvalidStoreResponse);
            }
            finish_page(rows, page, scope, |r| {
                time_page_key(r.bound_at, r.id.clone())
            })
        })
    }
    fn unbind_device_binding(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        binding_id: String,
        expected_version: u64,
        operation_id: String,
        reason: String,
    ) -> Result<AccessAuditEvent, AccessError> {
        // Resolve the account only after management authorization. execute() locks
        // that account in sorted order and rechecks the exact binding under lock.
        let row = self.get_device_binding(
            context.clone(),
            tenant.clone(),
            device.clone(),
            binding_id.clone(),
        )?;
        self.execute(
            context,
            AccessAdminCommand {
                tenant_id: tenant,
                mutation: AccessAdminMutation::UnbindDeviceBinding {
                    device_id: device,
                    binding_id,
                    account_id: row.account_id,
                    expected_version,
                    operation_id,
                    reason,
                },
            },
        )
    }
    fn device_operation_result(
        &self,
        context: AccessAdminContext,
        tenant: String,
        device: String,
        operation_id: String,
    ) -> Result<super::super::DeviceOperationReceipt, AccessError> {
        super::super::validate_device_operation_id(&operation_id)?;
        validate_id(&device, 128, "device_id")?;
        self.store.admin_transaction(|tx| {
            self.authorize_management_read(
                tx,
                &context,
                &tenant,
                AccessAdminOperation::ManageDevices,
            )?;
            let (_, event) = tx
                .device_operation(&context.actor, &tenant, &operation_id)?
                .ok_or(AccessError::NotFound("device_operation"))?;
            let receipt = event
                .device_receipt(&operation_id)
                .ok_or(AccessError::InvalidStoreResponse)?;
            if receipt.device_id != device {
                return Err(AccessError::NotFound("device_operation"));
            }
            Ok(receipt)
        })
    }
}

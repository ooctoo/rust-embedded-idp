use super::*;
use crate::access::{
    service::{finish_page, time_page_key},
    AccessListScope, AccessPage, AccessPageRequest, TenantProofDevice,
};

/// Management projection; never includes JWKs, account credentials or bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDeviceRecord {
    pub device: TenantProofDevice,
    pub name: String,
    pub registered_at: SystemTime,
    pub last_seen_at: Option<SystemTime>,
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
}

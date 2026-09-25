use super::{access_db_error, epoch, invalid, time, PostgresTenantAuthTransaction};
use embedded_idp_core::{access::*, AccountDeviceBindingStatus, DeviceStatus, StoreError};
use postgres::Row;
use std::time::SystemTime;
use uuid::Uuid;

impl TenantDeviceManagementTransaction for PostgresTenantAuthTransaction<'_> {
    fn subject_devices(
        &mut self,
        actor: &AccessActor,
        client: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<TenantSubjectDevice>, StoreError> {
        page.validate(&AccessListScope::SubjectDevices {
            tenant_id: actor.tenant_id.clone(),
            subject_id: actor.subject_id.clone(),
            client_id: client.into(),
        })
        .map_err(|_| invalid())?;
        let account = Uuid::parse_str(&actor.subject_id).map_err(|_| invalid())?;
        let after = page
            .cursor
            .as_ref()
            .map(|c| Uuid::parse_str(&c.after[0]))
            .transpose()
            .map_err(|_| StoreError::Conflict("device.cursor"))?;
        self.tx.query(&format!("select d.*,b.status as binding_status from {s}.devices d join {s}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id where d.tenant_id=$1 and b.account_id=$2 and d.client_id=$3 and b.status<>'unbound' and ($4::uuid is null or d.id>$4) order by d.id limit $5",s=self.schema),&[&actor.tenant_id,&account,&client,&after,&(page.fetch_limit() as i64)]).map_err(access_db_error)?.iter().map(decode_device).collect()
    }
    fn subject_device(
        &mut self,
        actor: &AccessActor,
        client: &str,
        device: &str,
    ) -> Result<Option<TenantSubjectDevice>, StoreError> {
        let (Ok(account), Ok(device)) =
            (Uuid::parse_str(&actor.subject_id), Uuid::parse_str(device))
        else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select d.*,b.status as binding_status from {s}.devices d join {s}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id where d.tenant_id=$1 and b.account_id=$2 and d.client_id=$3 and d.id=$4 and b.status<>'unbound'",s=self.schema),&[&actor.tenant_id,&account,&client,&device]).map_err(access_db_error)?.as_ref().map(decode_device).transpose()
    }
    fn record_heartbeat(
        &mut self,
        tenant: &str,
        device: &str,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let device = Uuid::parse_str(device).map_err(|_| invalid())?;
        let now = epoch(now)?;
        if self.tx.execute(&format!("update {}.devices set last_seen_at_epoch=greatest(coalesce(last_seen_at_epoch,$3),$3) where tenant_id=$1 and id=$2 and status='active'",self.schema),&[&tenant,&device,&now]).map_err(access_db_error)?!=1 {return Err(StoreError::Conflict("device.heartbeat"));}
        Ok(())
    }
    fn unbind_subject_device(
        &mut self,
        actor: &AccessActor,
        device: &str,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let account = Uuid::parse_str(&actor.subject_id).map_err(|_| invalid())?;
        let device = Uuid::parse_str(device).map_err(|_| invalid())?;
        let now = epoch(now)?;
        let tenant = &actor.tenant_id;
        let s = self.schema;
        // The actor account lock serializes every affected session/login. Touch
        // sessions before bindings, following the authentication lock order.
        self.tx.execute(&format!("update {s}.auth_sessions set status='revoked' where tenant_id=$1 and account_id=$2 and device_id=$3 and status in ('active','pending')"),&[tenant,&account,&device]).map_err(access_db_error)?;
        self.tx.execute(&format!("update {s}.refresh_tokens f set revoked_at_epoch=$4,revocation_reason='client_revocation' where f.tenant_id=$1 and exists(select 1 from {s}.auth_sessions x where x.tenant_id=f.tenant_id and x.id=f.session_id and x.account_id=$2 and x.device_id=$3)"),&[tenant,&account,&device,&now]).map_err(access_db_error)?;
        if self.tx.execute(&format!("update {s}.account_device_bindings set status='unbound',unbound_at_epoch=$4 where tenant_id=$1 and account_id=$2 and device_id=$3 and status<>'unbound'"),&[tenant,&account,&device,&now]).map_err(access_db_error)?!=1 {return Err(StoreError::Conflict("device.binding"));}
        Ok(())
    }
}
pub(super) fn decode_admin_device(r: &Row) -> Result<AccessDeviceRecord, StoreError> {
    Ok(AccessDeviceRecord {
        device: TenantProofDevice {
            tenant_id: r.get("tenant_id"),
            id: r.get::<_, Uuid>("id").to_string(),
            client_id: r.get("client_id"),
            proof_key_id: r.get("proof_key_id"),
            status: match r.get::<_, &str>("status") {
                "pending" => DeviceStatus::Pending,
                "active" => DeviceStatus::Active,
                "disabled" => DeviceStatus::Disabled,
                "revoked" => DeviceStatus::Revoked,
                _ => return Err(invalid()),
            },
        },
        name: r.get("device_name"),
        registered_at: time(r.get("registered_at_epoch"))?,
        last_seen_at: r
            .get::<_, Option<i64>>("last_seen_at_epoch")
            .map(time)
            .transpose()?,
    })
}
fn decode_device(r: &Row) -> Result<TenantSubjectDevice, StoreError> {
    let record = decode_admin_device(r)?;
    Ok(TenantSubjectDevice {
        device: record.device,
        name: record.name,
        registered_at: record.registered_at,
        last_seen_at: record.last_seen_at,
        binding_status: match r.get::<_, &str>("binding_status") {
            "active" => AccountDeviceBindingStatus::Active,
            "suspended" => AccountDeviceBindingStatus::Suspended,
            _ => return Err(invalid()),
        },
    })
}

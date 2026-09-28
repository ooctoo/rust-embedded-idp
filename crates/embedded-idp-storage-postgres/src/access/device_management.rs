use super::{access_db_error, epoch, invalid, time, PostgresTenantAuthTransaction};
use embedded_idp_core::{access::*, AccountDeviceBindingStatus, DeviceStatus, StoreError};
use postgres::{Row, Transaction};
use serde_json::{json, Value};
use std::time::SystemTime;
use uuid::Uuid;

impl TenantDeviceManagementTransaction for PostgresTenantAuthTransaction<'_> {
    fn self_device_operation(
        &mut self,
        actor: &AccessActor,
        operation_id: &str,
    ) -> Result<Option<([u8; 32], DeviceOperationReceipt)>, StoreError> {
        let account = Uuid::parse_str(&actor.subject_id).map_err(|_| invalid())?;
        let operation = Uuid::parse_str(operation_id).map_err(|_| invalid())?;
        self.tx.query_opt(&format!("select id,occurred_at_epoch,authentication_source,operation,device_command_sha256,change_json::text as change_text from {}.access_audit_events where actor_domain=$1 and actor_id=$2 and target_domain=$1 and device_operation_id=$3",self.schema),&[&actor.tenant_id,&account,&operation]).map_err(access_db_error)?.map(|row| {
            if row.get::<_, &str>("authentication_source") != "device_session" || row.get::<_, &str>("operation") != "device.binding.unbind.self" { return Err(StoreError::Conflict("device_operation_conflict")); }
            let digest: [u8; 32] = row.get::<_, Vec<u8>>("device_command_sha256").try_into().map_err(|_| invalid())?;
            let change: Value = serde_json::from_str(&row.get::<_, String>("change_text")).map_err(|_| invalid())?;
            let after = change.get("after").ok_or_else(invalid)?;
            let field = |name: &str| after.get(name).and_then(Value::as_str).ok_or_else(invalid);
            if field("account_id")? != actor.subject_id { return Err(invalid()); }
            Ok((digest, DeviceOperationReceipt {
                operation_id: operation_id.into(), audit_id: row.get::<_, Uuid>("id").to_string(),
                device_id: field("device_id")?.into(), binding_id: Some(field("binding_id")?.into()),
                operation: "device.binding.unbind.self", occurred_at: time(row.get("occurred_at_epoch"))?,
                result_version: after.get("version").and_then(Value::as_u64).ok_or_else(invalid)?,
                result_status: field("status")?.into(),
            }))
        }).transpose()
    }
    fn append_self_unbind_audit(
        &mut self,
        actor: &AccessActor,
        receipt: &DeviceOperationReceipt,
        digest: &[u8; 32],
        request_id: &str,
    ) -> Result<(), StoreError> {
        let version = receipt.result_version.checked_sub(1).ok_or_else(invalid)?;
        let binding = receipt.binding_id.as_ref().ok_or_else(invalid)?;
        let change = json!({"kind":"device.binding","reason":"self_service","before":{"tenant_id":actor.tenant_id,"device_id":receipt.device_id,"binding_id":binding,"account_id":actor.subject_id,"status":"active","version":version},"after":{"tenant_id":actor.tenant_id,"device_id":receipt.device_id,"binding_id":binding,"account_id":actor.subject_id,"status":"unbound","version":receipt.result_version}}).to_string();
        self.tx.execute(&format!("insert into {}.access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,target_business_id,operation,request_id,change_json,device_operation_id,device_command_sha256) values($1,$2,$3,$4,$5,'device_session',$4,null,'device.binding.unbind.self',$6,$7::text::jsonb,$8,$9)",self.schema),&[&Uuid::parse_str(&receipt.audit_id).map_err(|_| invalid())?,&epoch(receipt.occurred_at)?,&Uuid::parse_str(&actor.subject_id).map_err(|_| invalid())?,&actor.tenant_id,&Uuid::parse_str(&actor.session_id).map_err(|_| invalid())?,&request_id,&change,&Uuid::parse_str(&receipt.operation_id).map_err(|_| invalid())?,&digest.as_slice()]).map_err(access_db_error)?;
        Ok(())
    }
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
        self.tx.query(&format!("select d.*,(select k.version from {s}.device_proof_keys k where k.tenant_id=d.tenant_id and k.device_id=d.id and k.key_id=d.proof_key_id) as key_version,b.id as binding_id,b.version as binding_version,b.status as binding_status from {s}.devices d join {s}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id where d.tenant_id=$1 and b.account_id=$2 and d.client_id=$3 and b.status<>'unbound' and ($4::uuid is null or d.id>$4) order by d.id limit $5",s=self.schema),&[&actor.tenant_id,&account,&client,&after,&(page.fetch_limit() as i64)]).map_err(access_db_error)?.iter().map(decode_device).collect()
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
        self.tx.query_opt(&format!("select d.*,(select k.version from {s}.device_proof_keys k where k.tenant_id=d.tenant_id and k.device_id=d.id and k.key_id=d.proof_key_id) as key_version,b.id as binding_id,b.version as binding_version,b.status as binding_status from {s}.devices d join {s}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id where d.tenant_id=$1 and b.account_id=$2 and d.client_id=$3 and d.id=$4 and b.status<>'unbound'",s=self.schema),&[&actor.tenant_id,&account,&client,&device]).map_err(access_db_error)?.as_ref().map(decode_device).transpose()
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
        binding_id: &str,
        expected_version: u64,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let account = Uuid::parse_str(&actor.subject_id).map_err(|_| invalid())?;
        let device = Uuid::parse_str(device).map_err(|_| invalid())?;
        let binding_id = Uuid::parse_str(binding_id).map_err(|_| invalid())?;
        let expected_version = i64::try_from(expected_version).map_err(|_| invalid())?;
        let now = epoch(now)?;
        let tenant = &actor.tenant_id;
        let s = self.schema;
        revoke_device_account_credentials(
            &mut self.tx,
            s,
            tenant,
            &account,
            &device,
            now,
            "client_revocation",
        )?;
        if self.tx.execute(&format!("update {s}.account_device_bindings set status='unbound',unbound_at_epoch=$4,version=version+1 where tenant_id=$1 and account_id=$2 and device_id=$3 and id=$5 and version=$6 and status='active'"),&[tenant,&account,&device,&now,&binding_id,&expected_version]).map_err(access_db_error)?!=1 {return Err(StoreError::Conflict("device_binding_version"));}
        Ok(())
    }
}
/// The tenant and account locks are held by both callers. Keep credential
/// cleanup in the same transaction as the exact binding update.
pub(super) fn revoke_device_account_credentials(
    tx: &mut Transaction<'_>,
    s: &str,
    tenant: &str,
    account: &Uuid,
    device: &Uuid,
    now: i64,
    reason: &str,
) -> Result<(), StoreError> {
    tx.execute(&format!("delete from {s}.authorization_codes c where c.tenant_id=$1 and c.account_id=$2 and exists(select 1 from {s}.auth_sessions x where x.tenant_id=c.tenant_id and x.id=c.source_session_id and x.device_id=$3)"),&[&tenant,account,device]).map_err(access_db_error)?;
    tx.execute(&format!("update {s}.auth_tenant_selections p set revoked_at_epoch=$4 where p.source_tenant_id=$1 and p.account_id=$2 and p.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where x.tenant_id=p.source_tenant_id and x.id=p.source_session_id and x.device_id=$3)"),&[&tenant,account,device,&now]).map_err(access_db_error)?;
    tx.execute(&format!("update {s}.auth_sessions set status='revoked' where tenant_id=$1 and account_id=$2 and device_id=$3 and status in ('active','pending')"),&[&tenant,account,device]).map_err(access_db_error)?;
    tx.execute(&format!("update {s}.refresh_tokens f set revoked_at_epoch=$4,revocation_reason=$5 where f.tenant_id=$1 and f.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where x.tenant_id=f.tenant_id and x.id=f.session_id and x.account_id=$2 and x.device_id=$3)"),&[&tenant,account,device,&now,&reason]).map_err(access_db_error)?;
    Ok(())
}

pub(super) fn decode_device_binding(r: &Row) -> Result<AccessDeviceBindingRecord, StoreError> {
    Ok(AccessDeviceBindingRecord {
        tenant_id: r.get("tenant_id"),
        id: r.get::<_, Uuid>("id").to_string(),
        device_id: r.get::<_, Uuid>("device_id").to_string(),
        account_id: r.get::<_, Uuid>("account_id").to_string(),
        status: match r.get::<_, &str>("status") {
            "active" => AccountDeviceBindingStatus::Active,
            "suspended" => AccountDeviceBindingStatus::Suspended,
            "unbound" => AccountDeviceBindingStatus::Unbound,
            _ => return Err(invalid()),
        },
        version: u64::try_from(r.get::<_, i64>("version")).map_err(|_| invalid())?,
        bound_at: time(r.get("bound_at_epoch"))?,
        unbound_at: r
            .get::<_, Option<i64>>("unbound_at_epoch")
            .map(time)
            .transpose()?,
        last_authenticated_at: r
            .get::<_, Option<i64>>("last_authenticated_at_epoch")
            .map(time)
            .transpose()?,
    })
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
            version: u64::try_from(r.get::<_, i64>("version")).map_err(|_| invalid())?,
            key_version: r
                .get::<_, Option<i64>>("key_version")
                .map(|v| u64::try_from(v).map_err(|_| invalid()))
                .transpose()?,
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
        binding_id: r.get::<_, Uuid>("binding_id").to_string(),
        binding_version: u64::try_from(r.get::<_, i64>("binding_version"))
            .map_err(|_| invalid())?,
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

use super::{access_db_error, epoch, invalid, time, PostgresTenantAuthTransaction};
use embedded_idp_core::{access::*, AccountDeviceBindingStatus, StoreError};
use postgres::Row;
use std::time::SystemTime;
use uuid::Uuid;

fn uuid(value: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::Conflict("access.uuid"))
}
fn grant_state(value: &str) -> Result<ScanGrantState, StoreError> {
    Ok(match value {
        "waiting_user" => ScanGrantState::WaitingUser,
        "waiting_device" => ScanGrantState::WaitingDevice,
        "awaiting_approval" => ScanGrantState::AwaitingApproval,
        "approved" => ScanGrantState::Approved,
        "issued" => ScanGrantState::Issued,
        "denied" => ScanGrantState::Denied,
        "cancelled" => ScanGrantState::Cancelled,
        "expired" => ScanGrantState::Expired,
        "invalidated" => ScanGrantState::Invalidated,
        _ => return Err(invalid()),
    })
}
fn delivery_state(value: &str) -> Result<ScanDeliveryState, StoreError> {
    Ok(match value {
        "recoverable" => ScanDeliveryState::Recoverable,
        "acknowledged" => ScanDeliveryState::Acknowledged,
        "revoked" => ScanDeliveryState::Revoked,
        _ => return Err(invalid()),
    })
}
fn mode(value: &str) -> Result<ScanLoginMode, StoreError> {
    Ok(match value {
        "device_display" => ScanLoginMode::DeviceDisplay,
        "phone_display" => ScanLoginMode::PhoneDisplay,
        _ => return Err(invalid()),
    })
}
fn mode_value(value: ScanLoginMode) -> &'static str {
    match value {
        ScanLoginMode::DeviceDisplay => "device_display",
        ScanLoginMode::PhoneDisplay => "phone_display",
    }
}
fn origin_action(value: &str) -> Result<ScanOriginAction, StoreError> {
    match value {
        "create" => Ok(ScanOriginAction::Create),
        "claim" => Ok(ScanOriginAction::Claim),
        _ => Err(invalid()),
    }
}
fn decode_origin_closure(row: &Row) -> Result<ScanOriginClosure, StoreError> {
    Ok(ScanOriginClosure {
        tenant_id: row.get("tenant_id"),
        host_scope: row.get("host_scope"),
        entry_id: row.get("entry_id"),
        device_id: row.get::<_, Uuid>("device_id").to_string(),
        origin_action: origin_action(row.get("origin_action"))?,
        origin_operation_id: row.get("origin_operation_id"),
        delivery_secret_hash: row
            .get::<_, Vec<u8>>("delivery_secret_hash")
            .try_into()
            .map_err(|_| invalid())?,
        grant_id: row
            .get::<_, Option<Uuid>>("grant_id")
            .map(|id| id.to_string()),
        closed_by_key_id: row.get("closed_by_key_id"),
        closed_at: time(row.get("closed_at_epoch"))?,
    })
}
fn encrypted(row: &Row, prefix: &str) -> Result<Option<EncryptedScanResult>, StoreError> {
    let key: Option<String> = row.get(format!("{prefix}_key_id").as_str());
    let nonce: Option<Vec<u8>> = row.get(format!("{prefix}_nonce").as_str());
    let ciphertext: Option<Vec<u8>> = row.get(format!("{prefix}_ciphertext").as_str());
    match (key, nonce, ciphertext) {
        (None, None, None) => Ok(None),
        (Some(key), Some(nonce), Some(ciphertext)) => Ok(Some(EncryptedScanResult {
            key_id: key,
            nonce: nonce.try_into().map_err(|_| invalid())?,
            ciphertext,
        })),
        _ => Err(invalid()),
    }
}
fn decode_grant(row: &Row) -> Result<ScanGrantRecord, StoreError> {
    let source = match (
        row.get::<_, Option<Uuid>>("source_account_id"),
        row.get::<_, Option<Uuid>>("source_session_id"),
        row.get::<_, Option<String>>("source_client_id"),
        row.get::<_, Option<i64>>("source_authenticated_at_epoch"),
    ) {
        (None, None, None, None) => None,
        (Some(account), Some(session), Some(client), Some(at)) => Some(ScanSourceReference {
            account_id: account.to_string(),
            session_id: session.to_string(),
            client_id: client,
            authenticated_at: time(at)?,
        }),
        _ => return Err(invalid()),
    };
    let target = match (
        row.get::<_, Option<Uuid>>("target_device_id"),
        row.get::<_, Option<String>>("target_key_id"),
        row.get::<_, Option<i64>>("target_device_version"),
        row.get::<_, Option<i64>>("target_key_version"),
    ) {
        (None, None, None, None) => None,
        (Some(device), Some(key), Some(dv), Some(kv)) => Some(ScanTargetReference {
            device_id: device.to_string(),
            key_id: key,
            device_version: u64::try_from(dv).map_err(|_| invalid())?,
            key_version: u64::try_from(kv).map_err(|_| invalid())?,
        }),
        _ => return Err(invalid()),
    };
    Ok(ScanGrantRecord {
        tenant_id: row.get("tenant_id"),
        host_scope: row.get("host_scope"),
        entry_id: row.get("entry_id"),
        id: row.get::<_, Uuid>("id").to_string(),
        mode: mode(row.get("mode"))?,
        target_client_id: row.get("target_client_id"),
        state: grant_state(row.get("state"))?,
        version: u64::try_from(row.get::<_, i64>("version")).map_err(|_| invalid())?,
        source,
        target,
        code_digest: row
            .get::<_, Vec<u8>>("code_digest")
            .try_into()
            .map_err(|_| invalid())?,
        presentation: encrypted(row, "presentation")?,
        delivery_secret_hash: row
            .get::<_, Option<Vec<u8>>>("delivery_secret_hash")
            .map(|v| v.try_into().map_err(|_| invalid()))
            .transpose()?,
        confirmation_revision: row.get("confirmation_revision"),
        created_at: time(row.get("created_at_epoch"))?,
        expires_at: time(row.get("expires_at_epoch"))?,
        code_expires_at: time(row.get("code_expires_at_epoch"))?,
        approved_until: row
            .get::<_, Option<i64>>("approved_until_epoch")
            .map(time)
            .transpose()?,
    })
}
fn decode_delivery(row: &Row) -> Result<ScanDeliveryRecord, StoreError> {
    Ok(ScanDeliveryRecord {
        tenant_id: row.get("tenant_id"),
        grant_id: row.get::<_, Uuid>("grant_id").to_string(),
        issuance_operation_id: row.get("issuance_operation_id"),
        session_id: row.get::<_, Uuid>("session_id").to_string(),
        state: delivery_state(row.get("state"))?,
        binding_id: row.get::<_, Uuid>("binding_id").to_string(),
        binding_version: u64::try_from(row.get::<_, i64>("binding_version"))
            .map_err(|_| invalid())?,
        result: encrypted(row, "result")?,
        receipt_nonce_hash: row
            .get::<_, Option<Vec<u8>>>("receipt_nonce_hash")
            .map(|v| v.try_into().map_err(|_| invalid()))
            .transpose()?,
        recover_until: time(row.get("recover_until_epoch"))?,
        created_at: time(row.get("created_at_epoch"))?,
        release_authorized_at: row
            .get::<_, Option<i64>>("release_authorized_at_epoch")
            .map(time)
            .transpose()?,
        acknowledged_at: row
            .get::<_, Option<i64>>("acknowledged_at_epoch")
            .map(time)
            .transpose()?,
        revoked_at: row
            .get::<_, Option<i64>>("revoked_at_epoch")
            .map(time)
            .transpose()?,
        reason: row.get("reason"),
    })
}

impl TenantScanLoginTransaction for PostgresTenantAuthTransaction<'_> {
    fn find_scan_grant(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        id: &str,
    ) -> Result<Option<ScanGrantRecord>, StoreError> {
        let Ok(id) = uuid(id) else { return Ok(None) };
        self.tx.query_opt(&format!("select * from {}.scan_login_grants where tenant_id=$1 and host_scope=$2 and entry_id=$3 and id=$4",self.schema),&[&tenant,&scope,&entry,&id]).map_err(access_db_error)?.as_ref().map(decode_grant).transpose()
    }
    fn find_scan_code(
        &mut self,
        tenant: Option<&str>,
        scope: &str,
        entry: &str,
        digest: &[u8; 32],
    ) -> Result<Option<ScanGrantRecord>, StoreError> {
        self.tx.query_opt(&format!("select * from {}.scan_login_grants where ($1::text is null or tenant_id=$1) and host_scope=$2 and entry_id=$3 and code_digest=$4",self.schema),&[&tenant,&scope,&entry,&&digest[..]]).map_err(access_db_error)?.as_ref().map(decode_grant).transpose()
    }
    fn lock_scan_grant(
        &mut self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<ScanGrantRecord>, StoreError> {
        let Ok(id) = uuid(id) else { return Ok(None) };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.scan_login_grants where tenant_id=$1 and id=$2 for update",
                    self.schema
                ),
                &[&tenant, &id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_grant)
            .transpose()
    }
    fn insert_scan_grant(&mut self, g: &ScanGrantRecord) -> Result<(), StoreError> {
        let source = &g.source;
        let target = &g.target;
        let presentation = &g.presentation;
        self.tx.execute(&format!("insert into {}.scan_login_grants(tenant_id,host_scope,entry_id,id,mode,target_client_id,state,version,code_digest,source_account_id,source_session_id,source_client_id,source_authenticated_at_epoch,target_device_id,target_key_id,target_device_version,target_key_version,presentation_key_id,presentation_nonce,presentation_ciphertext,delivery_secret_hash,confirmation_revision,created_at_epoch,expires_at_epoch,code_expires_at_epoch,approved_until_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)",self.schema),&[&g.tenant_id,&g.host_scope,&g.entry_id,&uuid(&g.id)?,&mode_value(g.mode),&g.target_client_id,&g.state.as_str(),&i64::try_from(g.version).map_err(|_|invalid())?,&&g.code_digest[..],&source.as_ref().map(|x|uuid(&x.account_id)).transpose()?,&source.as_ref().map(|x|uuid(&x.session_id)).transpose()?,&source.as_ref().map(|x|x.client_id.as_str()),&source.as_ref().map(|x|epoch(x.authenticated_at)).transpose()?,&target.as_ref().map(|x|uuid(&x.device_id)).transpose()?,&target.as_ref().map(|x|x.key_id.as_str()),&target.as_ref().map(|x|i64::try_from(x.device_version).map_err(|_|invalid())).transpose()?,&target.as_ref().map(|x|i64::try_from(x.key_version).map_err(|_|invalid())).transpose()?,&presentation.as_ref().map(|x|x.key_id.as_str()),&presentation.as_ref().map(|x|&x.nonce[..]),&presentation.as_ref().map(|x|x.ciphertext.as_slice()),&g.delivery_secret_hash.as_ref().map(|x|&x[..]),&g.confirmation_revision,&epoch(g.created_at)?,&epoch(g.expires_at)?,&epoch(g.code_expires_at)?,&g.approved_until.map(epoch).transpose()?]).map_err(access_db_error)?;
        Ok(())
    }
    fn update_scan_grant(&mut self, g: &ScanGrantRecord, expected: u64) -> Result<(), StoreError> {
        let changed=self.tx.execute(&format!("update {}.scan_login_grants set state=$3,version=$4,source_account_id=$5,source_session_id=$6,source_client_id=$7,source_authenticated_at_epoch=$8,target_device_id=$9,target_key_id=$10,target_device_version=$11,target_key_version=$12,presentation_key_id=$13,presentation_nonce=$14,presentation_ciphertext=$15,delivery_secret_hash=$16,confirmation_revision=$17,approved_until_epoch=$18 where tenant_id=$1 and id=$2 and version=$19",self.schema),&[&g.tenant_id,&uuid(&g.id)?,&g.state.as_str(),&i64::try_from(g.version).map_err(|_|invalid())?,&g.source.as_ref().map(|x|uuid(&x.account_id)).transpose()?,&g.source.as_ref().map(|x|uuid(&x.session_id)).transpose()?,&g.source.as_ref().map(|x|x.client_id.as_str()),&g.source.as_ref().map(|x|epoch(x.authenticated_at)).transpose()?,&g.target.as_ref().map(|x|uuid(&x.device_id)).transpose()?,&g.target.as_ref().map(|x|x.key_id.as_str()),&g.target.as_ref().map(|x|i64::try_from(x.device_version).map_err(|_|invalid())).transpose()?,&g.target.as_ref().map(|x|i64::try_from(x.key_version).map_err(|_|invalid())).transpose()?,&g.presentation.as_ref().map(|x|x.key_id.as_str()),&g.presentation.as_ref().map(|x|&x.nonce[..]),&g.presentation.as_ref().map(|x|x.ciphertext.as_slice()),&g.delivery_secret_hash.as_ref().map(|x|&x[..]),&g.confirmation_revision,&g.approved_until.map(epoch).transpose()?,&i64::try_from(expected).map_err(|_|invalid())?]).map_err(access_db_error)?;
        if changed != 1 {
            return Err(StoreError::Conflict("scan.grant.version"));
        }
        Ok(())
    }
    fn find_scan_operation(
        &mut self,
        t: &str,
        s: &str,
        e: &str,
        a: &str,
        action: &str,
        id: &str,
    ) -> Result<Option<ScanOperationRecord>, StoreError> {
        self.tx.query_opt(&format!("select * from {}.scan_login_operations where tenant_id=$1 and host_scope=$2 and entry_id=$3 and actor_id=$4 and action=$5 and operation_id=$6",self.schema),&[&t,&s,&e,&a,&action,&id]).map_err(access_db_error)?.map(|r|Ok(ScanOperationRecord{tenant_id:r.get("tenant_id"),host_scope:r.get("host_scope"),entry_id:r.get("entry_id"),actor_id:r.get("actor_id"),action:r.get("action"),operation_id:r.get("operation_id"),fingerprint:r.get::<_,Vec<u8>>("fingerprint").try_into().map_err(|_|invalid())?,grant_id:r.get::<_,Uuid>("grant_id").to_string(),created_at:time(r.get("created_at_epoch"))?})).transpose()
    }
    fn insert_scan_operation(&mut self, r: &ScanOperationRecord) -> Result<(), StoreError> {
        self.tx.execute(&format!("insert into {}.scan_login_operations(tenant_id,host_scope,entry_id,actor_id,action,operation_id,fingerprint,grant_id,created_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9)",self.schema),&[&r.tenant_id,&r.host_scope,&r.entry_id,&r.actor_id,&r.action,&r.operation_id,&&r.fingerprint[..],&uuid(&r.grant_id)?,&epoch(r.created_at)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn find_scan_origin_closure(
        &mut self,
        tenant: &str,
        scope: &str,
        entry: &str,
        device: &str,
        action: ScanOriginAction,
        operation_id: &str,
    ) -> Result<Option<ScanOriginClosure>, StoreError> {
        let Ok(device) = uuid(device) else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select * from {}.scan_login_origin_closures where tenant_id=$1 and host_scope=$2 and entry_id=$3 and device_id=$4 and origin_action=$5 and origin_operation_id=$6", self.schema), &[&tenant, &scope, &entry, &device, &action.as_str(), &operation_id]).map_err(access_db_error)?.as_ref().map(decode_origin_closure).transpose()
    }
    fn insert_scan_origin_closure(
        &mut self,
        closure: &ScanOriginClosure,
    ) -> Result<(), StoreError> {
        self.tx.execute(&format!("insert into {}.scan_login_origin_closures(tenant_id,host_scope,entry_id,device_id,origin_action,origin_operation_id,delivery_secret_hash,grant_id,closed_by_key_id,closed_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", self.schema), &[&closure.tenant_id, &closure.host_scope, &closure.entry_id, &uuid(&closure.device_id)?, &closure.origin_action.as_str(), &closure.origin_operation_id, &&closure.delivery_secret_hash[..], &closure.grant_id.as_ref().map(|id| uuid(id)).transpose()?, &closure.closed_by_key_id, &epoch(closure.closed_at)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn lock_scan_delivery(
        &mut self,
        t: &str,
        g: &str,
    ) -> Result<Option<ScanDeliveryRecord>, StoreError> {
        let Ok(g) = uuid(g) else { return Ok(None) };
        self.tx.query_opt(&format!("select * from {}.scan_login_deliveries where tenant_id=$1 and grant_id=$2 for update",self.schema),&[&t,&g]).map_err(access_db_error)?.as_ref().map(decode_delivery).transpose()
    }
    fn find_scan_delivery(
        &mut self,
        t: &str,
        g: &str,
    ) -> Result<Option<ScanDeliveryRecord>, StoreError> {
        let Ok(g) = uuid(g) else { return Ok(None) };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.scan_login_deliveries where tenant_id=$1 and grant_id=$2",
                    self.schema
                ),
                &[&t, &g],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_delivery)
            .transpose()
    }
    fn scan_grant_tenant(
        &mut self,
        scope: &str,
        entry: &str,
        id: &str,
    ) -> Result<Option<String>, StoreError> {
        let Ok(id) = uuid(id) else { return Ok(None) };
        let rows=self.tx.query(&format!("select tenant_id from {}.scan_login_grants where host_scope=$1 and entry_id=$2 and id=$3 limit 2",self.schema),&[&scope,&entry,&id]).map_err(access_db_error)?;
        if rows.len() > 1 {
            return Err(StoreError::Conflict("scan.ambiguous_grant"));
        }
        Ok(rows.first().map(|r| r.get(0)))
    }
    fn insert_scan_delivery(&mut self, r: &ScanDeliveryRecord) -> Result<(), StoreError> {
        self.tx.execute(&format!("insert into {}.scan_login_deliveries(tenant_id,grant_id,issuance_operation_id,session_id,state,binding_id,binding_version,result_key_id,result_nonce,result_ciphertext,receipt_nonce_hash,recover_until_epoch,created_at_epoch,release_authorized_at_epoch,acknowledged_at_epoch,revoked_at_epoch,reason) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",self.schema),&[&r.tenant_id,&uuid(&r.grant_id)?,&r.issuance_operation_id,&uuid(&r.session_id)?,&r.state.as_str(),&uuid(&r.binding_id)?,&i64::try_from(r.binding_version).map_err(|_|invalid())?,&r.result.as_ref().map(|x|x.key_id.as_str()),&r.result.as_ref().map(|x|&x.nonce[..]),&r.result.as_ref().map(|x|x.ciphertext.as_slice()),&r.receipt_nonce_hash.as_ref().map(|x|&x[..]),&epoch(r.recover_until)?,&epoch(r.created_at)?,&r.release_authorized_at.map(epoch).transpose()?,&r.acknowledged_at.map(epoch).transpose()?,&r.revoked_at.map(epoch).transpose()?,&r.reason]).map_err(access_db_error)?;
        Ok(())
    }
    fn update_scan_delivery(
        &mut self,
        r: &ScanDeliveryRecord,
        expected: ScanDeliveryState,
    ) -> Result<(), StoreError> {
        let changed=self.tx.execute(&format!("update {}.scan_login_deliveries set state=$3,result_key_id=$4,result_nonce=$5,result_ciphertext=$6,receipt_nonce_hash=$7,release_authorized_at_epoch=$8,acknowledged_at_epoch=$9,revoked_at_epoch=$10,reason=$11 where tenant_id=$1 and grant_id=$2 and state=$12",self.schema),&[&r.tenant_id,&uuid(&r.grant_id)?,&r.state.as_str(),&r.result.as_ref().map(|x|x.key_id.as_str()),&r.result.as_ref().map(|x|&x.nonce[..]),&r.result.as_ref().map(|x|x.ciphertext.as_slice()),&r.receipt_nonce_hash.as_ref().map(|x|&x[..]),&r.release_authorized_at.map(epoch).transpose()?,&r.acknowledged_at.map(epoch).transpose()?,&r.revoked_at.map(epoch).transpose()?,&r.reason,&expected.as_str()]).map_err(access_db_error)?;
        if changed != 1 {
            return Err(StoreError::Conflict("scan.delivery.state"));
        }
        Ok(())
    }
    fn scan_binding_snapshot(
        &mut self,
        t: &str,
        a: &str,
        d: &str,
    ) -> Result<Option<ScanBindingSnapshot>, StoreError> {
        let (Ok(a), Ok(d)) = (uuid(a), uuid(d)) else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select id,version,status from {}.account_device_bindings where tenant_id=$1 and account_id=$2 and device_id=$3",self.schema),&[&t,&a,&d]).map_err(access_db_error)?.map(|r|Ok(ScanBindingSnapshot{id:r.get::<_,Uuid>("id").to_string(),version:u64::try_from(r.get::<_,i64>("version")).map_err(|_|invalid())?,status:match r.get::<_,&str>("status"){ "active"=>AccountDeviceBindingStatus::Active,"suspended"=>AccountDeviceBindingStatus::Suspended,"unbound"=>AccountDeviceBindingStatus::Unbound,_=>return Err(invalid())}})).transpose()
    }
    fn scan_account_label(&mut self, a: &str) -> Result<String, StoreError> {
        let Ok(a) = uuid(a) else {
            return Err(StoreError::Conflict("access.uuid"));
        };
        self.tx
            .query_opt(
                &format!("select email from {}.accounts where id=$1", self.schema),
                &[&a],
            )
            .map_err(access_db_error)?
            .map(|r| r.get("email"))
            .ok_or_else(|| StoreError::Conflict("scan.account"))
    }
    fn activate_scan_session(&mut self, t: &str, s: &str) -> Result<(), StoreError> {
        let s = uuid(s)?;
        if self.tx.execute(&format!("update {}.auth_sessions set status='active' where tenant_id=$1 and id=$2 and status='pending'",self.schema),&[&t,&s]).map_err(access_db_error)?!=1{return Err(StoreError::Conflict("scan.session.activate"))}
        Ok(())
    }
    fn revoke_scan_session(&mut self, t: &str, s: &str, now: SystemTime) -> Result<(), StoreError> {
        let s = uuid(s)?;
        let n = epoch(now)?;
        let row = self
            .tx
            .query_opt(
                &format!(
                    "select status from {}.auth_sessions where tenant_id=$1 and id=$2 for update",
                    self.schema
                ),
                &[&t, &s],
            )
            .map_err(access_db_error)?
            .ok_or(StoreError::NotFound("scan.session"))?;
        if !matches!(row.get::<_, &str>(0), "pending" | "revoked" | "expired") {
            return Err(StoreError::Conflict("scan.already_active"));
        }
        self.tx.execute(&format!("update {}.auth_sessions set status='revoked' where tenant_id=$1 and id=$2 and status='pending'",self.schema),&[&t,&s]).map_err(access_db_error)?;
        let reason = crate::transaction::encode_refresh_revocation_reason(
            embedded_idp_core::RefreshTokenRevocationReason::ClientRevocation,
        );
        self.tx.execute(&format!("update {}.refresh_tokens set revoked_at_epoch=$3,revocation_reason=$4 where tenant_id=$1 and session_id=$2 and revoked_at_epoch is null",self.schema),&[&t,&s,&n,&reason]).map_err(access_db_error)?;
        Ok(())
    }
    fn expired_scan_deliveries(
        &mut self,
        scope: &str,
        entry: &str,
        now: SystemTime,
        limit: u32,
    ) -> Result<Vec<ScanGrantRecord>, StoreError> {
        self.tx.query(&format!("select g.* from {}.scan_login_grants g left join {}.scan_login_deliveries d on d.tenant_id=g.tenant_id and d.grant_id=g.id where g.host_scope=$1 and g.entry_id=$2 and ((g.state in ('waiting_user','waiting_device','awaiting_approval','approved') and (g.expires_at_epoch<=$3 or (g.state='waiting_device' and g.code_expires_at_epoch<=$3) or (g.state='approved' and g.approved_until_epoch<=$3))) or (d.state='recoverable' and d.recover_until_epoch<=$3)) order by g.expires_at_epoch,g.id limit $4",self.schema,self.schema),&[&scope,&entry,&epoch(now)?,&(limit as i64)]).map_err(access_db_error)?.iter().map(decode_grant).collect()
    }
    fn append_scan_audit(&mut self, e: &ScanAuditEvent) -> Result<(), StoreError> {
        self.tx.execute(&format!("insert into {}.scan_login_audit_events(id,tenant_id,host_scope,grant_id,actor_kind,actor_id,operation,operation_id,session_id,decision_id,occurred_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",self.schema),&[&uuid(&e.id)?,&e.tenant_id,&e.host_scope,&uuid(&e.grant_id)?,&e.actor_kind,&e.actor_id,&e.operation,&e.operation_id,&e.session_id.as_ref().map(|x|uuid(x)).transpose()?,&e.decision_id,&epoch(e.occurred_at)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn pending_scan_count(
        &mut self,
        t: &str,
        s: &str,
        e: &str,
        source: Option<&str>,
        device: Option<&str>,
        now: SystemTime,
    ) -> Result<u64, StoreError> {
        let source = source.map(uuid).transpose()?;
        let device = device.map(uuid).transpose()?;
        let n:i64=self.tx.query_one(&format!("select count(*) from {}.scan_login_grants g left join {}.scan_login_deliveries d on d.tenant_id=g.tenant_id and d.grant_id=g.id where g.tenant_id=$1 and g.host_scope=$2 and g.entry_id=$3 and ((g.state in ('waiting_user','waiting_device','awaiting_approval','approved') and g.expires_at_epoch>$4 and (g.state<>'waiting_device' or g.code_expires_at_epoch>$4) and (g.state<>'approved' or g.approved_until_epoch>$4)) or (d.state='recoverable' and d.recover_until_epoch>$4)) and ($5::uuid is null or g.source_session_id=$5) and ($6::uuid is null or g.target_device_id=$6)",self.schema,self.schema),&[&t,&s,&e,&epoch(now)?,&source,&device]).map_err(access_db_error)?.get(0);
        u64::try_from(n).map_err(|_| invalid())
    }
}

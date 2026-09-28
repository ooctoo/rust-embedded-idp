use super::{access_db_error, epoch, invalid, time, PostgresTenantAuthTransaction};
use embedded_idp_core::{
    access::*, AccountDeviceBindingStatus, DeviceProofKeyStatus, DeviceProofPurpose, DeviceStatus,
    StoreError,
};
use uuid::Uuid;

impl TenantDeviceProofTransaction for PostgresTenantAuthTransaction<'_> {
    fn key_metadata(
        &mut self,
        tenant: &str,
        device: &str,
        key: &str,
    ) -> Result<Option<DeviceKeyMetadata>, StoreError> {
        let Ok(device) = Uuid::parse_str(device) else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select tenant_id,device_id,key_id,algorithm,version,status,registered_at_epoch,retired_at_epoch from {}.device_proof_keys where tenant_id=$1 and device_id=$2 and key_id=$3",self.schema), &[&tenant,&device,&key]).map_err(access_db_error)?.map(|r| Ok(DeviceKeyMetadata {
            tenant_id:r.get("tenant_id"),device_id:r.get::<_,Uuid>("device_id").to_string(),key_id:r.get("key_id"),algorithm:r.get("algorithm"),
            version:u64::try_from(r.get::<_,i64>("version")).map_err(|_|invalid())?,
            status:match r.get::<_,&str>("status") {"active"=>DeviceProofKeyStatus::Active,"retired"=>DeviceProofKeyStatus::Retired,_=>return Err(invalid())},
            registered_at:time(r.get("registered_at_epoch"))?,retired_at:r.get::<_,Option<i64>>("retired_at_epoch").map(time).transpose()?,
        })).transpose()
    }
    fn registration_for_device(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<TenantDeviceRegistration>, StoreError> {
        let Ok(device) = Uuid::parse_str(device) else {
            return Ok(None);
        };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.device_registrations where tenant_id=$1 and device_id=$2",
                    self.schema
                ),
                &[&tenant, &device],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_registration)
            .transpose()
    }
    fn lock_proof_device(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<TenantProofDevice>, StoreError> {
        let Ok(id) = Uuid::parse_str(device) else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select d.tenant_id,d.id,d.client_id,d.proof_key_id,d.status,d.version,k.version as key_version from {s}.devices d left join {s}.device_proof_keys k on k.tenant_id=d.tenant_id and k.device_id=d.id and k.key_id=d.proof_key_id where d.tenant_id=$1 and d.id=$2 for update of d",s=self.schema), &[&tenant,&id])
            .map_err(access_db_error)?.map(|r| Ok(TenantProofDevice {
                tenant_id:r.get("tenant_id"),id:r.get::<_,Uuid>("id").to_string(),client_id:r.get("client_id"),proof_key_id:r.get("proof_key_id"),
                status:match r.get::<_,&str>("status") {"pending"=>DeviceStatus::Pending,"active"=>DeviceStatus::Active,"disabled"=>DeviceStatus::Disabled,"revoked"=>DeviceStatus::Revoked,_=>return Err(invalid())},
                version:u64::try_from(r.get::<_,i64>("version")).map_err(|_|invalid())?,
                key_version:r.get::<_,Option<i64>>("key_version").map(|v|u64::try_from(v).map_err(|_|invalid())).transpose()?,
            })).transpose()
    }
    fn lock_proof_key(
        &mut self,
        tenant: &str,
        device: &str,
        key: &str,
    ) -> Result<Option<TenantProofKey>, StoreError> {
        let Ok(device) = Uuid::parse_str(device) else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select tenant_id,device_id,key_id,public_jwk,version,status from {}.device_proof_keys where tenant_id=$1 and device_id=$2 and key_id=$3 for update",self.schema), &[&tenant,&device,&key])
            .map_err(access_db_error)?.map(|r| Ok(TenantProofKey {
                tenant_id:r.get("tenant_id"),device_id:r.get::<_,Uuid>("device_id").to_string(),key_id:r.get("key_id"),public_jwk:r.get("public_jwk"),
                version:u64::try_from(r.get::<_,i64>("version")).map_err(|_|invalid())?,
                status:match r.get::<_,&str>("status") {"active"=>DeviceProofKeyStatus::Active,"retired"=>DeviceProofKeyStatus::Retired,_=>return Err(invalid())},
            })).transpose()
    }
    fn lock_proof_binding(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<TenantProofBinding>, StoreError> {
        let (Ok(account), Ok(device)) = (Uuid::parse_str(account), Uuid::parse_str(device)) else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select tenant_id,account_id,device_id,status from {}.account_device_bindings where tenant_id=$1 and account_id=$2 and device_id=$3 and status<>'unbound' for update",self.schema), &[&tenant,&account,&device])
            .map_err(access_db_error)?.map(|r| Ok(TenantProofBinding {
                tenant_id:r.get("tenant_id"),account_id:r.get::<_,Uuid>("account_id").to_string(),device_id:r.get::<_,Uuid>("device_id").to_string(),
                status:match r.get::<_,&str>("status") {"active"=>AccountDeviceBindingStatus::Active,"suspended"=>AccountDeviceBindingStatus::Suspended,_=>return Err(invalid())},
            })).transpose()
    }
    fn lock_proof_challenge(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantProofChallenge>, StoreError> {
        self.tx.query_opt(&format!("select * from {}.device_nonces where tenant_id=$1 and challenge_digest=$2 for update",self.schema), &[&tenant,&&digest[..]])
            .map_err(access_db_error)?.map(|r| Ok(TenantProofChallenge {
                tenant_id:r.get("tenant_id"),id:r.get::<_,Uuid>("id").to_string(),device_id:r.get::<_,Uuid>("device_id").to_string(),
                purpose:DeviceProofPurpose::new(r.get::<_,String>("purpose")).map_err(|_|invalid())?,
                challenge_digest:r.get::<_,Vec<u8>>("challenge_digest").try_into().map_err(|_|invalid())?,
                issued_at:time(r.get("issued_at_epoch"))?,expires_at:time(r.get("expires_at_epoch"))?,consumed_at:r.get::<_,Option<i64>>("consumed_at_epoch").map(time).transpose()?,
            })).transpose()
    }
    fn insert_proof_challenge(&mut self, c: &TenantProofChallenge) -> Result<(), StoreError> {
        let id = Uuid::parse_str(&c.id).map_err(|_| invalid())?;
        let device = Uuid::parse_str(&c.device_id).map_err(|_| invalid())?;
        self.tx.execute(&format!("insert into {}.device_nonces(tenant_id,id,device_id,purpose,challenge_digest,issued_at_epoch,expires_at_epoch,consumed_at_epoch) values ($1,$2,$3,$4,$5,$6,$7,$8)",self.schema),
            &[&c.tenant_id,&id,&device,&c.purpose.as_str(),&&c.challenge_digest[..],&epoch(c.issued_at)?,&epoch(c.expires_at)?,&c.consumed_at.map(epoch).transpose()?]).map_err(access_db_error)?;
        Ok(())
    }
    fn consume_proof_challenge(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
        now: std::time::SystemTime,
    ) -> Result<bool, StoreError> {
        Ok(self.tx.execute(&format!("update {}.device_nonces set consumed_at_epoch=$3 where tenant_id=$1 and challenge_digest=$2 and consumed_at_epoch is null and issued_at_epoch<=$3 and expires_at_epoch>$3",self.schema), &[&tenant,&&digest[..],&epoch(now)?]).map_err(access_db_error)? == 1)
    }
}

impl TenantDeviceLifecycleTransaction for PostgresTenantAuthTransaction<'_> {
    fn append_rotation_audit(
        &mut self,
        actor: &AccessActor,
        device: &TenantProofDevice,
        before: &TenantProofKey,
        after: &TenantProofKey,
        now: std::time::SystemTime,
        audit_id: &str,
        request_id: &str,
    ) -> Result<(), StoreError> {
        if actor.tenant_id != device.tenant_id
            || device.id != before.device_id
            || device.id != after.device_id
        {
            return Err(invalid());
        }
        let change = serde_json::json!({"kind":"device.key.rotate","tenant_id":device.tenant_id,"device_id":device.id,
            "before":{"key_id":before.key_id,"key_version":before.version,"device_version":device.version,"status":"active"},
            "after":{"key_id":after.key_id,"key_version":after.version,"device_version":device.version.checked_add(1).ok_or_else(invalid)?,"status":"active"}}).to_string();
        self.tx.execute(&format!("insert into {}.access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,target_business_id,operation,request_id,change_json) values($1,$2,$3,$4,$5,'device_session',$4,null,'device.key.rotate',$6,$7::text::jsonb)",self.schema), &[&Uuid::parse_str(audit_id).map_err(|_|invalid())?,&epoch(now)?,&Uuid::parse_str(&actor.subject_id).map_err(|_|invalid())?,&actor.tenant_id,&Uuid::parse_str(&actor.session_id).map_err(|_|invalid())?,&request_id,&change]).map_err(access_db_error)?;
        Ok(())
    }
    fn registration(
        &mut self,
        tenant: &str,
        client: &str,
        scope: &str,
        request_id: &str,
    ) -> Result<Option<TenantDeviceRegistration>, StoreError> {
        let request_id = Uuid::parse_str(request_id).map_err(|_| invalid())?;
        self.tx.query_opt(&format!("select * from {}.device_registrations where tenant_id=$1 and client_id=$2 and registration_scope=$3 and registration_request_id=$4",self.schema),&[&tenant,&client,&scope,&request_id]).map_err(access_db_error)?.as_ref().map(decode_registration).transpose()
    }
    fn insert_registration(&mut self, r: &TenantDeviceRegistration) -> Result<(), StoreError> {
        let request_id = Uuid::parse_str(&r.registration_request_id).map_err(|_| invalid())?;
        let device = Uuid::parse_str(&r.device_id).map_err(|_| invalid())?;
        self.tx
            .query_one(
                "select pg_advisory_xact_lock(hashtext('embedded-idp-device-key:' || $1))",
                &[&r.expected_key_id],
            )
            .map_err(access_db_error)?;
        let occupied: bool = self.tx.query_one(&format!("select exists(select 1 from {s}.device_proof_keys where key_id=$1) or exists(select 1 from {s}.device_registrations where expected_key_id=$1)",s=self.schema),&[&r.expected_key_id]).map_err(access_db_error)?.get(0);
        if occupied {
            return Err(StoreError::Conflict("device_key"));
        }
        self.tx.execute(&format!("insert into {}.device_registrations(tenant_id,client_id,registration_scope,registration_request_id,device_id,device_name,expected_key_id,public_jwk,created_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",self.schema),&[&r.tenant_id,&r.client_id,&r.registration_scope,&request_id,&device,&r.device_name,&r.expected_key_id,&r.public_jwk,&epoch(r.created_at)?,&epoch(r.expires_at)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn complete_registration_record(
        &mut self,
        tenant: &str,
        device: &str,
        now: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        let device = Uuid::parse_str(device).map_err(|_| invalid())?;
        if self.tx.execute(&format!("update {}.device_registrations set completed_at_epoch=$3 where tenant_id=$1 and device_id=$2 and completed_at_epoch is null and created_at_epoch<=$3 and expires_at_epoch>$3",self.schema),&[&tenant,&device,&epoch(now)?]).map_err(access_db_error)?!=1 { return Err(StoreError::Conflict("device_registration")); }
        Ok(())
    }
    fn insert_pending_device(
        &mut self,
        d: &TenantProofDevice,
        name: &str,
        now: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        let id = Uuid::parse_str(&d.id).map_err(|_| invalid())?;
        self.tx.execute(&format!("insert into {}.devices(tenant_id,id,client_id,device_name,status,registered_at_epoch) values($1,$2,$3,$4,'pending',$5)",self.schema),&[&d.tenant_id,&id,&d.client_id,&name,&epoch(now)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn activate_device_key(
        &mut self,
        key: &TenantProofKey,
        old: Option<&str>,
        now: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        let device = Uuid::parse_str(&key.device_id).map_err(|_| invalid())?;
        let version = i64::try_from(key.version).map_err(|_| invalid())?;
        let now = epoch(now)?;
        self.tx
            .query_one(
                "select pg_advisory_xact_lock(hashtext('embedded-idp-device-key:' || $1))",
                &[&key.key_id],
            )
            .map_err(access_db_error)?;
        let reserved_elsewhere: bool = self.tx.query_one(&format!("select exists(select 1 from {s}.device_registrations where expected_key_id=$1 and (tenant_id<>$2 or device_id<>$3)) or exists(select 1 from {s}.device_proof_keys where key_id=$1)",s=self.schema),&[&key.key_id,&key.tenant_id,&device]).map_err(access_db_error)?.get(0);
        if reserved_elsewhere {
            return Err(StoreError::Conflict("device_key"));
        }
        if let Some(old) = old {
            if self.tx.execute(&format!("update {}.device_proof_keys set status='retired',retired_at_epoch=$4 where tenant_id=$1 and device_id=$2 and key_id=$3 and status='active'",self.schema),&[&key.tenant_id,&device,&old,&now]).map_err(access_db_error)?!=1 {return Err(StoreError::Conflict("device.key"))}
        }
        self.tx.execute(&format!("insert into {}.device_proof_keys(tenant_id,device_id,key_id,algorithm,public_jwk,version,status,registered_at_epoch) values($1,$2,$3,'ed25519',$4,$5,'active',$6)",self.schema),&[&key.tenant_id,&device,&key.key_id,&key.public_jwk,&version,&now]).map_err(access_db_error)?;
        let status = if old.is_some() { "active" } else { "pending" };
        if self.tx.execute(&format!("update {}.devices set proof_key_id=$3,status='active',last_seen_at_epoch=$4,version=version+1 where tenant_id=$1 and id=$2 and proof_key_id is not distinct from $5 and status=$6",self.schema),&[&key.tenant_id,&device,&key.key_id,&now,&old,&status]).map_err(access_db_error)?!=1 {return Err(StoreError::Conflict("device.state"))}
        Ok(())
    }
}
fn decode_registration(r: &postgres::Row) -> Result<TenantDeviceRegistration, StoreError> {
    Ok(TenantDeviceRegistration {
        tenant_id: r.get("tenant_id"),
        client_id: r.get("client_id"),
        registration_scope: r.get("registration_scope"),
        registration_request_id: r.get::<_, Uuid>("registration_request_id").to_string(),
        device_id: r.get::<_, Uuid>("device_id").to_string(),
        device_name: r.get("device_name"),
        expected_key_id: r.get("expected_key_id"),
        public_jwk: r.get("public_jwk"),
        created_at: time(r.get("created_at_epoch"))?,
        expires_at: time(r.get("expires_at_epoch"))?,
        completed_at: r
            .get::<_, Option<i64>>("completed_at_epoch")
            .map(time)
            .transpose()?,
    })
}

impl TenantDeviceLoginTransaction for PostgresTenantAuthTransaction<'_> {
    fn insert_login_binding(
        &mut self,
        b: &TenantProofBinding,
        id: &str,
        now: std::time::SystemTime,
        session_id: &str,
        audit_id: &str,
        request_id: &str,
    ) -> Result<(), StoreError> {
        let id = Uuid::parse_str(id).map_err(|_| invalid())?;
        let account = Uuid::parse_str(&b.account_id).map_err(|_| invalid())?;
        let device = Uuid::parse_str(&b.device_id).map_err(|_| invalid())?;
        self.tx
            .execute(
                &format!(
                    "insert into {}.account_device_bindings
             (tenant_id,id,account_id,device_id,status,bound_at_epoch,last_authenticated_at_epoch)
             values($1,$2,$3,$4,'active',$5,$5)",
                    self.schema
                ),
                &[&b.tenant_id, &id, &account, &device, &epoch(now)?],
            )
            .map_err(access_db_error)?;
        let change = serde_json::json!({"kind":"device.binding.create","tenant_id":b.tenant_id,"device_id":b.device_id,"account_id":b.account_id,"binding_id":id.to_string(),"before":null,"after":{"status":"active","version":1,"bound_at_unix_secs":epoch(now)?}}).to_string();
        self.tx.execute(&format!("insert into {}.access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,target_business_id,operation,request_id,change_json) values($1,$2,$3,$4,$5,'device_session',$4,null,'device.binding.create',$6,$7::text::jsonb)",self.schema), &[&Uuid::parse_str(audit_id).map_err(|_|invalid())?,&epoch(now)?,&account,&b.tenant_id,&Uuid::parse_str(session_id).map_err(|_|invalid())?,&request_id,&change]).map_err(access_db_error)?;
        Ok(())
    }
}
impl PostgresTenantAuthTransaction<'_> {
    pub(super) fn read_session_device(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<TenantSessionDevice>, StoreError> {
        let (Ok(account), Ok(device)) = (Uuid::parse_str(account), Uuid::parse_str(device)) else {
            return Ok(None);
        };
        // A single snapshot, no device row locks: source-tenant authentication
        // must not lock source and target devices in opposite order during switches.
        // Device/binding revocation must hold the domain/account locks already
        // held by this authentication transaction. Key rotation keeps a current key.
        self.tx.query_opt(&format!(
            "select d.tenant_id,d.id,d.client_id,d.proof_key_id,d.status as device_status,d.version as device_version,
                    k.key_id,k.public_jwk,k.version,k.status as key_status,
                    b.account_id,b.status as binding_status
             from {s}.devices d
             join {s}.device_proof_keys k on k.tenant_id=d.tenant_id and k.device_id=d.id and k.key_id=d.proof_key_id
             join {s}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id
             where d.tenant_id=$1 and d.id=$2 and b.account_id=$3 and b.status<>'unbound'",
            s=self.schema), &[&tenant, &device, &account]).map_err(access_db_error)?
            .map(|r| {
                let tenant: String = r.get("tenant_id");
                let device = r.get::<_,Uuid>("id").to_string();
                Ok(TenantSessionDevice {
                    device: TenantProofDevice {
                        tenant_id: tenant.clone(), id: device.clone(), client_id:r.get("client_id"), proof_key_id:r.get("proof_key_id"),
                        status:match r.get::<_,&str>("device_status") {"pending"=>DeviceStatus::Pending,"active"=>DeviceStatus::Active,"disabled"=>DeviceStatus::Disabled,"revoked"=>DeviceStatus::Revoked,_=>return Err(invalid())},
                        version:u64::try_from(r.get::<_,i64>("device_version")).map_err(|_|invalid())?,
                        key_version:Some(u64::try_from(r.get::<_,i64>("version")).map_err(|_|invalid())?),
                    },
                    key: TenantProofKey {
                        tenant_id:tenant.clone(), device_id:device.clone(), key_id:r.get("key_id"), public_jwk:r.get("public_jwk"),
                        version:u64::try_from(r.get::<_,i64>("version")).map_err(|_|invalid())?,
                        status:match r.get::<_,&str>("key_status") {"active"=>DeviceProofKeyStatus::Active,"retired"=>DeviceProofKeyStatus::Retired,_=>return Err(invalid())},
                    },
                    binding: TenantProofBinding {
                        tenant_id:tenant, device_id:device, account_id:r.get::<_,Uuid>("account_id").to_string(),
                        status:match r.get::<_,&str>("binding_status") {"active"=>AccountDeviceBindingStatus::Active,"suspended"=>AccountDeviceBindingStatus::Suspended,_=>return Err(invalid())},
                    },
                })
            }).transpose()
    }
}

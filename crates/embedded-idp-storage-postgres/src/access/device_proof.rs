use super::{access_db_error, epoch, invalid, time, PostgresTenantAuthTransaction};
use embedded_idp_core::{
    access::*, AccountDeviceBindingStatus, DeviceProofKeyStatus, DeviceProofPurpose, DeviceStatus,
    StoreError,
};
use uuid::Uuid;

impl TenantDeviceProofTransaction for PostgresTenantAuthTransaction<'_> {
    fn lock_proof_device(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<TenantProofDevice>, StoreError> {
        let Ok(id) = Uuid::parse_str(device) else {
            return Ok(None);
        };
        self.tx.query_opt(&format!("select tenant_id,id,client_id,proof_key_id,status from {}.devices where tenant_id=$1 and id=$2 for update",self.schema), &[&tenant,&id])
            .map_err(access_db_error)?.map(|r| Ok(TenantProofDevice {
                tenant_id:r.get("tenant_id"),id:r.get::<_,Uuid>("id").to_string(),client_id:r.get("client_id"),proof_key_id:r.get("proof_key_id"),
                status:match r.get::<_,&str>("status") {"pending"=>DeviceStatus::Pending,"active"=>DeviceStatus::Active,"disabled"=>DeviceStatus::Disabled,"revoked"=>DeviceStatus::Revoked,_=>return Err(invalid())},
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
        if let Some(old) = old {
            if self.tx.execute(&format!("update {}.device_proof_keys set status='retired',retired_at_epoch=$4 where tenant_id=$1 and device_id=$2 and key_id=$3 and status='active'",self.schema),&[&key.tenant_id,&device,&old,&now]).map_err(access_db_error)?!=1 {return Err(StoreError::Conflict("device.key"))}
        }
        self.tx.execute(&format!("insert into {}.device_proof_keys(tenant_id,device_id,key_id,algorithm,public_jwk,version,status,registered_at_epoch) values($1,$2,$3,'ed25519',$4,$5,'active',$6)",self.schema),&[&key.tenant_id,&device,&key.key_id,&key.public_jwk,&version,&now]).map_err(access_db_error)?;
        let status = if old.is_some() { "active" } else { "pending" };
        if self.tx.execute(&format!("update {}.devices set proof_key_id=$3,status='active',last_seen_at_epoch=$4 where tenant_id=$1 and id=$2 and proof_key_id is not distinct from $5 and status=$6",self.schema),&[&key.tenant_id,&device,&key.key_id,&now,&old,&status]).map_err(access_db_error)?!=1 {return Err(StoreError::Conflict("device.state"))}
        Ok(())
    }
}

impl TenantDeviceLoginTransaction for PostgresTenantAuthTransaction<'_> {
    fn insert_login_binding(
        &mut self,
        b: &TenantProofBinding,
        id: &str,
        now: std::time::SystemTime,
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
            "select d.tenant_id,d.id,d.client_id,d.proof_key_id,d.status as device_status,
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

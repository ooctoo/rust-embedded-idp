use super::{
    access_db_error, authentication::decode_session, epoch, invalid, time,
    PostgresTenantAuthTransaction,
};
use crate::transaction::{decode_refresh_revocation_reason, encode_refresh_revocation_reason};
use embedded_idp_core::{access::*, StoreError};
use postgres::Row;
use std::time::SystemTime;
use uuid::Uuid;

impl TenantRefreshTransaction for PostgresTenantAuthTransaction<'_> {
    fn find_refresh(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantRefreshRecord>, StoreError> {
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.refresh_tokens where token_digest=$1",
                    self.schema
                ),
                &[&&digest[..]],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_refresh)
            .transpose()
    }
    fn lock_refresh_session(
        &mut self,
        tenant: &str,
        session: &str,
    ) -> Result<Option<TenantSession>, StoreError> {
        let Ok(session) = Uuid::parse_str(session) else {
            return Ok(None);
        };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.auth_sessions where tenant_id=$1 and id=$2 for update",
                    self.schema
                ),
                &[&tenant, &session],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_session)
            .transpose()
    }
    fn lock_refresh_record(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantRefreshRecord>, StoreError> {
        self.tx.query_opt(&format!("select * from {}.refresh_tokens where tenant_id=$1 and token_digest=$2 for update",self.schema), &[&tenant,&&digest[..]])
            .map_err(access_db_error)?.as_ref().map(decode_refresh).transpose()
    }
    fn rotate_refresh_records(
        &mut self,
        session: &TenantSession,
        previous: &TenantRefreshRecord,
        next: &TenantRefreshRecord,
    ) -> Result<(), StoreError> {
        let id = Uuid::parse_str(&session.id).map_err(|_| invalid())?;
        let next_id = Uuid::parse_str(&next.id).map_err(|_| invalid())?;
        let previous_id = Uuid::parse_str(&previous.id).map_err(|_| invalid())?;
        let version = i64::try_from(session.refresh_token_version).map_err(|_| invalid())?;
        let next_version = i64::try_from(next.token_version).map_err(|_| invalid())?;
        let now = epoch(next.issued_at)?;
        let expires = epoch(next.expires_at)?;
        if self
            .tx
            .execute(
                &format!(
                    "update {}.auth_sessions set refresh_token_version=$4
             where tenant_id=$1 and id=$2 and status='active' and refresh_token_version=$3
             and created_at_epoch<=$5 and expires_at_epoch>$5",
                    self.schema
                ),
                &[&session.tenant_id, &id, &version, &next_version, &now],
            )
            .map_err(access_db_error)?
            != 1
        {
            return Err(StoreError::Conflict("refresh.session"));
        }
        if self.tx.execute(&format!(
            "update {}.refresh_tokens set revoked_at_epoch=$5,revocation_reason='rotated'
             where tenant_id=$1 and id=$2 and session_id=$3 and token_digest=$4
             and revoked_at_epoch is null and token_version=$6 and issued_at_epoch<=$5 and expires_at_epoch>$5",
            self.schema), &[&session.tenant_id,&previous_id,&id,&&previous.token_digest[..],&now,&version]).map_err(access_db_error)? != 1 {
            return Err(StoreError::Conflict("refresh.token"));
        }
        self.tx.execute(&format!(
            "insert into {}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch)
             values($1,$2,$3,$4,$5,$6,$7)",self.schema),
            &[&session.tenant_id,&next_id,&id,&&next.token_digest[..],&next_version,&now,&expires]).map_err(access_db_error)?;
        Ok(())
    }
    fn revoke_refresh_family(
        &mut self,
        session: &TenantSession,
        reason: embedded_idp_core::RefreshTokenRevocationReason,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let id = Uuid::parse_str(&session.id).map_err(|_| invalid())?;
        let version = i64::try_from(session.refresh_token_version).map_err(|_| invalid())?;
        let now = epoch(now)?;
        if self.tx.execute(&format!(
            "update {}.auth_sessions set status='revoked' where tenant_id=$1 and id=$2 and status='active' and refresh_token_version=$3",
            self.schema), &[&session.tenant_id,&id,&version]).map_err(access_db_error)? != 1 {
            return Err(StoreError::Conflict("refresh.family"));
        }
        self.tx.execute(&format!(
            "update {}.refresh_tokens set revoked_at_epoch=$3,revocation_reason=$4 where tenant_id=$1 and session_id=$2",
            self.schema), &[&session.tenant_id,&id,&now,&encode_refresh_revocation_reason(reason)]).map_err(access_db_error)?;
        Ok(())
    }
}
fn decode_refresh(r: &Row) -> Result<TenantRefreshRecord, StoreError> {
    Ok(TenantRefreshRecord {
        tenant_id: r.get("tenant_id"),
        id: r.get::<_, Uuid>("id").to_string(),
        session_id: r.get::<_, Uuid>("session_id").to_string(),
        token_digest: r
            .get::<_, Vec<u8>>("token_digest")
            .try_into()
            .map_err(|_| invalid())?,
        token_version: u64::try_from(r.get::<_, i64>("token_version")).map_err(|_| invalid())?,
        issued_at: time(r.get("issued_at_epoch"))?,
        expires_at: time(r.get("expires_at_epoch"))?,
        revoked_at: r
            .get::<_, Option<i64>>("revoked_at_epoch")
            .map(time)
            .transpose()?,
        revocation_reason: r
            .get::<_, Option<String>>("revocation_reason")
            .map(decode_refresh_revocation_reason)
            .transpose()?,
    })
}

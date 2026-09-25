use super::{access_db_error, epoch, invalid, time, PostgresTenantAuthTransaction};
use crate::transaction::decode_client;
use embedded_idp_core::{access::*, OidcClient, PkceChallengeMethod, StoreError};
use postgres::Row;
use std::time::SystemTime;
use uuid::Uuid;

impl TenantOidcTransaction for PostgresTenantAuthTransaction<'_> {
    fn oidc_client(&mut self, client: &str) -> Result<Option<OidcClient>, StoreError> {
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.oidc_clients where client_id=$1 for share",
                    self.schema
                ),
                &[&client],
            )
            .map_err(access_db_error)?
            .map(decode_client)
            .transpose()
    }
    fn insert_authorization(&mut self, code: &TenantAuthorizationCode) -> Result<(), StoreError> {
        let account = Uuid::parse_str(&code.account_id).map_err(|_| invalid())?;
        let session = Uuid::parse_str(&code.source_session_id).map_err(|_| invalid())?;
        let method = code.code_challenge_method.map(|m| match m {
            PkceChallengeMethod::Plain => "plain",
            PkceChallengeMethod::S256 => "S256",
        });
        self.tx.execute(&format!("insert into {}.authorization_codes
            (tenant_id,code_digest,account_id,source_session_id,client_id,login_entry,redirect_uri,scope,nonce,code_challenge,code_challenge_method,created_at_epoch,expires_at_epoch)
            values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",self.schema),
            &[&code.tenant_id,&&code.code_digest[..],&account,&session,&code.client_id,&code.login_entry,&code.redirect_uri,&code.scope,&code.nonce,&code.code_challenge,&method,&epoch(code.created_at)?,&epoch(code.expires_at)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn find_authorization(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantAuthorizationCode>, StoreError> {
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.authorization_codes where code_digest=$1",
                    self.schema
                ),
                &[&&digest[..]],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_code)
            .transpose()
    }
    fn lock_authorization(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
    ) -> Result<Option<TenantAuthorizationCode>, StoreError> {
        self.tx.query_opt(&format!("select * from {}.authorization_codes where tenant_id=$1 and code_digest=$2 for update",self.schema), &[&tenant,&&digest[..]])
            .map_err(access_db_error)?.as_ref().map(decode_code).transpose()
    }
    fn consume_authorization(
        &mut self,
        tenant: &str,
        digest: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), StoreError> {
        if self.tx.execute(&format!("update {}.authorization_codes set consumed_at_epoch=$3 where tenant_id=$1 and code_digest=$2 and consumed_at_epoch is null and created_at_epoch<=$3 and expires_at_epoch>$3",self.schema), &[&tenant,&&digest[..],&epoch(now)?]).map_err(access_db_error)? != 1 {
            return Err(StoreError::Conflict("authorization_code"));
        }
        Ok(())
    }
}
fn decode_code(row: &Row) -> Result<TenantAuthorizationCode, StoreError> {
    Ok(TenantAuthorizationCode {
        tenant_id: row.get("tenant_id"),
        code_digest: row
            .get::<_, Vec<u8>>("code_digest")
            .try_into()
            .map_err(|_| invalid())?,
        account_id: row.get::<_, Uuid>("account_id").to_string(),
        source_session_id: row.get::<_, Uuid>("source_session_id").to_string(),
        client_id: row.get("client_id"),
        login_entry: row.get("login_entry"),
        redirect_uri: row.get("redirect_uri"),
        scope: row.get("scope"),
        nonce: row.get("nonce"),
        code_challenge: row.get("code_challenge"),
        code_challenge_method: row
            .get::<_, Option<String>>("code_challenge_method")
            .map(|m| match m.as_str() {
                "plain" => Ok(PkceChallengeMethod::Plain),
                "S256" => Ok(PkceChallengeMethod::S256),
                _ => Err(invalid()),
            })
            .transpose()?,
        created_at: time(row.get("created_at_epoch"))?,
        expires_at: time(row.get("expires_at_epoch"))?,
        consumed_at: row
            .get::<_, Option<i64>>("consumed_at_epoch")
            .map(time)
            .transpose()?,
    })
}

impl TenantOidcResourceTransaction for PostgresTenantAuthTransaction<'_> {
    fn user_profile(
        &mut self,
        tenant: &str,
        account: &str,
    ) -> Result<Option<TenantUserProfile>, StoreError> {
        let Ok(account) = Uuid::parse_str(account) else {
            return Ok(None);
        };
        Ok(self.tx.query_opt(&format!("select a.id,a.email,a.display_name from {}.accounts a join {}.access_memberships m on m.account_id=a.id where m.tenant_id=$1 and a.id=$2 and m.status='active' and a.status='active'",self.schema,self.schema),&[&tenant,&account]).map_err(access_db_error)?.map(|r|TenantUserProfile {subject_account_id:r.get::<_,Uuid>("id").to_string(),email:r.get("email"),display_name:r.get("display_name")}))
    }
}

use super::{
    access_db_error,
    authentication::decode_session,
    epoch,
    self_sessions::{lock_self_actor, self_actor_is_active},
    time, PostgresAccessStore,
};
use crate::{security_runtime::check_runtime_in_transaction, PgTransaction};
use embedded_idp_core::{access::*, SecurityDigest, StoreError};
use std::time::SystemTime;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

pub struct PostgresSelfSessionMutationTransaction<'a> {
    tx: PgTransaction<'a>,
    schema: &'a str,
}

impl SelfSessionMutationStore for PostgresAccessStore {
    type Transaction<'a> = PostgresSelfSessionMutationTransaction<'a>;

    fn self_session_mutation<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        actor: Option<&AccessActor>,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        if mode != self.mode {
            return Err(AccessError::ModeMismatch);
        }
        let mut client = self.adapter.connect()?;
        let mut tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        tx.batch_execute("set local statement_timeout='5s'; set local lock_timeout='5s'")
            .map_err(access_db_error)?;
        let schema = self.adapter.schema_name();
        let lock = if actor.is_some() { "update" } else { "share" };
        tx.query_one(
            &format!("select singleton from {schema}.access_state where singleton for {lock}"),
            &[],
        )
        .map_err(access_db_error)?;
        self.verify(&mut tx)?;
        check_runtime_in_transaction(&mut tx, schema, mode, authority)?;
        if let Some(actor) = actor {
            lock_self_actor(&mut tx, schema, actor)?;
        }
        let mut transaction = PostgresSelfSessionMutationTransaction { tx, schema };
        let result = run(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}

fn id(value: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::Conflict("security.invalid_id"))
}
fn digest(key_id: String, bytes: Vec<u8>) -> Result<SecurityDigest, StoreError> {
    Ok(SecurityDigest {
        key_id,
        bytes: bytes
            .try_into()
            .map_err(|_| StoreError::Backend("invalid security receipt".into()))?,
    })
}

impl SelfSessionMutationTransaction for PostgresSelfSessionMutationTransaction<'_> {
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        self_actor_is_active(&mut self.tx, self.schema, actor, now)
    }

    fn receipt(
        &mut self,
        purpose: SecurityReceiptPurpose,
        operation: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        let row = self.tx.query_opt(
            &format!("select account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch from {}.security_receipts where purpose=$1 and operation_id=$2", self.schema),
            &[&purpose.as_str(), &operation],
        ).map_err(access_db_error)?;
        row.map(|row| {
            Ok(SecurityOperationReceipt {
                purpose,
                operation_id: operation,
                account_id: row.get::<_, Uuid>(0).to_string(),
                secret_digest: digest(row.get(1), row.get(2))?,
                command_digest: digest(row.get(3), row.get(4))?,
                completed_at: time(row.get(5))?,
                expires_at: time(row.get(6))?,
            })
        })
        .transpose()
    }

    fn receipt_count(&mut self) -> Result<u64, StoreError> {
        let count: i64 = self
            .tx
            .query_one(
                &format!("select count(*) from {}.security_receipts", self.schema),
                &[],
            )
            .map_err(access_db_error)?
            .get(0);
        count
            .try_into()
            .map_err(|_| StoreError::Backend("invalid security receipt count".into()))
    }

    fn owned_session(
        &mut self,
        actor: &AccessActor,
        target_tenant: &str,
        target_session: &str,
    ) -> Result<Option<TenantSession>, StoreError> {
        self.tx.query_opt(
            &format!("select * from {}.auth_sessions where tenant_id=$1 and id=$2 and account_id=$3 for update", self.schema),
            &[&target_tenant,&id(target_session)?,&id(&actor.subject_id)?],
        ).map_err(access_db_error)?.as_ref().map(decode_session).transpose()
    }

    fn revoke_session_credentials(
        &mut self,
        actor: &AccessActor,
        target_tenant: &str,
        target_session: &str,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let s = self.schema;
        let target = id(target_session)?;
        let subject = id(&actor.subject_id)?;
        let now = epoch(now)?;
        // Evaluate this same set before changing delivery state. Recoverable
        // produced sessions cannot yet act as sources for further scan grants.
        // Already-acknowledged independent sessions are deliberately excluded.
        let scope = format!("x.account_id=$3 and ((x.tenant_id=$1 and x.id=$2) or exists(
            select 1 from {s}.scan_login_deliveries d join {s}.scan_login_grants g on g.id=d.grant_id and g.tenant_id=d.tenant_id
            where d.tenant_id=x.tenant_id and d.session_id=x.id and d.state='recoverable'
              and g.tenant_id=$1 and g.source_session_id=$2 and g.source_account_id=$3))");
        self.tx.execute(
            &format!("update {s}.auth_sessions x set status='revoked' where {scope} and x.status<>'revoked'"),
            &[&target_tenant,&target,&subject],
        ).map_err(access_db_error)?;
        self.tx.execute(
            &format!("update {s}.refresh_tokens f set revoked_at_epoch=$4,revocation_reason='administrative' where f.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where {scope} and x.tenant_id=f.tenant_id and x.id=f.session_id)"),
            &[&target_tenant,&target,&subject,&now],
        ).map_err(access_db_error)?;
        self.tx.execute(
            &format!("delete from {s}.authorization_codes c where exists(select 1 from {s}.auth_sessions x where {scope} and x.tenant_id=c.tenant_id and x.id=c.source_session_id)"),
            &[&target_tenant,&target,&subject],
        ).map_err(access_db_error)?;
        self.tx.execute(
            &format!("update {s}.auth_tenant_selections p set revoked_at_epoch=$4 where p.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where {scope} and x.tenant_id=p.source_tenant_id and x.id=p.source_session_id)"),
            &[&target_tenant,&target,&subject,&now],
        ).map_err(access_db_error)?;

        // Both the source and the produced-session boundary clear recoverable
        // delivery secrets. Acknowledged non-target sessions retain their state.
        let grant_scope = format!("(g.tenant_id=$1 and g.source_session_id=$2 and g.source_account_id=$3) or exists(
            select 1 from {s}.scan_login_deliveries d join {s}.auth_sessions x on x.tenant_id=d.tenant_id and x.id=d.session_id
            where d.grant_id=g.id and d.tenant_id=g.tenant_id and d.tenant_id=$1 and d.session_id=$2 and x.account_id=$3)");
        self.tx.execute(
            &format!("update {s}.scan_login_grants g set
                state=case when g.state in ('waiting_user','waiting_device','awaiting_approval','approved','issued') then 'invalidated' else g.state end,
                version=g.version+1,presentation_key_id=null,presentation_nonce=null,presentation_ciphertext=null,delivery_secret_hash=null
                where {grant_scope}"),
            &[&target_tenant,&target,&subject],
        ).map_err(access_db_error)?;
        self.tx.execute(
            &format!("update {s}.scan_login_deliveries d set
                state=case when d.state='recoverable' or (d.tenant_id=$1 and d.session_id=$2) then 'revoked' else d.state end,
                revoked_at_epoch=case when d.state='recoverable' or (d.tenant_id=$1 and d.session_id=$2) then coalesce(d.revoked_at_epoch,$4) else d.revoked_at_epoch end,
                reason=case when d.state='recoverable' or (d.tenant_id=$1 and d.session_id=$2) then 'self_session_revoked' else d.reason end,
                result_key_id=null,result_nonce=null,result_ciphertext=null,receipt_nonce_hash=null
                where exists(select 1 from {s}.scan_login_grants g where g.id=d.grant_id and g.tenant_id=d.tenant_id and ({grant_scope}))"),
            &[&target_tenant,&target,&subject,&now],
        ).map_err(access_db_error)?;
        Ok(())
    }

    fn record_completion(
        &mut self,
        receipt: &SecurityOperationReceipt,
        event_id: Uuid,
    ) -> Result<(), StoreError> {
        let s = self.schema;
        let account = id(&receipt.account_id)?;
        let now = epoch(receipt.completed_at)?;
        let expires = epoch(receipt.expires_at)?;
        self.tx.execute(
            &format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9)"),
            &[&receipt.purpose.as_str(),&receipt.operation_id,&account,&receipt.secret_digest.key_id,&receipt.secret_digest.bytes.as_slice(),&receipt.command_digest.key_id,&receipt.command_digest.bytes.as_slice(),&now,&expires],
        ).map_err(access_db_error)?;
        self.tx.execute(
            &format!("insert into {s}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'session_revoked','accepted',$2,$3,$4)"),
            &[&event_id,&account,&receipt.operation_id,&now],
        ).map_err(access_db_error)?;
        Ok(())
    }
}

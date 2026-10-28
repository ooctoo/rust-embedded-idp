use super::{access_db_error, epoch, time, PostgresAccessStore};
use crate::{security_runtime::check_runtime_in_transaction, PgTransaction};
use embedded_idp_core::{access::*, SecurityDigest, SecurityEnvelope, StoreError};
use std::time::SystemTime;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

pub struct PostgresSecurityOutboxTransaction<'a> {
    tx: PgTransaction<'a>,
    schema: &'a str,
    mode: TenancyMode,
}
fn invalid() -> StoreError {
    StoreError::Backend("invalid security outbox projection".into())
}
fn digest(key_id: String, bytes: Vec<u8>) -> Result<SecurityDigest, StoreError> {
    Ok(SecurityDigest {
        key_id,
        bytes: bytes.try_into().map_err(|_| invalid())?,
    })
}
impl SecurityOutboxStore for PostgresAccessStore {
    type Transaction<'a> = PostgresSecurityOutboxTransaction<'a>;
    fn security_outbox_transaction<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
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
        tx.query_one(
            &format!("select singleton from {schema}.access_state where singleton for update"),
            &[],
        )
        .map_err(access_db_error)?;
        self.verify(&mut tx)?;
        check_runtime_in_transaction(&mut tx, schema, mode, authority)?;
        let mut transaction = PostgresSecurityOutboxTransaction { tx, schema, mode };
        let result = run(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}
impl PostgresSecurityOutboxTransaction<'_> {
    fn load(&mut self, id: Uuid) -> Result<Option<SecurityMailContext>, StoreError> {
        let s = self.schema;
        let Some(found)=self.tx.query_opt(&format!("select o.flow_id,f.account_id from {s}.security_email_outbox o join {s}.password_recovery_flows f on f.id=o.flow_id where o.id=$1"),&[&id]).map_err(access_db_error)? else{return Ok(None)};
        let flow_id: Uuid = found.get(0);
        let account_id: Option<Uuid> = found.get(1);
        let account = if let Some(account) = account_id {
            super::recovery_account::lock_recovery_account(&mut self.tx, s, self.mode, account)?
        } else {
            None
        };
        let f=self.tx.query_one(&format!("select subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts from {s}.password_recovery_flows where id=$1 for update"),&[&flow_id]).map_err(access_db_error)?;
        let flow_state = match f.get::<_, String>(10).as_str() {
            "pending" => RecoveryFlowState::Pending,
            "consumed" => RecoveryFlowState::Consumed,
            "invalidated" => RecoveryFlowState::Invalidated,
            "expired" => RecoveryFlowState::Expired,
            _ => return Err(invalid()),
        };
        let flow = RecoveryStartFlow {
            id: flow_id,
            subject_digest: f.get::<_, Vec<u8>>(0).try_into().map_err(|_| invalid())?,
            account_id: f.get(1),
            snapshot_credential_version: f
                .get::<_, Option<i64>>(2)
                .map(u64::try_from)
                .transpose()
                .map_err(|_| invalid())?,
            handle_digest: digest(f.get(3), f.get(4))?,
            code_digest: digest(f.get(5), f.get(6))?,
            created_at: time(f.get(7))?,
            expires_at: time(f.get(8))?,
            retained_until: time(f.get(9))?,
        };
        let o=self.tx.query_one(&format!("select state,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,lease_token,lease_until_epoch from {s}.security_email_outbox where id=$1 for update"),&[&id]).map_err(access_db_error)?;
        let state = match o.get::<_, String>(0).as_str() {
            "pending" => SecurityMailState::Pending,
            "sending" => SecurityMailState::Sending,
            "accepted" => SecurityMailState::Accepted,
            "rejected" => SecurityMailState::Rejected,
            "unknown" => SecurityMailState::Unknown,
            "cancelled" => SecurityMailState::Cancelled,
            "expired" => SecurityMailState::Expired,
            _ => return Err(invalid()),
        };
        let envelope = match (
            o.get::<_, Option<String>>(1),
            o.get::<_, Option<Vec<u8>>>(2),
        ) {
            (Some(key_id), Some(ciphertext)) => Some(SecurityEnvelope { key_id, ciphertext }),
            (None, None) => None,
            _ => return Err(invalid()),
        };
        Ok(Some(SecurityMailContext {
            outbox_id: id,
            flow_id,
            state,
            envelope,
            created_at: time(o.get(3))?,
            expires_at: time(o.get(4))?,
            next_attempt_at: time(o.get(5))?,
            attempts: u32::try_from(o.get::<_, i32>(6)).map_err(|_| invalid())?,
            lease_token: o.get(7),
            lease_until: o.get::<_, Option<i64>>(8).map(time).transpose()?,
            flow,
            flow_state,
            failed_attempts: u32::try_from(f.get::<_, i32>(11)).map_err(|_| invalid())?,
            account,
        }))
    }
    fn event(&mut self, id: Uuid, outbox: Uuid, outcome: &str, now: i64) -> Result<(), StoreError> {
        let s = self.schema;
        self.tx.execute(&format!("insert into {s}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) select $1,'email_delivery',$3,f.account_id,null,$4 from {s}.security_email_outbox o join {s}.password_recovery_flows f on f.id=o.flow_id where o.id=$2"),&[&id,&outbox,&outcome,&now]).map_err(access_db_error)?;
        Ok(())
    }
}
fn outcome_name(outcome: SecurityMailOutcome) -> &'static str {
    match outcome {
        SecurityMailOutcome::Accepted => "accepted",
        SecurityMailOutcome::Rejected => "rejected",
        SecurityMailOutcome::NotStarted => "not_started",
        SecurityMailOutcome::Unknown => "unknown",
    }
}
fn terminal_name(state: SecurityMailTerminal) -> &'static str {
    match state {
        SecurityMailTerminal::Accepted => "accepted",
        SecurityMailTerminal::Rejected => "rejected",
        SecurityMailTerminal::Unknown => "unknown",
        SecurityMailTerminal::Cancelled => "cancelled",
        SecurityMailTerminal::Expired => "expired",
    }
}
impl SecurityOutboxTransaction for PostgresSecurityOutboxTransaction<'_> {
    fn candidate(&mut self, now: SystemTime) -> Result<Option<SecurityMailContext>, StoreError> {
        let row=self.tx.query_opt(&format!("select id from {}.security_email_outbox where state='pending' and next_attempt_at_epoch<=$1 order by next_attempt_at_epoch,id limit 1",self.schema),&[&epoch(now)?]).map_err(access_db_error)?;
        match row {
            Some(row) => self.load(row.get(0)),
            None => Ok(None),
        }
    }
    fn current(&mut self, id: Uuid) -> Result<Option<SecurityMailContext>, StoreError> {
        self.load(id)
    }
    fn transition(
        &mut self,
        id: Uuid,
        expected_lease: Option<Uuid>,
        change: SecurityMailTransition,
        event_id: Option<Uuid>,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        if id.is_nil()
            || expected_lease.is_some_and(|id| id.is_nil())
            || event_id.is_some_and(|id| id.is_nil())
        {
            return Err(invalid());
        }
        let s = self.schema;
        let now = epoch(now)?;
        let predicate="id=$1 and (($2::uuid is null and state='pending') or ($2::uuid is not null and state='sending' and lease_token=$2))";
        let (changed, outcome) = match change {
            SecurityMailTransition::Sending {
                lease_token,
                lease_until,
            } => {
                let until = epoch(lease_until)?;
                if expected_lease.is_some()
                    || lease_token.is_nil()
                    || until.checked_sub(now) != Some(30)
                    || event_id.is_some()
                {
                    return Err(invalid());
                }
                (self.tx.execute(&format!("update {s}.security_email_outbox set state='sending',attempts=attempts+1,lease_token=$3,lease_until_epoch=$4 where {predicate} and attempts<3 and expires_at_epoch>$5"),&[&id,&expected_lease,&lease_token,&until,&now]).map_err(access_db_error)?,None)
            }
            SecurityMailTransition::Retry { next_attempt_at } => {
                let next = epoch(next_attempt_at)?;
                if expected_lease.is_none() || next <= now {
                    return Err(invalid());
                }
                (self.tx.execute(&format!("update {s}.security_email_outbox set state='pending',next_attempt_at_epoch=$3,lease_token=null,lease_until_epoch=null,last_outcome='not_started' where {predicate} and attempts<3 and expires_at_epoch>$3"),&[&id,&expected_lease,&next]).map_err(access_db_error)?,Some(SecurityMailOutcome::NotStarted))
            }
            SecurityMailTransition::Terminal { state, outcome } => {
                let state = terminal_name(state);
                let value = outcome.map(outcome_name);
                (self.tx.execute(&format!("update {s}.security_email_outbox set state=$3,last_outcome=$4,envelope_key_id=null,ciphertext=null,lease_token=null,lease_until_epoch=null where {predicate}"),&[&id,&expected_lease,&state,&value]).map_err(access_db_error)?,outcome)
            }
        };
        if changed == 0 {
            return Ok(false);
        }
        if let Some(event) = event_id {
            let value = outcome.ok_or_else(invalid)?;
            self.event(
                event,
                id,
                if value == SecurityMailOutcome::NotStarted {
                    "rejected"
                } else {
                    outcome_name(value)
                },
                now,
            )?;
        }
        Ok(true)
    }
    fn cleanup(
        &mut self,
        now: SystemTime,
        limit: u32,
        event_ids: &[Uuid],
    ) -> Result<u32, StoreError> {
        if !(1..=100).contains(&limit)
            || event_ids.len() != limit as usize
            || event_ids.iter().any(Uuid::is_nil)
            || event_ids
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != event_ids.len()
        {
            return Err(invalid());
        }
        let now = epoch(now)?;
        let s = self.schema;
        let mut remaining = i64::from(limit);
        let rows=self.tx.query(&format!("select id from {s}.security_email_outbox where state='sending' and (lease_until_epoch<=$1 or expires_at_epoch<=$1) order by lease_until_epoch,id limit $2"),&[&now,&remaining]).map_err(access_db_error)?;
        for (row, event_id) in rows.iter().zip(event_ids) {
            let id: Uuid = row.get(0);
            self.tx.execute(&format!("update {s}.security_email_outbox set state='unknown',last_outcome='unknown',envelope_key_id=null,ciphertext=null,lease_token=null,lease_until_epoch=null where id=$1"),&[&id]).map_err(access_db_error)?;
            self.event(*event_id, id, "unknown", now)?;
        }
        remaining -= rows.len() as i64;
        // Each statement consumes only its selected root rows; FK cascades are bounded
        // by the unique outbox/start-receipt per flow.
        let statements=[
   format!("with selected as (select id from {s}.security_email_outbox where state='pending' and expires_at_epoch<=$1 order by expires_at_epoch,id limit $2) update {s}.security_email_outbox set state='expired',last_outcome='not_started',envelope_key_id=null,ciphertext=null,lease_token=null,lease_until_epoch=null where id in(select id from selected)"),
   format!("with selected as (select operation_id from {s}.password_recovery_start_receipts where expires_at_epoch<=$1 order by expires_at_epoch,operation_id limit $2) delete from {s}.password_recovery_start_receipts where operation_id in(select operation_id from selected)"),
   format!("with selected as (select id from {s}.password_recovery_flows where state='pending' and expires_at_epoch<=$1 order by expires_at_epoch,id limit $2) update {s}.password_recovery_flows set state='expired' where id in(select id from selected)"),
   format!("with selected as (select id from {s}.password_recovery_flows where retained_until_epoch<=$1 order by retained_until_epoch,id limit $2) delete from {s}.password_recovery_flows where id in(select id from selected)"),
   format!("with selected as (select purpose,operation_id from {s}.security_receipts where expires_at_epoch<=$1 order by expires_at_epoch,purpose,operation_id limit $2) delete from {s}.security_receipts where (purpose,operation_id) in(select purpose,operation_id from selected)"),
   format!("with selected as (select subject_digest from {s}.password_recovery_budgets b where expires_at_epoch<=$1 and not exists(select 1 from {s}.password_recovery_flows f where f.subject_digest=b.subject_digest) order by expires_at_epoch,subject_digest limit $2) delete from {s}.password_recovery_budgets where subject_digest in(select subject_digest from selected)"),
   format!("with selected as (select id from {s}.security_events where $1::bigint>=2592000 and occurred_at_epoch<=$1-2592000 order by occurred_at_epoch,id limit $2) delete from {s}.security_events where id in(select id from selected)"),
  ];
        for sql in statements {
            if remaining == 0 {
                break;
            }
            let changed = self
                .tx
                .execute(&sql, &[&now, &remaining])
                .map_err(access_db_error)?;
            remaining -= i64::try_from(changed).map_err(|_| invalid())?;
        }
        u32::try_from(i64::from(limit) - remaining).map_err(|_| invalid())
    }
}

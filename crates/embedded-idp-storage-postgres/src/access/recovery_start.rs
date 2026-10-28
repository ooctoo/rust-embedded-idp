use super::{access_db_error, epoch, time, PostgresAccessStore};
use crate::{security_runtime::check_runtime_in_transaction, PgTransaction};
use embedded_idp_core::{access::*, SecurityDigest, SecurityEnvelope, StoreError};
use std::time::{Duration, SystemTime};
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

pub struct PostgresRecoveryStartTransaction<'a> {
    tx: PgTransaction<'a>,
    schema: &'a str,
    mode: TenancyMode,
}
impl RecoveryStartStore for PostgresAccessStore {
    type Transaction<'a> = PostgresRecoveryStartTransaction<'a>;
    fn recovery_start_transaction<R>(
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
        let mut transaction = PostgresRecoveryStartTransaction { tx, schema, mode };
        let result = run(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}
fn invalid() -> StoreError {
    StoreError::Backend("invalid recovery storage projection".into())
}
fn digest(key_id: String, bytes: Vec<u8>) -> Result<SecurityDigest, StoreError> {
    Ok(SecurityDigest {
        key_id,
        bytes: bytes.try_into().map_err(|_| invalid())?,
    })
}

impl RecoveryStartTransaction for PostgresRecoveryStartTransaction<'_> {
    fn start_receipt(
        &mut self,
        operation: Uuid,
    ) -> Result<Option<RecoveryStartReceipt>, StoreError> {
        self.tx.query_opt(&format!("select flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch from {}.password_recovery_start_receipts where operation_id=$1", self.schema), &[&operation])
            .map_err(access_db_error)?.map(|row| Ok(RecoveryStartReceipt {
                operation_id: operation, flow_id: row.get(0), request_digest: digest(row.get(1), row.get(2))?,
                handle_envelope: SecurityEnvelope { key_id: row.get(3), ciphertext: row.get(4) },
                created_at: time(row.get(5))?, expires_at: time(row.get(6))?,
            })).transpose()
    }

    fn lock_start_context(
        &mut self,
        email: &str,
        subject: &[u8; 32],
    ) -> Result<RecoveryStartContext, StoreError> {
        let s = self.schema;
        // Discovery is stable under the exclusive state barrier. Acquire all
        // tenant locks before the target account, matching existing writers.
        let found = self
            .tx
            .query_opt(
                &format!("select id from {s}.accounts where email=$1"),
                &[&email],
            )
            .map_err(access_db_error)?;
        let account = if let Some(found) = found {
            let id: Uuid = found.get(0);
            Some(
                super::recovery_account::lock_recovery_account(&mut self.tx, s, self.mode, id)?
                    .ok_or_else(invalid)?,
            )
        } else {
            None
        };
        let budget = self.tx.query_opt(&format!("select window_start_epoch,expires_at_epoch,start_count,failure_count from {s}.password_recovery_budgets where subject_digest=$1 for update"), &[&subject.as_slice()])
            .map_err(access_db_error)?.map(|row| Ok(RecoveryBudget {
                subject_digest: *subject, window_start: time(row.get(0))?, expires_at: time(row.get(1))?,
                start_count: u32::try_from(row.get::<_, i32>(2)).map_err(|_| invalid())?,
                failure_count: u32::try_from(row.get::<_, i32>(3)).map_err(|_| invalid())?,
            })).transpose()?;
        let counts = self.tx.query_one(&format!("select (select count(*) from {s}.password_recovery_flows),(select count(*) from {s}.security_email_outbox),(select count(*) from {s}.password_recovery_budgets)"), &[]).map_err(access_db_error)?;
        Ok(RecoveryStartContext {
            account,
            budget,
            flow_count: u64::try_from(counts.get::<_, i64>(0)).map_err(|_| invalid())?,
            outbox_count: u64::try_from(counts.get::<_, i64>(1)).map_err(|_| invalid())?,
            budget_count: u64::try_from(counts.get::<_, i64>(2)).map_err(|_| invalid())?,
        })
    }

    fn close_subject_flows(
        &mut self,
        subject: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let s = self.schema;
        let _ = epoch(now)?;
        // Clear pending/sending payloads before changing the flow predicate.
        self.tx.execute(&format!("update {s}.security_email_outbox o set state='cancelled',last_outcome=case when o.state='sending' then 'unknown' else 'not_started' end,envelope_key_id=null,ciphertext=null,lease_token=null,lease_until_epoch=null where o.state in ('pending','sending') and exists(select 1 from {s}.password_recovery_flows f where f.id=o.flow_id and f.subject_digest=$1 and f.state='pending')"), &[&subject.as_slice()]).map_err(access_db_error)?;
        self.tx.execute(&format!("update {s}.password_recovery_flows set state='invalidated' where subject_digest=$1 and state='pending'"), &[&subject.as_slice()]).map_err(access_db_error)?;
        Ok(())
    }

    fn record_start(&mut self, bundle: &RecoveryStartBundle) -> Result<(), StoreError> {
        validate_bundle(bundle)?;
        let s = self.schema;
        let b = &bundle.budget;
        let f = &bundle.flow;
        let r = &bundle.receipt;
        let o = &bundle.outbox;
        let now = epoch(f.created_at)?;
        let expires = epoch(f.expires_at)?;
        let retained = epoch(f.retained_until)?;
        let version = f
            .snapshot_credential_version
            .map(i64::try_from)
            .transpose()
            .map_err(|_| invalid())?;
        self.tx.execute(&format!("insert into {s}.password_recovery_budgets(subject_digest,window_start_epoch,expires_at_epoch,start_count,failure_count) values($1,$2,$3,$4,$5) on conflict(subject_digest) do update set window_start_epoch=excluded.window_start_epoch,expires_at_epoch=excluded.expires_at_epoch,start_count=excluded.start_count,failure_count=excluded.failure_count"), &[&b.subject_digest.as_slice(),&epoch(b.window_start)?,&epoch(b.expires_at)?,&(b.start_count as i32),&(b.failure_count as i32)]).map_err(access_db_error)?;
        self.tx.execute(&format!("insert into {s}.password_recovery_flows(id,subject_digest,account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',0)"), &[&f.id,&f.subject_digest.as_slice(),&f.account_id,&version,&f.handle_digest.key_id,&f.handle_digest.bytes.as_slice(),&f.code_digest.key_id,&f.code_digest.bytes.as_slice(),&now,&expires,&retained]).map_err(access_db_error)?;
        self.tx.execute(&format!("insert into {s}.password_recovery_start_receipts(operation_id,flow_id,request_key_id,request_digest,envelope_key_id,ciphertext,created_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8)"), &[&r.operation_id,&r.flow_id,&r.request_digest.key_id,&r.request_digest.bytes.as_slice(),&r.handle_envelope.key_id,&r.handle_envelope.ciphertext,&now,&expires]).map_err(access_db_error)?;
        let key = o.envelope.as_ref().map(|e| e.key_id.as_str());
        let ciphertext = o.envelope.as_ref().map(|e| e.ciphertext.as_slice());
        let state = if key.is_some() {
            "pending"
        } else {
            "cancelled"
        };
        let outcome: Option<&str> = if key.is_some() {
            None
        } else {
            Some("not_started")
        };
        self.tx.execute(&format!("insert into {s}.security_email_outbox(id,flow_id,envelope_key_id,ciphertext,state,created_at_epoch,expires_at_epoch,next_attempt_at_epoch,attempts,last_outcome) values($1,$2,$3,$4,$5,$6,$7,$6,0,$8)"), &[&o.id,&o.flow_id,&key,&ciphertext,&state,&now,&expires,&outcome]).map_err(access_db_error)?;
        self.tx.execute(&format!("insert into {s}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'recovery_started','accepted',$2,$3,$4)"), &[&bundle.event_id,&f.account_id,&r.operation_id,&now]).map_err(access_db_error)?;
        Ok(())
    }
}

fn validate_bundle(bundle: &RecoveryStartBundle) -> Result<(), StoreError> {
    let b = &bundle.budget;
    let f = &bundle.flow;
    let r = &bundle.receipt;
    let o = &bundle.outbox;
    if f.id.is_nil()
        || o.id.is_nil()
        || bundle.event_id.is_nil()
        || r.operation_id.is_nil()
        || f.id == o.id
        || f.id == bundle.event_id
        || o.id == bundle.event_id
        || o.flow_id != f.id
        || r.flow_id != f.id
        || b.subject_digest != f.subject_digest
        || f.account_id.is_some_and(|id| id.is_nil())
        || f.account_id.is_some() != f.snapshot_credential_version.is_some()
        || f.account_id.is_some() != o.envelope.is_some()
        || f.snapshot_credential_version
            .is_some_and(|v| v == 0 || v > i64::MAX as u64)
        || f.created_at != r.created_at
        || f.created_at != o.created_at
        || f.expires_at != r.expires_at
        || f.expires_at != o.expires_at
        || f.created_at.checked_add(Duration::from_secs(900)) != Some(f.expires_at)
        || f.created_at.checked_add(Duration::from_secs(86400)) != Some(f.retained_until)
        || b.window_start.checked_add(Duration::from_secs(3600)) != Some(b.expires_at)
        || b.window_start > f.created_at
        || b.expires_at <= f.created_at
        || !(1..=3).contains(&b.start_count)
        || b.failure_count > 10
    {
        return Err(invalid());
    }
    Ok(())
}

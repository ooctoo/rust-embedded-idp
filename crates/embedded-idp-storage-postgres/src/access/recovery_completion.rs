use super::{access_db_error, epoch, time, PostgresAccessStore};
use crate::{security_runtime::check_runtime_in_transaction, PgTransaction};
use embedded_idp_core::{access::*, SecretString, SecurityDigest, StoreError};
use std::time::SystemTime;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

pub struct PostgresRecoveryCompletionTransaction<'a> {
    tx: PgTransaction<'a>,
    schema: &'a str,
    flow_id: Option<Uuid>,
    account: Option<RecoveryAccountSnapshot>,
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
impl RecoveryCompletionStore for PostgresAccessStore {
    type Transaction<'a> = PostgresRecoveryCompletionTransaction<'a>;
    fn recovery_completion_transaction<R>(
        &self,
        mode: TenancyMode,
        authority: &str,
        flow_id: Option<Uuid>,
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
        let account = if let Some(flow) = flow_id {
            let id = tx
                .query_opt(
                    &format!("select account_id from {schema}.password_recovery_flows where id=$1"),
                    &[&flow],
                )
                .map_err(access_db_error)?
                .and_then(|r| r.get::<_, Option<Uuid>>(0));
            if let Some(id) = id {
                super::recovery_account::lock_recovery_account(&mut tx, schema, mode, id)?
            } else {
                None
            }
        } else {
            None
        };
        let mut transaction = PostgresRecoveryCompletionTransaction {
            tx,
            schema,
            flow_id,
            account,
        };
        let result = run(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}
impl RecoveryCompletionTransaction for PostgresRecoveryCompletionTransaction<'_> {
    fn receipt(
        &mut self,
        operation_id: Uuid,
    ) -> Result<Option<SecurityOperationReceipt>, StoreError> {
        self.tx.query_opt(&format!("select account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch from {}.security_receipts where purpose='password_recovery' and operation_id=$1",self.schema), &[&operation_id]).map_err(access_db_error)?.map(|row| Ok(SecurityOperationReceipt {
            purpose: SecurityReceiptPurpose::PasswordRecovery, operation_id, account_id: row.get::<_,Uuid>(0).to_string(), secret_digest: digest(row.get(1),row.get(2))?, command_digest: digest(row.get(3),row.get(4))?, completed_at: time(row.get(5))?, expires_at: time(row.get(6))?,
        })).transpose()
    }
    fn context(&mut self, flow_id: Uuid) -> Result<Option<RecoveryCompletionContext>, StoreError> {
        if self.flow_id != Some(flow_id) {
            return Err(invalid());
        }
        let s = self.schema;
        let Some(subject_row) = self
            .tx
            .query_opt(
                &format!("select subject_digest from {s}.password_recovery_flows where id=$1"),
                &[&flow_id],
            )
            .map_err(access_db_error)?
        else {
            return Ok(None);
        };
        let subject: Vec<u8> = subject_row.get(0);
        let subject_digest: [u8; 32] = subject.as_slice().try_into().map_err(|_| invalid())?;
        let b = self.tx.query_opt(&format!("select window_start_epoch,expires_at_epoch,start_count,failure_count from {s}.password_recovery_budgets where subject_digest=$1 for update"), &[&subject]).map_err(access_db_error)?.ok_or_else(invalid)?;
        let budget = RecoveryBudget {
            subject_digest,
            window_start: time(b.get(0))?,
            expires_at: time(b.get(1))?,
            start_count: u32::try_from(b.get::<_, i32>(2)).map_err(|_| invalid())?,
            failure_count: u32::try_from(b.get::<_, i32>(3)).map_err(|_| invalid())?,
        };
        let row = self.tx.query_opt(&format!("select account_id,snapshot_credential_version,handle_key_id,handle_digest,code_key_id,code_digest,created_at_epoch,expires_at_epoch,retained_until_epoch,state,failed_attempts from {s}.password_recovery_flows where id=$1 for update"), &[&flow_id]).map_err(access_db_error)?.ok_or_else(invalid)?;
        let state = match row.get::<_, String>(9).as_str() {
            "pending" => RecoveryFlowState::Pending,
            "consumed" => RecoveryFlowState::Consumed,
            "invalidated" => RecoveryFlowState::Invalidated,
            "expired" => RecoveryFlowState::Expired,
            _ => return Err(invalid()),
        };
        Ok(Some(RecoveryCompletionContext {
            flow: RecoveryStartFlow {
                id: flow_id,
                subject_digest,
                account_id: row.get(0),
                snapshot_credential_version: row
                    .get::<_, Option<i64>>(1)
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| invalid())?,
                handle_digest: digest(row.get(2), row.get(3))?,
                code_digest: digest(row.get(4), row.get(5))?,
                created_at: time(row.get(6))?,
                expires_at: time(row.get(7))?,
                retained_until: time(row.get(8))?,
            },
            state,
            failed_attempts: u32::try_from(row.get::<_, i32>(10)).map_err(|_| invalid())?,
            budget,
            account: self.account.clone(),
        }))
    }
    fn record_failure(
        &mut self,
        flow_id: Uuid,
        budget: &RecoveryBudget,
        failed_attempts: u32,
        now: SystemTime,
        event_id: Uuid,
    ) -> Result<(), StoreError> {
        if self.flow_id != Some(flow_id)
            || event_id.is_nil()
            || !(1..=5).contains(&failed_attempts)
            || budget.failure_count == 0
            || budget.failure_count > 10
            || budget.start_count > 3
        {
            return Err(invalid());
        }
        let s = self.schema;
        let now = epoch(now)?;
        let start = epoch(budget.window_start)?;
        let expires = epoch(budget.expires_at)?;
        if start > now || expires - start != 3600 || expires <= now {
            return Err(invalid());
        }
        let changed=self.tx.execute(&format!("update {s}.password_recovery_flows set failed_attempts=$2,state=case when $2=5 then 'invalidated' else state end where id=$1 and state='pending' and failed_attempts=$2-1 and subject_digest=$3 and expires_at_epoch>$4"), &[&flow_id,&(failed_attempts as i32),&budget.subject_digest.as_slice(),&now]).map_err(access_db_error)?;
        if changed != 1 {
            return Err(invalid());
        }
        let changed=self.tx.execute(&format!("update {s}.password_recovery_budgets set window_start_epoch=$2,expires_at_epoch=$3,start_count=$4,failure_count=$5 where subject_digest=$1"), &[&budget.subject_digest.as_slice(),&start,&expires,&(budget.start_count as i32),&(budget.failure_count as i32)]).map_err(access_db_error)?;
        if changed != 1 {
            return Err(invalid());
        }
        if failed_attempts == 5 {
            self.tx.execute(&format!("update {s}.security_email_outbox set state='cancelled',last_outcome=case when state='sending' then 'unknown' else 'not_started' end,envelope_key_id=null,ciphertext=null,lease_token=null,lease_until_epoch=null where flow_id=$1 and state in ('pending','sending')"), &[&flow_id]).map_err(access_db_error)?;
        }
        self.tx.execute(&format!("insert into {s}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) select $1,'recovery_failed','rejected',account_id,null,$3 from {s}.password_recovery_flows where id=$2"), &[&event_id,&flow_id,&now]).map_err(access_db_error)?;
        Ok(())
    }
    fn receipt_count(&mut self) -> Result<u64, StoreError> {
        let n: i64 = self
            .tx
            .query_one(
                &format!("select count(*) from {}.security_receipts", self.schema),
                &[],
            )
            .map_err(access_db_error)?
            .get(0);
        n.try_into().map_err(|_| invalid())
    }
    fn complete(
        &mut self,
        flow_id: Uuid,
        account_id: Uuid,
        expected_version: u64,
        new_hash: &SecretString,
        now: SystemTime,
        receipt: &SecurityOperationReceipt,
        event_id: Uuid,
    ) -> Result<(), StoreError> {
        if self.flow_id != Some(flow_id)
            || account_id.is_nil()
            || event_id.is_nil()
            || receipt.operation_id.is_nil()
            || receipt.purpose != SecurityReceiptPurpose::PasswordRecovery
            || receipt.account_id != account_id.to_string()
            || receipt.completed_at != now
            || new_hash.expose_secret().is_empty()
        {
            return Err(invalid());
        }
        let version = i64::try_from(expected_version).map_err(|_| invalid())?;
        if version <= 0 {
            return Err(invalid());
        }
        let now = epoch(now)?;
        let expires = epoch(receipt.expires_at)?;
        if expires.checked_sub(now) != Some(86400) {
            return Err(invalid());
        }
        let s = self.schema;
        let changed=self.tx.execute(&format!("update {s}.password_recovery_flows set state='consumed' where id=$1 and account_id=$2 and snapshot_credential_version=$3 and state='pending' and expires_at_epoch>$4 and failed_attempts<5"), &[&flow_id,&account_id,&version,&now]).map_err(access_db_error)?;
        if changed != 1 {
            return Err(StoreError::Conflict("recovery.changed"));
        }
        let changed=self.tx.execute(&format!("update {s}.accounts set password_hash=$3 where id=$1 and security_credential_version=$2 and status='active'"), &[&account_id,&version,&new_hash.expose_secret()]).map_err(access_db_error)?;
        if changed != 1 {
            return Err(StoreError::Conflict("recovery.changed"));
        }
        super::password_retirement::retire_account_credentials(&mut self.tx, s, account_id, now)?;
        self.tx.execute(&format!("insert into {s}.security_receipts(purpose,operation_id,account_id,secret_key_id,secret_digest,command_key_id,command_digest,completed_at_epoch,expires_at_epoch) values('password_recovery',$1,$2,$3,$4,$5,$6,$7,$8)"), &[&receipt.operation_id,&account_id,&receipt.secret_digest.key_id,&receipt.secret_digest.bytes.as_slice(),&receipt.command_digest.key_id,&receipt.command_digest.bytes.as_slice(),&now,&expires]).map_err(access_db_error)?;
        self.tx.execute(&format!("insert into {s}.security_events(id,kind,outcome,account_id,operation_id,occurred_at_epoch) values($1,'recovery_completed','accepted',$2,$3,$4)"), &[&event_id,&account_id,&receipt.operation_id,&now]).map_err(access_db_error)?;
        Ok(())
    }
}

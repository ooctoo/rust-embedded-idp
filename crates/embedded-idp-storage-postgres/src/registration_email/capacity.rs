use super::{support::*, *};
use postgres::Row;

impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    /// P owns only global admission and an operation reservation; never an account lock.
    pub(super) fn reserve(
        &self,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
        digest: &[u8],
        rows: i64,
    ) -> Result<i64, RegistrationEmailError> {
        let mut client = self.connect()?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        if kind == RegistrationEmailOperationKind::Register {
            self.ensure_registration_open(&mut tx)?;
        } else if kind == RegistrationEmailOperationKind::Resend {
            self.require_runtime_open(&mut tx)?;
        }
        let at = now(&mut tx)?;
        check_registration_operation_freshness(&operation, at)?;
        let cap = tx
            .query_one(
                &format!(
                    "select * from {} where authority=$1 for update",
                    self.table("capacity")
                ),
                &[&self.scope.authority],
            )
            .map_err(db)?;
        if cap.get::<_, i64>("last_time") > at {
            return Err(RegistrationEmailError::Unavailable);
        }
        let mut reclaim = None;
        if let Some(old) = self.operation(&mut tx, kind, operation)? {
            self.check_digest(&old, digest)?;
            if old.get::<_, String>("phase") == "attached"
                || (old.get::<_, String>("phase") == "reserved"
                    && old.get::<_, i64>("lease_until") > at)
            {
                let fence = old.get("fence");
                tx.commit().map_err(db)?;
                return Ok(fence);
            }
            // NOWAIT prevents P from holding the global row while a private transaction finishes.
            tx.batch_execute("savepoint registration_reclaim")
                .map_err(db)?;
            let locked=tx.query_one(&format!("select phase,fence,reserved_rows from {} where authority=$1 and product=$2 and kind=$3 and operation_id=$4 for update nowait",self.table("operations")),&[&self.scope.authority,&self.scope.product,&kind.as_str(),&operation]).map_err(db)?;
            if locked.get::<_, String>("phase") == "attached" {
                let fence = locked.get("fence");
                tx.commit().map_err(db)?;
                return Ok(fence);
            }
            reclaim = Some((
                locked.get::<_, i64>("fence"),
                locked.get::<_, i64>("reserved_rows"),
                locked.get::<_, String>("phase") == "reserved",
            ));
        }
        let counters=tx.query_one(&format!("select
            (select count(*) from {} where authority=$1)+(select coalesce(sum(case when phase='attached' then 1 else reserved_rows end),0)::bigint from {} where authority=$1 and kind<>'verify') as starts,
            (select coalesce(sum(case when phase='attached' then 1 else reserved_rows end),0)::bigint from {} where authority=$1 and kind='verify') as verifies,
            (select count(*) from {} where authority=$1)+(select count(*) from {} where authority=$1 and phase='reserved' and kind<>'verify') as subjects,
            (select count(*) from {} where authority=$1 and product=$2)+(select count(*) from {} where authority=$1 and product=$2 and phase='reserved' and kind<>'verify') as buckets",
            self.table("contexts"),self.table("operations"),self.table("operations"),self.table("subjects"),self.table("operations"),self.table("buckets"),self.table("operations")),&[&self.scope.authority,&self.scope.product]).map_err(db)?;
        let mut all: Vec<i64> = cap.get("all_times");
        let mut starts: Vec<i64> = cap.get("start_times");
        if all.iter().chain(&starts).any(|t| *t > at) {
            return Err(RegistrationEmailError::Unavailable);
        }
        trim_rolling_history(
            &mut all,
            at,
            self.policy.authority_new_operation_window_secs,
        );
        trim_rolling_history(
            &mut starts,
            at,
            self.policy.authority_new_operation_window_secs,
        );
        let verify = kind == RegistrationEmailOperationKind::Verify;
        let extra = rows - reclaim.map_or(0, |(_, reserved, _)| reserved);
        let bucket_extra = if reclaim.is_some_and(|(_, _, reserved)| reserved) {
            0
        } else {
            1
        };
        if (reclaim.is_none()
            && (all.len() >= self.policy.authority_new_operation_limit as usize
                || (!verify
                    && starts.len() >= self.policy.authority_new_operation_start_ceiling as usize)))
            || (verify
                && counters.get::<_, i64>("verifies") + extra
                    > self.policy.durable_context_receipts_verify_reserve as i64)
            || (!verify
                && (counters.get::<_, i64>("starts") + extra
                    > (self.policy.durable_context_receipts_cap
                        - self.policy.durable_context_receipts_verify_reserve)
                        as i64
                    || (counters.get::<_, i64>("subjects") + bucket_extra
                        > self.policy.authority_subject_bucket_cap as i64)
                    || (counters.get::<_, i64>("buckets") + bucket_extra
                        > self.policy.product_subject_bucket_cap as i64)))
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        if reclaim.is_none() {
            all.push(at);
            if !verify {
                starts.push(at)
            }
        }
        tx.execute(&format!("update {} set all_times=$2,start_times=$3,last_time=$4,start_rows=$5,verify_rows=$6,subjects=$7,buckets=$8 where authority=$1",self.table("capacity")),&[&self.scope.authority,&all,&starts,&at,&counters.get::<_,i64>("starts"),&counters.get::<_,i64>("verifies"),&counters.get::<_,i64>("subjects"),&counters.get::<_,i64>("buckets")]).map_err(db)?;
        let lease = at + self.policy.capacity_reservation_lease_secs;
        let retain = at
            + self.policy.operation_id_max_age_secs
            + self.policy.operation_id_future_skew_secs
            + self.policy.attempt_replay_grace_secs;
        if let Some((fence, _, _)) = reclaim {
            let next = fence + 1;
            tx.execute(&format!("update {} set phase='reserved',reserved_rows=$5,lease_until=$6,fence=$7 where authority=$1 and product=$2 and kind=$3 and operation_id=$4",self.table("operations")),&[&self.scope.authority,&self.scope.product,&kind.as_str(),&operation,&rows,&lease,&next]).map_err(db)?;
            tx.commit().map_err(db)?;
            return Ok(next);
        }
        tx.execute(&format!("insert into {}(authority,product,kind,operation_id,request_digest,phase,reserved_rows,lease_until,fence,retain_until) values($1,$2,$3,$4,$5,'reserved',$6,$7,1,$8)",self.table("operations")),&[&self.scope.authority,&self.scope.product,&kind.as_str(),&operation,&digest,&rows,&lease,&retain]).map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(1)
    }
    pub(super) fn lock_operation(
        &self,
        tx: &mut transport::Transaction<'_>,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
        digest: &[u8],
        fence: i64,
    ) -> Result<Row, RegistrationEmailError> {
        let row=tx.query_one(&format!("select * from {} where authority=$1 and product=$2 and kind=$3 and operation_id=$4 for update",self.table("operations")),&[&self.scope.authority,&self.scope.product,&kind.as_str(),&operation]).map_err(db)?;
        self.check_digest(&row, digest)?;
        if row.get::<_, i64>("fence") != fence || row.get::<_, String>("phase") == "cancelled" {
            return Err(RegistrationEmailError::Unavailable);
        }
        if row.get::<_, String>("phase") == "reserved"
            && row.get::<_, i64>("lease_until") <= now(tx)?
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        Ok(row)
    }
    pub(super) fn early_operation(
        &self,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
        digest: &[u8],
    ) -> Result<Option<Row>, RegistrationEmailError> {
        let mut client = self.connect_readonly()?;
        let mut tx = client.transaction().map_err(db)?;
        tx.batch_execute("set transaction read only; set local transaction_timeout='5s'; set local statement_timeout='5s'; set local lock_timeout='1s'").map_err(db)?;
        check_registration_operation_freshness(&operation, now(&mut tx)?)?;
        if let Some(row) = self.operation(&mut tx, kind, operation)? {
            self.check_digest(&row, digest)?;
            if row.get::<_, String>("phase") == "attached" {
                tx.commit().map_err(db)?;
                return Ok(Some(row));
            }
        }
        Ok(None)
    }
}

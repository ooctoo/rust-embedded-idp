use super::super::{support::*, *};

impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    /// Explicit bounded upkeep, never invoked by startup or readiness.
    pub fn maintain(&self, limit: i64) -> Result<u64, RegistrationEmailError> {
        if !(1..=200).contains(&limit) {
            return Err(RegistrationEmailError::InvalidInput("maintenance_limit"));
        }
        self.phase_cancel_and_receipts(limit)?;
        self.phase_reap_work(limit)?;
        self.phase_clear_candidates(limit)?;
        let removed = self.phase_gc_contexts(limit)?;
        self.phase_gc_scope_state(limit)?;
        Ok(removed)
    }

    fn phase_cancel_and_receipts(&self, limit: i64) -> Result<(), RegistrationEmailError> {
        let mut client = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let at = now(&mut tx)?;

        tx.execute(
            &format!(
                "with candidates as ( \
                   select authority,product,kind,operation_id \
                   from {} \
                   where authority=$1 and product=$2 and phase='reserved' and lease_until<=$3 \
                   order by lease_until,operation_id \
                   limit $4 for update skip locked \
                 ) \
                 update {} o set phase='cancelled',fence=fence+1,reserved_rows=1 \
                 from candidates c \
                 where (o.authority,o.product,o.kind,o.operation_id)= \
                       (c.authority,c.product,c.kind,c.operation_id)",
                self.table("operations"),
                self.table("operations")
            ),
            &[&self.scope.authority, &self.scope.product, &at, &limit],
        )
        .map_err(db)?;

        // Expired SMTP leases become unknown. The payload is cleared, but the
        // unknown row remains counted until physical stop evidence arrives.
        tx.execute(
            &format!(
                "with candidates as ( \
                   select d.id \
                   from {} d join {} x on x.id=d.context_id \
                   where x.authority=$1 and x.product=$2 and d.status='claimed' \
                     and d.lease_until<=$3 \
                   order by d.lease_until,d.id \
                   limit $4 for update of d skip locked \
                 ) \
                 update {} d set status='unknown',payload_cipher=''::bytea \
                 from candidates c where d.id=c.id",
                self.table("deliveries"),
                self.table("contexts"),
                self.table("deliveries")
            ),
            &[&self.scope.authority, &self.scope.product, &at, &limit],
        )
        .map_err(db)?;

        // A reserved delivery has no external claim. Once its context expires,
        // clear its encrypted payload before context GC can remove the row.
        tx.execute(
            &format!(
                "with candidates as ( \
                   select d.id \
                   from {} d join {} x on x.id=d.context_id \
                   where x.authority=$1 and x.product=$2 and d.status='reserved' \
                     and x.expires_at<=$3 \
                   order by x.expires_at,d.id \
                   limit $4 for update of d skip locked \
                 ) \
                 update {} d set status='expired',payload_cipher=''::bytea,stop_confirmed=true \
                 from candidates c where d.id=c.id",
                self.table("deliveries"),
                self.table("contexts"),
                self.table("deliveries")
            ),
            &[&self.scope.authority, &self.scope.product, &at, &limit],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
    }

    fn phase_reap_work(&self, limit: i64) -> Result<(), RegistrationEmailError> {
        let mut client = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let at = now(&mut tx)?;
        tx.execute(
            &format!(
                "with candidates as ( \
                   select authority,product,kind,operation_id \
                   from {} \
                   where authority=$1 and product=$2 and retain_until<$3 \
                   order by retain_until,operation_id \
                   limit $4 for update skip locked \
                 ) \
                 delete from {} o using candidates c \
                 where (o.authority,o.product,o.kind,o.operation_id)= \
                       (c.authority,c.product,c.kind,c.operation_id)",
                self.table("operations"),
                self.table("operations")
            ),
            &[&self.scope.authority, &self.scope.product, &at, &limit],
        )
        .map_err(db)?;

        let event_cutoff = at - self.policy.anonymous_security_event_retention_days as i64 * 86_400;
        tx.execute(
            &format!(
                "with candidates as ( \
                   select id \
                   from {} \
                   where authority=$1 and product=$2 and created_at<$3 \
                   order by created_at,id \
                   limit $4 for update skip locked \
                 ) \
                 delete from {} e using candidates c where e.id=c.id",
                self.table("events"),
                self.table("events")
            ),
            &[
                &self.scope.authority,
                &self.scope.product,
                &event_cutoff,
                &limit,
            ],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
    }
}

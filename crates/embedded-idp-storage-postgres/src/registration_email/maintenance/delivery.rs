use super::super::{support::*, *};
use postgres::{Row, Transaction};

impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    /// No network effect: only the IDP delivery adapter can consume this claim.
    pub fn claim_delivery(
        &self,
        effect: Uuid,
    ) -> Result<Option<RegistrationEmailDeliveryClaim>, RegistrationEmailError> {
        let mut client = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        let candidate = tx
            .query_opt(
                &format!(
                    "select d.context_id from {} d join {} x on x.id=d.context_id \
                     where d.id=$1 and x.authority=$2 and x.product=$3",
                    self.table("deliveries"),
                    self.table("contexts")
                ),
                &[&effect, &self.scope.authority, &self.scope.product],
            )
            .map_err(db)?;
        let Some(candidate) = candidate else {
            tx.rollback().map_err(db)?;
            return Ok(None);
        };
        let id: Uuid = candidate.get(0);
        let Some(ctx) = self.try_context(&mut tx, id)? else {
            tx.rollback().map_err(db)?;
            return Ok(None);
        };
        let global: bool = tx
            .query_one(
                "select pg_try_advisory_xact_lock(hashtextextended($1,914235))",
                &[&format!("registration-smtp:{}", self.scope.authority)],
            )
            .map_err(db)?
            .get(0);
        if !global {
            tx.rollback().map_err(db)?;
            return Ok(None);
        }
        let active: i64 = tx
            .query_one(
                &format!(
                    "select count(*) from {} d join {} x on x.id=d.context_id \
                     where x.authority=$1 and (d.status='claimed' \
                       or (d.status='unknown' and not d.stop_confirmed))",
                    self.table("deliveries"),
                    self.table("contexts")
                ),
                &[&self.scope.authority],
            )
            .map_err(db)?
            .get(0);
        if active >= self.policy.smtp_concurrency as i64 {
            tx.rollback().map_err(db)?;
            return Ok(None);
        }
        let work = tx
            .query_one(
                &format!(
                    "select * from {} where id=$1 for update",
                    self.table("deliveries")
                ),
                &[&effect],
            )
            .map_err(db)?;
        let at = now(&mut tx)?;
        let seq: i64 = work.get("seq");
        if work.get::<_, String>("status") != "reserved" {
            tx.rollback().map_err(db)?;
            return Ok(None);
        }
        if ctx.get::<_, i64>("expires_at") <= at
            || ctx.get::<_, Option<i64>>("current_seq") != Some(seq)
            || ctx.get::<_, Option<Uuid>>("completed_operation").is_some()
        {
            tx.execute(
                &format!(
                    "update {} set status='expired',payload_cipher=''::bytea, \
                     stop_confirmed=true where id=$1",
                    self.table("deliveries")
                ),
                &[&effect],
            )
            .map_err(db)?;
            tx.commit().map_err(db)?;
            return Ok(None);
        }
        let token = Uuid::now_v7();
        let lease = (at + self.policy.smtp_lease_secs).min(ctx.get("expires_at"));
        tx.execute(
            &format!(
                "update {} set status='claimed',claim_token=$2,lease_until=$3 where id=$1",
                self.table("deliveries")
            ),
            &[&effect, &token, &lease],
        )
        .map_err(db)?;
        let intent = tx
            .query_one(
                &format!(
                    "select kind,operation_id from {} where context_id=$1 and seq=$2",
                    self.table("intents")
                ),
                &[&id, &seq],
            )
            .map_err(db)?;
        self.event(
            &mut tx,
            intent.get("operation_id"),
            delivery_kind(&intent)?,
            None,
            Some(id),
            "claimed",
            at,
        )?;
        tx.commit().map_err(db)?;
        Ok(Some(RegistrationEmailDeliveryClaim {
            effect_id: effect,
            context_id: id,
            sequence: seq,
            claim_token: token,
            lease_until: lease,
        }))
    }

    pub fn finish_delivery(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
        result: RegistrationEmailDeliveryResult,
    ) -> Result<(), RegistrationEmailError> {
        let mut client = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let row = self.locked_delivery(&mut tx, claim.effect_id, "claimed")?;
        let Some(row) = row else {
            return Err(RegistrationEmailError::Unavailable);
        };
        self.check_claim(&row, claim)?;
        let at = now(&mut tx)?;
        let lease: i64 = row
            .get::<_, Option<i64>>("lease_until")
            .ok_or(RegistrationEmailError::Unavailable)?;
        let context: Uuid = row.get("context_id");
        let kind = delivery_kind(&row)?;
        let status = if at >= lease || result == RegistrationEmailDeliveryResult::Unknown {
            "unknown"
        } else {
            match result {
                RegistrationEmailDeliveryResult::Sent => "sent",
                RegistrationEmailDeliveryResult::Failed => "failed",
                RegistrationEmailDeliveryResult::Unknown => "unknown",
            }
        };
        let stopped = result != RegistrationEmailDeliveryResult::Unknown;
        let n = tx
            .execute(
                &format!(
                    "update {} set status=$3,stop_confirmed=$4,payload_cipher=''::bytea \
                     where id=$1 and claim_token=$2 and status='claimed'",
                    self.table("deliveries")
                ),
                &[&claim.effect_id, &claim.claim_token, &status, &stopped],
            )
            .map_err(db)?;
        if n != 1 {
            return Err(RegistrationEmailError::Unavailable);
        }
        self.event(
            &mut tx,
            row.get("operation_id"),
            kind,
            None,
            Some(context),
            status,
            at,
        )?;
        tx.commit().map_err(db)
    }

    /// Trusted operator/effect evidence only; never an unauthenticated HTTP operation.
    pub fn confirm_delivery_stopped(
        &self,
        claim: &RegistrationEmailDeliveryClaim,
    ) -> Result<(), RegistrationEmailError> {
        let mut client = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let row = self.locked_delivery(&mut tx, claim.effect_id, "unknown")?;
        let Some(row) = row else {
            return Err(RegistrationEmailError::Unavailable);
        };
        self.check_claim(&row, claim)?;
        let context: Uuid = row.get("context_id");
        let kind = delivery_kind(&row)?;
        let n = tx
            .execute(
                &format!(
                    "update {} set stop_confirmed=true where id=$1 and claim_token=$2 \
                     and status='unknown'",
                    self.table("deliveries")
                ),
                &[&claim.effect_id, &claim.claim_token],
            )
            .map_err(db)?;
        if n != 1 {
            return Err(RegistrationEmailError::Unavailable);
        }
        let at = now(&mut tx)?;
        self.event(
            &mut tx,
            row.get("operation_id"),
            kind,
            None,
            Some(context),
            "stop_confirmed",
            at,
        )?;
        tx.commit().map_err(db)
    }

    fn locked_delivery(
        &self,
        tx: &mut Transaction<'_>,
        effect: Uuid,
        status: &str,
    ) -> Result<Option<Row>, RegistrationEmailError> {
        tx.query_opt(
            &format!(
                "select d.claim_token,d.context_id,d.seq,d.lease_until,d.status,i.kind,i.operation_id \
                 from {} d join {} x on x.id=d.context_id \
                 join {} i on i.context_id=d.context_id and i.seq=d.seq \
                 where d.id=$1 and x.authority=$2 and x.product=$3 and d.status=$4 \
                 for update of d",
                self.table("deliveries"),
                self.table("contexts"),
                self.table("intents")
            ),
            &[&effect, &self.scope.authority, &self.scope.product, &status],
        )
        .map_err(db)
    }

    fn check_claim(
        &self,
        row: &Row,
        claim: &RegistrationEmailDeliveryClaim,
    ) -> Result<(), RegistrationEmailError> {
        let token: Option<Uuid> = row.get("claim_token");
        let context: Uuid = row.get("context_id");
        let sequence: i64 = row.get("seq");
        let lease: Option<i64> = row.get("lease_until");
        if token != Some(claim.claim_token)
            || context != claim.context_id
            || sequence != claim.sequence
            || lease != Some(claim.lease_until)
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        Ok(())
    }
}

fn delivery_kind(row: &Row) -> Result<RegistrationEmailOperationKind, RegistrationEmailError> {
    match row.get::<_, String>("kind").as_str() {
        "register" => Ok(RegistrationEmailOperationKind::Register),
        "resend" => Ok(RegistrationEmailOperationKind::Resend),
        _ => Err(RegistrationEmailError::Unavailable),
    }
}

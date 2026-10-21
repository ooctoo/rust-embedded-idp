use super::*;
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub(super) fn claim_next_preparation(
        &self,
    ) -> Result<Option<RegistrationEmailPreparationClaim>, RegistrationEmailError> {
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        let rows=tx.query(&format!("select i.context_id,i.seq from {} i join {} x on x.id=i.context_id where x.authority=$1 and x.product=$2 and x.tenant_id=$3 and i.status='reserved' and i.claim_token is null order by i.created_at,i.context_id,i.seq limit 32",self.table("intents"),self.table("contexts")),&[&self.scope.authority,&self.scope.product,&self.scope.tenant]).map_err(db)?;
        tx.commit().map_err(db)?;
        for row in rows {
            if let Some(claim) = self.claim_specific_preparation(row.get(0), row.get(1))? {
                return Ok(Some(claim));
            }
        }
        Ok(None)
    }
    pub(in crate::registration_email) fn claim_specific_preparation(
        &self,
        context: Uuid,
        sequence: i64,
    ) -> Result<Option<RegistrationEmailPreparationClaim>, RegistrationEmailError> {
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        self.require_runtime_open(&mut tx)?;
        let Some(ctx) = self.try_context(&mut tx, context)? else {
            return Ok(None);
        };
        if ctx.get::<_, String>("authority") != self.scope.authority
            || ctx.get::<_, String>("product") != self.scope.product
            || ctx.get::<_, String>("tenant_id") != self.scope.tenant
        {
            return Ok(None);
        }
        let got: bool = tx
            .query_one(
                "select pg_try_advisory_xact_lock(hashtextextended($1,914236))",
                &[&format!("registration-claim:{}", self.scope.authority)],
            )
            .map_err(db)?
            .get(0);
        if !got {
            return Ok(None);
        }
        let at = now(&mut tx)?;
        let active:i64=tx.query_one(&format!("select count(*) from {} i join {} x on x.id=i.context_id where x.authority=$1 and i.status='reserved' and i.claim_token is not null and i.lease_until>$2",self.table("intents"),self.table("contexts")),&[&self.scope.authority,&at]).map_err(db)?.get(0);
        if active >= self.policy.processing_concurrency as i64 {
            return Ok(None);
        }
        let Some(row)=tx.query_opt(&format!("select status,claim_token,lease_until from {} where context_id=$1 and seq=$2 for update",self.table("intents")),&[&context,&sequence]).map_err(db)? else{return Ok(None)};
        let status: String = row.get("status");
        let token: Option<Uuid> = row.get("claim_token");
        let existing: Option<i64> = row.get("lease_until");
        if status == "prepared" {
            if let (Some(token), Some(lease)) = (token, existing) {
                return Ok(Some(RegistrationEmailPreparationClaim {
                    context_id: context,
                    sequence,
                    claim_token: token,
                    lease_until: lease,
                }));
            }
            return Ok(None);
        }
        if status != "reserved" || token.is_some() || ctx.get::<_, i64>("expires_at") <= at {
            return Ok(None);
        }
        let token = Uuid::now_v7();
        let lease = (at + self.policy.processing_lease_secs).min(ctx.get("expires_at"));
        tx.execute(
            &format!(
                "update {} set claim_token=$3,lease_until=$4 where context_id=$1 and seq=$2",
                self.table("intents")
            ),
            &[&context, &sequence, &token, &lease],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(Some(RegistrationEmailPreparationClaim {
            context_id: context,
            sequence,
            claim_token: token,
            lease_until: lease,
        }))
    }
}

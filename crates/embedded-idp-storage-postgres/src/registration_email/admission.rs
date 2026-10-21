use super::{support::*, *};
use postgres::{Row, Transaction};
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub fn register(
        &self,
        prepared: &PreparedRegistrationEmail,
    ) -> Result<RegistrationEmailAccepted, RegistrationEmailError> {
        if prepared.scope() != &self.scope {
            return Err(RegistrationEmailError::InvalidInput("scope"));
        }
        let op = prepared.operation();
        let kind = RegistrationEmailOperationKind::Register;
        if let Some(row) = self.early_operation(kind, op, prepared.request())? {
            let mut c = self
                .adapter
                .connect()
                .map_err(RegistrationEmailError::Store)?;
            return self.acceptance(&mut *c, &row);
        }
        let fence = self.reserve(kind, op, prepared.request(), 2)?;
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        self.ensure_registration_open(&mut tx)?;
        let old = self.lock_operation(&mut tx, kind, op, prepared.request(), fence)?;
        if old.get::<_, String>("phase") == "attached" {
            let result = self.acceptance(&mut tx, &old)?;
            tx.commit().map_err(db)?;
            return Ok(result);
        }
        let at = now(&mut tx)?;
        let expiry = at + self.policy.context_lifetime_secs;
        let permit = self.send_permit(&mut tx, prepared.subject(), at, true)?;
        tx.execute(&format!("insert into {}(id,authority,product,tenant_id,subject,lookup_digest,seed,email_cipher,password_cipher,accepted_at,expires_at,deliverable,wrong_count,accepted_seq,prepared) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,0,1,false)",self.table("contexts")),&[&prepared.context(),&self.scope.authority,&self.scope.product,&self.scope.tenant,&prepared.subject().as_slice(),&prepared.lookup().as_slice(),&prepared.seed().as_slice(),&prepared.email_cipher(),&prepared.password_cipher(),&at,&expiry,&permit]).map_err(db)?;
        if permit {
            self.intent(&mut tx, prepared.context(), 1, kind, op, at)?
        }
        self.finish_operation(
            &mut tx,
            kind,
            op,
            Some(prepared.context()),
            "accepted",
            at,
            expiry,
        )?;
        self.event(
            &mut tx,
            op,
            kind,
            Some(prepared.subject()),
            Some(prepared.context()),
            "accepted",
            at,
        )?;
        tx.commit().map_err(db)?;
        Ok(RegistrationEmailAccepted {
            verification_context: self.crypto.context_token(&self.scope, prepared.seed()),
            accepted_at_unix_secs: at,
            context_lifetime_secs: self.policy.context_lifetime_secs,
            resend_after_secs: self.policy.product_email_send_gap_secs,
        })
    }
    pub fn resend(&self, operation: Uuid, token: &str) -> Result<(), RegistrationEmailError> {
        validate_token(token)?;
        let kind = RegistrationEmailOperationKind::Resend;
        let digest =
            self.crypto
                .request_digest(&self.scope, kind, &operation, &fields(&[token.as_bytes()]));
        if self.early_operation(kind, operation, &digest)?.is_some() {
            return Ok(());
        }
        let fence = self.reserve(kind, operation, &digest, 1)?;
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        self.ensure_registration_open(&mut tx)?;
        let old = self.lock_operation(&mut tx, kind, operation, &digest, fence)?;
        if old.get::<_, String>("phase") == "attached" {
            tx.commit().map_err(db)?;
            return Ok(());
        }
        let lookup = self.crypto.context_digest(token);
        let ctx = tx
            .query_opt(
                &format!(
                    "select * from {} where lookup_digest=$1 and authority=$2 and product=$3",
                    self.table("contexts")
                ),
                &[
                    &lookup.as_slice(),
                    &self.scope.authority,
                    &self.scope.product,
                ],
            )
            .map_err(db)?;
        let at = now(&mut tx)?;
        let mut context = None;
        let mut expiry = at;
        if let Some(ctx) = ctx {
            let id: Uuid = ctx.get("id");
            context = Some(id);
            expiry = ctx.get("expires_at");
            let subject: Vec<u8> = ctx.get("subject");
            if ctx.get::<_, bool>("deliverable")
                && expiry > at
                && ctx.get::<_, Option<Uuid>>("completed_operation").is_none()
                && ctx.get::<_, i32>("wrong_count") < self.policy.context_wrong_limit as i32
                && self.subject_lock(&mut tx, &subject)?
            {
                tx.batch_execute("savepoint registration_resend_permit")
                    .map_err(db)?;
                // Bucket locks precede context. Roll back any charge if context changed or is busy.
                let permit = self.send_permit(&mut tx, &subject, at, false)?;
                let locked = if permit {
                    self.try_context(&mut tx, id)?
                } else {
                    None
                };
                if let Some(locked) = locked.filter(|locked| {
                    locked.get::<_, bool>("deliverable")
                        && locked.get::<_, i64>("expires_at") > at
                        && locked
                            .get::<_, Option<Uuid>>("completed_operation")
                            .is_none()
                        && locked.get::<_, i32>("wrong_count")
                            < self.policy.context_wrong_limit as i32
                }) {
                    if locked.get::<_, i64>("expires_at") > now(&mut tx)? {
                        let seq = locked.get::<_, i64>("accepted_seq") + 1;
                        tx.execute(
                            &format!(
                                "update {} set accepted_seq=$2 where id=$1",
                                self.table("contexts")
                            ),
                            &[&id, &seq],
                        )
                        .map_err(db)?;
                        self.intent(&mut tx, id, seq, kind, operation, at)?;
                        tx.batch_execute("release savepoint registration_resend_permit")
                            .map_err(db)?;
                    } else {
                        tx.batch_execute("rollback to savepoint registration_resend_permit; release savepoint registration_resend_permit").map_err(db)?;
                    }
                } else {
                    tx.batch_execute("rollback to savepoint registration_resend_permit; release savepoint registration_resend_permit").map_err(db)?;
                }
            }
        }
        self.finish_operation(&mut tx, kind, operation, context, "accepted", at, expiry)?;
        self.event(&mut tx, operation, kind, None, context, "accepted", at)?;
        tx.commit().map_err(db)
    }
    pub(super) fn try_context(
        &self,
        tx: &mut Transaction<'_>,
        id: Uuid,
    ) -> Result<Option<Row>, RegistrationEmailError> {
        tx.batch_execute("savepoint registration_context_try")
            .map_err(db)?;
        match tx.query_opt(
            &format!(
                "select * from {} where id=$1 for no key update nowait",
                self.table("contexts")
            ),
            &[&id],
        ) {
            Ok(row) => {
                tx.batch_execute("release savepoint registration_context_try")
                    .map_err(db)?;
                Ok(row)
            }
            Err(e) if e.code() == Some(&postgres::error::SqlState::LOCK_NOT_AVAILABLE) => {
                tx.batch_execute("rollback to savepoint registration_context_try; release savepoint registration_context_try").map_err(db)?;
                Ok(None)
            }
            Err(e) => Err(db(e)),
        }
    }
    fn intent(
        &self,
        tx: &mut Transaction<'_>,
        id: Uuid,
        seq: i64,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
        at: i64,
    ) -> Result<(), RegistrationEmailError> {
        tx.execute(&format!("insert into {}(context_id,seq,kind,status,created_at,operation_id) values($1,$2,$3,'reserved',$4,$5)",self.table("intents")),&[&id,&seq,&kind.as_str(),&at,&operation]).map_err(db)?;
        Ok(())
    }
    pub(super) fn send_permit(
        &self,
        tx: &mut Transaction<'_>,
        subject: &[u8],
        at: i64,
        new_context: bool,
    ) -> Result<bool, RegistrationEmailError> {
        if !self.subject_lock(tx, subject)? {
            return Ok(false);
        }
        let expiry = at
            + self.policy.authority_email_send_window_24h_secs
            + self.policy.bucket_retention_extra_secs;
        tx.execute(&format!("insert into {}(authority,subject,sends,wrongs,blocked_until,last_time,retain_until) values($1,$2,'{{}}','{{}}',0,$3,$4) on conflict do nothing",self.table("subjects")),&[&self.scope.authority,&subject,&at,&expiry]).map_err(db)?;
        tx.execute(&format!("insert into {}(authority,product,subject,sends,wrongs,blocked_until,last_time,retain_until) values($1,$2,$3,'{{}}','{{}}',0,$4,$5) on conflict do nothing",self.table("buckets")),&[&self.scope.authority,&self.scope.product,&subject,&at,&expiry]).map_err(db)?;
        let authority = tx
            .query_one(
                &format!(
                    "select * from {} where authority=$1 and subject=$2 for no key update",
                    self.table("subjects")
                ),
                &[&self.scope.authority, &subject],
            )
            .map_err(db)?;
        let product=tx.query_one(&format!("select * from {} where authority=$1 and product=$2 and subject=$3 for no key update",self.table("buckets")),&[&self.scope.authority,&self.scope.product,&subject]).map_err(db)?;
        let mut a: Vec<i64> = authority.get("sends");
        let mut p: Vec<i64> = product.get("sends");
        if authority.get::<_, i64>("last_time") > at
            || product.get::<_, i64>("last_time") > at
            || a.iter().chain(&p).any(|t| *t > at)
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        if authority.get::<_, i64>("blocked_until") > at
            || product.get::<_, i64>("blocked_until") > at
        {
            return Ok(false);
        }
        trim_rolling_history(&mut a, at, self.policy.authority_email_send_window_24h_secs);
        trim_rolling_history(&mut p, at, self.policy.product_email_send_window_24h_secs);
        if a.last()
            .is_some_and(|t| at - *t < self.policy.authority_email_send_gap_secs)
            || p.last()
                .is_some_and(|t| at - *t < self.policy.product_email_send_gap_secs)
            || !rolling_allowed(
                &a,
                at,
                self.policy.authority_email_send_window_24h_secs,
                self.policy.authority_email_send_limit_24h as usize,
            )
            || !rolling_allowed(
                &p,
                at,
                self.policy.product_email_send_window_24h_secs,
                self.policy.product_email_send_limit_24h as usize,
            )
            || !rolling_allowed(
                &p,
                at,
                self.policy.product_email_send_window_30m_secs,
                self.policy.product_email_send_limit_30m as usize,
            )
        {
            return Ok(false);
        }
        if new_context {
            let slots=tx.query_one(&format!("select count(*) as all_slots,count(*) filter(where product=$2) as product_slots from {} where authority=$1 and subject=$3 and deliverable and expires_at>$4",self.table("contexts")),&[&self.scope.authority,&self.scope.product,&subject,&at]).map_err(db)?;
            if slots.get::<_, i64>("all_slots")
                >= self.policy.context_slots_per_authority_email as i64
                || slots.get::<_, i64>("product_slots")
                    >= self.policy.context_count_per_product_email as i64
            {
                return Ok(false);
            }
        }
        a.push(at);
        p.push(at);
        tx.execute(&format!("update {} set sends=$3,last_time=$4,retain_until=$5 where authority=$1 and subject=$2",self.table("subjects")),&[&self.scope.authority,&subject,&a,&at,&expiry]).map_err(db)?;
        tx.execute(&format!("update {} set sends=$4,last_time=$5,retain_until=$6 where authority=$1 and product=$2 and subject=$3",self.table("buckets")),&[&self.scope.authority,&self.scope.product,&subject,&p,&at,&expiry]).map_err(db)?;
        Ok(true)
    }
}

use super::{support::*, *};
use tokio_postgres::Row;
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub fn verify(
        &self,
        operation: Uuid,
        token: &str,
        code: &str,
    ) -> Result<RegistrationEmailVerification, RegistrationEmailError> {
        validate_token(token)?;
        if code.chars().count() > 64 {
            return Err(RegistrationEmailError::InvalidInput("verification_code"));
        }
        let kind = RegistrationEmailOperationKind::Verify;
        let digest = self.crypto.request_digest(
            &self.scope,
            kind,
            &operation,
            &fields(&[token.as_bytes(), code.as_bytes()]),
        );
        if let Some(old) = self.early_operation(kind, operation, &digest)? {
            return Ok(
                if old.get::<_, Option<String>>("result").as_deref() == Some("verified") {
                    RegistrationEmailVerification::Verified
                } else {
                    RegistrationEmailVerification::Unavailable
                },
            );
        }
        let lookup = self.crypto.context_digest(token);
        let mut c = self.connect()?;
        let initial=c.query_opt(&format!("select id,subject from {} where authority=$1 and product=$2 and lookup_digest=$3",self.table("contexts")),&[&self.scope.authority,&self.scope.product,&lookup.as_slice()]).map_err(db)?;
        let Some(initial) = initial else {
            return Ok(RegistrationEmailVerification::Unavailable);
        };
        let id: Uuid = initial.get("id");
        let subject: Vec<u8> = initial.get("subject");
        let fence = self.reserve(kind, operation, &digest, 1)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        let old = self.lock_operation(&mut tx, kind, operation, &digest, fence)?;
        if old.get::<_, String>("phase") == "attached" {
            let result = if old.get::<_, Option<String>>("result").as_deref() == Some("verified") {
                RegistrationEmailVerification::Verified
            } else {
                RegistrationEmailVerification::Unavailable
            };
            tx.commit().map_err(db)?;
            return Ok(result);
        }
        let at = now(&mut tx)?;
        let mut verified = false;
        let mut reason = "unavailable";
        let mut expiry = at;
        if self.subject_lock(&mut tx, &subject)? {
            // The subject advisory gate covers all anonymous bucket mutations, including missing rows.
            let a = tx
                .query_opt(
                    &format!(
                        "select * from {} where authority=$1 and subject=$2 for no key update",
                        self.table("subjects")
                    ),
                    &[&self.scope.authority, &subject],
                )
                .map_err(db)?;
            let p=tx.query_opt(&format!("select * from {} where authority=$1 and product=$2 and subject=$3 for no key update",self.table("buckets")),&[&self.scope.authority,&self.scope.product,&subject]).map_err(db)?;
            if let Some(ctx) = self.try_context(&mut tx, id)? {
                expiry = ctx.get("expires_at");
                if let (Some(a), Some(p), Some(seq)) =
                    (a, p, ctx.get::<_, Option<i64>>("current_seq"))
                {
                    let current = tx
                        .query_opt(
                            &format!(
                                "select * from {} where context_id=$1 and seq=$2 for no key update",
                                self.table("codes")
                            ),
                            &[&id, &seq],
                        )
                        .map_err(db)?;
                    if let Some(current) = current {
                        let checked_at = now(&mut tx)?;
                        let state = classify_registration_email_code_state(
                            true,
                            true,
                            !ctx.get::<_, bool>("deliverable"),
                            checked_at,
                            expiry,
                            Some(current.get("expires_at")),
                            ctx.get::<_, Option<Uuid>>("completed_operation").is_some()
                                || current.get::<_, Option<i64>>("consumed_at").is_some(),
                            ctx.get::<_, i32>("wrong_count") as u32,
                            self.policy.context_wrong_limit,
                        );
                        self.validate_bucket_time(&a, &p, checked_at)?;
                        if state.is_ready()
                            && current.get::<_, i64>("issued_at") <= checked_at
                            && a.get::<_, i64>("blocked_until") <= checked_at
                            && p.get::<_, i64>("blocked_until") <= checked_at
                            && rolling_allowed(
                                &a.get::<_, Vec<i64>>("wrongs"),
                                checked_at,
                                self.policy.authority_email_wrong_window_secs,
                                self.policy.authority_email_wrong_limit as usize,
                            )
                            && rolling_allowed(
                                &p.get::<_, Vec<i64>>("wrongs"),
                                checked_at,
                                self.policy.product_email_wrong_window_secs,
                                self.policy.product_email_wrong_limit as usize,
                            )
                        {
                            let actual = self.crypto.code_digest(&self.scope, &id, code);
                            if self
                                .crypto
                                .digests_equal(&actual, &current.get::<_, Vec<u8>>("digest"))
                            {
                                verified = self.activate(&mut tx, &ctx, id, checked_at)?;
                                if verified {
                                    tx.execute(&format!("update {} set consumed_at=$3 where context_id=$1 and seq=$2",self.table("codes")),&[&id,&seq,&checked_at]).map_err(db)?;
                                    tx.execute(&format!("update {} set completed_operation=$2,password_cipher=''::bytea where id=$1",self.table("contexts")),&[&id,&operation]).map_err(db)?;
                                }
                            } else {
                                self.charge_wrong(&mut tx, &a, &p, id, &subject, checked_at)?;
                                reason = "wrong_code";
                            }
                        }
                    }
                }
            }
        }
        let result = if verified { "verified" } else { "unavailable" };
        self.finish_operation(&mut tx, kind, operation, Some(id), result, at, expiry)?;
        self.event(
            &mut tx,
            operation,
            kind,
            Some(&subject),
            Some(id),
            if verified { "verified" } else { reason },
            at,
        )?;
        tx.commit().map_err(db)?;
        Ok(if verified {
            RegistrationEmailVerification::Verified
        } else {
            RegistrationEmailVerification::Unavailable
        })
    }
    fn validate_bucket_time(
        &self,
        a: &Row,
        p: &Row,
        at: i64,
    ) -> Result<(), RegistrationEmailError> {
        let aw: Vec<i64> = a.get("wrongs");
        let pw: Vec<i64> = p.get("wrongs");
        if a.get::<_, i64>("last_time") > at
            || p.get::<_, i64>("last_time") > at
            || aw.iter().chain(&pw).any(|t| *t > at)
        {
            return Err(RegistrationEmailError::Unavailable);
        }
        Ok(())
    }
    fn charge_wrong(
        &self,
        tx: &mut transport::Transaction<'_>,
        a: &Row,
        p: &Row,
        id: Uuid,
        subject: &[u8],
        at: i64,
    ) -> Result<(), RegistrationEmailError> {
        let mut aw: Vec<i64> = a.get("wrongs");
        let mut pw: Vec<i64> = p.get("wrongs");
        trim_rolling_history(&mut aw, at, self.policy.authority_email_wrong_window_secs);
        trim_rolling_history(&mut pw, at, self.policy.product_email_wrong_window_secs);
        aw.push(at);
        pw.push(at);
        let ab = if aw.len() >= self.policy.authority_email_wrong_limit as usize {
            at + self.policy.authority_email_wrong_window_secs
        } else {
            a.get("blocked_until")
        };
        let pb = if pw.len() >= self.policy.product_email_wrong_limit as usize {
            at + self.policy.product_email_wrong_window_secs
        } else {
            p.get("blocked_until")
        };
        tx.execute(&format!("update {} set wrongs=$3,blocked_until=$4,last_time=$5,retain_until=greatest(retain_until,$6) where authority=$1 and subject=$2",self.table("subjects")),&[&self.scope.authority,&subject,&aw,&ab,&at,&(at+self.policy.authority_email_send_window_24h_secs+self.policy.bucket_retention_extra_secs)]).map_err(db)?;
        tx.execute(&format!("update {} set wrongs=$4,blocked_until=$5,last_time=$6,retain_until=greatest(retain_until,$7) where authority=$1 and product=$2 and subject=$3",self.table("buckets")),&[&self.scope.authority,&self.scope.product,&subject,&pw,&pb,&at,&(at+self.policy.authority_email_send_window_24h_secs+self.policy.bucket_retention_extra_secs)]).map_err(db)?;
        tx.execute(
            &format!(
                "update {} set wrong_count=wrong_count+1 where id=$1",
                self.table("contexts")
            ),
            &[&id],
        )
        .map_err(db)?;
        Ok(())
    }
}

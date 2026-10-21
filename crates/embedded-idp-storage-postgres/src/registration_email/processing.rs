use super::{support::*, *};
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    /// B is an IDP-internal storage operation. It neither creates identities nor sends mail.
    pub fn prepare(
        &self,
        context: Uuid,
        sequence: i64,
    ) -> Result<RegistrationEmailPreparation, RegistrationEmailError> {
        match self.claim_specific_preparation(context, sequence)? {
            Some(claim) => self.prepare_claimed_inner(&claim),
            None => Err(RegistrationEmailError::Unavailable),
        }
    }

    pub(super) fn prepare_claimed_inner(
        &self,
        claim: &RegistrationEmailPreparationClaim,
    ) -> Result<RegistrationEmailPreparation, RegistrationEmailError> {
        let context = claim.context_id;
        let sequence = claim.sequence;
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin(&mut tx)?;
        let mut slot = false;
        for n in 0..self.policy.processing_concurrency as i32 {
            let got: bool = tx
                .query_one(
                    "select pg_try_advisory_xact_lock(hashtext($1),$2)",
                    &[
                        &format!("registration-processing:{}", self.scope.authority),
                        &n,
                    ],
                )
                .map_err(db)?
                .get(0);
            if got {
                slot = true;
                break;
            }
        }
        if !slot {
            return Err(RegistrationEmailError::Unavailable);
        }
        let ctx=tx.query_opt(&format!("select * from {} where id=$1 and authority=$2 and product=$3 for no key update",self.table("contexts")),&[&context,&self.scope.authority,&self.scope.product]).map_err(db)?.ok_or(RegistrationEmailError::Unavailable)?;
        let intent = tx
            .query_opt(
                &format!(
                    "select * from {} where context_id=$1 and seq=$2",
                    self.table("intents")
                ),
                &[&context, &sequence],
            )
            .map_err(db)?
            .ok_or(RegistrationEmailError::Unavailable)?;
        let stored_token: Option<Uuid> = intent.get("claim_token");
        let stored_lease: Option<i64> = intent.get("lease_until");
        let at_claim = now(&mut tx)?;
        if stored_token != Some(claim.claim_token) || stored_lease != Some(claim.lease_until) {
            return Err(RegistrationEmailError::Unavailable);
        }
        if intent.get::<_, String>("status") == "prepared" {
            if ctx.get::<_, i64>("accepted_seq") != sequence {
                tx.execute(
                    &format!(
                        "update {} set status='superseded' where context_id=$1 and seq=$2",
                        self.table("intents")
                    ),
                    &[&context, &sequence],
                )
                .map_err(db)?;
                tx.commit().map_err(db)?;
                return Ok(RegistrationEmailPreparation::Superseded);
            }
            tx.commit().map_err(db)?;
            return Ok(RegistrationEmailPreparation::Prepared);
        }
        if intent.get::<_, String>("status") != "reserved" || claim.lease_until <= at_claim {
            return Err(RegistrationEmailError::Unavailable);
        }
        let kind = if intent.get::<_, String>("kind") == "register" {
            RegistrationEmailOperationKind::Register
        } else {
            RegistrationEmailOperationKind::Resend
        };
        let operation: Uuid = intent.get("operation_id");
        let at = now(&mut tx)?;
        let latest = ctx.get::<_, i64>("accepted_seq") == sequence;
        if !latest
            || !ctx.get::<_, bool>("deliverable")
            || ctx.get::<_, i64>("expires_at") <= at
            || at - intent.get::<_, i64>("created_at") > self.policy.processing_queue_max_age_secs
        {
            tx.execute(
                &format!(
                    "update {} set status=$3 where context_id=$1 and seq=$2",
                    self.table("intents")
                ),
                &[
                    &context,
                    &sequence,
                    &if latest { "expired" } else { "superseded" },
                ],
            )
            .map_err(db)?;
            self.event(
                &mut tx,
                operation,
                kind,
                None,
                Some(context),
                if latest { "expired" } else { "superseded" },
                at,
            )?;
            if now(&mut tx)? >= claim.lease_until {
                return Err(RegistrationEmailError::Unavailable);
            }
            tx.commit().map_err(db)?;
            return Ok(if latest {
                RegistrationEmailPreparation::Suppressed
            } else {
                RegistrationEmailPreparation::Superseded
            });
        }
        let email = String::from_utf8(self.crypto.open(
            "email",
            &self.scope,
            &context,
            &ctx.get::<_, Vec<u8>>("email_cipher"),
        )?)
        .map_err(|_| RegistrationEmailError::Unavailable)?;
        let s = self.adapter.schema_name();
        let account=tx.query_opt(&format!("select a.id,a.status,a.registration_tenant_id,a.registration_security_revision,a.registration_invalidated_at,m.status as member_status,m.version as member_version,m.registration_invalidated_at as member_invalidated_at,(select invalidated_at from {s}.registration_email_member_tombstones t where t.tenant=$2 and t.account_id=a.id) as member_deleted_at from {s}.accounts a left join {s}.access_memberships m on m.account_id=a.id and m.tenant_id=$2 where a.email=$1"),&[&email,&self.scope.tenant]).map_err(db)?;
        let eligible = account.as_ref().is_none_or(|a| {
            a.get::<_, String>("status") == "pending_verification"
                && a.get::<_, String>("registration_tenant_id") == self.scope.tenant
                && a.get::<_, Option<String>>("member_status").as_deref() == Some("active")
                && ctx.get::<_, i64>("accepted_at") > a.get::<_, i64>("registration_invalidated_at")
                && ctx.get::<_, i64>("accepted_at")
                    > a.get::<_, Option<i64>>("member_invalidated_at")
                        .unwrap_or(i64::MAX)
                && ctx.get::<_, i64>("accepted_at")
                    > a.get::<_, Option<i64>>("member_deleted_at").unwrap_or(0)
        });
        let deleted = tx
            .query_opt(
                &format!(
                    "select invalidated_at from {} where email=$1",
                    self.table("tombstones")
                ),
                &[&email],
            )
            .map_err(db)?;
        let stale_email =
            deleted.is_some_and(|row| ctx.get::<_, i64>("accepted_at") <= row.get::<_, i64>(0));
        if !eligible || stale_email {
            tx.execute(
                &format!(
                    "update {} set status='suppressed' where context_id=$1 and seq=$2",
                    self.table("intents")
                ),
                &[&context, &sequence],
            )
            .map_err(db)?;
            self.event(
                &mut tx,
                operation,
                kind,
                None,
                Some(context),
                "suppressed",
                at,
            )?;
            if now(&mut tx)? >= claim.lease_until {
                return Err(RegistrationEmailError::Unavailable);
            }
            tx.commit().map_err(db)?;
            return Ok(RegistrationEmailPreparation::Suppressed);
        }
        let mut selected = None;
        for _ in 0..self.policy.code_distinct_draw_limit {
            let code = self.crypto.random_code()?;
            let digest = self
                .crypto
                .code_digest(&self.scope, &context, code.expose_secret());
            let exists: bool = tx
                .query_one(
                    &format!(
                        "select exists(select 1 from {} where context_id=$1 and digest=$2)",
                        self.table("codes")
                    ),
                    &[&context, &digest.as_slice()],
                )
                .map_err(db)?
                .get(0);
            if !exists {
                selected = Some((code, digest));
                break;
            }
        }
        let (code, digest) = selected.ok_or(RegistrationEmailError::Unavailable)?;
        let expiry: i64 = ctx.get("expires_at");
        let payload = self.crypto.seal(
            "delivery",
            &self.scope,
            &context,
            &fields(&[
                email.as_bytes(),
                code.expose_secret().as_bytes(),
                expiry.to_string().as_bytes(),
            ]),
        )?;
        tx.execute(
            &format!(
                "insert into {}(context_id,seq,digest,issued_at,expires_at) values($1,$2,$3,$4,$5)",
                self.table("codes")
            ),
            &[&context, &sequence, &digest.as_slice(), &at, &expiry],
        )
        .map_err(db)?;
        let bound = account.as_ref().map(|a| a.get::<_, Uuid>("id"));
        let rev = account
            .as_ref()
            .map(|a| a.get::<_, i64>("registration_security_revision"));
        tx.execute(&format!("update {} set prepared=true,current_seq=$2,bound_account=$3,bound_revision=$4,bound_member_version=$5 where id=$1",self.table("contexts")),&[&context,&sequence,&bound,&rev,&account.as_ref().and_then(|a|a.get::<_,Option<i64>>("member_version"))]).map_err(db)?;
        tx.execute(&format!("insert into {}(id,context_id,seq,payload_cipher,status,stop_confirmed) values($1,$2,$3,$4,'reserved',false)",self.table("deliveries")),&[&Uuid::now_v7(),&context,&sequence,&payload]).map_err(db)?;
        tx.execute(
            &format!(
                "update {} set status='prepared' where context_id=$1 and seq=$2",
                self.table("intents")
            ),
            &[&context, &sequence],
        )
        .map_err(db)?;
        self.event(
            &mut tx,
            operation,
            kind,
            None,
            Some(context),
            "prepared",
            at,
        )?;
        if now(&mut tx)? >= claim.lease_until {
            return Err(RegistrationEmailError::Unavailable);
        }
        tx.commit().map_err(db)?;
        Ok(RegistrationEmailPreparation::Prepared)
    }
}

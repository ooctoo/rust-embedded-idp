use super::*;
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub(super) fn runtime_facts_inner(
        &self,
    ) -> Result<RegistrationEmailRuntimeFacts, RegistrationEmailError> {
        let f = self
            .adapter
            .inspect_registration_email_foundation(&self.scope)
            .map_err(RegistrationEmailError::Store)?;
        let ready = f.state_present
            && f.binding_matches
            && f.tables_complete
            && f.columns_complete
            && f.indexes_complete
            && f.constraints_complete
            && f.triggers_complete
            && f.legacy_codes_consumed
            && f.mode == Some(self.scope.mode)
            && f.version.as_deref() == Some(crate::REGISTRATION_EMAIL_SCHEMA_VERSION);
        if !ready {
            return Ok(RegistrationEmailRuntimeFacts::default());
        }
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let present: Option<String> = tx
            .query_one(
                "select to_regclass($1)::text",
                &[&self.table("runtime_state")],
            )
            .map_err(db)?
            .get(0);
        if present.is_none() {
            return Ok(RegistrationEmailRuntimeFacts::default());
        }
        let state=tx.query_opt(&format!("select paused from {} where authority=$1 and version=$2 and policy_revision=$3",self.table("runtime_state")),&[&self.scope.authority,&crate::REGISTRATION_EMAIL_RUNTIME_VERSION,&(self.policy.revision as i32)]).map_err(db)?;
        let Some(state) = state else {
            return Ok(RegistrationEmailRuntimeFacts::default());
        };
        let at = now(&mut tx)?;
        let counts=tx.query_one(&format!("select (select count(*) from {} i join {} x on x.id=i.context_id where x.authority=$1 and i.status='reserved' and (i.created_at<$2 or (i.claim_token is not null and i.lease_until<=$3))), (select count(*) from {} d join {} x on x.id=d.context_id where x.authority=$1 and ((d.status='unknown' and not d.stop_confirmed) or (d.status='claimed' and d.lease_until<=$3)))",self.table("intents"),self.table("contexts"),self.table("deliveries"),self.table("contexts")),&[&self.scope.authority,&(at-self.policy.processing_queue_max_age_secs),&at]).map_err(db)?;
        let result = RegistrationEmailRuntimeFacts {
            store_ready: true,
            accepting: !state.get::<_, bool>("paused"),
            overdue_processing: counts.get::<_, i64>(0) as u64,
            unresolved_delivery: counts.get::<_, i64>(1) as u64,
        };
        tx.commit().map_err(db)?;
        Ok(result)
    }
    pub(super) fn set_paused(&self, paused: bool) -> Result<(), RegistrationEmailError> {
        if !paused {
            let facts = self.runtime_facts_inner()?;
            if !facts.store_ready || facts.overdue_processing > 0 || facts.unresolved_delivery > 0 {
                return Err(RegistrationEmailError::Unavailable);
            }
        }
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let at = now(&mut tx)?;
        let state=tx.query_opt(&format!("select paused from {} where authority=$1 and version=$2 and policy_revision=$3 for update",self.table("runtime_state")),&[&self.scope.authority,&crate::REGISTRATION_EMAIL_RUNTIME_VERSION,&(self.policy.revision as i32)]).map_err(db)?.ok_or(RegistrationEmailError::Unavailable)?;
        if state.get::<_, bool>(0) == paused {
            tx.commit().map_err(db)?;
            return Ok(());
        }
        if !paused {
            let blocked: bool = tx.query_one(&format!("select exists(select 1 from {} i join {} x on x.id=i.context_id where x.authority=$1 and i.status='reserved' and (i.created_at<$2 or (i.claim_token is not null and i.lease_until<=$3))) or exists(select 1 from {} d join {} x on x.id=d.context_id where x.authority=$1 and ((d.status='unknown' and not d.stop_confirmed) or (d.status='claimed' and d.lease_until<=$3)))",self.table("intents"),self.table("contexts"),self.table("deliveries"),self.table("contexts")),&[&self.scope.authority,&(at-self.policy.processing_queue_max_age_secs),&at]).map_err(db)?.get(0);
            if blocked {
                return Err(RegistrationEmailError::Unavailable);
            }
        }
        let n=tx.execute(&format!("update {} set paused=$2,updated_at=$3 where authority=$1 and version=$4 and policy_revision=$5",self.table("runtime_state")),&[&self.scope.authority,&paused,&at,&crate::REGISTRATION_EMAIL_RUNTIME_VERSION,&(self.policy.revision as i32)]).map_err(db)?;
        if n != 1 {
            return Err(RegistrationEmailError::Unavailable);
        }
        self.event(
            &mut tx,
            Uuid::now_v7(),
            RegistrationEmailOperationKind::Register,
            None,
            None,
            if paused {
                "runtime_paused"
            } else {
                "runtime_resumed"
            },
            at,
        )?;
        tx.commit().map_err(db)
    }
    pub(super) fn maintain_runtime_inner(&self) -> Result<(), RegistrationEmailError> {
        let mut c = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = c.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let at = now(&mut tx)?;
        let installed = self.runtime_lock(&mut tx, true)?.is_some();
        let rows=tx.query(&format!("select i.context_id,i.seq from {} i join {} x on x.id=i.context_id where x.authority=$1 and x.product=$2 and x.tenant_id=$3 and i.status='reserved' and (i.created_at<$4 or (i.claim_token is not null and i.lease_until<=$5)) order by i.created_at,i.context_id,i.seq limit 200",self.table("intents"),self.table("contexts")),&[&self.scope.authority,&self.scope.product,&self.scope.tenant,&(at-self.policy.processing_queue_max_age_secs),&at]).map_err(db)?;
        if installed && !rows.is_empty() {
            self.pause_runtime_locked(&mut tx)?;
        }
        for row in rows {
            let id: Uuid = row.get(0);
            let seq: i64 = row.get(1);
            if self.try_context(&mut tx, id)?.is_some() {
                let changed=tx.query_opt(&format!("update {} set status='expired' where context_id=$1 and seq=$2 and status='reserved' and (created_at<$3 or (claim_token is not null and lease_until<=$4)) returning kind,operation_id",self.table("intents")),&[&id,&seq,&(at-self.policy.processing_queue_max_age_secs),&at]).map_err(db)?;
                if let Some(changed) = changed {
                    let kind = match changed.get::<_, String>("kind").as_str() {
                        "register" => RegistrationEmailOperationKind::Register,
                        "resend" => RegistrationEmailOperationKind::Resend,
                        _ => return Err(RegistrationEmailError::Unavailable),
                    };
                    self.event(
                        &mut tx,
                        changed.get("operation_id"),
                        kind,
                        None,
                        Some(id),
                        "expired",
                        at,
                    )?;
                }
            }
        }
        tx.commit().map_err(db)?;
        // Runtime reaps only expired work/claims. Full retention GC remains an
        // explicit maintenance command, never startup/readiness side effects.
        self.phase_cancel_and_receipts(200)?;
        Ok(())
    }
}

use super::*;
use embedded_idp_core::StoreError;
use postgres::{GenericClient, Row, Transaction};
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub(super) fn table(&self, name: &str) -> String {
        format!("{}.registration_email_{name}", self.adapter.schema_name())
    }
    pub(super) fn tx_begin(&self, tx: &mut Transaction<'_>) -> Result<(), RegistrationEmailError> {
        self.begin(tx, true)
    }
    pub(super) fn ensure_registration_open(
        &self,
        tx: &mut Transaction<'_>,
    ) -> Result<(), RegistrationEmailError> {
        let open: bool = tx
            .query_one(
                &format!(
                    "select allow_registration from {}.access_tenants where id=$1",
                    self.adapter.schema_name()
                ),
                &[&self.scope.tenant],
            )
            .map_err(db)?
            .get(0);
        if !open {
            return Err(RegistrationEmailError::RegistrationClosed);
        }
        Ok(())
    }
    pub(super) fn tx_begin_maintenance(
        &self,
        tx: &mut Transaction<'_>,
    ) -> Result<(), RegistrationEmailError> {
        self.begin(tx, false)
    }
    fn begin(&self, tx: &mut Transaction<'_>, active: bool) -> Result<(), RegistrationEmailError> {
        tx.batch_execute(&format!("set local transaction_timeout='{}s'; set local statement_timeout='{}s'; set local lock_timeout='1s'; set local idle_in_transaction_session_timeout='{}s'",self.policy.db_transaction_deadline_secs,self.policy.db_transaction_deadline_secs,self.policy.db_transaction_deadline_secs)).map_err(db)?;
        let s = self.adapter.schema_name();
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for share"),
            &[],
        )
        .map_err(db)?;
        let row = tx
            .query_opt(
                &format!("select status from {s}.access_tenants where id=$1 for share"),
                &[&self.scope.tenant],
            )
            .map_err(db)?
            .ok_or(RegistrationEmailError::Unavailable)?;
        if active && row.get::<_, String>(0) != "active" {
            return Err(RegistrationEmailError::Unavailable);
        }
        let bound = tx
            .query_opt(
                &format!(
                    "select 1 from {} where authority=$1 and product=$2 and tenant_id=$3",
                    self.table("products")
                ),
                &[
                    &self.scope.authority,
                    &self.scope.product,
                    &self.scope.tenant,
                ],
            )
            .map_err(db)?;
        if bound.is_none() {
            return Err(RegistrationEmailError::Unavailable);
        }
        Ok(())
    }
    pub(super) fn subject_lock(
        &self,
        tx: &mut Transaction<'_>,
        subject: &[u8],
    ) -> Result<bool, RegistrationEmailError> {
        let key = i64::from_be_bytes(
            subject[..8]
                .try_into()
                .map_err(|_| RegistrationEmailError::Unavailable)?,
        );
        Ok(tx
            .query_one("select pg_try_advisory_xact_lock($1)", &[&key])
            .map_err(db)?
            .get(0))
    }
    pub(super) fn event(
        &self,
        tx: &mut Transaction<'_>,
        operation: Uuid,
        kind: RegistrationEmailOperationKind,
        subject: Option<&[u8]>,
        context: Option<Uuid>,
        reason: &str,
        now: i64,
    ) -> Result<(), RegistrationEmailError> {
        tx.execute(&format!("insert into {}(id,authority,product,operation_id,kind,reason,subject,context_id,policy_revision,created_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",self.table("events")),&[&Uuid::now_v7(),&self.scope.authority,&self.scope.product,&operation,&kind.as_str(),&reason,&subject,&context,&format!("email-r{}",self.policy.revision),&now]).map_err(db)?;
        Ok(())
    }
    pub(super) fn operation(
        &self,
        tx: &mut impl GenericClient,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
    ) -> Result<Option<Row>, RegistrationEmailError> {
        tx.query_opt(&format!("select * from {} where authority=$1 and product=$2 and kind=$3 and operation_id=$4",self.table("operations")),&[&self.scope.authority,&self.scope.product,&kind.as_str(),&operation]).map_err(db)
    }
    pub(super) fn check_digest(
        &self,
        row: &Row,
        digest: &[u8],
    ) -> Result<(), RegistrationEmailError> {
        if !self
            .crypto
            .digests_equal(&row.get::<_, Vec<u8>>("request_digest"), digest)
        {
            return Err(RegistrationEmailError::RequestConflict);
        }
        Ok(())
    }
    pub(super) fn acceptance(
        &self,
        tx: &mut impl GenericClient,
        row: &Row,
    ) -> Result<RegistrationEmailAccepted, RegistrationEmailError> {
        let id: Uuid = row.get("context_id");
        let ctx = tx
            .query_one(
                &format!(
                    "select seed,accepted_at from {} where id=$1",
                    self.table("contexts")
                ),
                &[&id],
            )
            .map_err(db)?;
        let seed: Vec<u8> = ctx.get("seed");
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| RegistrationEmailError::Unavailable)?;
        Ok(RegistrationEmailAccepted {
            verification_context: self.crypto.context_token(&self.scope, &seed),
            accepted_at_unix_secs: ctx.get("accepted_at"),
            context_lifetime_secs: self.policy.context_lifetime_secs,
            resend_after_secs: self.policy.product_email_send_gap_secs,
        })
    }
    pub(super) fn finish_operation(
        &self,
        tx: &mut Transaction<'_>,
        kind: RegistrationEmailOperationKind,
        operation: Uuid,
        context: Option<Uuid>,
        result: &str,
        now: i64,
        expires: i64,
    ) -> Result<(), RegistrationEmailError> {
        let retain = expires.max(
            now + self.policy.operation_id_max_age_secs + self.policy.operation_id_future_skew_secs,
        ) + self.policy.attempt_replay_grace_secs;
        tx.execute(&format!("update {} set phase='attached',context_id=$5,result=$6,accepted_at=$7,retain_until=$8 where authority=$1 and product=$2 and kind=$3 and operation_id=$4",self.table("operations")),&[&self.scope.authority,&self.scope.product,&kind.as_str(),&operation,&context,&result,&now,&retain]).map_err(db)?;
        Ok(())
    }
}
pub(super) fn db(_: postgres::Error) -> RegistrationEmailError {
    RegistrationEmailError::Store(StoreError::Backend(
        "registration storage unavailable".into(),
    ))
}
pub(super) fn now(tx: &mut impl GenericClient) -> Result<i64, RegistrationEmailError> {
    Ok(tx
        .query_one(
            "select floor(extract(epoch from clock_timestamp()))::bigint",
            &[],
        )
        .map_err(db)?
        .get(0))
}
pub(super) fn fields(values: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        out.extend_from_slice(&(v.len() as u32).to_be_bytes());
        out.extend_from_slice(v);
    }
    out
}

pub(super) fn validate_token(token: &str) -> Result<(), RegistrationEmailError> {
    let bytes = token.as_bytes();
    if bytes.len() != 43
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(b))
        || !b"AEIMQUYcgkosw048".contains(&bytes[42])
    {
        return Err(RegistrationEmailError::InvalidInput("verification_context"));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::validate_token;
    #[test]
    fn opaque_tokens_require_canonical_length_alphabet_and_tail() {
        assert!(validate_token(&"A".repeat(43)).is_ok());
        for token in [
            "A".repeat(42),
            "A".repeat(44),
            format!("{}B", "A".repeat(42)),
            format!("{}=", "A".repeat(42)),
            "例".repeat(43),
        ] {
            assert!(validate_token(&token).is_err());
        }
    }
}

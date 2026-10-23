use super::super::{support::*, *};

impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    /// Clear the encrypted candidate while retaining the context receipt history.
    pub(super) fn phase_clear_candidates(&self, limit: i64) -> Result<(), RegistrationEmailError> {
        let mut client = self.connect()?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let at = now(&mut tx)?;
        let wrong_limit = self.policy.context_wrong_limit as i32;
        let rows = tx
            .query(
                &format!(
                    "select id from {} \
                     where authority=$1 and product=$2 and octet_length(password_cipher)>0 \
                       and (expires_at<=$3 or completed_operation is not null \
                            or wrong_count >= $4) \
                     order by expires_at,id limit $5",
                    self.table("contexts")
                ),
                &[
                    &self.scope.authority,
                    &self.scope.product,
                    &at,
                    &wrong_limit,
                    &limit,
                ],
            )
            .map_err(db)?;
        for row in rows {
            let id: Uuid = row.get(0);
            let Some(ctx) = self.try_context(&mut tx, id)? else {
                continue;
            };
            let exhausted = ctx.get::<_, i32>("wrong_count") >= wrong_limit;
            let clear = ctx.get::<_, i64>("expires_at") <= at
                || ctx.get::<_, Option<Uuid>>("completed_operation").is_some()
                || exhausted;
            if !clear {
                continue;
            }
            tx.execute(
                &format!(
                    "update {} set password_cipher=''::bytea where id=$1",
                    self.table("contexts")
                ),
                &[&id],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }
}

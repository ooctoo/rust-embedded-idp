use super::{support::*, *};
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    /// Optional only for I1's internal foundation ports. The new profile requires installation.
    pub(super) fn runtime_lock(
        &self,
        tx: &mut transport::Transaction<'_>,
        exclusive: bool,
    ) -> Result<Option<bool>, RegistrationEmailError> {
        let exists: Option<String> = tx
            .query_one(
                "select to_regclass($1)::text",
                &[&self.table("runtime_state")],
            )
            .map_err(db)?
            .get(0);
        if exists.is_none() {
            return Ok(None);
        }
        let lock = if exclusive { "for update" } else { "for share" };
        let row=tx.query_opt(&format!("select paused from {} where authority=$1 and version=$2 and policy_revision=$3 {lock}",self.table("runtime_state")),&[&self.scope.authority,&crate::REGISTRATION_EMAIL_RUNTIME_VERSION,&(self.policy.revision as i32)]).map_err(db)?.ok_or(RegistrationEmailError::Unavailable)?;
        Ok(Some(row.get(0)))
    }
    pub(super) fn require_runtime_open(
        &self,
        tx: &mut transport::Transaction<'_>,
    ) -> Result<(), RegistrationEmailError> {
        if self.runtime_lock(tx, false)? == Some(true) {
            return Err(RegistrationEmailError::RegistrationClosed);
        }
        Ok(())
    }
    pub(super) fn pause_runtime_locked(
        &self,
        tx: &mut transport::Transaction<'_>,
    ) -> Result<(), RegistrationEmailError> {
        tx.execute(&format!("update {} set paused=true,updated_at=floor(extract(epoch from clock_timestamp()))::bigint where authority=$1 and not paused",self.table("runtime_state")),&[&self.scope.authority]).map_err(db)?;
        Ok(())
    }
}

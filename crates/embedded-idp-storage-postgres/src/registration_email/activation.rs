use super::{support::*, *};
use postgres::Row;
impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub(super) fn activate(
        &self,
        tx: &mut transport::Transaction<'_>,
        ctx: &Row,
        id: Uuid,
        _at: i64,
    ) -> Result<bool, RegistrationEmailError> {
        let email = String::from_utf8(self.crypto.open(
            "email",
            &self.scope,
            &id,
            &ctx.get::<_, Vec<u8>>("email_cipher"),
        )?)
        .map_err(|_| RegistrationEmailError::Unavailable)?;
        let (hash, name) = decode_registration_candidate(&self.crypto.open(
            "candidate",
            &self.scope,
            &id,
            &ctx.get::<_, Vec<u8>>("password_cipher"),
        )?)?;
        let s = self.adapter.schema_name();
        let account = tx
            .query_opt(
                &format!("select * from {s}.accounts where email=$1 for update"),
                &[&email],
            )
            .map_err(db)?;
        let checked_at = now(tx)?;
        if checked_at >= ctx.get::<_, i64>("expires_at") {
            return Ok(false);
        }
        let expected: Option<Uuid> = ctx.get("bound_account");
        if let Some(a) = account {
            let aid: Uuid = a.get("id");
            if expected != Some(aid)
                || a.get::<_, String>("status") != "pending_verification"
                || a.get::<_, String>("registration_tenant_id") != self.scope.tenant
                || ctx.get::<_, Option<i64>>("bound_revision")
                    != Some(a.get("registration_security_revision"))
                || ctx.get::<_, i64>("accepted_at")
                    <= a.get::<_, i64>("registration_invalidated_at")
            {
                return Ok(false);
            }
            let member=tx.query_opt(&format!("select status,version,registration_invalidated_at from {s}.access_memberships where tenant_id=$1 and account_id=$2 for share"),&[&self.scope.tenant,&aid]).map_err(db)?;
            if member.is_none_or(|m| {
                m.get::<_, String>("status") != "active"
                    || Some(m.get::<_, i64>("version"))
                        != ctx.get::<_, Option<i64>>("bound_member_version")
                    || ctx.get::<_, i64>("accepted_at")
                        <= m.get::<_, i64>("registration_invalidated_at")
            }) {
                return Ok(false);
            }
            let deleted = tx
                .query_opt(
                    &format!(
                        "select invalidated_at from {} where tenant=$1 and account_id=$2",
                        self.table("member_tombstones")
                    ),
                    &[&self.scope.tenant, &aid],
                )
                .map_err(db)?;
            if deleted.is_some_and(|t| ctx.get::<_, i64>("accepted_at") <= t.get::<_, i64>(0)) {
                return Ok(false);
            }
            tx.execute(&format!("update {s}.accounts set password_hash=$2,display_name=$3,status='active' where id=$1"),&[&aid,&hash.expose_secret(),&name]).map_err(db)?;
        } else {
            if expected.is_some() {
                return Ok(false);
            }
            tx.batch_execute("savepoint registration_new_identity")
                .map_err(db)?;
            let aid = Uuid::now_v7();
            let inserted=tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,display_name,status,created_at_epoch) values($1,$2,$3,$4,$5,'active',$6) on conflict(email) do nothing"),&[&aid,&self.scope.tenant,&email,&hash.expose_secret(),&name,&checked_at]).map_err(db)?;
            if inserted == 0 {
                return Ok(false);
            }
            let tomb = tx
                .query_opt(
                    &format!(
                        "select invalidated_at from {} where email=$1",
                        self.table("tombstones")
                    ),
                    &[&email],
                )
                .map_err(db)?;
            if tomb.is_some_and(|t| ctx.get::<_, i64>("accepted_at") <= t.get::<_, i64>(0)) {
                tx.batch_execute("rollback to savepoint registration_new_identity; release savepoint registration_new_identity").map_err(db)?;
                return Ok(false);
            }
            tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',$3)"),&[&self.scope.tenant,&aid,&checked_at]).map_err(db)?;
            tx.batch_execute("release savepoint registration_new_identity")
                .map_err(db)?;
        }
        Ok(true)
    }
}

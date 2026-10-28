use super::{access_db_error, authentication::decode_session, epoch, PostgresAccessStore};
use embedded_idp_core::{
    access::{
        AccessActor, SelfSessionCursor, SelfSessionReadStore, SelfSessionReadTransaction,
        TenancyMode, TenantSession,
    },
    StoreError,
};
use std::time::SystemTime;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::{PgExecutor, PgTransaction};

/// A read transaction holding the authenticated actor's revocation locks.
pub struct PostgresSelfSessionReadTransaction<'a> {
    tx: PgTransaction<'a>,
    schema: &'a str,
}

impl SelfSessionReadStore for PostgresAccessStore {
    type Transaction<'a> = PostgresSelfSessionReadTransaction<'a>;

    fn self_session_read<R>(
        &self,
        mode: TenancyMode,
        actor: &AccessActor,
        run: impl FnOnce(
            &mut Self::Transaction<'_>,
        ) -> Result<R, embedded_idp_core::access::AccessError>,
    ) -> Result<R, embedded_idp_core::access::AccessError> {
        if mode != self.mode {
            return Err(embedded_idp_core::access::AccessError::ModeMismatch);
        }
        let mut client = self.adapter.connect()?;
        let mut tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        tx.batch_execute("set local statement_timeout='5s'; set local lock_timeout='5s'")
            .map_err(access_db_error)?;
        let schema = self.adapter.schema_name();
        tx.query_one(
            &format!("select singleton from {schema}.access_state where singleton for share"),
            &[],
        )
        .map_err(access_db_error)?;
        self.verify(&mut tx)?;
        let mut transaction = PostgresSelfSessionReadTransaction { tx, schema };
        transaction.lock_actor(actor)?;
        let result = run(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}

impl PostgresSelfSessionReadTransaction<'_> {
    fn lock_actor(&mut self, actor: &AccessActor) -> Result<(), StoreError> {
        lock_self_actor(&mut self.tx, self.schema, actor)
    }
}

impl SelfSessionReadTransaction for PostgresSelfSessionReadTransaction<'_> {
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        self_actor_is_active(&mut self.tx, self.schema, actor, now)
    }

    fn sessions_for_subject(
        &mut self,
        subject: &str,
        after: Option<&SelfSessionCursor>,
        limit: u32,
    ) -> Result<Vec<TenantSession>, StoreError> {
        if !(1..=51).contains(&limit) {
            return Err(StoreError::Conflict("access.self_sessions_limit"));
        }
        let account_id = match Uuid::parse_str(subject) {
            Ok(id) => id,
            Err(_) => return Ok(Vec::new()),
        };
        let after_tenant = after.map(|cursor| cursor.tenant_id.as_str());
        let after_session = after
            .map(|cursor| Uuid::parse_str(&cursor.session_id))
            .transpose()
            .map_err(|_| StoreError::Conflict("access.self_sessions_cursor"))?;
        let rows = self
            .tx
            .query(
                &format!(
                    "select x.* from {}.auth_sessions x
                     where x.account_id=$1 and x.status='active'
                       and ($2::text is null or x.tenant_id > $2 collate \"C\"
                            or (x.tenant_id = $2 collate \"C\" and x.id > $3::uuid))
                     order by x.tenant_id collate \"C\", x.id
                     limit $4",
                    self.schema
                ),
                &[&account_id, &after_tenant, &after_session, &(limit as i64)],
            )
            .map_err(access_db_error)?;
        rows.iter().map(decode_session).collect()
    }
}

pub(super) fn lock_self_actor(
    tx: &mut impl PgExecutor,
    schema: &str,
    actor: &AccessActor,
) -> Result<(), StoreError> {
    let Ok(account_id) = Uuid::parse_str(&actor.subject_id) else {
        return Ok(());
    };
    let Ok(session_id) = Uuid::parse_str(&actor.session_id) else {
        return Ok(());
    };
    if tx
        .query_opt(
            &format!("select id from {schema}.access_tenants where id=$1 for share"),
            &[&actor.tenant_id],
        )
        .map_err(access_db_error)?
        .is_none()
    {
        return Ok(());
    }
    if tx
        .query_opt(
            &format!("select id from {schema}.accounts where id=$1 for share"),
            &[&account_id],
        )
        .map_err(access_db_error)?
        .is_none()
    {
        return Ok(());
    }
    // Do not filter by status/scope: even a bad actor row must be locked
    // before Core samples its clock and evaluates the final predicate.
    tx
            .query_opt(
                &format!("select id from {schema}.auth_sessions where tenant_id=$1 and id=$2 and account_id=$3 for share"),
                &[&actor.tenant_id, &session_id, &account_id],
            )
            .map_err(access_db_error)?;
    Ok(())
}

pub(super) fn self_actor_is_active(
    tx: &mut impl PgExecutor,
    schema: &str,
    actor: &AccessActor,
    now: SystemTime,
) -> Result<bool, StoreError> {
    let Ok(account_id) = Uuid::parse_str(&actor.subject_id) else {
        return Ok(false);
    };
    let Ok(session_id) = Uuid::parse_str(&actor.session_id) else {
        return Ok(false);
    };

    let now_epoch = epoch(now)?;
    let active = tx.query_opt(
            &format!(
                "select x.* from {schema}.auth_sessions x
                 where x.tenant_id=$1 and x.id=$2 and x.account_id=$3 and x.scope is null
                   and x.status='active' and x.created_at_epoch<=$4 and x.authenticated_at_epoch<=x.created_at_epoch and x.expires_at_epoch>$4
                   and exists(select 1 from {schema}.accounts a where a.id=x.account_id and a.status='active')
                   and exists(select 1 from {schema}.access_memberships m where m.tenant_id=x.tenant_id and m.account_id=x.account_id and m.status='active')
                   and exists(select 1 from {schema}.access_tenants t where t.id=x.tenant_id and t.status='active')
                   and (x.device_id is null or exists(
                       select 1 from {schema}.devices d
                       join {schema}.device_proof_keys k on k.tenant_id=d.tenant_id and k.device_id=d.id and k.key_id=d.proof_key_id
                       join {schema}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id and b.account_id=x.account_id
                       where d.tenant_id=x.tenant_id and d.id=x.device_id and d.client_id=x.client_id
                         and d.status='active' and k.status='active' and b.status='active'
                   ))
                 "
            ),
            &[&actor.tenant_id, &session_id, &account_id, &now_epoch],
        ).map_err(access_db_error)?;
    Ok(active.is_some())
}

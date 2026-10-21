use super::super::{support::*, *};

impl<C: RegistrationEmailCrypto> PostgresRegistrationEmailStore<C> {
    pub(super) fn phase_gc_contexts(&self, limit: i64) -> Result<u64, RegistrationEmailError> {
        let mut client = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let at = now(&mut tx)?;
        let rows = tx
            .query(
                &format!(
                    "select x.id from {} x \
                     where x.authority=$1 and x.product=$2 and x.expires_at<=$3 \
                       and not exists(select 1 from {} o where o.context_id=x.id) \
                       and not exists(select 1 from {} d where d.context_id=x.id \
                         and (d.status='claimed' or (d.status='unknown' and not d.stop_confirmed))) \
                     order by x.expires_at,x.id limit $4",
                    self.table("contexts"),
                    self.table("operations"),
                    self.table("deliveries")
                ),
                &[&self.scope.authority, &self.scope.product, &at, &limit],
            )
            .map_err(db)?;
        let mut removed = 0;
        for row in rows {
            let id: Uuid = row.get(0);
            let Some(ctx) = self.try_context(&mut tx, id)? else {
                continue;
            };
            if ctx.get::<_, i64>("expires_at") > at {
                continue;
            }
            // The context is the only authoritative lock in this phase. An
            // operation may be attached after this non-locking check; those
            // old-key receipts carry no identity effect and are retained by
            // their operation row independently of this context cleanup.
            let operation_exists: bool = tx
                .query_one(
                    &format!(
                        "select exists(select 1 from {} where context_id=$1)",
                        self.table("operations")
                    ),
                    &[&id],
                )
                .map_err(db)?
                .get(0);
            if operation_exists {
                continue;
            }
            // Match the context -> code -> delivery lock order used by
            // preparation and verification. Deliveries must be removed before
            // codes because the delivery FK references the code receipt.
            tx.query(
                &format!(
                    "select seq from {} where context_id=$1 order by seq for update",
                    self.table("codes")
                ),
                &[&id],
            )
            .map_err(db)?;
            let delivery = tx
                .query_opt(
                    &format!(
                        "select 1 from {} where context_id=$1 \
                         and (status='claimed' or (status='unknown' and not stop_confirmed)) \
                         limit 1 for update",
                        self.table("deliveries")
                    ),
                    &[&id],
                )
                .map_err(db)?;
            if delivery.is_some() {
                continue;
            }
            tx.execute(
                &format!(
                    "update {} set payload_cipher=''::bytea where context_id=$1",
                    self.table("deliveries")
                ),
                &[&id],
            )
            .map_err(db)?;
            tx.execute(
                &format!(
                    "delete from {} where context_id=$1",
                    self.table("deliveries")
                ),
                &[&id],
            )
            .map_err(db)?;
            tx.execute(
                &format!("delete from {} where context_id=$1", self.table("codes")),
                &[&id],
            )
            .map_err(db)?;
            tx.execute(
                &format!("delete from {} where context_id=$1", self.table("intents")),
                &[&id],
            )
            .map_err(db)?;
            removed += tx
                .execute(
                    &format!("delete from {} where id=$1", self.table("contexts")),
                    &[&id],
                )
                .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(removed)
    }

    pub(super) fn phase_gc_scope_state(&self, limit: i64) -> Result<(), RegistrationEmailError> {
        let mut client = self
            .adapter
            .connect()
            .map_err(RegistrationEmailError::Store)?;
        let mut tx = client.transaction().map_err(db)?;
        self.tx_begin_maintenance(&mut tx)?;
        let at = now(&mut tx)?;
        let buckets = tx
            .query(
                &format!(
                    "select subject from {} \
                     where authority=$1 and product=$2 and retain_until<=$3 \
                     order by retain_until,subject limit $4",
                    self.table("buckets")
                ),
                &[&self.scope.authority, &self.scope.product, &at, &limit],
            )
            .map_err(db)?;
        for row in buckets {
            let subject: Vec<u8> = row.get("subject");
            self.gc_bucket(&mut tx, &subject, at)?;
        }

        // A subject can outlive its last bucket, so scan subject retention
        // independently. The authority row is shared by every product.
        let subjects = tx
            .query(
                &format!(
                    "select subject from {} where authority=$1 and retain_until<=$2 \
                     order by retain_until,subject limit $3",
                    self.table("subjects")
                ),
                &[&self.scope.authority, &at, &limit],
            )
            .map_err(db)?;
        for row in subjects {
            let subject: Vec<u8> = row.get("subject");
            if !self.subject_lock(&mut tx, &subject)? {
                continue;
            }
            self.delete_subject_if_unreferenced(&mut tx, &subject, at)?;
        }

        tx.execute(
            &format!(
                "with candidates as ( \
                   select email from {} where retain_until<=$1 \
                   order by retain_until,email limit $2 for update skip locked \
                 ) \
                 delete from {} t using candidates c where t.email=c.email",
                self.table("tombstones"),
                self.table("tombstones")
            ),
            &[&at, &limit],
        )
        .map_err(db)?;
        tx.execute(
            &format!(
                "with candidates as ( \
                   select tenant,account_id from {} \
                   where tenant=$1 and retain_until<=$2 \
                   order by retain_until,account_id limit $3 for update skip locked \
                 ) \
                 delete from {} t using candidates c \
                 where t.tenant=c.tenant and t.account_id=c.account_id",
                self.table("member_tombstones"),
                self.table("member_tombstones")
            ),
            &[&self.scope.tenant, &at, &limit],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
    }

    fn gc_bucket(
        &self,
        tx: &mut postgres::Transaction<'_>,
        subject: &[u8],
        at: i64,
    ) -> Result<(), RegistrationEmailError> {
        if !self.subject_lock(tx, subject)? {
            return Ok(());
        }
        let bucket = tx
            .query_opt(
                &format!(
                    "select retain_until from {} \
                     where authority=$1 and product=$2 and subject=$3 for update",
                    self.table("buckets")
                ),
                &[&self.scope.authority, &self.scope.product, &subject],
            )
            .map_err(db)?;
        let Some(bucket) = bucket else {
            return Ok(());
        };
        if bucket.get::<_, i64>("retain_until") > at {
            return Ok(());
        }
        let retained = tx
            .query_one(
                &format!(
                    "select exists(select 1 from {} \
                     where authority=$1 and product=$2 and subject=$3)",
                    self.table("contexts")
                ),
                &[&self.scope.authority, &self.scope.product, &subject],
            )
            .map_err(db)?
            .get(0);
        if retained {
            return Ok(());
        }
        tx.execute(
            &format!(
                "delete from {} where authority=$1 and product=$2 and subject=$3",
                self.table("buckets")
            ),
            &[&self.scope.authority, &self.scope.product, &subject],
        )
        .map_err(db)?;
        self.delete_subject_if_unreferenced(tx, subject, at)
    }

    fn delete_subject_if_unreferenced(
        &self,
        tx: &mut postgres::Transaction<'_>,
        subject: &[u8],
        at: i64,
    ) -> Result<(), RegistrationEmailError> {
        // Lock a bucket before the shared authority subject row. The advisory
        // subject lock serializes this with all send/verify bucket mutations.
        let bucket = tx
            .query_opt(
                &format!(
                    "select product from {} where authority=$1 and subject=$2 \
                     limit 1 for update",
                    self.table("buckets")
                ),
                &[&self.scope.authority, &subject],
            )
            .map_err(db)?;
        if bucket.is_some() {
            return Ok(());
        }
        let context = tx
            .query_one(
                &format!(
                    "select exists(select 1 from {} where authority=$1 and subject=$2)",
                    self.table("contexts")
                ),
                &[&self.scope.authority, &subject],
            )
            .map_err(db)?
            .get(0);
        if context {
            return Ok(());
        }
        let subject_row = tx
            .query_opt(
                &format!(
                    "select retain_until from {} where authority=$1 and subject=$2 for update",
                    self.table("subjects")
                ),
                &[&self.scope.authority, &subject],
            )
            .map_err(db)?;
        if subject_row.is_some_and(|row| row.get::<_, i64>("retain_until") <= at) {
            tx.execute(
                &format!(
                    "delete from {} where authority=$1 and subject=$2",
                    self.table("subjects")
                ),
                &[&self.scope.authority, &subject],
            )
            .map_err(db)?;
        }
        Ok(())
    }
}

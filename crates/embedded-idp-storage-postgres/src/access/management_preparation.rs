use super::*;
use embedded_idp_core::access::{
    AccessAdminTransaction, ManagementClientPreparation, ManagementClientPreparationResult,
    ManagementClientPreparationStore,
};
use postgres::IsolationLevel;

impl PostgresStorageAdapter {
    /// Explicit optional additive migration. Online startup and P3 never run DDL.
    pub fn prepare_management_client_audit_schema(
        &self,
        mode: TenancyMode,
    ) -> Result<(), StoreError> {
        let mut connection = self.connect()?;
        let mut tx = connection.transaction().map_err(access_db_error)?;
        let s = self.schema_name();
        validate_layout(&mut tx, s)?;
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for update"),
            &[],
        )
        .map_err(access_db_error)?;
        schema_facts(&mut tx, s, mode)?;
        let exists: bool = tx
            .query_one(
                "select to_regclass($1) is not null",
                &[&format!("{s}.management_client_preparation_audit")],
            )
            .map_err(access_db_error)?
            .get(0);
        if !exists {
            tx.batch_execute(&format!("create table {s}.management_client_preparation_audit (id uuid primary key, occurred_at_epoch bigint not null, client_id text not null, request_id text not null, configuration_digest text not null)" )).map_err(access_db_error)?;
        }
        validate_audit_layout(&mut tx, s)?;
        tx.commit().map_err(access_db_error)
    }
}
fn validate_audit_layout(tx: &mut impl GenericClient, s: &str) -> Result<(), StoreError> {
    // Hold a relation lock through commit: a concurrent ALTER/TRIGGER/RULE must
    // not change the audited write after its layout has been checked.
    let exists: bool = tx
        .query_one(
            "select to_regclass($1) is not null",
            &[&format!("{s}.management_client_preparation_audit")],
        )
        .map_err(access_db_error)?
        .get(0);
    if !exists {
        return Err(StoreError::Conflict(
            "access.management_preparation_audit_migration_required",
        ));
    }
    tx.batch_execute(&format!(
        "lock table {s}.management_client_preparation_audit in row exclusive mode"
    ))
    .map_err(access_db_error)?;
    let valid: bool = tx.query_one(
        "select count(*)=5 from information_schema.columns
         where table_schema=$1 and table_name='management_client_preparation_audit'
           and is_nullable='NO' and column_default is null and is_generated='NEVER'
           and ((column_name='id' and data_type='uuid')
             or (column_name='occurred_at_epoch' and data_type='bigint')
             or (column_name in ('client_id','request_id','configuration_digest') and data_type='text'))",
        &[&s],
    ).map_err(access_db_error)?.get(0);
    let exact: bool = tx.query_one(
        "select exists(select 1 from pg_class where oid=to_regclass($2)
                         and relkind='r' and relpersistence='p' and not relrowsecurity)
           and (select count(*)=5 from information_schema.columns
                where table_schema=$1 and table_name='management_client_preparation_audit')
           and exists(select 1 from pg_constraint where conrelid=to_regclass($2)
                and contype='p' and convalidated and not condeferrable
                and conkey=array[(select attnum from pg_attribute where attrelid=to_regclass($2)
                                  and attname='id' and not attisdropped)]::smallint[])
           and not exists(select 1 from pg_constraint where conrelid=to_regclass($2) and contype not in ('p','n'))
           and not exists(select 1 from pg_trigger where tgrelid=to_regclass($2) and not tgisinternal)
           and not exists(select 1 from pg_rewrite where ev_class=to_regclass($2))
           and not exists(select 1 from pg_inherits where inhrelid=to_regclass($2) or inhparent=to_regclass($2))",
        &[&s, &format!("{s}.management_client_preparation_audit")],
    ).map_err(access_db_error)?.get(0);
    if !valid || !exact {
        return Err(StoreError::Conflict(
            "access.management_preparation_audit_migration_required",
        ));
    }
    Ok(())
}
impl ManagementClientPreparationStore for PostgresStorageAdapter {
    fn prepare_management_client(
        &self,
        plan: &ManagementClientPreparation,
    ) -> Result<ManagementClientPreparationResult, StoreError> {
        let mut connection = self.connect()?;
        let mut tx = connection
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        let s = self.schema_name();
        validate_layout(&mut tx, s)?;
        tx.query_one(
            &format!("select singleton from {s}.access_state where singleton for update"),
            &[],
        )
        .map_err(access_db_error)?;
        if !schema_facts(&mut tx, s, plan.mode())?.bootstrap_completed {
            return Err(StoreError::Conflict("access.bootstrap_required"));
        }
        let mut admin = super::admin::PostgresAccessAdminTransaction {
            tx,
            schema: s,
            mode: plan.mode(),
            actor: None,
        };
        if !admin.has_effective_security_admin("0", RoleKind::SystemAdmin)? {
            return Err(StoreError::Conflict("access.last_security_admin"));
        }
        let mut tx = admin.tx;
        validate_audit_layout(&mut tx, s)?;
        let c = plan.client();
        let redirects = serde_json::to_string(&c.redirect_uris).map_err(|_| invalid())?;
        let now = epoch(plan.occurred_at())?;
        let created=tx.execute(&format!("insert into {s}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,client_secret_hash,created_at_epoch) values($1,$2,$3,'public_desktop',true,null,$4) on conflict(client_id) do nothing"),&[&c.client_id,&c.client_name,&redirects,&now]).map_err(access_db_error)?==1;
        let current = crate::transaction::decode_client(
            tx.query_one(
                &format!("select * from {s}.oidc_clients where client_id=$1 for update"),
                &[&c.client_id],
            )
            .map_err(access_db_error)?,
        )?;
        if !plan.matches(&current) {
            return Ok(ManagementClientPreparationResult::Conflict);
        }
        if created {
            let configuration = plan.configuration_digest();
            let audited = tx.execute(&format!("insert into {s}.management_client_preparation_audit(id,occurred_at_epoch,client_id,request_id,configuration_digest) values($1,$2,$3,$4,$5)"),&[&Uuid::parse_str(plan.audit_id()).map_err(|_| invalid())?,&now,&c.client_id,&plan.request_id(),&configuration]).map_err(access_db_error)?;
            if audited != 1 {
                return Err(invalid());
            }
        }
        tx.commit().map_err(access_db_error)?;
        Ok(if created {
            ManagementClientPreparationResult::Created
        } else {
            ManagementClientPreparationResult::AlreadyMatches
        })
    }
}

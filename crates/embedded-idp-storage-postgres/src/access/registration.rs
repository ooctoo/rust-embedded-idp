use super::{access_db_error, decode_tenant, epoch, time, PostgresAccessStore};
use embedded_idp_core::{
    access::{
        MembershipStatus, Tenant, TenantEmailVerificationState, TenantEmailVerificationStore,
        TenantEmailVerificationTransaction, TenantMembership, TenantRegistrationError,
        TenantVerificationAccount,
    },
    EmailVerificationCode, StoreError,
};
use postgres::{IsolationLevel, Transaction};
use uuid::Uuid;

/// Created only by `verification_transaction`; it owns one pooled transaction.
pub struct PostgresTenantEmailVerificationTransaction<'a> {
    tx: Transaction<'a>,
    schema: &'a str,
    tenant_id: &'a str,
    tenant: Option<Tenant>,
}

impl TenantEmailVerificationStore for PostgresAccessStore {
    type Transaction<'a> = PostgresTenantEmailVerificationTransaction<'a>;

    fn verification_transaction<T, F>(
        &self,
        tenant_id: &str,
        operation: F,
    ) -> Result<T, TenantRegistrationError>
    where
        F: FnOnce(&mut Self::Transaction<'_>) -> Result<T, TenantRegistrationError>,
    {
        self.mode.validate_business_tenant(tenant_id)?;
        let mut client = self.adapter.connect()?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        let schema = self.adapter.schema_name();
        transaction
            .query_one(
                &format!("select singleton from {schema}.access_state where singleton for share"),
                &[],
            )
            .map_err(access_db_error)?;
        self.verify(&mut transaction)?;
        let tenant = transaction
            .query_opt(
                &format!("select * from {schema}.access_tenants where id=$1 for share"),
                &[&tenant_id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_tenant)
            .transpose()?;
        let mut transaction = PostgresTenantEmailVerificationTransaction {
            tx: transaction,
            schema,
            tenant_id,
            tenant,
        };
        let result = operation(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}

impl TenantEmailVerificationTransaction for PostgresTenantEmailVerificationTransaction<'_> {
    fn load_verification_account(
        &mut self,
        email: &str,
    ) -> Result<Option<TenantVerificationAccount>, StoreError> {
        let Some(tenant) = self.tenant.clone() else {
            return Ok(None);
        };
        let Some(account) = self
            .tx
            .query_opt(
                &format!(
                    "select id,status,registration_tenant_id from {}.accounts where email=$1 for update",
                    self.schema
                ),
                &[&email],
            )
            .map_err(access_db_error)?
        else {
            return Ok(None);
        };
        let account_id: Uuid = account.get("id");
        let account_pending_verification =
            account.get::<_, &str>("status") == "pending_verification";
        let Some(member) = self
            .tx
            .query_opt(
                &format!("select * from {}.access_memberships where tenant_id=$1 and account_id=$2 for share", self.schema),
                &[&self.tenant_id, &account_id],
            )
            .map_err(access_db_error)?
        else {
            return Ok(None);
        };
        Ok(Some(TenantVerificationAccount {
            account_id: account_id.to_string(),
            email: email.into(),
            registration_tenant_id: account.get("registration_tenant_id"),
            tenant,
            membership: TenantMembership {
                tenant_id: member.get("tenant_id"),
                subject_id: member.get::<_, Uuid>("account_id").to_string(),
                status: match member.get::<_, &str>("status") {
                    "active" => MembershipStatus::Active,
                    "suspended" => MembershipStatus::Suspended,
                    "removed" => MembershipStatus::Removed,
                    _ => return Err(StoreError::Backend("invalid access storage data".into())),
                },
                joined_at: time(member.get("joined_at_epoch"))?,
                version: u64::try_from(member.get::<_, i64>("version"))
                    .map_err(|_| StoreError::Backend("invalid access storage data".into()))?,
            },
            pending_verification: account_pending_verification,
        }))
    }
    fn load_verification(
        &mut self,
        email: &str,
        code: &str,
    ) -> Result<Option<TenantEmailVerificationState>, StoreError> {
        let Some(account) = self.load_verification_account(email)? else {
            return Ok(None);
        };
        let account_id = Uuid::parse_str(&account.account_id)
            .map_err(|_| StoreError::Conflict("access.uuid"))?;
        let Some(verification) = self
            .tx
            .query_opt(
                &format!("select * from {}.email_verification_codes where tenant_id=$1 and account_id=$2 and email=$3 and code=$4 order by issued_at_epoch desc,id desc limit 1 for update", self.schema),
                &[&self.tenant_id, &account_id, &email, &code],
            )
            .map_err(access_db_error)?
        else {
            return Ok(None);
        };
        Ok(Some(TenantEmailVerificationState {
            registration_tenant_id: account.registration_tenant_id,
            tenant: account.tenant,
            membership: account.membership,
            account_pending_verification: account.pending_verification,
            verification: EmailVerificationCode {
                id: verification.get::<_, Uuid>("id").to_string(),
                account_id: verification.get::<_, Uuid>("account_id").to_string(),
                email: verification.get("email"),
                code: verification.get("code"),
                issued_at: time(verification.get("issued_at_epoch"))?,
                expires_at: time(verification.get("expires_at_epoch"))?,
                consumed_at: verification
                    .get::<_, Option<i64>>("consumed_at_epoch")
                    .map(time)
                    .transpose()?,
            },
        }))
    }

    fn replace_verification(&mut self, code: &EmailVerificationCode) -> Result<(), StoreError> {
        let account =
            Uuid::parse_str(&code.account_id).map_err(|_| StoreError::Conflict("account.id"))?;
        let id = Uuid::parse_str(&code.id).map_err(|_| StoreError::Conflict("verification.id"))?;
        let now = epoch(code.issued_at)?;
        let expires = epoch(code.expires_at)?;
        self.tx.execute(
            &format!("update {}.email_verification_codes set consumed_at_epoch=$4 where tenant_id=$1 and account_id=$2 and email=$3 and consumed_at_epoch is null", self.schema),
            &[&self.tenant_id, &account, &code.email, &now],
        ).map_err(access_db_error)?;
        self.tx.execute(
            &format!("insert into {}.email_verification_codes(tenant_id,id,account_id,email,code,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7)", self.schema),
            &[&self.tenant_id, &id, &account, &code.email, &code.code, &now, &expires],
        ).map_err(access_db_error)?;
        Ok(())
    }

    fn activate_verified_account(
        &mut self,
        account_id: &str,
        verification_id: &str,
        now: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        let account_id =
            Uuid::parse_str(account_id).map_err(|_| StoreError::Conflict("access.uuid"))?;
        let verification_id =
            Uuid::parse_str(verification_id).map_err(|_| StoreError::Conflict("access.uuid"))?;
        let now = epoch(now)?;
        let account_updated = self
            .tx
            .execute(
                &format!("update {}.accounts set status='active' where id=$1 and status='pending_verification'", self.schema),
                &[&account_id],
            )
            .map_err(access_db_error)?;
        if account_updated != 1 {
            return Err(StoreError::Conflict("email_verification.account"));
        }
        let verification_updated = self
            .tx
            .execute(
                &format!("update {}.email_verification_codes set consumed_at_epoch=$4 where tenant_id=$1 and id=$2 and account_id=$3 and consumed_at_epoch is null and issued_at_epoch<=$4 and expires_at_epoch>$4", self.schema),
                &[&self.tenant_id, &verification_id, &account_id, &now],
            )
            .map_err(access_db_error)?;
        if verification_updated != 1 {
            return Err(StoreError::Conflict("email_verification.code"));
        }
        Ok(())
    }
}

use super::{access_db_error, decode_tenant, epoch, invalid, time, PostgresAccessStore};
use embedded_idp_core::{
    access::{
        AccessListScope, AccessPageRequest, MembershipStatus, SelectionSource, SubjectTenant,
        Tenant, TenantAuthError, TenantAuthStore, TenantAuthTransaction, TenantLoginIdentity,
        TenantMembership, TenantSelectionRecord, TenantSession,
    },
    SecretString, SessionStatus, StoreError,
};
use postgres::{IsolationLevel, Row, Transaction};
use uuid::Uuid;

/// Created only by `auth_transaction`; it owns one pooled transaction.
pub struct PostgresTenantAuthTransaction<'a> {
    pub(super) tx: Transaction<'a>,
    pub(super) schema: &'a str,
}

impl TenantAuthStore for PostgresAccessStore {
    type Transaction<'a> = PostgresTenantAuthTransaction<'a>;

    fn auth_transaction<R>(
        &self,
        mode: embedded_idp_core::access::TenancyMode,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, TenantAuthError>,
    ) -> Result<R, TenantAuthError> {
        if mode != self.mode {
            return Err(embedded_idp_core::access::AccessError::ModeMismatch.into());
        }
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
        let mut transaction = PostgresTenantAuthTransaction {
            tx: transaction,
            schema,
        };
        let result = run(&mut transaction)?;
        transaction.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}

impl TenantAuthTransaction for PostgresTenantAuthTransaction<'_> {
    fn lock_tenants(&mut self, tenant_ids: &[String]) -> Result<(), StoreError> {
        let mut tenant_ids = tenant_ids.to_vec();
        tenant_ids.sort();
        tenant_ids.dedup();
        for tenant_id in tenant_ids {
            self.tx
                .query_opt(
                    &format!(
                        "select id from {}.access_tenants where id=$1 for share",
                        self.schema
                    ),
                    &[&tenant_id],
                )
                .map_err(access_db_error)?;
        }
        Ok(())
    }

    fn lock_account_by_email(
        &mut self,
        email: &str,
    ) -> Result<Option<TenantLoginIdentity>, StoreError> {
        self.tx
            .query_opt(
                &format!(
                    "select id,password_hash,status from {}.accounts where email=$1 for update",
                    self.schema
                ),
                &[&email],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_identity)
            .transpose()
    }

    // ponytail: account writes and authentication serialize per account; benchmark
    // before adding a separate shared-lock read path with the same revocation guarantees.
    fn lock_account(
        &mut self,
        account_id: &str,
    ) -> Result<Option<TenantLoginIdentity>, StoreError> {
        let Ok(account_id) = Uuid::parse_str(account_id) else {
            return Ok(None);
        };
        self.tx
            .query_opt(
                &format!(
                    "select id,password_hash,status from {}.accounts where id=$1 for update",
                    self.schema
                ),
                &[&account_id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_identity)
            .transpose()
    }

    fn client_exists(&mut self, client_id: &str) -> Result<bool, StoreError> {
        Ok(self
            .tx
            .query_one(
                &format!(
                    "select exists(select 1 from {}.oidc_clients where client_id=$1)",
                    self.schema
                ),
                &[&client_id],
            )
            .map_err(access_db_error)?
            .get(0))
    }

    fn tenant(&mut self, tenant_id: &str) -> Result<Option<Tenant>, StoreError> {
        self.tx
            .query_opt(
                &format!("select * from {}.access_tenants where id=$1", self.schema),
                &[&tenant_id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_tenant)
            .transpose()
    }

    fn membership(
        &mut self,
        tenant_id: &str,
        account_id: &str,
    ) -> Result<Option<TenantMembership>, StoreError> {
        let Ok(account_id) = Uuid::parse_str(account_id) else {
            return Ok(None);
        };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.access_memberships where tenant_id=$1 and account_id=$2",
                    self.schema
                ),
                &[&tenant_id, &account_id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_membership)
            .transpose()
    }

    fn find_selection(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantSelectionRecord>, StoreError> {
        self.selection(digest, "")
    }

    fn lock_selection(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<TenantSelectionRecord>, StoreError> {
        self.selection(digest, " for update")
    }

    fn insert_selection(&mut self, record: &TenantSelectionRecord) -> Result<(), StoreError> {
        let id = parse_uuid(&record.id)?;
        let account_id = parse_uuid(&record.account_id)?;
        let (source_tenant_id, source_session_id) = match &record.source {
            Some(source) => (
                Some(source.tenant_id.as_str()),
                Some(parse_uuid(&source.session_id)?),
            ),
            None => (None, None),
        };
        self.tx
            .execute(
                &format!("insert into {}.auth_tenant_selections(id,ticket_digest,account_id,client_id,login_entry,purpose,authenticated_at_epoch,expires_at_epoch,consumed_at_epoch,revoked_at_epoch,source_tenant_id,source_session_id) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", self.schema),
                &[&id, &&record.ticket_digest[..], &account_id, &record.client_id, &record.login_entry, &record.purpose, &epoch(record.authenticated_at)?, &epoch(record.expires_at)?, &record.consumed_at.map(epoch).transpose()?, &record.revoked_at.map(epoch).transpose()?, &source_tenant_id, &source_session_id],
            )
            .map_err(access_db_error)?;
        Ok(())
    }

    fn consume_selection(
        &mut self,
        id: &str,
        now: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        let id = parse_uuid(id)?;
        let now = epoch(now)?;
        if self.tx.execute(&format!("update {}.auth_tenant_selections set consumed_at_epoch=$2 where id=$1 and consumed_at_epoch is null and revoked_at_epoch is null and authenticated_at_epoch<=$2 and expires_at_epoch>$2", self.schema), &[&id,&now]).map_err(access_db_error)? != 1 {
            return Err(StoreError::Conflict("selection.consume"));
        }
        Ok(())
    }

    fn list_tenants(
        &mut self,
        account_id: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<SubjectTenant>, StoreError> {
        page.validate(&AccessListScope::SubjectTenants {
            subject_id: account_id.into(),
        })
        .map_err(|_| StoreError::Conflict("access.page"))?;
        let account_id = match Uuid::parse_str(account_id) {
            Ok(value) => value,
            Err(_) => return Ok(vec![]),
        };
        let after = page.cursor.as_ref().map(|cursor| cursor.after[0].as_str());
        self.tx.query(&format!("select t.*,m.account_id,m.status as member_status,m.version as member_version,m.joined_at_epoch from {}.access_memberships m join {}.access_tenants t on t.id=m.tenant_id where m.account_id=$1 and m.status<>'removed' and t.id<>'0' and ($2::text is null or t.id>$2 collate \"C\") order by t.id limit $3", self.schema, self.schema), &[&account_id,&after,&(page.fetch_limit() as i64)]).map_err(access_db_error)?.iter().map(|row| {
            let tenant=decode_tenant(row)?;
            Ok(SubjectTenant { membership: TenantMembership { tenant_id:tenant.id.clone(), subject_id:row.get::<_,Uuid>("account_id").to_string(), status:decode_membership_status(row.get("member_status"))?, joined_at:time(row.get("joined_at_epoch"))?, version:u64::try_from(row.get::<_,i64>("member_version")).map_err(|_| invalid())? }, tenant })
        }).collect()
    }

    fn session_device(
        &mut self,
        tenant: &str,
        account: &str,
        device: &str,
    ) -> Result<Option<embedded_idp_core::access::TenantSessionDevice>, StoreError> {
        self.read_session_device(tenant, account, device)
    }
    fn session(
        &mut self,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<Option<TenantSession>, StoreError> {
        let Ok(session_id) = Uuid::parse_str(session_id) else {
            return Ok(None);
        };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.auth_sessions where tenant_id=$1 and id=$2",
                    self.schema
                ),
                &[&tenant_id, &session_id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_session)
            .transpose()
    }

    fn insert_session(
        &mut self,
        session: &TenantSession,
        refresh_id: &str,
        digest: &[u8; 32],
        refresh_expires_at: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        let id = parse_uuid(&session.id)?;
        let account_id = parse_uuid(&session.account_id)?;
        let refresh_id = parse_uuid(refresh_id)?;
        let device_id = session.device_id.as_deref().map(parse_uuid).transpose()?;
        self.tx.execute(&format!("insert into {}.auth_sessions(tenant_id,id,account_id,client_id,device_id,status,created_at_epoch,expires_at_epoch,refresh_token_version,scope,authenticated_at_epoch,purpose) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)", self.schema), &[&session.tenant_id,&id,&account_id,&session.client_id,&device_id,&session_status(&session.status),&epoch(session.created_at)?,&epoch(session.expires_at)?,&i64::try_from(session.refresh_token_version).map_err(|_|invalid())?,&session.scope,&epoch(session.authenticated_at)?,&match session.purpose { embedded_idp_core::AccessTokenPurpose::Business => "business", embedded_idp_core::AccessTokenPurpose::Management => "management" }]).map_err(access_db_error)?;
        self.tx.execute(&format!("insert into {}.refresh_tokens(tenant_id,id,session_id,token_digest,token_version,issued_at_epoch,expires_at_epoch) values($1,$2,$3,$4,$5,$6,$7)", self.schema), &[&session.tenant_id,&refresh_id,&id,&&digest[..],&i64::try_from(session.refresh_token_version).map_err(|_|invalid())?,&epoch(session.created_at)?,&epoch(refresh_expires_at)?]).map_err(access_db_error)?;
        Ok(())
    }
}

impl PostgresTenantAuthTransaction<'_> {
    fn selection(
        &mut self,
        digest: &[u8; 32],
        lock: &str,
    ) -> Result<Option<TenantSelectionRecord>, StoreError> {
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.auth_tenant_selections where ticket_digest=$1{}",
                    self.schema, lock
                ),
                &[&&digest[..]],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_selection)
            .transpose()
    }
}

fn parse_uuid(value: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::Conflict("access.uuid"))
}
fn decode_identity(row: &Row) -> Result<TenantLoginIdentity, StoreError> {
    Ok(TenantLoginIdentity {
        id: row.get::<_, Uuid>("id").to_string(),
        password_hash: SecretString::new(row.get::<_, String>("password_hash")),
        active: row.get::<_, &str>("status") == "active",
    })
}
fn decode_membership_status(value: &str) -> Result<MembershipStatus, StoreError> {
    match value {
        "active" => Ok(MembershipStatus::Active),
        "suspended" => Ok(MembershipStatus::Suspended),
        "removed" => Ok(MembershipStatus::Removed),
        _ => Err(invalid()),
    }
}
fn decode_membership(row: &Row) -> Result<TenantMembership, StoreError> {
    Ok(TenantMembership {
        tenant_id: row.get("tenant_id"),
        subject_id: row.get::<_, Uuid>("account_id").to_string(),
        status: decode_membership_status(row.get("status"))?,
        joined_at: time(row.get("joined_at_epoch"))?,
        version: u64::try_from(row.get::<_, i64>("version")).map_err(|_| invalid())?,
    })
}
fn session_status(value: &SessionStatus) -> &'static str {
    match value {
        SessionStatus::Pending => "pending",
        SessionStatus::Active => "active",
        SessionStatus::Revoked => "revoked",
        SessionStatus::Expired => "expired",
    }
}
pub(super) fn decode_session(row: &Row) -> Result<TenantSession, StoreError> {
    Ok(TenantSession {
        purpose: match row.get::<_, &str>("purpose") {
            "business" => embedded_idp_core::AccessTokenPurpose::Business,
            "management" => embedded_idp_core::AccessTokenPurpose::Management,
            _ => return Err(invalid()),
        },
        tenant_id: row.get("tenant_id"),
        id: row.get::<_, Uuid>("id").to_string(),
        account_id: row.get::<_, Uuid>("account_id").to_string(),
        client_id: row.get("client_id"),
        device_id: row
            .get::<_, Option<Uuid>>("device_id")
            .map(|id| id.to_string()),
        scope: row.get("scope"),
        authenticated_at: time(row.get("authenticated_at_epoch"))?,
        status: match row.get::<_, &str>("status") {
            "pending" => SessionStatus::Pending,
            "active" => SessionStatus::Active,
            "revoked" => SessionStatus::Revoked,
            "expired" => SessionStatus::Expired,
            _ => return Err(invalid()),
        },
        created_at: time(row.get("created_at_epoch"))?,
        expires_at: time(row.get("expires_at_epoch"))?,
        refresh_token_version: u64::try_from(row.get::<_, i64>("refresh_token_version"))
            .map_err(|_| invalid())?,
    })
}
fn decode_selection(row: &Row) -> Result<TenantSelectionRecord, StoreError> {
    let digest: [u8; 32] = row
        .get::<_, Vec<u8>>("ticket_digest")
        .try_into()
        .map_err(|_| invalid())?;
    let source = match (
        row.get::<_, Option<String>>("source_tenant_id"),
        row.get::<_, Option<Uuid>>("source_session_id"),
    ) {
        (None, None) => None,
        (Some(tenant_id), Some(session_id)) => Some(SelectionSource {
            tenant_id,
            session_id: session_id.to_string(),
        }),
        _ => return Err(invalid()),
    };
    Ok(TenantSelectionRecord {
        id: row.get::<_, Uuid>("id").to_string(),
        ticket_digest: digest,
        account_id: row.get::<_, Uuid>("account_id").to_string(),
        client_id: row.get("client_id"),
        login_entry: row.get("login_entry"),
        purpose: row.get("purpose"),
        authenticated_at: time(row.get("authenticated_at_epoch"))?,
        expires_at: time(row.get("expires_at_epoch"))?,
        consumed_at: row
            .get::<_, Option<i64>>("consumed_at_epoch")
            .map(time)
            .transpose()?,
        revoked_at: row
            .get::<_, Option<i64>>("revoked_at_epoch")
            .map(time)
            .transpose()?,
        source,
    })
}

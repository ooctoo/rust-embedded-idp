use super::*;
use embedded_idp_core::access::*;
use postgres::{IsolationLevel, Transaction};
use serde_json::{json, Value};

/// Created only by the store runner; every operation stays on one pooled connection.
pub struct PostgresAccessAdminTransaction<'a> {
    tx: Transaction<'a>,
    schema: &'a str,
    mode: TenancyMode,
    actor: Option<Uuid>,
}

pub(crate) fn check_readiness(
    store: &PostgresAccessStore,
    catalog: &PermissionCatalog,
) -> Result<(), StoreError> {
    let mut client = store.adapter.connect()?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .read_only(true)
        .start()
        .map_err(access_db_error)?;
    let schema = store.adapter.schema_name();
    let mut transaction = PostgresAccessAdminTransaction {
        tx,
        schema,
        mode: store.mode,
        actor: None,
    };
    validate_layout(&mut transaction.tx, schema)?;
    if !schema_facts(&mut transaction.tx, schema, store.mode)?.bootstrap_completed {
        return Err(StoreError::Conflict("access.bootstrap_required"));
    }
    for expected in catalog.definitions() {
        if expected.category == PermissionCategory::Business {
            continue;
        }
        let actual = transaction
            .tx
            .query_opt(
                &format!(
                    "select category, enabled from {schema}.access_permissions where tenant_id='0' and resource_type=$1 and action=$2"
                ),
                &[&expected.key.resource_type, &expected.key.action],
            )
            .map_err(access_db_error)?
            .ok_or(StoreError::Conflict("access.readiness_catalog"))?;
        if actual.get::<_, String>("category") != category_name(expected.category)
            || !actual.get::<_, bool>("enabled")
        {
            return Err(StoreError::Conflict("access.readiness_catalog"));
        }
    }
    if !transaction.has_effective_security_admin("0", RoleKind::SystemAdmin)? {
        return Err(StoreError::Conflict("access.last_security_admin"));
    }
    transaction.tx.commit().map_err(access_db_error)
}

impl AccessAdminStore for PostgresAccessStore {
    type Transaction<'a> = PostgresAccessAdminTransaction<'a>;

    fn admin_transaction<R>(
        &self,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError> {
        let mut client = self.adapter.connect()?;
        // Each read after a lock wait must observe the preceding writer's commit.
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        let mut tx = PostgresAccessAdminTransaction {
            tx,
            schema: self.adapter.schema_name(),
            mode: self.mode,
            actor: None,
        };
        let result = run(&mut tx)?;
        tx.tx.commit().map_err(access_db_error)?;
        Ok(result)
    }
}

// Only enum-selected SQL keywords enter query text; all request values stay bound.
fn list_order(page: &AccessPageRequest) -> (&'static str, &'static str) {
    match page.sort_order.unwrap_or(AccessSortOrder::Desc) {
        AccessSortOrder::Asc => ("asc", ">"),
        AccessSortOrder::Desc => ("desc", "<"),
    }
}

fn uuid(value: &str) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value).map_err(|_| StoreError::Conflict("access.uuid"))
}
fn version(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Conflict("access.version"))
}
fn decode_admin_tenant(row: &postgres::Row) -> Result<AccessTenantRecord, StoreError> {
    Ok(AccessTenantRecord {
        created_at: time(row.get("created_at_epoch"))?,
        tenant: decode_tenant(row)?,
        version: u64::try_from(row.get::<_, i64>("version")).map_err(|_| invalid())?,
    })
}
fn changed(count: u64) -> Result<(), StoreError> {
    if count == 1 {
        Ok(())
    } else {
        Err(StoreError::Conflict("access.concurrent_write"))
    }
}
fn device_status(status: &embedded_idp_core::DeviceStatus) -> &'static str {
    match status {
        embedded_idp_core::DeviceStatus::Pending => "pending",
        embedded_idp_core::DeviceStatus::Active => "active",
        embedded_idp_core::DeviceStatus::Disabled => "disabled",
        embedded_idp_core::DeviceStatus::Revoked => "revoked",
    }
}
fn role_status(value: RoleStatus) -> &'static str {
    match value {
        RoleStatus::Active => "active",
        RoleStatus::Disabled => "disabled",
    }
}
fn role_kind(value: RoleKind) -> &'static str {
    match value {
        RoleKind::Business => "business",
        RoleKind::SystemAdmin => "system_admin",
        RoleKind::TenantSecurityAdmin => "tenant_security_admin",
    }
}
fn member_status(value: MembershipStatus) -> &'static str {
    match value {
        MembershipStatus::Active => "active",
        MembershipStatus::Suspended => "suspended",
        MembershipStatus::Removed => "removed",
    }
}
fn tenant_status(value: TenantStatus) -> &'static str {
    match value {
        TenantStatus::Active => "active",
        TenantStatus::Suspended => "suspended",
        TenantStatus::Archived => "archived",
    }
}
fn resource_id(scope: &ResourceScope) -> Option<&str> {
    match scope {
        ResourceScope::Type => None,
        ResourceScope::Instance(id) => Some(id),
    }
}
fn decode_member(row: &Row) -> Result<TenantMembership, StoreError> {
    Ok(TenantMembership {
        tenant_id: row.get("tenant_id"),
        subject_id: row.get::<_, Uuid>("account_id").to_string(),
        status: match row.get::<_, &str>("status") {
            "active" => MembershipStatus::Active,
            "suspended" => MembershipStatus::Suspended,
            "removed" => MembershipStatus::Removed,
            _ => return Err(invalid()),
        },
        joined_at: time(row.get("joined_at_epoch"))?,
        version: u64::try_from(row.get::<_, i64>("version")).map_err(|_| invalid())?,
    })
}
fn decode_binding(row: &Row) -> Result<RoleBinding, StoreError> {
    Ok(RoleBinding {
        created_at: time(row.get("created_at_epoch"))?,
        id: row.get::<_, Uuid>("id").to_string(),
        tenant_id: row.get("tenant_id"),
        subject_id: row.get::<_, Uuid>("account_id").to_string(),
        role_id: row.get::<_, Uuid>("role_id").to_string(),
        resource_type: row.get("resource_type"),
        scope: row
            .get::<_, Option<String>>("resource_id")
            .map_or(ResourceScope::Type, ResourceScope::Instance),
    })
}

impl AccessAdminTransaction for PostgresAccessAdminTransaction<'_> {
    fn insert_admin_tenant(
        &mut self,
        record: &AccessTenantRecord,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let t = &record.tenant;
        self.tx.execute(&format!("insert into {}.access_tenants(id,kind,name,status,allow_registration,version,created_at_epoch) values($1,'tenant',$2,$3,$4,$5,$6)", self.schema), &[&t.id,&t.name,&tenant_status(t.status),&t.allow_registration,&version(record.version)?,&epoch(now)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn insert_admin_account(
        &mut self,
        account: &AccessAccountRecord,
        password_hash: &embedded_idp_core::SecretString,
    ) -> Result<(), StoreError> {
        let member = account.membership.as_ref().ok_or_else(invalid)?;
        let id = uuid(&account.account_id)?;
        let s = self.schema;
        self.tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,display_name,status,created_at_epoch) values($1,$2,$3,$4,$5,$6,$7)"),&[&id,&member.tenant_id,&account.email,&password_hash.expose_secret(),&account.display_name,&identity_status(account.status),&epoch(account.created_at)?]).map_err(access_db_error)?;
        self.tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch) values($1,$2,$3,$4,$5)"),&[&member.tenant_id,&id,&member_status(member.status),&version(member.version)?,&epoch(member.joined_at)?]).map_err(access_db_error)?;
        Ok(())
    }
    fn update_account_security(
        &mut self,
        before: &AccessAccountRecord,
        status: AccountIdentityStatus,
        password_hash: Option<&embedded_idp_core::SecretString>,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        let id = uuid(&before.account_id)?;
        let s = self.schema;
        let now = epoch(now)?;
        let hash = password_hash.map(|s| s.expose_secret());
        changed(self.tx.execute(&format!("update {s}.accounts set status=$3,password_hash=coalesce($4,password_hash) where id=$1 and status=$2"),&[&id,&identity_status(before.status),&identity_status(status),&hash]).map_err(access_db_error)?)?;
        if status != before.status || hash.is_some() {
            self.tx.execute(&format!("update {s}.auth_sessions set status='revoked' where account_id=$1 and status<>'revoked'"),&[&id]).map_err(access_db_error)?;
            self.tx.execute(&format!("update {s}.refresh_tokens f set revoked_at_epoch=$2,revocation_reason='administrative' where f.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where x.tenant_id=f.tenant_id and x.id=f.session_id and x.account_id=$1)"),&[&id,&now]).map_err(access_db_error)?;
            self.tx
                .execute(
                    &format!("delete from {s}.authorization_codes where account_id=$1"),
                    &[&id],
                )
                .map_err(access_db_error)?;
            self.tx
                .execute(
                    &format!("delete from {s}.email_verification_codes where account_id=$1"),
                    &[&id],
                )
                .map_err(access_db_error)?;
            self.tx.execute(&format!("update {s}.auth_tenant_selections set revoked_at_epoch=$2 where account_id=$1 and revoked_at_epoch is null"),&[&id,&now]).map_err(access_db_error)?;
        }
        Ok(())
    }
    fn account_admin_tenants(
        &mut self,
        subject: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        if limit == 0 || limit > 200 {
            return Err(invalid());
        }
        self.tx.query(&format!("select t.id from {s}.access_tenants t join {s}.access_memberships m on m.tenant_id=t.id where m.account_id=$1 and m.status='active' and t.status='active' and exists(select 1 from {s}.access_role_bindings b join {s}.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id where b.tenant_id=m.tenant_id and b.account_id=m.account_id and b.resource_id is null and r.status='active' and ((t.id='0' and r.kind='system_admin' and b.resource_type='idp.platform') or (t.id<>'0' and r.kind='tenant_security_admin' and b.resource_type='idp.tenant'))) and ($2::text is null or t.id>$2) order by t.id limit $3",s=self.schema),&[&uuid(subject)?,&after,&(limit as i64)]).map_err(access_db_error).map(|rows|rows.iter().map(|r|r.get(0)).collect())
    }

    fn admin_account(
        &mut self,
        tenant: Option<&str>,
        account: &str,
    ) -> Result<Option<AccessAccountRecord>, StoreError> {
        let Ok(account) = Uuid::parse_str(account) else {
            return Ok(None);
        };
        Ok(self
            .query_admin_accounts(
                tenant,
                Some(account),
                &AdminAccountFilter::default(),
                &AccessPageRequest {
                    sort_order: None,
                    limit: 1,
                    cursor: None,
                },
            )?
            .into_iter()
            .next())
    }
    fn admin_accounts(
        &mut self,
        tenant: Option<&str>,
        filter: &AdminAccountFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AccessAccountRecord>, StoreError> {
        filter.validate(tenant).map_err(|_| invalid())?;
        page.validate(&AccessListScope::AdminAccounts {
            tenant_id: tenant.map(str::to_owned),
            filter: filter.clone(),
        })
        .map_err(|_| invalid())?;
        self.query_admin_accounts(tenant, None, filter, page)
    }

    fn admin_client(
        &mut self,
        id: &str,
    ) -> Result<Option<embedded_idp_core::OidcClient>, StoreError> {
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.oidc_clients where client_id=$1 for share",
                    self.schema
                ),
                &[&id],
            )
            .map_err(access_db_error)?
            .map(crate::transaction::decode_client)
            .transpose()
    }
    fn admin_clients(
        &mut self,
        filter: &AdminClientFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<embedded_idp_core::AdminClientRecord>, StoreError> {
        page.validate(&AccessListScope::AdminClients {
            filter: filter.clone(),
        })
        .map_err(|_| invalid())?;
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let after = page.cursor.as_ref().map(|c| &c.after[1]);
        let kind = filter.client_type.map(admin_client_type);
        self.tx.query(&format!("select * from {}.oidc_clients where ($1::text is null or (created_at_epoch,client_id collate \"C\"){comparison}($5,$1 collate \"C\")) and ($2::text is null or client_type=$2) and ($3::boolean is null or pkce_required=$3) order by created_at_epoch {order},client_id collate \"C\" {order} limit $4", self.schema), &[&after, &kind, &filter.pkce_required, &(page.fetch_limit() as i64), &after_time])
            .map_err(access_db_error)?.into_iter().map(|r| {
                let created_at = time(r.get("created_at_epoch"))?;
                let mut record = client_metadata(crate::transaction::decode_client(r)?);
                record.created_at = Some(created_at);
                Ok(record)
            }).collect()
    }
    fn upsert_admin_client(
        &mut self,
        client: &embedded_idp_core::OidcClient,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        client.validate().map_err(|_| invalid())?;
        let redirects = serde_json::to_string(&client.redirect_uris).map_err(|_| invalid())?;
        self.tx.execute(&format!("insert into {}.oidc_clients(client_id,client_name,redirect_uris_json,client_type,pkce_required,client_secret_hash,created_at_epoch) values($1,$2,$3,$4,$5,$6,$7) on conflict(client_id) do update set client_name=excluded.client_name,redirect_uris_json=excluded.redirect_uris_json,client_type=excluded.client_type,pkce_required=excluded.pkce_required,client_secret_hash=excluded.client_secret_hash", self.schema), &[&client.client_id,&client.client_name,&redirects,&admin_client_type(client.client_type),&client.pkce_required,&client.client_secret_hash,&epoch(now)?]).map_err(access_db_error)?;
        Ok(())
    }

    fn admin_session(
        &mut self,
        tenant: &str,
        session: &str,
    ) -> Result<Option<TenantSession>, StoreError> {
        let Ok(session) = Uuid::parse_str(session) else {
            return Ok(None);
        };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.auth_sessions where tenant_id=$1 and id=$2",
                    self.schema
                ),
                &[&tenant, &session],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(super::authentication::decode_session)
            .transpose()
    }
    fn admin_sessions(
        &mut self,
        tenant: &str,
        filter: &AdminSessionFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<TenantSession>, StoreError> {
        filter.validate().map_err(|_| invalid())?;
        page.validate(&AccessListScope::AdminSessions {
            tenant_id: tenant.into(),
            filter: filter.clone(),
        })
        .map_err(|_| invalid())?;
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let Ok(account) = filter
            .account_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
        else {
            return Ok(vec![]);
        };
        let Ok(device) = filter.device_id.as_deref().map(Uuid::parse_str).transpose() else {
            return Ok(vec![]);
        };
        let after = page
            .cursor
            .as_ref()
            .map(|c| uuid(&c.after[1]))
            .transpose()?;
        let status = filter.status.as_ref().map(admin_session_status);
        let created_after = filter.created_after.map(epoch).transpose()?;
        let created_before = filter.created_before.map(epoch).transpose()?;
        self.tx.query(&format!("select * from {}.auth_sessions where tenant_id=$1 and ($2::uuid is null or (created_at_epoch,id){comparison}($10,$2)) and ($3::uuid is null or account_id=$3) and ($4::text is null or client_id=$4) and ($5::uuid is null or device_id=$5) and ($6::text is null or status=$6) and ($7::bigint is null or created_at_epoch>=$7) and ($8::bigint is null or created_at_epoch<=$8) order by created_at_epoch {order},id {order} limit $9",self.schema),&[&tenant,&after,&account,&filter.client_id,&device,&status,&created_after,&created_before,&(page.fetch_limit() as i64), &after_time]).map_err(access_db_error)?.iter().map(super::authentication::decode_session).collect()
    }
    fn active_subject_session_count(
        &mut self,
        tenant: &str,
        subject: &str,
    ) -> Result<u64, StoreError> {
        let count:i64=self.tx.query_one(&format!("select count(*) from {}.auth_sessions where tenant_id=$1 and account_id=$2 and status in ('active','pending')",self.schema),&[&tenant,&uuid(subject)?]).map_err(access_db_error)?.get(0);
        u64::try_from(count).map_err(|_| invalid())
    }

    fn admin_device(
        &mut self,
        tenant: &str,
        device: &str,
    ) -> Result<Option<AccessDeviceRecord>, StoreError> {
        let Ok(device) = Uuid::parse_str(device) else {
            return Ok(None);
        };
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.devices where tenant_id=$1 and id=$2",
                    self.schema
                ),
                &[&tenant, &device],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(super::device_management::decode_admin_device)
            .transpose()
    }
    fn admin_devices(
        &mut self,
        tenant: &str,
        filter: &AdminDeviceFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AccessDeviceRecord>, StoreError> {
        filter.validate().map_err(|_| invalid())?;
        page.validate(&AccessListScope::AdminDevices {
            tenant_id: tenant.into(),
            filter: filter.clone(),
        })
        .map_err(|_| invalid())?;
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let Ok(account) = filter
            .account_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
        else {
            return Ok(vec![]);
        };
        let after = page
            .cursor
            .as_ref()
            .map(|c| uuid(&c.after[1]))
            .transpose()?;
        let status = filter.status.as_ref().map(device_status);
        let registered_after = filter.registered_after.map(epoch).transpose()?;
        let registered_before = filter.registered_before.map(epoch).transpose()?;
        let s = self.schema;
        // ponytail: optional filters can scan a tenant's time range; add a
        // measured composite index when acceptance benchmarks justify it.
        self.tx.query(&format!(
            "select d.* from {s}.devices d where d.tenant_id=$1
             and ($2::uuid is null or (d.registered_at_epoch,d.id){comparison}($9,$2))
             and ($3::uuid is null or exists(select 1 from {s}.account_device_bindings b
                 where b.tenant_id=d.tenant_id and b.device_id=d.id and b.account_id=$3 and b.status='active'))
             and ($4::text is null or d.client_id=$4)
             and ($5::text is null or d.status=$5)
             and ($6::bigint is null or d.registered_at_epoch>=$6)
             and ($7::bigint is null or d.registered_at_epoch<=$7)
             order by d.registered_at_epoch {order},d.id {order} limit $8"
        ), &[&tenant, &after, &account, &filter.client_id, &status, &registered_after, &registered_before, &(page.fetch_limit() as i64), &after_time])
            .map_err(access_db_error)?.iter().map(super::device_management::decode_admin_device).collect()
    }

    fn lock_scope(&mut self, scope: &AccessWriteScope) -> Result<(), AccessError> {
        if scope.mode != self.mode {
            return Err(AccessError::ModeMismatch);
        }
        let s = self.schema;
        let lock = if scope.exclusive_state {
            "update"
        } else {
            "share"
        };
        self.tx
            .query_one(
                &format!("select singleton from {s}.access_state where singleton for {lock}"),
                &[],
            )
            .map_err(access_db_error)?;
        if !schema_facts(&mut self.tx, s, self.mode)?.bootstrap_completed {
            return Err(AccessError::Conflict("access.bootstrap_required"));
        }
        // ponytail: management writes serialize per domain; split locks only after
        // measured write contention and a new proof of the last-admin invariant.
        let mut tenants = scope.tenant_ids.clone();
        tenants.sort();
        tenants.dedup();
        for tenant in tenants {
            self.tx
                .query_opt(
                    &format!("select id from {s}.access_tenants where id=$1 for update"),
                    &[&tenant],
                )
                .map_err(access_db_error)?;
        }
        let mut subjects = scope
            .subject_ids
            .iter()
            .map(|id| uuid(id))
            .collect::<Result<Vec<_>, _>>()?;
        subjects.sort();
        subjects.dedup();
        for subject in subjects {
            self.tx
                .query_opt(
                    &format!("select id from {s}.accounts where id=$1 for update"),
                    &[&subject],
                )
                .map_err(access_db_error)?;
        }
        Ok(())
    }
    fn actor_is_active(
        &mut self,
        actor: &AccessActor,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        self.actor = None;
        let s = self.schema;
        let subject = uuid(&actor.subject_id)?;
        let active = self.tx.query_one(&format!("select exists(select 1 from {s}.accounts a join {s}.access_memberships m on m.account_id=a.id join {s}.access_tenants t on t.id=m.tenant_id join {s}.auth_sessions x on x.tenant_id=m.tenant_id and x.account_id=m.account_id where a.id=$1 and m.tenant_id=$2 and x.id=$3 and x.purpose='management' and a.status='active' and m.status='active' and t.status='active' and x.status='active' and x.created_at_epoch<=$4 and x.expires_at_epoch>$4 and (x.device_id is null or exists(select 1 from {s}.devices d join {s}.device_proof_keys k on k.tenant_id=d.tenant_id and k.device_id=d.id and k.key_id=d.proof_key_id join {s}.account_device_bindings b on b.tenant_id=d.tenant_id and b.device_id=d.id and b.account_id=a.id where d.tenant_id=x.tenant_id and d.id=x.device_id and d.client_id=x.client_id and d.status='active' and k.status='active' and b.status='active')))"), &[&subject,&actor.tenant_id,&uuid(&actor.session_id)?,&epoch(now)?]).map_err(access_db_error)?.get(0);
        if active {
            self.actor = Some(subject);
        }
        Ok(active)
    }
    fn check_permission(&mut self, query: &AccessQuery) -> Result<bool, StoreError> {
        Ok(check_grants(
            &mut self.tx,
            self.schema,
            self.mode,
            std::slice::from_ref(query),
        )?[0])
    }
    fn tenant(&mut self, tenant: &str) -> Result<Option<Tenant>, StoreError> {
        self.tx
            .query_opt(
                &format!("select * from {}.access_tenants where id=$1", self.schema),
                &[&tenant],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_tenant)
            .transpose()
    }
    fn tenant_record(&mut self, tenant: &str) -> Result<Option<AccessTenantRecord>, StoreError> {
        self.tx
            .query_opt(
                &format!("select * from {}.access_tenants where id=$1", self.schema),
                &[&tenant],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_admin_tenant)
            .transpose()
    }
    fn admin_tenants(
        &mut self,
        filter: &AdminTenantFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AccessTenantRecord>, StoreError> {
        filter.validate().map_err(|_| invalid())?;
        page.validate(&AccessListScope::AdminTenants {
            filter: filter.clone(),
        })
        .map_err(|_| invalid())?;
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let after = page.cursor.as_ref().map(|c| &c.after[1]);
        let name = filter.name.as_ref().map(|s| s.to_ascii_lowercase());
        let status = filter.status.map(tenant_status);
        // ponytail: literal name search can scan real tenants; measure before
        // adding a search index.
        self.tx.query(&format!(
            "select * from {}.access_tenants where id<>'0'
             and ($1::text is null or (created_at_epoch,id){comparison}($6,$1 collate \"C\"))
             and ($2::text is null or id=$2)
             and ($3::text is null or strpos(translate(name,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),$3)>0)
             and ($4::text is null or status=$4)
             order by created_at_epoch {order},id {order} limit $5", self.schema),
            &[&after, &filter.tenant_id, &name, &status, &(page.fetch_limit() as i64), &after_time])
            .map_err(access_db_error)?.iter().map(decode_admin_tenant).collect()
    }
    fn resource_category(
        &mut self,
        tenant: &str,
        resource: &str,
    ) -> Result<Option<PermissionCategory>, StoreError> {
        let rows = self
            .tx
            .query(
                &format!(
                    "select distinct category from {}.access_permissions where tenant_id=$1 and resource_type=$2",
                    self.schema
                ),
                &[&tenant, &resource],
            )
            .map_err(access_db_error)?;
        if rows.len() > 1 {
            return Err(invalid());
        }
        rows.first()
            .map(|row| match row.get::<_, &str>(0) {
                "platform" => Ok(PermissionCategory::Platform),
                "tenant" => Ok(PermissionCategory::Tenant),
                "business" => Ok(PermissionCategory::Business),
                _ => Err(invalid()),
            })
            .transpose()
    }
    fn account_is_active(&mut self, subject: &str) -> Result<bool, StoreError> {
        Ok(self
            .tx
            .query_one(
                &format!(
                    "select exists(select 1 from {}.accounts where id=$1 and status='active')",
                    self.schema
                ),
                &[&uuid(subject)?],
            )
            .map_err(access_db_error)?
            .get(0))
    }
    fn membership(
        &mut self,
        tenant: &str,
        subject: &str,
    ) -> Result<Option<TenantMembership>, StoreError> {
        let Ok(id) = Uuid::parse_str(subject) else {
            return Ok(None);
        };
        if id.to_string() != subject {
            return Ok(None);
        }
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.access_memberships where tenant_id=$1 and account_id=$2",
                    self.schema
                ),
                &[&tenant, &id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_member)
            .transpose()
    }
    fn role(&mut self, tenant: &str, role: &str) -> Result<Option<AccessRoleRecord>, StoreError> {
        let Ok(id) = Uuid::parse_str(role) else {
            return Ok(None);
        };
        if id.to_string() != role {
            return Ok(None);
        }
        let Some(row) = self
            .tx
            .query_opt(
                &format!(
                    "select * from {}.access_roles where tenant_id=$1 and id=$2",
                    self.schema
                ),
                &[&tenant, &id],
            )
            .map_err(access_db_error)?
        else {
            return Ok(None);
        };
        let permissions: Vec<_> = self.tx.query(&format!("select resource_type,action from {}.access_role_permissions where tenant_id=$1 and role_id=$2 order by resource_type,action limit $3",self.schema), &[&tenant,&id,&((MAX_ROLE_PERMISSIONS+1) as i64)]).map_err(access_db_error)?.into_iter().map(|r| PermissionKey { resource_type:r.get(0), action:r.get(1) }).collect();
        if permissions.len() > MAX_ROLE_PERMISSIONS {
            return Err(invalid());
        }
        Ok(Some(AccessRoleRecord {
            role: decode_role(&row)?,
            permissions,
        }))
    }
    fn admin_roles(
        &mut self,
        tenant: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<Role>, StoreError> {
        page.validate(&AccessListScope::AdminRoles {
            tenant_id: tenant.into(),
        })
        .map_err(|_| invalid())?;
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let after = page
            .cursor
            .as_ref()
            .map(|c| uuid(&c.after[1]))
            .transpose()?;
        self.tx.query(&format!("select * from {}.access_roles where tenant_id=$1 and ($2::uuid is null or (created_at_epoch,id){comparison}($4,$2)) order by created_at_epoch {order},id {order} limit $3",self.schema),&[&tenant,&after,&(page.fetch_limit() as i64), &after_time])
            .map_err(access_db_error)?.iter().map(decode_role).collect()
    }
    fn permission(
        &mut self,
        key: &PermissionKey,
    ) -> Result<Option<PermissionDefinition>, StoreError> {
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.access_permissions where tenant_id='0' and resource_type=$1 and action=$2",
                    self.schema
                ),
                &[&key.resource_type, &key.action],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_permission)
            .transpose()
    }
    fn tenant_permission(
        &mut self,
        tenant: &str,
        key: &PermissionKey,
    ) -> Result<Option<PermissionDefinition>, StoreError> {
        self.tx
            .query_opt(
                &format!("select * from {}.access_permissions where tenant_id=$1 and resource_type=$2 and action=$3", self.schema),
                &[&tenant, &key.resource_type, &key.action],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_permission)
            .transpose()
    }
    fn admin_permissions(
        &mut self,
        scope: &AdminPermissionScope,
        filter: &AdminPermissionFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<PermissionDefinition>, StoreError> {
        scope.validate(self.mode).map_err(|_| invalid())?;
        filter.validate().map_err(|_| invalid())?;
        page.validate(&AccessListScope::AdminPermissions {
            scope: scope.clone(),
            filter: filter.clone(),
        })
        .map_err(|_| invalid())?;
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let categories: Vec<_> = [
            PermissionCategory::Business,
            PermissionCategory::Tenant,
            PermissionCategory::Platform,
        ]
        .into_iter()
        .filter(|c| scope.permits(self.mode, *c))
        .map(category_name)
        .collect();
        let resource = page.cursor.as_ref().map(|c| &c.after[1]);
        let action = page.cursor.as_ref().map(|c| &c.after[2]);
        let category = filter.category.map(category_name);
        let tenant = match scope {
            AdminPermissionScope::Tenant(t) => t.as_str(),
            AdminPermissionScope::Platform => SYSTEM_TENANT_ID,
        };
        self.tx.query(&format!("select * from {}.access_permissions where tenant_id=$1 and category=any($2) and ($3::text is null or (coalesce(created_at_epoch,0),resource_type,action){comparison}($9,$3 collate \"C\",$4 collate \"C\")) and ($5::text is null or resource_type=$5) and ($6::text is null or category=$6) and ($7::boolean is null or enabled=$7) order by coalesce(created_at_epoch,0) {order},resource_type {order},action {order} limit $8",self.schema),&[&tenant,&categories,&resource,&action,&filter.resource_type,&category,&filter.enabled,&(page.fetch_limit() as i64), &after_time])
            .map_err(access_db_error)?.iter().map(decode_permission).collect()
    }
    fn binding(&mut self, tenant: &str, binding: &str) -> Result<Option<RoleBinding>, StoreError> {
        let Ok(id) = Uuid::parse_str(binding) else {
            return Ok(None);
        };
        if id.to_string() != binding {
            return Ok(None);
        }
        self.tx
            .query_opt(
                &format!(
                    "select * from {}.access_role_bindings where tenant_id=$1 and id=$2",
                    self.schema
                ),
                &[&tenant, &id],
            )
            .map_err(access_db_error)?
            .as_ref()
            .map(decode_binding)
            .transpose()
    }
    fn admin_role_bindings(
        &mut self,
        tenant: &str,
        subject: &str,
        page: &AccessPageRequest,
    ) -> Result<Vec<RoleBinding>, StoreError> {
        page.validate(&AccessListScope::AdminRoleBindings {
            tenant_id: tenant.into(),
            subject_id: subject.into(),
        })
        .map_err(|_| invalid())?;
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let after = page
            .cursor
            .as_ref()
            .map(|c| uuid(&c.after[1]))
            .transpose()?;
        self.tx.query(&format!("select * from {}.access_role_bindings where tenant_id=$1 and account_id=$2 and ($3::uuid is null or (created_at_epoch,id){comparison}($5,$3)) order by created_at_epoch {order},id {order} limit $4",self.schema),&[&tenant,&uuid(subject)?,&after,&(page.fetch_limit() as i64), &after_time])
            .map_err(access_db_error)?.iter().map(decode_binding).collect()
    }
    fn security_role(
        &mut self,
        tenant: &str,
        kind: RoleKind,
    ) -> Result<Option<AccessRoleRecord>, StoreError> {
        let row = self
            .tx
            .query_opt(
                &format!(
                    "select id from {}.access_roles where tenant_id=$1 and kind=$2",
                    self.schema
                ),
                &[&tenant, &role_kind(kind)],
            )
            .map_err(access_db_error)?;
        match row {
            Some(row) => self.role(tenant, &row.get::<_, Uuid>(0).to_string()),
            None => Ok(None),
        }
    }
    fn security_binding(
        &mut self,
        tenant: &str,
        subject: &str,
        role: &str,
    ) -> Result<Option<RoleBinding>, StoreError> {
        self.tx.query_opt(&format!("select * from {}.access_role_bindings where tenant_id=$1 and account_id=$2 and role_id=$3 and resource_type=$4 and resource_id is null",self.schema), &[&tenant,&uuid(subject)?,&uuid(role)?,&if tenant=="0" { "idp.platform" } else { "idp.tenant" }]).map_err(access_db_error)?.as_ref().map(decode_binding).transpose()
    }
    fn apply_change(&mut self, change: &AccessChange, now: SystemTime) -> Result<(), StoreError> {
        let actor = self.actor.ok_or_else(invalid)?;
        let s = self.schema;
        let now = epoch(now)?;
        match change {
            AccessChange::PermissionChecked { .. }
            | AccessChange::Client { .. }
            | AccessChange::AccountCreated { .. }
            | AccessChange::AccountSecurity { .. } => return Err(invalid()),
            AccessChange::Session { before, .. } => {
                self.revoke_session_scope(&before.tenant_id, Some(&before.id), None, now)?;
            }
            AccessChange::SubjectSessionsRevoked {
                tenant_id,
                subject_id,
                active_session_count,
            } => {
                if self.revoke_session_scope(tenant_id, None, Some(subject_id), now)?
                    != *active_session_count
                {
                    return Err(StoreError::Conflict("session.concurrent_write"));
                }
            }
            AccessChange::Device { before, after } => {
                let tenant = &before.device.tenant_id;
                let device = uuid(&before.device.id)?;
                changed(self.tx.execute(&format!("update {s}.devices set status=$3 where tenant_id=$1 and id=$2 and status=$4"),&[tenant,&device,&device_status(&after.device.status),&device_status(&before.device.status)]).map_err(access_db_error)?)?;
                // The exclusive tenant lock excludes every authentication transaction
                // in this domain before any session/key/binding state is changed.
                self.tx.execute(&format!("update {s}.auth_sessions set status='revoked' where tenant_id=$1 and device_id=$2 and status in ('active','pending')"),&[tenant,&device]).map_err(access_db_error)?;
                self.tx.execute(&format!("update {s}.refresh_tokens f set revoked_at_epoch=$3,revocation_reason='administrative' where f.tenant_id=$1 and exists(select 1 from {s}.auth_sessions x where x.tenant_id=f.tenant_id and x.id=f.session_id and x.device_id=$2)"),&[tenant,&device,&now]).map_err(access_db_error)?;
                self.tx.execute(&format!("delete from {s}.authorization_codes c where c.tenant_id=$1 and exists(select 1 from {s}.auth_sessions x where x.tenant_id=c.tenant_id and x.id=c.source_session_id and x.device_id=$2)"),&[tenant,&device]).map_err(access_db_error)?;
                self.tx.execute(&format!("update {s}.auth_tenant_selections p set revoked_at_epoch=$3 where p.source_tenant_id=$1 and p.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where x.tenant_id=p.source_tenant_id and x.id=p.source_session_id and x.device_id=$2)"),&[tenant,&device,&now]).map_err(access_db_error)?;
                self.tx
                    .execute(
                        &format!(
                            "delete from {s}.device_nonces where tenant_id=$1 and device_id=$2"
                        ),
                        &[tenant, &device],
                    )
                    .map_err(access_db_error)?;
                if after.device.status == embedded_idp_core::DeviceStatus::Revoked {
                    self.tx.execute(&format!("update {s}.device_proof_keys set status='retired',retired_at_epoch=$3 where tenant_id=$1 and device_id=$2 and status='active'"),&[tenant,&device,&now]).map_err(access_db_error)?;
                    self.tx.execute(&format!("update {s}.account_device_bindings set status='unbound',unbound_at_epoch=$3 where tenant_id=$1 and device_id=$2 and status<>'unbound'"),&[tenant,&device,&now]).map_err(access_db_error)?;
                }
            }
            AccessChange::TenantCreated {
                record,
                administrator,
                permission_definitions,
                role,
                binding,
            } => {
                self.insert_admin_tenant(record, time(now)?)?;
                self.apply_change(
                    &AccessChange::Catalog {
                        changes: permission_definitions
                            .iter()
                            .cloned()
                            .map(|after| AccessPermissionChange {
                                before: None,
                                after,
                            })
                            .collect(),
                    },
                    time(now)?,
                )?;
                self.apply_change(
                    &AccessChange::Membership {
                        before: None,
                        after: administrator.clone(),
                    },
                    time(now)?,
                )?;
                self.apply_change(
                    &AccessChange::Role {
                        before: None,
                        after: Some(role.clone()),
                    },
                    time(now)?,
                )?;
                self.apply_change(
                    &AccessChange::Binding {
                        before: None,
                        after: Some(binding.clone()),
                    },
                    time(now)?,
                )?;
            }
            AccessChange::Tenant { before, after } => {
                let t = &after.tenant;
                changed(self.tx.execute(&format!("update {s}.access_tenants set name=$2,status=$3,allow_registration=$4,version=$5 where id=$1 and version=$6"), &[&t.id,&t.name,&tenant_status(t.status),&t.allow_registration,&version(after.version)?,&version(before.version)?]).map_err(access_db_error)?)?;
                if t.status != TenantStatus::Active {
                    self.tx.execute(&format!("update {s}.auth_sessions set status='revoked' where tenant_id=$1 and status<>'revoked'"), &[&t.id]).map_err(access_db_error)?;
                    self.tx.execute(&format!("update {s}.refresh_tokens set revoked_at_epoch=$2,revocation_reason='administrative' where tenant_id=$1 and revoked_at_epoch is null"), &[&t.id,&now]).map_err(access_db_error)?;
                    self.tx
                        .execute(
                            &format!("delete from {s}.authorization_codes where tenant_id=$1"),
                            &[&t.id],
                        )
                        .map_err(access_db_error)?;
                    self.tx
                        .execute(
                            &format!("delete from {s}.email_verification_codes where tenant_id=$1"),
                            &[&t.id],
                        )
                        .map_err(access_db_error)?;
                    self.tx
                        .execute(
                            &format!("delete from {s}.device_nonces where tenant_id=$1"),
                            &[&t.id],
                        )
                        .map_err(access_db_error)?;
                    self.tx.execute(&format!("update {s}.auth_tenant_selections x set revoked_at_epoch=$2 where revoked_at_epoch is null and (source_tenant_id=$1 or (source_tenant_id is null and exists(select 1 from {s}.access_memberships m where m.tenant_id=$1 and m.account_id=x.account_id and m.status<>'removed')))"), &[&t.id,&now]).map_err(access_db_error)?;
                }
            }
            AccessChange::Catalog { changes } => {
                for change in changes {
                    let p = &change.after;
                    if let Some(before) = &change.before {
                        changed(self.tx.execute(&format!("update {s}.access_permissions set description=$4,enabled=$5,archived=$6,version=$7 where tenant_id=$1 and resource_type=$2 and action=$3 and category=$8 and version=$9"), &[&p.tenant_id,&p.key.resource_type,&p.key.action,&p.description,&p.enabled,&p.archived,&version(p.version)?,&category_name(before.category),&version(before.version)?]).map_err(access_db_error)?)?;
                    } else {
                        self.tx.execute(&format!("insert into {s}.access_permissions(tenant_id,resource_type,action,category,description,enabled,archived,version,created_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8,$9)"), &[&p.tenant_id,&p.key.resource_type,&p.key.action,&category_name(p.category),&p.description,&p.enabled,&p.archived,&version(p.version)?,&now]).map_err(access_db_error)?;
                    }
                }
            }
            AccessChange::Role { before, after } => {
                match (before, after) {
                    (None, Some(record)) => {
                        let r = &record.role;
                        self.tx.execute(&format!("insert into {s}.access_roles(tenant_id,id,key,name,status,kind,version,created_at_epoch) values($1,$2,$3,$4,$5,$6,$7,$8)"), &[&r.tenant_id,&uuid(&r.id)?,&r.key,&r.name,&role_status(r.status),&role_kind(r.kind),&version(r.version)?,&now]).map_err(access_db_error)?;
                    }
                    (Some(before), Some(after)) => {
                        let r = &after.role;
                        changed(self.tx.execute(&format!("update {s}.access_roles set name=$3,status=$4,version=$5 where tenant_id=$1 and id=$2 and version=$6"), &[&before.role.tenant_id,&uuid(&before.role.id)?,&r.name,&role_status(r.status),&version(r.version)?,&version(before.role.version)?]).map_err(access_db_error)?)?;
                    }
                    (Some(before), None) => {
                        let tenant = &before.role.tenant_id;
                        let id = uuid(&before.role.id)?;
                        self.tx.execute(&format!("delete from {s}.access_role_bindings where tenant_id=$1 and role_id=$2"), &[&tenant,&id]).map_err(access_db_error)?;
                        self.tx.execute(&format!("delete from {s}.access_role_permissions where tenant_id=$1 and role_id=$2"), &[&tenant,&id]).map_err(access_db_error)?;
                        changed(self.tx.execute(&format!("delete from {s}.access_roles where tenant_id=$1 and id=$2 and version=$3"), &[&tenant,&id,&version(before.role.version)?]).map_err(access_db_error)?)?;
                    }
                    _ => return Err(invalid()),
                }
                if let Some(after) = after {
                    let tenant = &after.role.tenant_id;
                    let id = uuid(&after.role.id)?;
                    self.tx.execute(&format!("delete from {s}.access_role_permissions where tenant_id=$1 and role_id=$2"), &[&tenant,&id]).map_err(access_db_error)?;
                    for p in &after.permissions {
                        self.tx.execute(&format!("insert into {s}.access_role_permissions(tenant_id,role_id,resource_type,action) values($1,$2,$3,$4)"), &[&tenant,&id,&p.resource_type,&p.action]).map_err(access_db_error)?;
                    }
                    self.tx.execute(&format!("delete from {s}.access_role_bindings b where tenant_id=$1 and role_id=$2 and not exists(select 1 from {s}.access_role_permissions p where p.tenant_id=b.tenant_id and p.role_id=b.role_id and p.resource_type=b.resource_type)"), &[&tenant,&id]).map_err(access_db_error)?;
                }
            }
            AccessChange::Binding { before, after } => match (before, after) {
                (None, Some(b)) => {
                    self.tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,resource_id,created_at_epoch,created_by) values($1,$2,$3,$4,$5,$6,$7,$8)"), &[&uuid(&b.id)?,&b.tenant_id,&uuid(&b.subject_id)?,&uuid(&b.role_id)?,&b.resource_type,&resource_id(&b.scope),&now,&actor]).map_err(access_db_error)?;
                }
                (Some(b), None) => {
                    changed(self.tx.execute(&format!("delete from {s}.access_role_bindings where tenant_id=$1 and id=$2"), &[&b.tenant_id,&uuid(&b.id)?]).map_err(access_db_error)?)?;
                }
                _ => return Err(invalid()),
            },
            AccessChange::Membership { before, after } => {
                let tenant = &after.tenant_id;
                let subject = uuid(&after.subject_id)?;
                let removed = if after.status == MembershipStatus::Removed {
                    Some(now)
                } else {
                    None
                };
                if let Some(before) = before {
                    changed(self.tx.execute(&format!("update {s}.access_memberships set status=$3,version=$4,joined_at_epoch=$5,removed_at_epoch=$6 where tenant_id=$1 and account_id=$2 and version=$7"), &[&tenant,&subject,&member_status(after.status),&version(after.version)?,&epoch(after.joined_at)?,&removed,&version(before.version)?]).map_err(access_db_error)?)?;
                } else {
                    self.tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,version,joined_at_epoch,removed_at_epoch) values($1,$2,$3,$4,$5,$6)"), &[&tenant,&subject,&member_status(after.status),&version(after.version)?,&epoch(after.joined_at)?,&removed]).map_err(access_db_error)?;
                }
                if after.status != MembershipStatus::Active {
                    self.tx.execute(&format!("update {s}.auth_sessions set status='revoked' where tenant_id=$1 and account_id=$2 and status<>'revoked'"), &[&tenant,&subject]).map_err(access_db_error)?;
                    self.tx.execute(&format!("update {s}.refresh_tokens f set revoked_at_epoch=$3,revocation_reason='administrative' where f.tenant_id=$1 and f.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where x.tenant_id=f.tenant_id and x.id=f.session_id and x.account_id=$2)"), &[&tenant,&subject,&now]).map_err(access_db_error)?;
                    self.tx.execute(&format!("delete from {s}.authorization_codes where tenant_id=$1 and account_id=$2"), &[&tenant,&subject]).map_err(access_db_error)?;
                    self.tx.execute(&format!("delete from {s}.email_verification_codes where tenant_id=$1 and account_id=$2"), &[&tenant,&subject]).map_err(access_db_error)?;
                    self.tx.execute(&format!("update {s}.auth_tenant_selections set revoked_at_epoch=$3 where account_id=$2 and (source_tenant_id=$1 or source_tenant_id is null) and revoked_at_epoch is null"), &[&tenant,&subject,&now]).map_err(access_db_error)?;
                }
                if after.status == MembershipStatus::Removed {
                    self.tx.execute(&format!("delete from {s}.access_role_bindings where tenant_id=$1 and account_id=$2"), &[&tenant,&subject]).map_err(access_db_error)?;
                    self.tx.execute(&format!("update {s}.account_device_bindings set status='unbound',unbound_at_epoch=$3 where tenant_id=$1 and account_id=$2 and status<>'unbound'"), &[&tenant,&subject,&now]).map_err(access_db_error)?;
                }
            }
        }
        Ok(())
    }
    fn has_non_removed_membership(&mut self, subject: &str) -> Result<bool, StoreError> {
        Ok(self.tx.query_one(&format!("select exists(select 1 from {}.access_memberships where account_id=$1 and status<>'removed')",self.schema), &[&uuid(subject)?]).map_err(access_db_error)?.get(0))
    }
    fn has_effective_security_admin(
        &mut self,
        tenant: &str,
        kind: RoleKind,
    ) -> Result<bool, StoreError> {
        let resource = match kind {
            RoleKind::SystemAdmin => "idp.platform",
            RoleKind::TenantSecurityAdmin => "idp.tenant",
            RoleKind::Business => return Ok(false),
        };
        let category = if kind == RoleKind::SystemAdmin {
            PermissionCategory::Platform
        } else {
            PermissionCategory::Tenant
        };
        if !self.mode.permits(tenant, category) {
            return Ok(false);
        }
        let catalog = PermissionCatalog::new(vec![]).map_err(|_| invalid())?;
        let actions: Vec<_> = catalog
            .definitions()
            .filter(|p| p.key.resource_type == resource)
            .map(|p| p.key.action.as_str())
            .collect();
        let s = self.schema;
        Ok(self.tx.query_one(&format!("select exists(select 1 from {s}.access_role_bindings b join {s}.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id join {s}.access_memberships m on m.tenant_id=b.tenant_id and m.account_id=b.account_id join {s}.accounts a on a.id=m.account_id join {s}.access_tenants t on t.id=m.tenant_id where b.tenant_id=$1 and b.resource_type=$2 and b.resource_id is null and r.kind=$3 and r.status='active' and m.status='active' and a.status='active' and t.status='active' and not exists(select 1 from unnest($4::text[]) required(action) where not exists(select 1 from {s}.access_role_permissions rp join {s}.access_permissions p using(tenant_id,resource_type,action) where rp.tenant_id=r.tenant_id and rp.role_id=r.id and rp.resource_type=$2 and rp.action=required.action and p.enabled and not p.archived and p.category=$5)))"), &[&tenant,&resource,&role_kind(kind),&actions,&category_name(category)]).map_err(access_db_error)?.get(0))
    }
    fn admin_audit_events(
        &mut self,
        tenant: &str,
        filter: &AdminAuditFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AdminAuditRecord>, StoreError> {
        filter.validate().map_err(|_| invalid())?;
        page.validate(&AccessListScope::AdminAudit {
            tenant_id: tenant.into(),
            filter: filter.clone(),
        })
        .map_err(|_| invalid())?;
        let actor = match &filter.actor_id {
            None => None,
            Some(raw) => {
                let Ok(id) = Uuid::parse_str(raw) else {
                    return Ok(vec![]);
                };
                if id.to_string() != *raw {
                    return Ok(vec![]);
                }
                Some(id)
            }
        };
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let after_id = page
            .cursor
            .as_ref()
            .map(|c| uuid(&c.after[1]))
            .transpose()?;
        let start = filter.occurred_after.map(epoch).transpose()?;
        let end = filter.occurred_before.map(epoch).transpose()?;
        self.tx.query(&format!("select id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,operation,request_id from {}.access_audit_events where target_domain=$1 and ($2::bigint is null or (occurred_at_epoch,id){comparison}($2,$3)) and ($4::uuid is null or actor_id=$4) and ($5::text is null or operation=$5) and ($6::bigint is null or occurred_at_epoch >= $6) and ($7::bigint is null or occurred_at_epoch <= $7) order by occurred_at_epoch {order},id {order} limit $8",self.schema),&[&tenant,&after_time,&after_id,&actor,&filter.operation,&start,&end,&(page.fetch_limit() as i64)])
            .map_err(access_db_error)?.iter().map(decode_audit).collect()
    }
    fn admin_audit_event(
        &mut self,
        tenant: &str,
        id: &str,
    ) -> Result<Option<AdminAuditDetail>, StoreError> {
        let Ok(key) = Uuid::parse_str(id) else {
            return Ok(None);
        };
        if key.to_string() != id {
            return Ok(None);
        }
        self.tx.query_opt(&format!("select id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,operation,request_id,change_json::text as change_text from {}.access_audit_events where target_domain=$1 and id=$2",self.schema),&[&tenant,&key])
            .map_err(access_db_error)?.map(|r|Ok(AdminAuditDetail {event:decode_audit(&r)?,change_json:r.get("change_text")})).transpose()
    }
    fn append_audit(&mut self, event: &AccessAuditEvent) -> Result<(), StoreError> {
        if self.actor != Some(uuid(&event.context.actor.subject_id)?) {
            return Err(invalid());
        }
        let change = change_json(&event.change)?.to_string();
        self.tx.execute(&format!("insert into {}.access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,operation,request_id,change_json) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::jsonb)",self.schema), &[&uuid(&event.id)?,&epoch(event.occurred_at)?,&uuid(&event.context.actor.subject_id)?,&event.context.actor.tenant_id,&uuid(&event.context.actor.session_id)?,&event.context.authentication_source,&event.tenant_id,&event.operation,&event.context.request_id,&change]).map_err(access_db_error)?;
        Ok(())
    }
}

// Explicit projection: never serialize the account/session models or credentials.
fn change_json(change: &AccessChange) -> Result<Value, StoreError> {
    fn tenant(record: &AccessTenantRecord) -> Value {
        let t = &record.tenant;
        json!({"id":t.id,"name":t.name,"status":tenant_status(t.status),"allow_registration":t.allow_registration,"version":record.version})
    }
    fn permission(p: &PermissionDefinition) -> Value {
        json!({"tenant_id":p.tenant_id,"resource_type":p.key.resource_type,"action":p.key.action,"category":category_name(p.category),"description":p.description,"enabled":p.enabled,"archived":p.archived,"version":p.version})
    }
    fn role(record: &AccessRoleRecord) -> Value {
        let r = &record.role;
        json!({"id":r.id,"tenant_id":r.tenant_id,"key":r.key,"name":r.name,"status":role_status(r.status),"kind":role_kind(r.kind),"version":r.version,"permissions":record.permissions.iter().map(|p|json!({"resource_type":p.resource_type,"action":p.action})).collect::<Vec<_>>()})
    }
    fn binding(b: &RoleBinding) -> Value {
        let scope = match &b.scope {
            ResourceScope::Type => json!({"kind":"type"}),
            ResourceScope::Instance(id) => json!({"kind":"instance","resource_id":id}),
        };
        json!({"id":b.id,"tenant_id":b.tenant_id,"subject_id":b.subject_id,"role_id":b.role_id,"resource_type":b.resource_type,"scope":scope})
    }
    fn member(m: &TenantMembership) -> Result<Value, StoreError> {
        Ok(
            json!({"tenant_id":m.tenant_id,"subject_id":m.subject_id,"status":member_status(m.status),"version":m.version,"joined_at_epoch":epoch(m.joined_at)?}),
        )
    }
    fn client(c: &embedded_idp_core::AdminClientRecord) -> Value {
        json!({"client_id":c.client_id,"client_name":c.client_name,"redirect_uris":c.redirect_uris,"client_type":admin_client_type(c.client_type),"pkce_required":c.pkce_required,"client_secret_configured":c.client_secret_configured})
    }
    fn account(a: &AccessAccountRecord) -> Result<Value, StoreError> {
        Ok(
            json!({"account_id":a.account_id,"email":a.email,"display_name":a.display_name,"status":identity_status(a.status),"created_at_epoch":epoch(a.created_at)?,"membership":a.membership.as_ref().map(member).transpose()?}),
        )
    }
    Ok(match change {
        AccessChange::PermissionChecked { query, decision } => {
            json!({"kind":"access.check","tenant_id":query.tenant_id,"subject_id":query.subject_id,"resource_type":query.resource_type,"action":query.action,"resource_id":query.resource_id,"decision":match decision {AccessDecision::Allow=>"allow",AccessDecision::Deny=>"deny"}})
        }
        AccessChange::AccountCreated { after } => {
            json!({"kind":"account.create","before":null,"after":account(after)?})
        }
        AccessChange::AccountSecurity {
            before,
            after,
            password_changed,
        } => {
            json!({"kind":"account.security","before":account(before)?,"after":account(after)?,"password_changed":password_changed})
        }
        AccessChange::Client {
            before,
            after,
            secret_changed,
        } => {
            json!({"kind":"client","before":before.as_ref().map(client),"after":client(after),"secret_changed":secret_changed})
        }
        AccessChange::Session { before, after } => {
            let session = |s: &TenantSession| json!({"session_id":s.id,"tenant_id":s.tenant_id,"account_id":s.account_id,"client_id":s.client_id,"device_id":s.device_id,"status":admin_session_status(&s.status)});
            json!({"kind":"session","before":session(before),"after":session(after)})
        }
        AccessChange::SubjectSessionsRevoked {
            tenant_id,
            subject_id,
            active_session_count,
        } => {
            json!({"kind":"subject.sessions","tenant_id":tenant_id,"subject_id":subject_id,"before":{"active_pending_sessions":active_session_count},"after":{"active_pending_sessions":0}})
        }
        AccessChange::Device { before, after } => {
            let device = |r: &AccessDeviceRecord| json!({"device_id":r.device.id,"tenant_id":r.device.tenant_id,"client_id":r.device.client_id,"status":device_status(&r.device.status)});
            json!({"kind":"device","before":device(before),"after":device(after)})
        }
        AccessChange::TenantCreated {
            record,
            administrator,
            permission_definitions,
            role: admin_role,
            binding: admin_binding,
        } => {
            json!({"kind":"tenant.create","before":null,"after":{"tenant":tenant(record),"administrator":member(administrator)?,"permissions":permission_definitions.iter().map(permission).collect::<Vec<_>>(),"role":role(admin_role),"binding":binding(admin_binding)}})
        }
        AccessChange::Tenant { before, after } => {
            json!({"kind":"tenant","before":tenant(before),"after":tenant(after)})
        }
        AccessChange::Catalog { changes } => {
            json!({"kind":"catalog","changes":changes.iter().map(|c|json!({"before":c.before.as_ref().map(permission),"after":permission(&c.after)})).collect::<Vec<_>>()})
        }
        AccessChange::Role { before, after } => {
            json!({"kind":"role","before":before.as_ref().map(role),"after":after.as_ref().map(role)})
        }
        AccessChange::Binding { before, after } => {
            json!({"kind":"binding","before":before.as_ref().map(binding),"after":after.as_ref().map(binding)})
        }
        AccessChange::Membership { before, after } => {
            json!({"kind":"membership","before":before.as_ref().map(member).transpose()?,"after":member(after)?})
        }
    })
}

impl AccessBootstrapStore for PostgresStorageAdapter {
    fn bootstrap_access(
        &self,
        plan: &AccessBootstrap,
    ) -> Result<AccessBootstrapResult, StoreError> {
        let mut client = self.connect()?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(access_db_error)?;
        let s = self.schema_name();
        let mut store = PostgresAccessAdminTransaction {
            tx,
            schema: s,
            mode: plan.mode(),
            actor: None,
        };
        validate_layout(&mut store.tx, s)?;
        store
            .tx
            .query_one(
                &format!("select singleton from {s}.access_state where singleton for update"),
                &[],
            )
            .map_err(access_db_error)?;
        let facts = schema_facts(&mut store.tx, s, plan.mode())?;
        if facts.bootstrap_completed {
            if !store.has_effective_security_admin("0", RoleKind::SystemAdmin)? {
                return Err(StoreError::Conflict("access.last_security_admin"));
            }
            store.tx.commit().map_err(access_db_error)?;
            return Ok(AccessBootstrapResult::AlreadyInitialized);
        }
        let occupied: bool = store.tx.query_one(&format!("select exists(select 1 from {s}.accounts) or exists(select 1 from {s}.access_roles) or exists(select 1 from {s}.access_audit_events) or exists(select 1 from {s}.access_tenants where id<>'0')"), &[]).map_err(access_db_error)?.get(0);
        if occupied {
            return Err(StoreError::Conflict("access.bootstrap_not_empty"));
        }
        let account = plan.account();
        let subject = uuid(&account.id)?;
        let role = uuid(plan.role_id())?;
        let binding = uuid(plan.binding_id())?;
        let now = epoch(account.created_at)?;
        store
            .tx
            .query_one(
                &format!("select id from {s}.access_tenants where id='0' for update"),
                &[],
            )
            .map_err(access_db_error)?;
        store.tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,display_name,status,created_at_epoch) values($1,'0',$2,$3,$4,'active',$5)"), &[&subject,&account.email,&account.password_hash,&account.display_name,&now]).map_err(access_db_error)?;
        store.tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values('0',$1,'active',$2)"), &[&subject,&now]).map_err(access_db_error)?;
        store.tx.execute(&format!("insert into {s}.access_roles(tenant_id,id,key,name,status,kind,created_at_epoch) values('0',$1,'system_admin','System administrator','active','system_admin',$2)"), &[&role,&now]).map_err(access_db_error)?;
        let catalog = PermissionCatalog::new(vec![]).map_err(|_| invalid())?;
        for definition in catalog
            .definitions()
            .filter(|p| p.category == PermissionCategory::Platform)
        {
            let key = &definition.key;
            // Never repair or re-enable a changed permission directory implicitly.
            let actual = store.permission(key)?.ok_or_else(invalid)?;
            if !actual.enabled || actual.category != definition.category {
                return Err(StoreError::Conflict("access.bootstrap_catalog"));
            }
            store.tx.execute(&format!("insert into {s}.access_role_permissions(tenant_id,role_id,resource_type,action) values('0',$1,$2,$3)"), &[&role,&key.resource_type,&key.action]).map_err(access_db_error)?;
        }
        store.tx.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,account_id,role_id,resource_type,created_at_epoch,created_by) values($1,'0',$2,$3,'idp.platform',$4,$2)"), &[&binding,&subject,&role,&now]).map_err(access_db_error)?;
        if !store.has_effective_security_admin("0", RoleKind::SystemAdmin)? {
            return Err(StoreError::Conflict("access.last_security_admin"));
        }
        let change=json!({"kind":"bootstrap","before":null,"after":{"subject_id":account.id,"tenant_id":"0","role_id":plan.role_id(),"binding_id":plan.binding_id()}}).to_string();
        store.tx.execute(&format!("insert into {s}.access_audit_events(id,occurred_at_epoch,actor_id,actor_domain,actor_session_id,authentication_source,target_domain,operation,request_id,change_json) values($1,$2,$3,'0',null,'offline_bootstrap','0','access.bootstrap',$4,$5::text::jsonb)"), &[&uuid(plan.audit_id())?,&now,&subject,&plan.request_id(),&change]).map_err(access_db_error)?;
        store
            .tx
            .execute(
                &format!(
                    "update {s}.access_state set bootstrap_completed_at_epoch=$1 where singleton"
                ),
                &[&now],
            )
            .map_err(access_db_error)?;
        store.tx.commit().map_err(access_db_error)?;
        Ok(AccessBootstrapResult::Initialized)
    }
}

fn admin_session_status(status: &embedded_idp_core::SessionStatus) -> &'static str {
    match status {
        embedded_idp_core::SessionStatus::Pending => "pending",
        embedded_idp_core::SessionStatus::Active => "active",
        embedded_idp_core::SessionStatus::Revoked => "revoked",
        embedded_idp_core::SessionStatus::Expired => "expired",
    }
}
impl PostgresAccessAdminTransaction<'_> {
    fn revoke_session_scope(
        &mut self,
        tenant: &str,
        session: Option<&str>,
        subject: Option<&str>,
        now: i64,
    ) -> Result<u64, StoreError> {
        if session.is_some() == subject.is_some() {
            return Err(invalid());
        }
        let session = session.map(uuid).transpose()?;
        let subject = subject.map(uuid).transpose()?;
        let s = self.schema;
        // Identical bound scope for every credential family. No ID list is loaded.
        let scope="x.tenant_id=$1 and ($2::uuid is null or x.id=$2) and ($3::uuid is null or x.account_id=$3)";
        let changed=self.tx.execute(&format!("update {s}.auth_sessions x set status='revoked' where {scope} and (($2::uuid is not null and x.status<>'revoked') or x.status in ('active','pending'))"),&[&tenant,&session,&subject]).map_err(access_db_error)?;
        self.tx.execute(&format!("update {s}.refresh_tokens f set revoked_at_epoch=$4,revocation_reason='administrative' where exists(select 1 from {s}.auth_sessions x where {scope} and x.tenant_id=f.tenant_id and x.id=f.session_id)"),&[&tenant,&session,&subject,&now]).map_err(access_db_error)?;
        self.tx.execute(&format!("delete from {s}.authorization_codes c where exists(select 1 from {s}.auth_sessions x where {scope} and x.tenant_id=c.tenant_id and x.id=c.source_session_id)"),&[&tenant,&session,&subject]).map_err(access_db_error)?;
        self.tx.execute(&format!("update {s}.auth_tenant_selections p set revoked_at_epoch=$4 where p.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where {scope} and x.tenant_id=p.source_tenant_id and x.id=p.source_session_id)"),&[&tenant,&session,&subject,&now]).map_err(access_db_error)?;
        Ok(changed)
    }
}

fn admin_client_type(kind: embedded_idp_core::OidcClientType) -> &'static str {
    match kind {
        embedded_idp_core::OidcClientType::PublicDesktop => "public_desktop",
        embedded_idp_core::OidcClientType::ConfidentialWeb => "confidential_web",
    }
}

impl PostgresAccessAdminTransaction<'_> {
    fn query_admin_accounts(
        &mut self,
        tenant: Option<&str>,
        account: Option<Uuid>,
        filter: &AdminAccountFilter,
        page: &AccessPageRequest,
    ) -> Result<Vec<AccessAccountRecord>, StoreError> {
        let (order, comparison) = list_order(page);
        let after_time = page
            .cursor
            .as_ref()
            .map(|c| c.after[0].parse::<i64>().map_err(|_| invalid()))
            .transpose()?;
        let after = page
            .cursor
            .as_ref()
            .map(|c| uuid(&c.after[1]))
            .transpose()?;
        let time_column = if tenant.is_some() {
            "m.joined_at_epoch"
        } else {
            "a.created_at_epoch"
        };
        let status = filter.status.map(identity_status);
        let member = filter.membership_status.map(member_status);
        let email = filter.email.as_ref().map(|e| e.to_ascii_lowercase());
        let since = filter.created_after.map(epoch).transpose()?;
        let until = filter.created_before.map(epoch).transpose()?;
        // ponytail: literal substring search scans eligible rows; add a search
        // index only when measured account volume and latency require it.
        self.tx.query(&format!("select a.id,a.email,a.display_name,a.status as identity_status,a.created_at_epoch,m.tenant_id,m.account_id,m.status,m.version,m.joined_at_epoch from {s}.accounts a left join {s}.access_memberships m on m.account_id=a.id and m.tenant_id=$1 where ($1::text is null or m.tenant_id=$1) and ($2::uuid is null or a.id=$2) and ($3::uuid is null or ({time_column},a.id){comparison}($10,$3)) and ($4::text is null or a.status=$4) and ($5::text is null or m.status=$5) and ($6::text is null or strpos(translate(a.email,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),$6)>0) and ($7::bigint is null or a.created_at_epoch>=$7) and ($8::bigint is null or a.created_at_epoch<=$8) order by {time_column} {order},a.id {order} limit $9",s=self.schema),&[&tenant,&account,&after,&status,&member,&email,&since,&until,&(page.fetch_limit() as i64), &after_time]).map_err(access_db_error)?.iter().map(|row| {
            let membership=if row.get::<_,Option<String>>("tenant_id").is_some(){Some(decode_member(row)?)}else{None};
            let status=match row.get::<_,String>("identity_status").as_str() {
                "pending_verification"=>AccountIdentityStatus::PendingVerification,
                "active"=>AccountIdentityStatus::Active,
                "disabled"=>AccountIdentityStatus::Disabled,
                "closed"=>AccountIdentityStatus::Closed,
                _=>return Err(invalid()),
            };
            Ok(AccessAccountRecord{account_id:row.get::<_,Uuid>("id").to_string(),email:row.get("email"),display_name:row.get("display_name"),status,created_at:time(row.get("created_at_epoch"))?,membership})
        }).collect()
    }
}
fn identity_status(status: AccountIdentityStatus) -> &'static str {
    match status {
        AccountIdentityStatus::PendingVerification => "pending_verification",
        AccountIdentityStatus::Active => "active",
        AccountIdentityStatus::Disabled => "disabled",
        AccountIdentityStatus::Closed => "closed",
    }
}

fn decode_audit(row: &postgres::Row) -> Result<AdminAuditRecord, StoreError> {
    Ok(AdminAuditRecord {
        id: row.get::<_, Uuid>("id").to_string(),
        occurred_at: time(row.get("occurred_at_epoch"))?,
        actor_id: row.get::<_, Uuid>("actor_id").to_string(),
        actor_domain: row.get("actor_domain"),
        actor_session_id: row
            .get::<_, Option<Uuid>>("actor_session_id")
            .map(|id| id.to_string()),
        authentication_source: row.get("authentication_source"),
        target_domain: row.get("target_domain"),
        operation: row.get("operation"),
        request_id: row.get("request_id"),
    })
}

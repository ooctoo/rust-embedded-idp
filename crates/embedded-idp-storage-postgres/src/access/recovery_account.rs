use super::access_db_error;
use crate::PgTransaction;
use embedded_idp_core::{access::*, SecretString, StoreError};
use uuid::Uuid;
fn invalid() -> StoreError {
    StoreError::Backend("invalid recovery storage projection".into())
}
// Caller holds access_state UPDATE before discovery and sorted tenant/account locks.
pub(super) fn lock_recovery_account(
    tx: &mut PgTransaction<'_>,
    s: &str,
    mode: TenancyMode,
    id: Uuid,
) -> Result<Option<RecoveryAccountSnapshot>, StoreError> {
    let tenants: Vec<String> = tx.query(&format!("select tenant_id from {s}.access_memberships where account_id=$1 order by tenant_id collate \"C\""), &[&id])
                .map_err(access_db_error)?.into_iter().map(|r| r.get(0)).collect();
    for tenant in &tenants {
        tx.query_opt(
            &format!("select id from {s}.access_tenants where id=$1 for share"),
            &[tenant],
        )
        .map_err(access_db_error)?;
    }
    let row = tx.query_opt(&format!("select email,status,security_credential_version from {s}.accounts where id=$1 for update"), &[&id]).map_err(access_db_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let version: i64 = row.get(2);
    if version <= 0 {
        return Err(invalid());
    }
    let member: bool = tx.query_one(&format!("select exists(select 1 from {s}.access_memberships m join {s}.access_tenants t on t.id=m.tenant_id where m.account_id=$1 and m.status='active' and t.status='active')"), &[&id]).map_err(access_db_error)?.get(0);
    Ok(Some(RecoveryAccountSnapshot {
        account_id: id,
        email: SecretString::new(row.get::<_, String>(0)),
        credential_version: version as u64,
        active: row.get::<_, String>(1) == "active",
        has_active_membership: member,
        has_effective_security_admin: effective_security_admin(tx, s, mode, id, &tenants)?,
    }))
}
fn effective_security_admin(
    tx: &mut PgTransaction<'_>,
    schema: &str,
    mode: TenancyMode,
    account: Uuid,
    tenants: &[String],
) -> Result<bool, StoreError> {
    let catalog = PermissionCatalog::new(vec![]).map_err(|_| invalid())?;
    for tenant in tenants {
        let (kind, resource, category, category_name) = if tenant == "0" {
            (
                "system_admin",
                "idp.platform",
                PermissionCategory::Platform,
                "platform",
            )
        } else if mode == TenancyMode::Enabled {
            (
                "tenant_security_admin",
                "idp.tenant",
                PermissionCategory::Tenant,
                "tenant",
            )
        } else {
            continue;
        };
        if !mode.permits(tenant, category) {
            continue;
        }
        let actions: Vec<&str> = catalog
            .definitions()
            .filter(|p| p.key.resource_type == resource)
            .map(|p| p.key.action.as_str())
            .collect();
        let s = schema;
        let exists: bool = tx.query_one(&format!("select exists(
                select 1 from {s}.access_role_bindings b
                join {s}.access_roles r on r.tenant_id=b.tenant_id and r.business_id=b.business_id and r.id=b.role_id
                join {s}.access_memberships m on m.tenant_id=b.tenant_id and m.account_id=b.account_id
                join {s}.accounts a on a.id=m.account_id
                join {s}.access_tenants t on t.id=m.tenant_id
                where b.account_id=$1 and b.tenant_id=$2 and b.business_id='idp' and b.scope_kind='type'
                  and b.resource_type=$3 and r.kind=$4 and r.status='active' and m.status='active'
                  and a.status='active' and t.status='active'
                  and not exists(select 1 from unnest($5::text[]) required(action) where not exists(
                    select 1 from {s}.access_role_permissions rp join {s}.access_permissions p using(tenant_id,business_id,resource_type,action)
                    where rp.tenant_id=r.tenant_id and rp.business_id='idp' and rp.role_id=r.id
                    and rp.resource_type=$3 and rp.action=required.action and p.enabled and not p.archived and p.category=$6)))"),
                &[&account, &tenant, &resource, &kind, &actions, &category_name],
            ).map_err(access_db_error)?.get(0);
        if exists {
            return Ok(true);
        }
    }
    Ok(false)
}

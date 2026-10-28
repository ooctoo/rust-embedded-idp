use super::access_db_error;
use crate::PgTransaction;
use embedded_idp_core::StoreError;
use uuid::Uuid;
// Requires the exclusive access_state barrier and account lock.
pub(super) fn retire_account_credentials(
    tx: &mut PgTransaction<'_>,
    s: &str,
    account: Uuid,
    now: i64,
) -> Result<(), StoreError> {
    tx.execute(&format!("update {s}.auth_sessions set status='revoked' where account_id=$1 and status<>'revoked'"), &[&account]).map_err(access_db_error)?;
    tx.execute(&format!("update {s}.refresh_tokens f set revoked_at_epoch=$2,revocation_reason='administrative' where f.revoked_at_epoch is null and exists(select 1 from {s}.auth_sessions x where x.tenant_id=f.tenant_id and x.id=f.session_id and x.account_id=$1)"), &[&account,&now]).map_err(access_db_error)?;
    tx.execute(
        &format!("delete from {s}.authorization_codes where account_id=$1"),
        &[&account],
    )
    .map_err(access_db_error)?;
    tx.execute(
        &format!("delete from {s}.email_verification_codes where account_id=$1"),
        &[&account],
    )
    .map_err(access_db_error)?;
    tx.execute(&format!("update {s}.auth_tenant_selections set revoked_at_epoch=$2 where account_id=$1 and revoked_at_epoch is null"), &[&account,&now]).map_err(access_db_error)?;
    // All states remain in the membership query: updating grant/delivery state
    // must not shrink the set before all recoverable secrets are cleared.
    let grant_scope = format!("g.source_account_id=$1 or exists(select 1 from {s}.scan_login_deliveries d join {s}.auth_sessions x on x.tenant_id=d.tenant_id and x.id=d.session_id where d.grant_id=g.id and d.tenant_id=g.tenant_id and x.account_id=$1)");
    tx.execute(&format!("update {s}.scan_login_grants g set state=case when g.state in ('waiting_user','waiting_device','awaiting_approval','approved','issued') then 'invalidated' else g.state end,version=g.version+1,presentation_key_id=null,presentation_nonce=null,presentation_ciphertext=null,delivery_secret_hash=null where {grant_scope}"), &[&account]).map_err(access_db_error)?;
    tx.execute(&format!("update {s}.scan_login_deliveries d set state='revoked',revoked_at_epoch=coalesce(d.revoked_at_epoch,$2),reason=coalesce(d.reason,'password_changed'),result_key_id=null,result_nonce=null,result_ciphertext=null,receipt_nonce_hash=null where exists(select 1 from {s}.scan_login_grants g where g.id=d.grant_id and g.tenant_id=d.tenant_id and ({grant_scope}))"), &[&account,&now]).map_err(access_db_error)?;
    tx.execute(&format!("update {s}.password_recovery_flows set state='invalidated' where account_id=$1 and state='pending'"), &[&account]).map_err(access_db_error)?;
    tx.execute(&format!("update {s}.security_email_outbox o set state=case when o.state in ('pending','sending') then 'cancelled' else o.state end,last_outcome=case when o.state='pending' then 'not_started' when o.state='sending' then 'unknown' else o.last_outcome end,envelope_key_id=null,ciphertext=null,lease_token=null,lease_until_epoch=null where exists(select 1 from {s}.password_recovery_flows f where f.id=o.flow_id and f.account_id=$1)"), &[&account]).map_err(access_db_error)?;
    tx.execute(&format!("delete from {s}.password_recovery_start_receipts r where exists(select 1 from {s}.password_recovery_flows f where f.id=r.flow_id and f.account_id=$1)"), &[&account]).map_err(access_db_error)?;
    Ok(())
}

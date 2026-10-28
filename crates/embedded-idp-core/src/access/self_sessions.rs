use super::{query::validate_id, AccessActor, AccessError, TenancyMode, TenantSession};
use crate::{AccessTokenPurpose, Clock, SessionStatus, StoreError};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSessionCursor {
    pub subject_id: String,
    pub tenant_id: String,
    pub session_id: String,
}
#[derive(Debug, Clone)]
pub struct SelfSessionPageRequest {
    pub limit: u32,
    pub cursor: Option<SelfSessionCursor>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSessionSummary {
    pub tenant_id: String,
    pub session_id: String,
    pub client_id: String,
    pub purpose: AccessTokenPurpose,
    pub device_id: Option<String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub status: SessionStatus,
    pub current: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfSessionPage {
    pub items: Vec<SelfSessionSummary>,
    pub next_cursor: Option<SelfSessionCursor>,
}

pub trait SelfSessionReadTransaction {
    /// After the runner has locked the actor rows, recheck current facts.
    /// Recheck account/membership/tenant/session activity and credential times,
    /// device/current key/binding validity. Require the actor session's scope
    /// to be None: delegated OAuth sessions cannot act on global self security.
    fn actor_is_active(&mut self, actor: &AccessActor, now: SystemTime)
        -> Result<bool, StoreError>;
    /// Only this account's database-active sessions, including delegated ones,
    /// ordered by (tenant_id bytewise, canonical UUID session id), strictly after
    /// the cursor. The service requests at most 51 records for lookahead.
    fn sessions_for_subject(
        &mut self,
        subject: &str,
        after: Option<&SelfSessionCursor>,
        limit: u32,
    ) -> Result<Vec<TenantSession>, StoreError>;
}
pub trait SelfSessionReadStore: Send + Sync {
    type Transaction<'a>: SelfSessionReadTransaction
    where
        Self: 'a;
    /// Acquire state, tenant, account and exact actor session locks before
    /// invoking the closure, so the service samples its Clock after lock waits.
    /// Keep locks until the read completes; errors must release all locks.
    fn self_session_read<R>(
        &self,
        mode: TenancyMode,
        actor: &AccessActor,
        run: impl FnOnce(&mut Self::Transaction<'_>) -> Result<R, AccessError>,
    ) -> Result<R, AccessError>;
}
pub trait SelfSessionService: Send + Sync {
    fn list_sessions(
        &self,
        actor: AccessActor,
        page: SelfSessionPageRequest,
    ) -> Result<SelfSessionPage, AccessError>;
}
pub struct CoreSelfSessionService<S, C> {
    mode: TenancyMode,
    store: S,
    clock: C,
}
impl<S, C> CoreSelfSessionService<S, C> {
    pub fn new(mode: TenancyMode, store: S, clock: C) -> Self {
        Self { mode, store, clock }
    }
}
fn canonical_session_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
impl<S: SelfSessionReadStore, C: Clock + Send + Sync> SelfSessionService
    for CoreSelfSessionService<S, C>
{
    fn list_sessions(
        &self,
        actor: AccessActor,
        page: SelfSessionPageRequest,
    ) -> Result<SelfSessionPage, AccessError> {
        actor.validate(self.mode)?;
        if !(1..=50).contains(&page.limit) {
            return Err(AccessError::InvalidInput("limit"));
        }
        if let Some(cursor) = &page.cursor {
            if cursor.subject_id != actor.subject_id
                || validate_id(&cursor.tenant_id, 128, "tenant").is_err()
                || !canonical_session_id(&cursor.session_id)
            {
                return Err(AccessError::InvalidCursor);
            }
        }
        self.store.self_session_read(self.mode, &actor, |tx| {
            let now = self.clock.now();
            if !tx.actor_is_active(&actor, now)? {
                return Err(AccessError::Forbidden);
            }
            let mut rows =
                tx.sessions_for_subject(&actor.subject_id, page.cursor.as_ref(), page.limit + 1)?;
            if rows.len() > page.limit as usize + 1 {
                return Err(AccessError::InvalidStoreResponse);
            }
            let mut previous = page
                .cursor
                .as_ref()
                .map(|c| (c.tenant_id.as_str(), c.session_id.as_str()));
            for row in &rows {
                let key = (row.tenant_id.as_str(), row.id.as_str());
                if (self.mode == TenancyMode::Disabled && row.tenant_id != "0")
                    || row.account_id != actor.subject_id
                    || row.status != SessionStatus::Active
                    || validate_id(&row.tenant_id, 128, "tenant").is_err()
                    || !canonical_session_id(&row.id)
                    || row.created_at > now
                    || row.authenticated_at > row.created_at
                    || row.expires_at <= row.created_at
                    || previous.is_some_and(|p| p >= key)
                {
                    return Err(AccessError::InvalidStoreResponse);
                }
                previous = Some(key);
            }
            let more = rows.len() > page.limit as usize;
            rows.truncate(page.limit as usize);
            let next_cursor = if more {
                rows.last().map(|row| SelfSessionCursor {
                    subject_id: actor.subject_id.clone(),
                    tenant_id: row.tenant_id.clone(),
                    session_id: row.id.clone(),
                })
            } else {
                None
            };
            let items = rows
                .into_iter()
                .map(|row| SelfSessionSummary {
                    current: row.tenant_id == actor.tenant_id && row.id == actor.session_id,
                    tenant_id: row.tenant_id,
                    session_id: row.id,
                    client_id: row.client_id,
                    purpose: row.purpose,
                    device_id: row.device_id,
                    created_at: row.created_at,
                    expires_at: row.expires_at,
                    status: if row.expires_at <= now {
                        SessionStatus::Expired
                    } else {
                        SessionStatus::Active
                    },
                })
                .collect();
            Ok(SelfSessionPage { items, next_cursor })
        })
    }
}

#[cfg(test)]
#[path = "self_sessions_tests.rs"]
mod tests;

use crate::{
    http_support::unix_time_secs,
    tenant_admin::{error, target},
    tenant_auth::{call, no_store},
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::HeaderMap,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{access::*, SessionStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

#[derive(Clone)]
struct AdminState {
    mode: TenancyMode,
    service: Arc<dyn TenantSessionAdminService>,
}
/// The host must inject a trusted management AccessAdminContext, as for devices.
pub fn tenant_session_admin_router(
    mode: TenancyMode,
    service: Arc<dyn TenantSessionAdminService>,
) -> Router {
    Router::new()
        .route("/admin/sessions", get(list))
        .route("/admin/sessions/:session_id", get(detail))
        .route("/admin/sessions/:session_id/revoke", post(revoke))
        .route(
            "/admin/accounts/:account_id/sessions/revoke",
            post(revoke_subject),
        )
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pending,
    Active,
    Revoked,
    Expired,
}
impl Status {
    fn core(&self) -> SessionStatus {
        match self {
            Self::Pending => SessionStatus::Pending,
            Self::Active => SessionStatus::Active,
            Self::Revoked => SessionStatus::Revoked,
            Self::Expired => SessionStatus::Expired,
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    account_id: Option<String>,
    client_id: Option<String>,
    device_id: Option<String>,
    status: Option<Status>,
    created_after_unix_secs: Option<u64>,
    created_before_unix_secs: Option<u64>,
}
impl Filter {
    fn core(&self) -> Result<AdminSessionFilter, AccessError> {
        fn time(value: Option<u64>) -> Result<Option<SystemTime>, AccessError> {
            value
                .map(|v| {
                    SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(v))
                        .ok_or(AccessError::InvalidInput("created_time"))
                })
                .transpose()
        }
        Ok(AdminSessionFilter {
            account_id: self.account_id.clone(),
            client_id: self.client_id.clone(),
            device_id: self.device_id.clone(),
            status: self.status.as_ref().map(Status::core),
            created_after: time(self.created_after_unix_secs)?,
            created_before: time(self.created_before_unix_secs)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    account_id: Option<String>,
    client_id: Option<String>,
    device_id: Option<String>,
    status: Option<Status>,
    created_after_unix_secs: Option<u64>,
    created_before_unix_secs: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: String,
    filter: Filter,
    after: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}
fn session_json(s: TenantSession) -> Value {
    json!({"tenant_id":s.tenant_id,"session_id":s.id,"account_id":s.account_id,"client_id":s.client_id,"device_id":s.device_id,
        "status":match s.status {SessionStatus::Active=>"active",SessionStatus::Pending=>"pending",SessionStatus::Revoked=>"revoked",SessionStatus::Expired=>"expired"},
        "created_at_unix_secs":unix_time_secs(s.created_at),"expires_at_unix_secs":unix_time_secs(s.expires_at),"authenticated_at_unix_secs":unix_time_secs(s.authenticated_at),"scope":s.scope})
}
async fn list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let filter = Filter {
        account_id: query.account_id,
        client_id: query.client_id,
        device_id: query.device_id,
        status: query.status,
        created_after_unix_secs: query.created_after_unix_secs,
        created_before_unix_secs: query.created_before_unix_secs,
    };
    let core_filter = match filter.core() {
        Ok(v) => v,
        Err(e) => return error(e),
    };
    let cursor = match query.cursor {
        None => None,
        Some(raw) => {
            if raw.len() > 4096 {
                return error(AccessError::InvalidCursor);
            }
            let Some(c) = Base64UrlUnpadded::decode_vec(&raw)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Cursor>(&bytes).ok())
            else {
                return error(AccessError::InvalidCursor);
            };
            let stored = match c.filter.core() {
                Ok(v) => v,
                Err(_) => return error(AccessError::InvalidCursor),
            };
            Some(AccessCursor {
                version: c.version,
                scope: AccessListScope::AdminSessions {
                    tenant_id: c.tenant_id,
                    filter: stored,
                },
                after: vec![c.after],
            })
        }
    };
    match call(move || {
        state.service.list_sessions(
            context,
            tenant,
            core_filter,
            AccessPageRequest {
                limit: query.limit.unwrap_or(50),
                cursor,
            },
        )
    })
    .await
    {
        Ok(page) => {
            let next = match page.next_cursor {
                None => None,
                Some(c) => {
                    let AccessListScope::AdminSessions { tenant_id, .. } = c.scope else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    if c.after.len() != 1 {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
                            tenant_id,
                            filter,
                            after: c.after[0].clone(),
                        })
                        .unwrap(),
                    ))
                }
            };
            Json(json!({"items":page.items.into_iter().map(session_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(session): Path<String>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || state.service.get_session(context, tenant, session)).await {
        Ok(s) => Json(session_json(s)).into_response(),
        Err(e) => error(e),
    }
}
async fn revoke(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(_): Json<EmptyBody>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::RevokeSession { session_id },
    )
    .await
}
async fn revoke_subject(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject_id): Path<String>,
    Json(_): Json<EmptyBody>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::RevokeSubjectSessions { subject_id },
    )
    .await
}
async fn change(
    state: AdminState,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    mutation: AccessAdminMutation,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move||state.service.execute(context,AccessAdminCommand{tenant_id:tenant,mutation})).await {
        Ok(event)=>match event.change {
            AccessChange::Session{after,..}=>Json(json!({"session":session_json(after),"audit_id":event.id})).into_response(),
            AccessChange::SubjectSessionsRevoked{tenant_id,subject_id,active_session_count}=>Json(json!({"tenant_id":tenant_id,"account_id":subject_id,"revoked_session_count":active_session_count,"audit_id":event.id})).into_response(),
            _=>error(AccessError::InvalidStoreResponse),
        },Err(e)=>error(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_admin_rejects_caller_time_and_filter_overflow() {
        assert!(serde_json::from_str::<EmptyBody>(r#"{"revoked_at_unix_secs":1}"#).is_err());
        assert!(serde_json::from_str::<EmptyBody>(r#"{"tenant_id":"other"}"#).is_err());
        let filter = Filter {
            account_id: None,
            client_id: None,
            device_id: None,
            status: None,
            created_after_unix_secs: Some(u64::MAX),
            created_before_unix_secs: None,
        };
        assert!(filter.core().and_then(|f| f.validate()).is_err());
        assert!(serde_json::from_str::<Cursor>(
            r#"{"version":1,"tenant_id":"t1","after":"s","filter":{},"actor_id":"root"}"#
        )
        .is_err());
    }
}

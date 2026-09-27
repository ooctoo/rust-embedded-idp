use crate::{
    tenant_admin::{error, platform_context, target, ManagementSortOrder},
    tenant_auth::{call, no_store},
};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::access::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

#[derive(Clone)]
struct AdminState {
    mode: TenancyMode,
    service: Arc<dyn AuditAdminService>,
}
/// Exact-domain audit reads behind host-verified management authentication.
pub fn audit_admin_router(mode: TenancyMode, service: Arc<dyn AuditAdminService>) -> Router {
    Router::new()
        .route("/admin/access/audit-events", get(list))
        .route("/admin/access/audit-events/:id", get(detail))
        .route("/admin/platform/audit-events", get(platform_list))
        .route("/admin/platform/audit-events/:id", get(platform_detail))
        .with_state(AdminState { mode, service })
        .layer(middleware::from_fn(no_store))
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    business_id: Option<String>,
    actor_id: Option<String>,
    operation: Option<String>,
    occurred_after_unix_secs: Option<u64>,
    occurred_before_unix_secs: Option<u64>,
}
impl Filter {
    fn core(&self) -> Result<AdminAuditFilter, AccessError> {
        fn time(v: Option<u64>) -> Result<Option<SystemTime>, AccessError> {
            v.map(|s| {
                SystemTime::UNIX_EPOCH
                    .checked_add(Duration::from_secs(s))
                    .ok_or(AccessError::InvalidInput("audit_time"))
            })
            .transpose()
        }
        Ok(AdminAuditFilter {
            business_id: self.business_id.clone(),
            actor_id: self.actor_id.clone(),
            operation: self.operation.clone(),
            occurred_after: time(self.occurred_after_unix_secs)?,
            occurred_before: time(self.occurred_before_unix_secs)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
    business_id: Option<String>,
    actor_id: Option<String>,
    operation: Option<String>,
    occurred_after_unix_secs: Option<u64>,
    occurred_before_unix_secs: Option<u64>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: String,
    filter: Filter,
    after: Vec<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
fn record_json(r: AdminAuditRecord) -> Value {
    json!({"audit_id":r.id,"occurred_at_unix_secs":r.occurred_at.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs(),"actor_id":r.actor_id,"actor_domain":r.actor_domain,"actor_session_id":r.actor_session_id,"authentication_source":r.authentication_source,"target_domain":r.target_domain,"target_business_id":r.target_business_id,"operation":r.operation,"request_id":r.request_id})
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
    list_scoped(state, context, tenant, query).await
}
async fn platform_list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    list_scoped(state, context, SYSTEM_TENANT_ID.into(), query).await
}
async fn list_scoped(
    state: AdminState,
    context: AccessAdminContext,
    tenant: String,
    query: PageQuery,
) -> Response {
    let filter = Filter {
        business_id: query.business_id,
        actor_id: query.actor_id,
        operation: query.operation,
        occurred_after_unix_secs: query.occurred_after_unix_secs,
        occurred_before_unix_secs: query.occurred_before_unix_secs,
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
                .and_then(|b| serde_json::from_slice::<Cursor>(&b).ok())
            else {
                return error(AccessError::InvalidCursor);
            };
            let cf = match c.filter.core() {
                Ok(v) => v,
                Err(_) => return error(AccessError::InvalidCursor),
            };
            Some(AccessCursor {
                version: c.version,
                scope: AccessListScope::AdminAudit {
                    tenant_id: c.tenant_id,
                    filter: cf,
                },
                after: c.after,
                sort_order: Some(c.sort_order.core()),
            })
        }
    };
    match call(move || {
        state.service.list_audit_events(
            context,
            tenant,
            core_filter,
            AccessPageRequest {
                limit: query.limit.unwrap_or(50),
                cursor,
                sort_order: Some(query.sort_order.core()),
            },
        )
    })
    .await
    {
        Ok(page) => {
            let next = match page.next_cursor {
                None => None,
                Some(c) => {
                    let AccessListScope::AdminAudit { tenant_id, .. } = c.scope else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
                            tenant_id,
                            filter,
                            after: c.after,
                            sort_order: ManagementSortOrder::from_core(
                                c.sort_order.unwrap_or(AccessSortOrder::Desc),
                            ),
                        })
                        .unwrap(),
                    ))
                }
            };
            Json(json!({"items":page.items.into_iter().map(record_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    get_scoped(state, context, tenant, id).await
}
async fn platform_detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    get_scoped(state, context, SYSTEM_TENANT_ID.into(), id).await
}
async fn get_scoped(
    state: AdminState,
    context: AccessAdminContext,
    tenant: String,
    id: String,
) -> Response {
    match call(move || state.service.get_audit_event(context, tenant, id)).await {
        Ok(detail) => {
            let Ok(change) = serde_json::from_str::<Value>(&detail.change_json) else {
                return error(AccessError::InvalidStoreResponse);
            };
            if !change.is_object() {
                return error(AccessError::InvalidStoreResponse);
            }
            let mut value = record_json(detail.event);
            value["change"] = change;
            Json(value).into_response()
        }
        Err(e) => error(e),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_filters_reject_invalid_ranges_and_unknown_authority_fields() {
        for raw in [
            "{\"actor_id\":\"a\",\"tenant_id\":\"other\"}",
            "{\"limit\":1,\"actor_domain\":\"0\"}",
        ] {
            assert!(serde_json::from_str::<PageQuery>(raw).is_err());
        }
        for (start, end) in [(Some(1001), Some(1000)), (Some(u64::MAX), None)] {
            let f = Filter {
                business_id: None,
                actor_id: None,
                operation: None,
                occurred_after_unix_secs: start,
                occurred_before_unix_secs: end,
            };
            assert!(f.core().and_then(|f| f.validate()).is_err());
        }
    }
}

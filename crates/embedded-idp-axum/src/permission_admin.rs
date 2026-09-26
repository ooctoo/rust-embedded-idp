use crate::{
    tenant_admin::{error, platform_context, target, ManagementSortOrder},
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
use embedded_idp_core::access::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
#[derive(Clone)]
struct AdminState {
    mode: TenancyMode,
    service: Arc<dyn PermissionAdminService>,
}
/// Tenant-scoped business permission definitions behind host-verified management authentication.
pub fn permission_admin_router(
    mode: TenancyMode,
    service: Arc<dyn PermissionAdminService>,
) -> Router {
    Router::new()
        .route("/admin/access/permissions", get(list).post(create))
        .route(
            "/admin/access/permissions/:resource_type/:action",
            get(detail).patch(update).delete(archive),
        )
        .route(
            "/admin/access/permissions/:resource_type/:action/enabled",
            post(set_enabled),
        )
        .route("/admin/platform/permissions", get(list_platform))
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(65536))
        .layer(middleware::from_fn(no_store))
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Category {
    Business,
    Tenant,
    Platform,
}
impl Category {
    fn core(self) -> PermissionCategory {
        match self {
            Self::Business => PermissionCategory::Business,
            Self::Tenant => PermissionCategory::Tenant,
            Self::Platform => PermissionCategory::Platform,
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    resource_type: Option<String>,
    category: Option<Category>,
    enabled: Option<bool>,
}
impl Filter {
    fn core(&self) -> AdminPermissionFilter {
        AdminPermissionFilter {
            resource_type: self.resource_type.clone(),
            category: self.category.map(Category::core),
            enabled: self.enabled,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
    resource_type: Option<String>,
    category: Option<Category>,
    enabled: Option<bool>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: Option<String>,
    filter: Filter,
    after: Vec<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    resource_type: String,
    action: String,
    description: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    description: String,
    expected_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    expected_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enabled {
    enabled: bool,
    expected_enabled: bool,
}
fn permission_json(p: PermissionDefinition) -> Value {
    json!({"tenant_id":p.tenant_id,"resource_type":p.key.resource_type,"action":p.key.action,"description":p.description,"category":match p.category {PermissionCategory::Business=>"business",PermissionCategory::Tenant=>"tenant",PermissionCategory::Platform=>"platform"},"enabled":p.enabled,"archived":p.archived,"version":p.version})
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
    list_scoped(state, context, AdminPermissionScope::Tenant(tenant), query).await
}
async fn list_platform(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    list_scoped(state, context, AdminPermissionScope::Platform, query).await
}
async fn list_scoped(
    state: AdminState,
    context: AccessAdminContext,
    scope: AdminPermissionScope,
    query: PageQuery,
) -> Response {
    let filter = Filter {
        resource_type: query.resource_type,
        category: query.category,
        enabled: query.enabled,
    };
    let core_filter = filter.core();
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
            Some(AccessCursor {
                version: c.version,
                scope: AccessListScope::AdminPermissions {
                    scope: c
                        .tenant_id
                        .map_or(AdminPermissionScope::Platform, AdminPermissionScope::Tenant),
                    filter: c.filter.core(),
                },
                after: c.after,
                sort_order: Some(c.sort_order.core()),
            })
        }
    };
    match call(move || {
        state.service.list_permissions(
            context,
            scope,
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
                    let AccessListScope::AdminPermissions { scope, .. } = c.scope else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    if c.after.len() != 3 {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    let tenant_id = match scope {
                        AdminPermissionScope::Tenant(t) => Some(t),
                        AdminPermissionScope::Platform => None,
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
            Json(json!({"items":page.items.into_iter().map(permission_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn change(
    state: AdminState,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    mutation: AccessAdminMutation,
) -> Response {
    let (context, tenant_id) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move ||state.service.execute(context,AccessAdminCommand {tenant_id,mutation})).await {
        Ok(event)=>match event.change {
            AccessChange::Catalog {changes}=>Json(json!({"audit_id":event.id,"changes":changes.into_iter().map(|c|json!({"before":c.before.map(permission_json),"after":permission_json(c.after)})).collect::<Vec<_>>()})).into_response(),
            _=>error(AccessError::InvalidStoreResponse),
        },
        Err(e)=>error(e),
    }
}
async fn detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((resource_type, action)): Path<(String, String)>,
) -> Response {
    let (context, tenant_id) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || {
        state.service.get_permission(
            context,
            tenant_id,
            PermissionKey {
                resource_type,
                action,
            },
        )
    })
    .await
    {
        Ok(permission) => Json(permission_json(permission)).into_response(),
        Err(e) => error(e),
    }
}
async fn create(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Json(body): Json<Create>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::CreatePermission {
            key: PermissionKey {
                resource_type: body.resource_type,
                action: body.action,
            },
            description: body.description,
        },
    )
    .await
}
async fn update(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((resource_type, action)): Path<(String, String)>,
    Json(body): Json<Update>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::UpdatePermission {
            key: PermissionKey {
                resource_type,
                action,
            },
            description: body.description,
            expected_version: body.expected_version,
        },
    )
    .await
}
async fn archive(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((resource_type, action)): Path<(String, String)>,
    Json(body): Json<Archive>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::ArchivePermission {
            key: PermissionKey {
                resource_type,
                action,
            },
            expected_version: body.expected_version,
        },
    )
    .await
}
async fn set_enabled(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path((resource_type, action)): Path<(String, String)>,
    Json(body): Json<Enabled>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::SetPermissionEnabled {
            permission: PermissionKey {
                resource_type,
                action,
            },
            enabled: body.enabled,
            expected_enabled: body.expected_enabled,
        },
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_writes_reject_extra_fields_and_require_versions() {
        for invalid in [
            r#"{"resource_type":"report","action":"read","description":"read","category":"platform"}"#,
            r#"{"resource_type":"report","action":"read","description":"read","tenant_id":"t1"}"#,
        ] {
            assert!(serde_json::from_str::<Create>(invalid).is_err());
        }
        assert!(serde_json::from_str::<Update>(r#"{"description":"read"}"#).is_err());
        assert!(serde_json::from_str::<Archive>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<Enabled>(r#"{"enabled":false}"#).is_err());
        assert!(serde_json::from_str::<Enabled>(
            r#"{"enabled":false,"expected_enabled":true,"actor_id":"admin"}"#
        )
        .is_err());
    }
}

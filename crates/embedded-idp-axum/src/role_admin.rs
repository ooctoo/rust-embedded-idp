use crate::{
    tenant_admin::{error, target, ManagementSortOrder},
    tenant_auth::{call, no_store},
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
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
    service: Arc<dyn RoleAdminService>,
}
/// Host-verified management context is required. Disabled retains local roles in
/// domain 0; Enabled requires a real target tenant, never the platform domain.
pub fn role_admin_router(mode: TenancyMode, service: Arc<dyn RoleAdminService>) -> Router {
    Router::new()
        .route("/admin/access/roles", get(list).post(create))
        .route(
            "/admin/access/roles/:role_id",
            get(detail).patch(update).delete(delete),
        )
        .route(
            "/admin/access/roles/:role_id/permissions",
            get(permissions).put(replace_permissions),
        )
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(65536))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: String,
    after: Vec<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    key: String,
    name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Active,
    Disabled,
}
impl Status {
    fn core(self) -> RoleStatus {
        match self {
            Self::Active => RoleStatus::Active,
            Self::Disabled => RoleStatus::Disabled,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    name: String,
    status: Status,
    expected_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Version {
    expected_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Permission {
    resource_type: String,
    action: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Permissions {
    permissions: Vec<Permission>,
    expected_version: u64,
}
pub(crate) fn role_json(r: Role) -> Value {
    json!({"tenant_id":r.tenant_id,"role_id":r.id,"key":r.key,"name":r.name,"version":r.version,
        "status":match r.status {RoleStatus::Active=>"active",RoleStatus::Disabled=>"disabled"},
        "kind":match r.kind {RoleKind::Business=>"business",RoleKind::SystemAdmin=>"system_admin",RoleKind::TenantSecurityAdmin=>"tenant_security_admin"}})
}
fn permission_json(keys: Vec<PermissionKey>) -> Vec<Value> {
    keys.into_iter()
        .map(|p| json!({"resource_type":p.resource_type,"action":p.action}))
        .collect()
}
fn record_json(r: AccessRoleRecord) -> Value {
    let mut result = role_json(r.role);
    result["permissions"] = json!(permission_json(r.permissions));
    result
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
    let cursor = match query.cursor {
        None => None,
        Some(raw) => {
            if raw.len() > 2048 {
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
                scope: AccessListScope::AdminRoles {
                    tenant_id: c.tenant_id,
                },
                after: c.after,
                sort_order: Some(c.sort_order.core()),
            })
        }
    };
    match call(move || {
        state.service.list_roles(
            context,
            tenant,
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
                    let AccessListScope::AdminRoles { tenant_id } = c.scope else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    if c.after.len() != 2 {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
                            tenant_id,
                            after: c.after,
                            sort_order: ManagementSortOrder::from_core(
                                c.sort_order.unwrap_or(AccessSortOrder::Desc),
                            ),
                        })
                        .unwrap(),
                    ))
                }
            };
            Json(json!({"items":page.items.into_iter().map(role_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn detail(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(role): Path<String>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move || state.service.get_role(context, tenant, role)).await {
        Ok(r) => Json(record_json(r)).into_response(),
        Err(e) => error(e),
    }
}
async fn permissions(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(role): Path<String>,
) -> Response {
    let (context, tenant) = match target(state.mode, context, &headers) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match call(move ||state.service.get_role(context,tenant,role)).await {
        Ok(r)=>Json(json!({"tenant_id":r.role.tenant_id,"role_id":r.role.id,"version":r.role.version,"items":permission_json(r.permissions)})).into_response(),Err(e)=>error(e),
    }
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
    match call(move || {
        state.service.execute(
            context,
            AccessAdminCommand {
                tenant_id: tenant,
                mutation,
            },
        )
    })
    .await
    {
        Ok(event) => match event.change {
            AccessChange::Role { before, after } => {
                let status = if before.is_none() {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                };
                (
                    status,
                    Json(json!({"role":after.map(record_json),"audit_id":event.id})),
                )
                    .into_response()
            }
            _ => error(AccessError::InvalidStoreResponse),
        },
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
        AccessAdminMutation::CreateRole {
            key: body.key,
            name: body.name,
        },
    )
    .await
}
async fn update(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(role_id): Path<String>,
    Json(body): Json<Update>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::UpdateRole {
            role_id,
            name: body.name,
            status: body.status.core(),
            expected_version: body.expected_version,
        },
    )
    .await
}
async fn delete(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(role_id): Path<String>,
    Json(body): Json<Version>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::DeleteRole {
            role_id,
            expected_version: body.expected_version,
        },
    )
    .await
}
async fn replace_permissions(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(role_id): Path<String>,
    Json(body): Json<Permissions>,
) -> Response {
    change(
        state,
        context,
        headers,
        AccessAdminMutation::ReplaceRolePermissions {
            role_id,
            permissions: body
                .permissions
                .into_iter()
                .map(|p| PermissionKey {
                    resource_type: p.resource_type,
                    action: p.action,
                })
                .collect(),
            expected_version: body.expected_version,
        },
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn role_bodies_reject_protected_kind_authority_and_missing_version() {
        assert!(serde_json::from_str::<Create>(
            r#"{"key":"reader","name":"Reader","kind":"system_admin"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Update>(r#"{"name":"Reader","status":"active"}"#).is_err());
        assert!(
            serde_json::from_str::<Version>(r#"{"expected_version":1,"tenant_id":"other"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Permissions>(r#"{"expected_version":1,"permissions":[{"resource_type":"report","action":"read","resource_id":"report1"}]}"#).is_err());
    }
}

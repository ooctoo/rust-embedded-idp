use crate::{
    tenant_admin::{
        business_id, business_target, error, optional_business_target, ManagementSortOrder,
    },
    tenant_auth::{call, no_store},
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get},
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
/// Independent management adapter for immutable role assignments. Host middleware
/// must inject verified management context; request values only select the target.
pub fn role_binding_admin_router(mode: TenancyMode, service: Arc<dyn RoleAdminService>) -> Router {
    Router::new()
        .route(
            "/admin/access/subjects/:subject_id/role-bindings",
            get(list).post(grant),
        )
        .route("/admin/access/role-bindings/:binding_id", delete(revoke))
        .with_state(AdminState { mode, service })
        .layer(DefaultBodyLimit::max(16384))
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
    business_id: Option<String>,
    subject_id: String,
    after: Vec<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Scope {
    Business {},
    Type {},
    Instance { resource_id: String },
}
impl Scope {
    fn core(self, resource_type: Option<String>) -> Result<RoleBindingScope, AccessError> {
        match (self, resource_type) {
            (Self::Business {}, None) => Ok(RoleBindingScope::Business),
            (Self::Type {}, Some(resource_type)) => Ok(RoleBindingScope::Resource {
                resource_type,
                scope: ResourceScope::Type,
            }),
            (Self::Instance { resource_id }, Some(resource_type)) => {
                Ok(RoleBindingScope::Resource {
                    resource_type,
                    scope: ResourceScope::Instance(resource_id),
                })
            }
            _ => Err(AccessError::InvalidInput("role_binding_scope")),
        }
    }
}
fn present_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    role_id: String,
    #[serde(default, deserialize_with = "present_string")]
    resource_type: Option<String>,
    scope: Scope,
}
pub(super) fn binding_json(b: RoleBinding) -> Value {
    let mut result = json!({"binding_id":b.id,"tenant_id":b.tenant_id,"business_id":b.business_id,"subject_id":b.subject_id,"role_id":b.role_id});
    match b.scope {
        RoleBindingScope::Business => result["scope"] = json!({"kind":"business"}),
        RoleBindingScope::Resource {
            resource_type,
            scope,
        } => {
            result["resource_type"] = json!(resource_type);
            result["scope"] = match scope {
                ResourceScope::Type => json!({"kind":"type"}),
                ResourceScope::Instance(id) => json!({"kind":"instance","resource_id":id}),
            };
        }
    }
    result
}

async fn list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
    Query(query): Query<PageQuery>,
) -> Response {
    let (context, tenant, business_id) =
        match optional_business_target(state.mode, context, &headers, true) {
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
                scope: AccessListScope::AdminRoleBindings {
                    tenant_id: c.tenant_id,
                    business_id: c.business_id,
                    subject_id: c.subject_id,
                },
                after: c.after,
                sort_order: Some(c.sort_order.core()),
            })
        }
    };
    match call(move || {
        state.service.list_subject_role_bindings(
            context,
            tenant,
            business_id,
            subject,
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
                    let AccessListScope::AdminRoleBindings {
                        tenant_id,
                        business_id,
                        subject_id,
                    } = c.scope
                    else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    if c.after.len() != 2 {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
                            tenant_id,
                            business_id,
                            subject_id,
                            after: c.after,
                            sort_order: ManagementSortOrder::from_core(
                                c.sort_order.unwrap_or(AccessSortOrder::Desc),
                            ),
                        })
                        .unwrap(),
                    ))
                }
            };
            Json(json!({"items":page.items.into_iter().map(binding_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
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
    let (context, tenant, _) = match business_target(state.mode, context, &headers, false) {
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
            AccessChange::Binding { before, after } => {
                let status = if before.is_none() {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                };
                (
                    status,
                    Json(json!({"binding":after.map(binding_json),"audit_id":event.id})),
                )
                    .into_response()
            }
            _ => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}
async fn grant(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject_id): Path<String>,
    Json(body): Json<Grant>,
) -> Response {
    let business_id = match business_id(&headers, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let scope = match body.scope.core(body.resource_type) {
        Ok(v) => v,
        Err(e) => return error(e),
    };
    change(
        state,
        context,
        headers,
        AccessAdminMutation::GrantRole {
            business_id,
            subject_id,
            role_id: body.role_id,
            scope,
        },
    )
    .await
}
async fn revoke(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(binding_id): Path<String>,
) -> Response {
    let business_id = match business_id(&headers, false) {
        Ok(v) => v,
        Err(e) => return e,
    };
    change(
        state,
        context,
        headers,
        AccessAdminMutation::RevokeRole {
            business_id,
            binding_id,
        },
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn business_scope_cannot_hide_a_resource_selection() {
        let body: Grant =
            serde_json::from_str(r#"{"role_id":"r","scope":{"kind":"business"}}"#).unwrap();
        assert_eq!(
            body.scope.core(body.resource_type).unwrap(),
            RoleBindingScope::Business
        );
        for raw in [
            r#"{"role_id":"r","resource_type":"report","scope":{"kind":"business"}}"#,
            r#"{"role_id":"r","scope":{"kind":"type"}}"#,
        ] {
            let body: Grant = serde_json::from_str(raw).unwrap();
            assert!(body.scope.core(body.resource_type).is_err());
        }
        assert!(serde_json::from_str::<Grant>(
            r#"{"role_id":"r","resource_type":null,"scope":{"kind":"business"}}"#
        )
        .is_err());
    }

    #[test]
    fn assignments_require_explicit_unambiguous_scope_and_reject_authority_fields() {
        for invalid in [
            r#"{"role_id":"r","resource_type":"report"}"#,
            r#"{"role_id":"r","resource_type":"report","scope":null}"#,
            r#"{"role_id":"r","resource_type":"report","scope":{"kind":"instance"}}"#,
            r#"{"role_id":"r","resource_type":"report","scope":{"kind":"type","resource_id":"r1"}}"#,
            r#"{"role_id":"r","resource_type":"report","scope":{"kind":"type"},"subject_id":"other"}"#,
            r#"{"role_id":"r","resource_type":"report","scope":{"kind":"type"},"actor_id":"admin"}"#,
        ] {
            assert!(serde_json::from_str::<Grant>(invalid).is_err(), "{invalid}");
        }
        let g: Grant = serde_json::from_str(
            r#"{"role_id":"r","resource_type":"report","scope":{"kind":"type"}}"#,
        )
        .unwrap();
        assert_eq!(
            g.scope.core(g.resource_type).unwrap(),
            RoleBindingScope::Resource {
                resource_type: "report".into(),
                scope: ResourceScope::Type
            }
        );
        let g:Grant=serde_json::from_str(r#"{"role_id":"r","resource_type":"report","scope":{"kind":"instance","resource_id":"report-1"}}"#).unwrap();
        assert_eq!(
            g.scope.core(g.resource_type).unwrap(),
            RoleBindingScope::Resource {
                resource_type: "report".into(),
                scope: ResourceScope::Instance("report-1".into())
            }
        );
    }
}

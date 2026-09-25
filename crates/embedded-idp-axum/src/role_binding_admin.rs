use crate::{
    tenant_admin::{error, target},
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
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    tenant_id: String,
    subject_id: String,
    after: String,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Scope {
    Type {},
    Instance { resource_id: String },
}
impl Scope {
    fn core(self) -> ResourceScope {
        match self {
            Self::Type {} => ResourceScope::Type,
            Self::Instance { resource_id } => ResourceScope::Instance(resource_id),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    role_id: String,
    resource_type: String,
    scope: Scope,
}
pub(super) fn binding_json(b: RoleBinding) -> Value {
    json!({"binding_id":b.id,"tenant_id":b.tenant_id,"subject_id":b.subject_id,"role_id":b.role_id,"resource_type":b.resource_type,
        "scope":match b.scope {ResourceScope::Type=>json!({"kind":"type"}),ResourceScope::Instance(id)=>json!({"kind":"instance","resource_id":id})}})
}
async fn list(
    State(state): State<AdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(subject): Path<String>,
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
                scope: AccessListScope::AdminRoleBindings {
                    tenant_id: c.tenant_id,
                    subject_id: c.subject_id,
                },
                after: vec![c.after],
            })
        }
    };
    match call(move || {
        state.service.list_subject_role_bindings(
            context,
            tenant,
            subject,
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
                    let AccessListScope::AdminRoleBindings {
                        tenant_id,
                        subject_id,
                    } = c.scope
                    else {
                        return error(AccessError::InvalidStoreResponse);
                    };
                    if c.after.len() != 1 {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
                            tenant_id,
                            subject_id,
                            after: c.after[0].clone(),
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
    change(
        state,
        context,
        headers,
        AccessAdminMutation::GrantRole {
            subject_id,
            role_id: body.role_id,
            resource_type: body.resource_type,
            scope: body.scope.core(),
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
    change(
        state,
        context,
        headers,
        AccessAdminMutation::RevokeRole { binding_id },
    )
    .await
}
#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(g.scope.core(), ResourceScope::Type);
        let g:Grant=serde_json::from_str(r#"{"role_id":"r","resource_type":"report","scope":{"kind":"instance","resource_id":"report-1"}}"#).unwrap();
        assert_eq!(g.scope.core(), ResourceScope::Instance("report-1".into()));
    }
}

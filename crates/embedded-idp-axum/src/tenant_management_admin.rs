use crate::{
    tenant_admin::{error, platform_context},
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
use embedded_idp_core::{access::*, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

/// Mount only behind host-verified management authentication. Disabled mode
/// exposes no tenant-management routes, independently of the supplied service.
pub fn tenant_management_admin_router(
    mode: TenancyMode,
    service: Arc<dyn TenantAdminService>,
    creation: Arc<dyn TenantCreationService>,
) -> Router {
    if mode == TenancyMode::Disabled {
        return Router::new();
    }
    Router::new()
        .route("/admin/tenants", get(list).post(create))
        .route("/admin/tenants/:tenant_id", get(detail).patch(update))
        .with_state(TenantAdminState { service, creation })
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Clone)]
struct TenantAdminState {
    service: Arc<dyn TenantAdminService>,
    creation: Arc<dyn TenantCreationService>,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Active,
    Suspended,
    Archived,
}
impl Status {
    fn core(self) -> TenantStatus {
        match self {
            Self::Active => TenantStatus::Active,
            Self::Suspended => TenantStatus::Suspended,
            Self::Archived => TenantStatus::Archived,
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    tenant_id: Option<String>,
    name: Option<String>,
    status: Option<Status>,
}
impl Filter {
    fn core(&self) -> AdminTenantFilter {
        AdminTenantFilter {
            tenant_id: self.tenant_id.clone(),
            name: self.name.clone(),
            status: self.status.map(Status::core),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    tenant_id: Option<String>,
    name: Option<String>,
    status: Option<Status>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    filter: Filter,
    after: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    tenant_id: String,
    name: String,
    allow_registration: bool,
    administrator: Administrator,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Administrator {
    Existing {
        subject_id: String,
    },
    New {
        email: String,
        password: String,
        display_name: Option<String>,
    },
}
impl Administrator {
    fn core(self) -> InitialTenantAdministrator {
        match self {
            Self::Existing { subject_id } => InitialTenantAdministrator::Existing { subject_id },
            Self::New {
                email,
                password,
                display_name,
            } => InitialTenantAdministrator::New {
                email,
                password: SecretString::new(password),
                display_name,
            },
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    name: String,
    status: Status,
    allow_registration: bool,
    expected_version: u64,
}
fn tenant_json(r: AccessTenantRecord) -> Value {
    json!({"tenant_id":r.tenant.id,"name":r.tenant.name,
        "status":match r.tenant.status {TenantStatus::Active=>"active",TenantStatus::Suspended=>"suspended",TenantStatus::Archived=>"archived"},
        "allow_registration":r.tenant.allow_registration,"version":r.version})
}
async fn list(
    State(state): State<TenantAdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let filter = Filter {
        tenant_id: query.tenant_id,
        name: query.name,
        status: query.status,
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
                scope: AccessListScope::AdminTenants {
                    filter: c.filter.core(),
                },
                after: vec![c.after],
            })
        }
    };
    match call(move || {
        state.service.list_tenants(
            context,
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
                    if !matches!(c.scope, AccessListScope::AdminTenants { .. })
                        || c.after.len() != 1
                    {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
                            filter,
                            after: c.after[0].clone(),
                        })
                        .unwrap(),
                    ))
                }
            };
            Json(json!({"items":page.items.into_iter().map(tenant_json).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn detail(
    State(state): State<TenantAdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(tenant): Path<String>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match call(move || state.service.get_tenant(context, tenant)).await {
        Ok(record) => Json(tenant_json(record)).into_response(),
        Err(e) => error(e),
    }
}
fn mutation_response(result: Result<AccessAuditEvent, AccessError>) -> Response {
    match result {
        Ok(event) => {
            let (status, record) = match event.change {
                AccessChange::TenantCreated { record, .. } => (StatusCode::CREATED, record),
                AccessChange::Tenant { after, .. } => (StatusCode::OK, after),
                _ => return error(AccessError::InvalidStoreResponse),
            };
            (
                status,
                Json(json!({"tenant":tenant_json(record),"audit_id":event.id})),
            )
                .into_response()
        }
        Err(e) => error(e),
    }
}
async fn create(
    State(state): State<TenantAdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Json(body): Json<Create>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    mutation_response(
        call(move || {
            state.creation.create_tenant(
                context,
                AdminCreateTenant {
                    tenant_id: body.tenant_id,
                    name: body.name,
                    allow_registration: body.allow_registration,
                    administrator: body.administrator.core(),
                },
            )
        })
        .await,
    )
}
async fn update(
    State(state): State<TenantAdminState>,
    context: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(body): Json<Update>,
) -> Response {
    let context = match platform_context(context, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    mutation_response(
        call(move || {
            state.service.execute(
                context,
                AccessAdminCommand {
                    tenant_id,
                    mutation: AccessAdminMutation::UpdateTenant {
                        name: body.name,
                        status: body.status.core(),
                        allow_registration: body.allow_registration,
                        expected_version: body.expected_version,
                    },
                },
            )
        })
        .await,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administrator_source_is_explicit_and_rejects_mixed_or_missing_credentials() {
        for administrator in [
            serde_json::json!({"kind":"existing","subject_id":"u"}),
            serde_json::json!({"kind":"new","email":"new@example.test","password":"Fixture-only-123"}),
        ] {
            let body = serde_json::json!({"tenant_id":"t","name":"Tenant","allow_registration":false,"administrator":administrator});
            assert!(serde_json::from_value::<Create>(body).is_ok());
        }
        for administrator in [
            serde_json::json!({"subject_id":"u"}),
            serde_json::json!({"kind":"new","email":"new@example.test"}),
            serde_json::json!({"kind":"existing","subject_id":"u","password":"ignored"}),
            serde_json::json!({"kind":"new","subject_id":"u","email":"new@example.test","password":"Fixture-only-123"}),
        ] {
            let body = serde_json::json!({"tenant_id":"t","name":"Tenant","allow_registration":false,"administrator":administrator});
            assert!(serde_json::from_value::<Create>(body).is_err());
        }
    }
    #[test]
    fn tenant_bodies_require_administrator_and_version_and_reject_authority_fields() {
        assert!(serde_json::from_str::<Create>(
            r#"{"tenant_id":"t","name":"Tenant","allow_registration":false}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Create>(r#"{"tenant_id":"t","name":"Tenant","allow_registration":false,"administrator_subject_id":"u","actor_id":"admin"}"#).is_err());
        assert!(serde_json::from_str::<Update>(
            r#"{"name":"Tenant","status":"active","allow_registration":false}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Update>(r#"{"name":"Tenant","status":"active","allow_registration":false,"expected_version":1,"tenant_id":"elsewhere"}"#).is_err());
        assert!(serde_json::from_str::<Update>(r#"{"name":"Tenant","status":"disabled","allow_registration":false,"expected_version":1}"#).is_err());
    }
}

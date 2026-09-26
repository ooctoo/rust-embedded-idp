use crate::{
    tenant_admin::{error, platform_context as context, ManagementSortOrder},
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
use embedded_idp_core::{access::*, AdminClientRecord, OidcClientType, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;

/// Deployment-scoped management routes. The host injects a trusted management context.
pub fn client_admin_router(service: Arc<dyn ClientAdminService>) -> Router {
    Router::new()
        .route("/admin/clients", get(list))
        .route(crate::http_paths::ADMIN_CLIENT_UPSERT_PATH, post(upsert))
        .route("/admin/clients/:client_id", get(detail))
        .with_state(service)
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn(no_store))
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    PublicDesktop,
    ConfidentialWeb,
}
impl Kind {
    fn core(self) -> OidcClientType {
        match self {
            Self::PublicDesktop => OidcClientType::PublicDesktop,
            Self::ConfidentialWeb => OidcClientType::ConfidentialWeb,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    client_type: Option<Kind>,
    pkce_required: Option<bool>,
}
impl Filter {
    fn core(&self) -> AdminClientFilter {
        AdminClientFilter {
            client_type: self.client_type.map(Kind::core),
            pkce_required: self.pkce_required,
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
    client_type: Option<Kind>,
    pkce_required: Option<bool>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    filter: Filter,
    after: Vec<String>,
    #[serde(default)]
    sort_order: ManagementSortOrder,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upsert {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    client_type: Kind,
    pkce_required: bool,
    client_secret: Option<String>,
}
fn metadata(c: AdminClientRecord) -> Value {
    json!({"client_id":c.client_id,"client_name":c.client_name,"redirect_uris":c.redirect_uris,"client_type":match c.client_type {OidcClientType::PublicDesktop=>"public_desktop",OidcClientType::ConfidentialWeb=>"confidential_web"},"pkce_required":c.pkce_required,"client_secret_configured":c.client_secret_configured})
}
async fn list(
    State(service): State<Arc<dyn ClientAdminService>>,
    context_value: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let context = match context(context_value, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let filter = Filter {
        client_type: query.client_type,
        pkce_required: query.pkce_required,
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
                scope: AccessListScope::AdminClients {
                    filter: c.filter.core(),
                },
                after: c.after,
                sort_order: Some(c.sort_order.core()),
            })
        }
    };
    match call(move || {
        service.list_clients(
            context,
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
                    if c.after.len() != 2
                        || !matches!(c.scope, AccessListScope::AdminClients { .. })
                    {
                        return error(AccessError::InvalidStoreResponse);
                    }
                    Some(Base64UrlUnpadded::encode_string(
                        &serde_json::to_vec(&Cursor {
                            version: c.version,
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
            Json(json!({"items":page.items.into_iter().map(metadata).collect::<Vec<_>>(),"has_more":page.has_more,"next_cursor":next})).into_response()
        }
        Err(e) => error(e),
    }
}
async fn detail(
    State(service): State<Arc<dyn ClientAdminService>>,
    context_value: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let context = match context(context_value, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match call(move || service.get_client(context, id)).await {
        Ok(c) => Json(metadata(c)).into_response(),
        Err(e) => error(e),
    }
}
async fn upsert(
    State(service): State<Arc<dyn ClientAdminService>>,
    context_value: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Json(body): Json<Upsert>,
) -> Response {
    let context = match context(context_value, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let command = AdminUpsertClient {
        client_id: body.client_id,
        client_name: body.client_name,
        redirect_uris: body.redirect_uris,
        client_type: body.client_type.core(),
        pkce_required: body.pkce_required,
        client_secret: body.client_secret.map(SecretString::new),
    };
    match call(move || service.upsert_client(context, command)).await {
        Ok(event) => match event.change {
            AccessChange::Client { after, .. } => {
                Json(json!({"client":metadata(after),"audit_id":event.id})).into_response()
            }
            _ => error(AccessError::InvalidStoreResponse),
        },
        Err(e) => error(e),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_payload_cannot_supply_hash_policy_or_actor() {
        let valid = json!({"client_id":"web","client_name":"Web","redirect_uris":["https://example.test/callback"],"client_type":"confidential_web","pkce_required":true,"client_secret":"fixture-only"});
        assert!(serde_json::from_value::<Upsert>(valid.clone()).is_ok());
        for key in [
            "client_secret_hash",
            "tenant_id",
            "actor_id",
            "login_policy",
        ] {
            let mut body = valid.clone();
            body[key] = json!("override");
            assert!(serde_json::from_value::<Upsert>(body).is_err());
        }
    }
}

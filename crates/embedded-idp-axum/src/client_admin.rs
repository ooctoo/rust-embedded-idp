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
        .route("/admin/clients/-/lookup", get(lookup))
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupQuery {
    client_id: String,
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
async fn lookup(
    State(service): State<Arc<dyn ClientAdminService>>,
    context_value: Option<Extension<AccessAdminContext>>,
    headers: HeaderMap,
    Query(query): Query<LookupQuery>,
) -> Response {
    let context = match context(context_value, &headers) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let id = query.client_id;
    let requested = id.clone();
    match call(move || service.get_client(context, id)).await {
        Ok(c) if c.client_id == requested => {
            Json(json!({"client_id":requested,"client":metadata(c)})).into_response()
        }
        Ok(_) => error(AccessError::InvalidStoreResponse),
        Err(AccessError::NotFound("client")) => {
            Json(json!({"client_id":requested,"client":null})).into_response()
        }
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
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    struct LookupService;
    impl ClientAdminService for LookupService {
        fn list_clients(
            &self,
            _: AccessAdminContext,
            _: AdminClientFilter,
            _: AccessPageRequest,
        ) -> Result<AccessPage<AdminClientRecord>, AccessError> {
            unreachable!()
        }
        fn get_client(
            &self,
            _: AccessAdminContext,
            id: String,
        ) -> Result<AdminClientRecord, AccessError> {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            {
                return Err(AccessError::InvalidInput("client_id"));
            }
            match id.as_str() {
                "missing" => return Err(AccessError::NotFound("client")),
                "other" => return Err(AccessError::NotFound("other")),
                "forbidden" => return Err(AccessError::Forbidden),
                _ => {}
            }
            Ok(AdminClientRecord {
                client_id: if id == "mismatch" { "wrong".into() } else { id },
                client_name: "Example".into(),
                redirect_uris: vec![],
                client_type: OidcClientType::PublicDesktop,
                pkce_required: true,
                client_secret_configured: false,
                created_at: None,
            })
        }
        fn upsert_client(
            &self,
            _: AccessAdminContext,
            _: AdminUpsertClient,
        ) -> Result<AccessAuditEvent, AccessError> {
            unreachable!()
        }
    }
    fn app() -> Router {
        client_admin_router(Arc::new(LookupService)).layer(Extension(AccessAdminContext {
            actor: AccessActor {
                tenant_id: "0".into(),
                subject_id: "admin".into(),
                session_id: "session".into(),
            },
            authentication_source: "test".into(),
            request_id: "request".into(),
        }))
    }
    async fn request(uri: &str) -> (StatusCode, Value) {
        let response = app()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 16384).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
    #[tokio::test]
    async fn exact_lookup_preserves_ids_and_classifies_service_results() {
        for (encoded, expected) in [
            ("%2E", "."),
            ("..", ".."),
            ("...", "..."),
            (".a", ".a"),
            ("a..", "a.."),
            ("-", "-"),
            ("lookup", "lookup"),
            ("upsert", "upsert"),
        ] {
            let (status, body) =
                request(&format!("/admin/clients/-/lookup?client_id={encoded}")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["client_id"], expected);
            assert_eq!(body["client"]["client_id"], expected);
        }
        let (status, body) = request("/admin/clients/-/lookup?client_id=missing").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["client"].is_null());
        for (id, expected) in [
            ("other", StatusCode::NOT_FOUND),
            ("forbidden", StatusCode::FORBIDDEN),
            ("mismatch", StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            assert_eq!(
                request(&format!("/admin/clients/-/lookup?client_id={id}"))
                    .await
                    .0,
                expected
            );
        }
        for id in ["-", "lookup"] {
            assert_eq!(
                request(&format!("/admin/clients/{id}")).await.0,
                StatusCode::OK
            );
        }
        assert_eq!(
            request("/admin/clients/upsert").await.0,
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    #[tokio::test]
    async fn lookup_rejects_ambiguous_or_invalid_query() {
        for query in [
            "",
            "client_id=",
            "client_id=.&client_id=.",
            "client_id=.&client_id=..",
            "client_id=.&other=x",
            "client_id=%252e",
            "client_id=%",
            "client_id=%FF",
            "client_id=a%2Fb",
        ] {
            assert_eq!(
                request(&format!("/admin/clients/-/lookup?{query}")).await.0,
                StatusCode::BAD_REQUEST,
                "{query}"
            );
        }
    }
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

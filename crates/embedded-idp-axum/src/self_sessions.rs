use crate::{
    http_support::{bearer_token, unix_time_secs},
    tenant_auth::{call, map_tenant_auth_error, no_store, tenant_error, tenant_header_matches},
};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{
    access::*, AccessTokenPurpose, IdGenerator, SecretString, SessionStatus, UuidV7IdGenerator,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
enum Authentication {
    Business(Arc<dyn TenantAuthenticationService>),
    Management(Arc<dyn ManagementAuthenticationService>),
}
#[derive(Clone)]
struct SessionState {
    authentication: Authentication,
    service: Arc<dyn SelfSessionService>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionQuery {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u8,
    subject_id: String,
    tenant_id: String,
    session_id: String,
}

pub fn self_session_router(
    authentication: Arc<dyn TenantAuthenticationService>,
    service: Arc<dyn SelfSessionService>,
) -> Router {
    router(
        "/auth/security/sessions",
        Authentication::Business(authentication),
        service,
    )
}
pub fn management_self_session_router(
    authentication: Arc<dyn ManagementAuthenticationService>,
    service: Arc<dyn SelfSessionService>,
) -> Router {
    router(
        "/admin/auth/security/sessions",
        Authentication::Management(authentication),
        service,
    )
}
fn router(
    path: &str,
    authentication: Authentication,
    service: Arc<dyn SelfSessionService>,
) -> Router {
    Router::new()
        .route(path, get(list))
        .with_state(SessionState {
            authentication,
            service,
        })
        .layer(middleware::from_fn(no_store))
}
async fn list(
    State(state): State<SessionState>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
) -> Response {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    }
    let Some(token) = bearer_token(&headers)
        .filter(|v| v.len() <= 16384)
        .map(str::to_owned)
    else {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    };
    let actor = call(move || match state.authentication {
        Authentication::Business(service) => service.authenticate(SecretString::new(token)),
        Authentication::Management(service) => service
            .authenticate(
                SecretString::new(token),
                UuidV7IdGenerator.next_id("self-read"),
            )
            .map(|context| context.actor),
    })
    .await;
    let actor = match actor {
        Ok(a) if tenant_header_matches(&headers, &a.tenant_id) => a,
        Ok(_) => return map_tenant_auth_error(TenantAuthError::InvalidSession),
        Err(e) => return map_tenant_auth_error(e),
    };
    if headers.contains_key("x-embedded-idp-business-id") {
        return session_error(AccessError::InvalidInput("business_header"));
    }
    list_for_actor(state.service, actor, query).await
}
pub(crate) async fn list_for_actor(
    service: Arc<dyn SelfSessionService>,
    actor: AccessActor,
    query: SessionQuery,
) -> Response {
    let page = match page(query) {
        Ok(p) => p,
        Err(e) => return session_error(e),
    };
    match call(move || service.list_sessions(actor, page)).await {
        Ok(page) => {
            let cursor = page.next_cursor.map(|c| {
                Base64UrlUnpadded::encode_string(
                    &serde_json::to_vec(&Cursor {
                        version: 1,
                        subject_id: c.subject_id,
                        tenant_id: c.tenant_id,
                        session_id: c.session_id,
                    })
                    .expect("fixed cursor fields"),
                )
            });
            let items:Vec<_>=page.items.into_iter().map(|s|json!({"tenant_id":s.tenant_id,"session_id":s.session_id,"client_id":s.client_id,"purpose":match s.purpose{AccessTokenPurpose::Business=>"business",AccessTokenPurpose::Management=>"management"},"device_id":s.device_id,"created_at":unix_time_secs(s.created_at),"expires_at":unix_time_secs(s.expires_at),"status":if s.status==SessionStatus::Expired{"expired"}else{"active"},"current":s.current})).collect();
            Json(json!({"items":items,"next_cursor":cursor})).into_response()
        }
        Err(e) => session_error(e),
    }
}
fn page(query: SessionQuery) -> Result<SelfSessionPageRequest, AccessError> {
    let cursor = match query.cursor {
        None => None,
        Some(encoded) => {
            if encoded.is_empty() || encoded.len() > 1024 {
                return Err(AccessError::InvalidCursor);
            }
            let bytes =
                Base64UrlUnpadded::decode_vec(&encoded).map_err(|_| AccessError::InvalidCursor)?;
            let cursor: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| AccessError::InvalidCursor)?;
            if cursor.version != 1 {
                return Err(AccessError::InvalidCursor);
            }
            Some(SelfSessionCursor {
                subject_id: cursor.subject_id,
                tenant_id: cursor.tenant_id,
                session_id: cursor.session_id,
            })
        }
    };
    Ok(SelfSessionPageRequest {
        limit: query.limit.unwrap_or(50),
        cursor,
    })
}
pub(crate) fn session_error(error: AccessError) -> Response {
    match error {
        AccessError::Forbidden => tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "a current first-party session is required",
        ),
        AccessError::InvalidInput(_) | AccessError::InvalidCursor | AccessError::ModeMismatch => {
            tenant_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            )
        }
        _ => tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ),
    }
}

#[cfg(test)]
#[path = "self_sessions_tests.rs"]
mod tests;

use super::*;
use crate::self_sessions::{list_for_actor, SessionQuery};
use embedded_idp_core::access::{SelfSecurityBrowserIdentityService, SelfSessionService};
#[derive(Clone)]
struct SecurityState {
    identity: Arc<dyn SelfSecurityBrowserIdentityService>,
    service: Arc<dyn SelfSessionService>,
    config: BrowserSessionHttpConfig,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRequest {
    expected: Expected,
    limit: Option<u32>,
    cursor: Option<String>,
}

pub fn browser_self_session_router(
    identity: Arc<dyn SelfSecurityBrowserIdentityService>,
    service: Arc<dyn SelfSessionService>,
    config: BrowserSessionHttpConfig,
) -> Result<Router, &'static str> {
    if identity.self_security_browser_purpose() != config.purpose
        || identity.self_security_browser_lifetime_secs() != config.development_ttl_secs
    {
        return Err("self security browser configuration mismatch");
    }
    let path = format!("{}/security/sessions", route_root(config.purpose));
    let state = SecurityState {
        identity,
        service,
        config,
    };
    Ok(Router::new()
        .route(&path, post(read))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(state, guard))
        .layer(middleware::from_fn(no_store)))
}
async fn guard(State(state): State<SecurityState>, request: Request, next: Next) -> Response {
    if !browser_headers_valid(request.headers(), &state.config)
        || request.headers().contains_key("x-embedded-idp-business-id")
    {
        return tenant_error(
            StatusCode::FORBIDDEN,
            "browser_origin_rejected",
            "browser request rejected",
        );
    }
    next.run(request).await
}
async fn read(
    State(state): State<SecurityState>,
    headers: HeaderMap,
    Json(body): Json<ReadRequest>,
) -> Response {
    let cookie = match credential(&headers, &state.config.cookie_name) {
        Ok(Some(c)) => c,
        Ok(None) => return map_tenant_auth_error(TenantAuthError::InvalidSession),
        Err(r) => return r,
    };
    let expected = BrowserSessionIdentity {
        tenant_id: body.expected.tenant_id,
        account_id: body.expected.account_id,
        session_id: body.expected.session_id,
        client_id: body.expected.client_id,
    };
    match call(move || {
        state
            .identity
            .authenticate_self_security_browser(cookie, expected)
    })
    .await
    {
        Ok(actor) => {
            list_for_actor(
                state.service,
                actor,
                SessionQuery {
                    limit: body.limit,
                    cursor: body.cursor,
                },
            )
            .await
        }
        Err(e) => map_tenant_auth_error(e),
    }
}

#[cfg(test)]
#[path = "self_sessions_tests.rs"]
mod tests;

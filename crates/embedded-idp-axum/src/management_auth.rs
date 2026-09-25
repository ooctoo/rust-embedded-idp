use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use embedded_idp_core::{
    access::*, IdGenerator, IssuedTokenBundle, SecretString, UuidV7IdGenerator,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    http_support::bearer_token,
    proof_http::AUTH_DEVICE_BODY_LIMIT_BYTES,
    tenant_auth::{
        call, capabilities_response, login_response, map_tenant_auth_error, no_store,
        selection_ticket, tenant_error, tenant_page_response, ticket_response, ListTenantsRequest,
        LoginRequest, SelectTenantRequest,
    },
};

type ManagementState = Arc<dyn ManagementAuthenticationService>;

/// Wrap the already assembled management API routes, then add independent login
/// routes. Call before nesting under the host's outer prefix. Business routes
/// must be merged separately. This adapter accepts explicit bearer credentials;
/// cookies, development subject headers and API keys do not authenticate requests.
pub fn management_router(
    service: Arc<dyn ManagementAuthenticationService>,
    admin_routes: Router,
) -> Router {
    let capabilities = service.login_capabilities();
    let mut auth = Router::new()
        .route("/admin/auth/capabilities", get(capabilities_handler))
        .route("/admin/auth/login", post(login))
        .route("/admin/auth/session", get(session))
        .route("/admin/auth/refresh", post(refresh))
        .route("/admin/auth/logout", post(logout));
    if capabilities.mode == TenancyMode::Enabled
        && capabilities.policy == LoginTenantPolicy::ChooseAfterAuthentication
    {
        auth = auth
            .route("/admin/auth/tenant-selection/tenants", get(list_tenants))
            .route("/admin/auth/tenant-selection/complete", post(select_tenant))
            .route("/admin/auth/me/tenant-selection", post(switch_tenant));
    }
    let auth = auth
        .with_state(service.clone())
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(auth_headers));
    let protected = if admin_routes.has_routes() {
        admin_routes.route_layer(middleware::from_fn_with_state(
            service,
            authenticate_management,
        ))
    } else {
        admin_routes
    };
    protected.merge(auth).layer(middleware::from_fn(no_store))
}

async fn authenticate_management(
    State(service): State<ManagementState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer_token(request.headers()).map(str::to_owned) else {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    };
    let request_id = UuidV7IdGenerator.next_id("request");
    let header_id = request_id.clone();
    match call(move || service.authenticate(SecretString::new(token), request_id)).await {
        Ok(context) => {
            // Overwrite, never reuse an upstream unverified context.
            request.extensions_mut().insert(context);
            let mut response = next.run(request).await;
            response
                .headers_mut()
                .insert("x-request-id", header_id.parse().expect("UUID header"));
            response
        }
        Err(error) => map_tenant_auth_error(error),
    }
}

// Authentication targets come from the trusted entry, signed session or explicit
// selection body. The target-tenant header belongs only to protected admin APIs.
async fn auth_headers(request: Request, next: Next) -> Response {
    if request.headers().contains_key("x-embedded-idp-tenant-id") {
        return tenant_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request is invalid",
        );
    }
    next.run(request).await
}

async fn capabilities_handler(State(service): State<ManagementState>) -> Response {
    capabilities_response(service.login_capabilities())
}

async fn login(
    State(service): State<ManagementState>,
    Json(request): Json<LoginRequest>,
) -> Response {
    login_response(
        call(move || {
            service.login(TenantPasswordLogin {
                email: request.email,
                password: SecretString::new(request.password),
            })
        })
        .await,
    )
}

async fn list_tenants(
    State(service): State<ManagementState>,
    headers: HeaderMap,
    Query(request): Query<ListTenantsRequest>,
) -> Response {
    let Some(ticket) = selection_ticket(&headers).map(str::to_owned) else {
        return map_tenant_auth_error(TenantAuthError::InvalidSelection);
    };
    let page = match request.into_page() {
        Ok(page) => page,
        Err(response) => return response,
    };
    match call(move || service.list_tenants(SecretString::new(ticket), page)).await {
        Ok(page) => match tenant_page_response(page) {
            Ok(body) => Json(body).into_response(),
            Err(response) => response,
        },
        Err(error) => map_tenant_auth_error(error),
    }
}

async fn select_tenant(
    State(service): State<ManagementState>,
    headers: HeaderMap,
    Json(request): Json<SelectTenantRequest>,
) -> Response {
    let Some(ticket) = selection_ticket(&headers).map(str::to_owned) else {
        return map_tenant_auth_error(TenantAuthError::InvalidSelection);
    };
    login_response(
        call(move || {
            service
                .select_tenant(SecretString::new(ticket), request.tenant_id)
                .map(TenantLoginOutcome::Authenticated)
        })
        .await,
    )
}

async fn session(State(service): State<ManagementState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers).map(str::to_owned) else {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    };
    match call(move || {
        service.authenticate(
            SecretString::new(token),
            UuidV7IdGenerator.next_id("request"),
        )
    })
    .await
    {
        Ok(context) => Json(json!({ "tenant_id":context.actor.tenant_id,
            "account_id":context.actor.subject_id, "session_id":context.actor.session_id }))
        .into_response(),
        Err(error) => map_tenant_auth_error(error),
    }
}

async fn switch_tenant(State(service): State<ManagementState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers).map(str::to_owned) else {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    };
    match call(move || service.begin_switch(SecretString::new(token))).await {
        Ok(ticket) => Json(ticket_response(ticket)).into_response(),
        Err(error) => map_tenant_auth_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshRequest {
    refresh_token: String,
}

async fn refresh(
    State(service): State<ManagementState>,
    Json(request): Json<RefreshRequest>,
) -> Response {
    match call(move || service.rotate_refresh(SecretString::new(request.refresh_token))).await {
        Ok(TenantRefreshOutcome::Rotated { session, tokens }) => {
            login_response(Ok(TenantLoginOutcome::Authenticated(TenantLoginSession {
                session,
                tokens: IssuedTokenBundle {
                    access_token: tokens.access_token.token,
                    access_expires_at: tokens.access_token.expires_at,
                    refresh_token: tokens.refresh_token,
                    refresh_expires_at: tokens.refresh_expires_at,
                    refresh_token_version: tokens.refresh_token_version,
                },
            })))
        }
        // Core has committed the family revocation before returning this outcome.
        Ok(TenantRefreshOutcome::ReuseDetected { .. }) => tenant_error(
            StatusCode::UNAUTHORIZED,
            "refresh_token_reuse_detected",
            "refresh token reuse detected",
        ),
        Err(error) => map_tenant_auth_error(error),
    }
}

async fn logout(State(service): State<ManagementState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers).map(str::to_owned) else {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    };
    match call(move || service.logout(SecretString::new(token))).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => map_tenant_auth_error(error),
    }
}

#[cfg(test)]
mod tests;

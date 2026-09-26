//! Optional same-origin browser transport. Ordinary APIs still require Bearer tokens.
use std::{sync::Arc, time::SystemTime};

use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use embedded_idp_core::{access::*, AccessTokenPurpose, IssuedTokenBundle, SecretString};
use serde::Deserialize;
use serde_json::json;

use crate::{
    http_support::unix_time_secs,
    proof_http::AUTH_DEVICE_BODY_LIMIT_BYTES,
    tenant_auth::{
        call, map_tenant_auth_error, no_store, selection_ticket, tenant_error, ticket_response,
        LoginRequest, SelectTenantRequest,
    },
};

/// Trusted external origin and cookie scope, including the host's outer prefix.
/// HTTP is accepted only for explicit loopback development origins.
#[derive(Clone, Debug)]
pub struct BrowserSessionHttpConfig {
    origin: String,
    cookie_name: String,
    cookie_path: String,
    secure: bool,
    purpose: AccessTokenPurpose,
}
impl BrowserSessionHttpConfig {
    pub fn new(
        origin: &str,
        cookie_name: &str,
        cookie_path: &str,
        purpose: AccessTokenPurpose,
    ) -> Result<Self, &'static str> {
        let uri: Uri = origin.parse().map_err(|_| "invalid browser origin")?;
        let scheme = uri.scheme_str().ok_or("invalid browser origin")?;
        let authority = uri.authority().ok_or("invalid browser origin")?;
        if uri.host().is_none_or(str::is_empty)
            || origin != format!("{scheme}://{authority}")
            || authority.as_str().contains('@')
            || !(scheme == "https"
                || scheme == "http"
                    && matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]")))
        {
            return Err("browser origin requires HTTPS or explicit loopback HTTP");
        }
        if cookie_name.is_empty()
            || cookie_name.len() > 64
            || cookie_name.starts_with("__Host-")
            || !cookie_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || cookie_name.starts_with("__Secure-") && scheme != "https"
        {
            return Err("invalid browser cookie name");
        }
        let root = route_root(purpose);
        if !cookie_path.ends_with(root)
            || !cookie_path.starts_with('/')
            || !cookie_path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            || cookie_path
                .split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err("invalid external browser cookie path");
        }
        Ok(Self {
            origin: origin.into(),
            cookie_name: cookie_name.into(),
            cookie_path: cookie_path.into(),
            secure: scheme == "https",
            purpose,
        })
    }
    fn cookie(&self, raw: &str, max_age: u64) -> HeaderValue {
        // raw is validated before this boundary; no user-controlled header syntax.
        HeaderValue::from_str(&format!(
            "{}={raw}; Path={}; Max-Age={max_age}; HttpOnly; SameSite=Strict{}",
            self.cookie_name,
            self.cookie_path,
            if self.secure { "; Secure" } else { "" }
        ))
        .expect("validated cookie values")
    }
    fn clear(&self, mut response: Response) -> Response {
        response
            .headers_mut()
            .append(header::SET_COOKIE, self.cookie("", 0));
        response
    }
}
fn route_root(purpose: AccessTokenPurpose) -> &'static str {
    match purpose {
        AccessTokenPurpose::Business => "/auth/browser",
        AccessTokenPurpose::Management => "/admin/auth/browser",
    }
}
#[derive(Clone)]
struct BrowserState {
    service: Arc<dyn BrowserSessionService>,
    config: BrowserSessionHttpConfig,
}

/// Merge with the existing business or management router. No existing paths are replaced.
pub fn browser_session_router(
    service: Arc<dyn BrowserSessionService>,
    config: BrowserSessionHttpConfig,
) -> Result<Router, &'static str> {
    if service.browser_purpose() != config.purpose {
        return Err("browser service purpose mismatch");
    }
    let root = route_root(config.purpose);
    let state = BrowserState { service, config };
    Ok(Router::new()
        .route(&format!("{root}/login"), post(login))
        .route(&format!("{root}/tenant-selection/complete"), post(select))
        .route(&format!("{root}/restore"), post(restore))
        .route(&format!("{root}/refresh"), post(refresh))
        .route(&format!("{root}/logout"), post(logout))
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .route_layer(middleware::from_fn_with_state(state, browser_guard))
        .layer(middleware::from_fn(no_store)))
}
fn exactly(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().is_some_and(|v| v == expected) && values.next().is_none()
}
async fn browser_guard(
    State(state): State<BrowserState>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    if !exactly(headers, "origin", &state.config.origin)
        || !exactly(headers, "x-embedded-idp-browser", "1")
        || headers.contains_key("sec-fetch-site")
            && !exactly(headers, "sec-fetch-site", "same-origin")
        || headers.contains_key("x-embedded-idp-tenant-id")
    {
        return tenant_error(
            StatusCode::FORBIDDEN,
            "browser_origin_rejected",
            "browser request rejected",
        );
    }
    next.run(request).await
}
fn valid_token(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 512
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn credential(headers: &HeaderMap, name: &str) -> Result<Option<SecretString>, Response> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        let value = header.to_str().map_err(|_| bad_cookie())?;
        for cookie in value.split(';') {
            let Some((key, value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() || !valid_token(value) {
                    return Err(bad_cookie());
                }
                found = Some(SecretString::new(value));
            }
        }
    }
    Ok(found)
}
fn bad_cookie() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "invalid browser cookie",
    )
}
fn browser_error(error: TenantAuthError) -> Response {
    match error {
        TenantAuthError::Access(AccessError::InvalidInput("browser_session_changed")) => {
            tenant_error(
                StatusCode::CONFLICT,
                "browser_session_changed",
                "browser session changed",
            )
        }
        other => map_tenant_auth_error(other),
    }
}
fn authenticated(config: &BrowserSessionHttpConfig, result: TenantLoginSession) -> Response {
    let raw = result.tokens.refresh_token.expose_secret();
    let max_age = result
        .tokens
        .refresh_expires_at
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs();
    if !valid_token(raw) || max_age == 0 {
        return tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "invalid browser token bundle",
        );
    }
    let cookie = config.cookie(raw, max_age);
    let s = result.session;
    let mut response = Json(json!({"status":"authenticated", "session": {
        "tenant_id":s.tenant_id,"account_id":s.account_id,"session_id":s.id,"client_id":s.client_id,
        "expires_at_unix_secs":unix_time_secs(s.expires_at)}, "tokens": {
        "access_token": result.tokens.access_token.into_exposed(),
        "access_expires_at_unix_secs":unix_time_secs(result.tokens.access_expires_at),
        "refresh_expires_at_unix_secs":unix_time_secs(result.tokens.refresh_expires_at)
    }}))
    .into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}
async fn login(State(state): State<BrowserState>, Json(body): Json<LoginRequest>) -> Response {
    match call(move || {
        state.service.browser_login(TenantPasswordLogin {
            email: body.email,
            password: SecretString::new(body.password),
        })
    })
    .await
    {
        Ok(TenantLoginOutcome::Authenticated(result)) => authenticated(&state.config, result),
        Ok(TenantLoginOutcome::SelectionRequired(ticket)) => {
            Json(ticket_response(ticket)).into_response()
        }
        Err(error) => browser_error(error),
    }
}
async fn select(
    State(state): State<BrowserState>,
    headers: HeaderMap,
    Json(body): Json<SelectTenantRequest>,
) -> Response {
    let Some(ticket) = selection_ticket(&headers).map(str::to_owned) else {
        return browser_error(TenantAuthError::InvalidSelection);
    };
    match call(move || {
        state
            .service
            .browser_select(SecretString::new(ticket), body.tenant_id)
    })
    .await
    {
        Ok(result) => authenticated(&state.config, result),
        Err(error) => browser_error(error),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedSession {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String,
}
impl From<ExpectedSession> for BrowserSessionIdentity {
    fn from(s: ExpectedSession) -> Self {
        Self {
            tenant_id: s.tenant_id,
            account_id: s.account_id,
            session_id: s.session_id,
            client_id: s.client_id,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRequest {
    expected_session: Option<ExpectedSession>,
}
async fn refresh(
    state: State<BrowserState>,
    headers: HeaderMap,
    body: Json<SessionRequest>,
) -> Response {
    if body.expected_session.is_none() {
        return tenant_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expected session is required",
        );
    }
    restore(state, headers, body).await
}
async fn restore(
    State(state): State<BrowserState>,
    headers: HeaderMap,
    Json(body): Json<SessionRequest>,
) -> Response {
    let token = match credential(&headers, &state.config.cookie_name) {
        Ok(Some(token)) => token,
        Ok(None) => {
            return state
                .config
                .clear(browser_error(TenantAuthError::InvalidRefresh))
        }
        Err(response) => return response,
    };
    let response = match call(move || {
        state
            .service
            .browser_refresh(token, body.expected_session.map(Into::into))
    })
    .await
    {
        Ok(TenantRefreshOutcome::Rotated { session, tokens }) => authenticated(
            &state.config,
            TenantLoginSession {
                session,
                tokens: IssuedTokenBundle {
                    access_token: tokens.access_token.token,
                    access_expires_at: tokens.access_token.expires_at,
                    refresh_token: tokens.refresh_token,
                    refresh_expires_at: tokens.refresh_expires_at,
                    refresh_token_version: tokens.refresh_token_version,
                },
            },
        ),
        Ok(TenantRefreshOutcome::ReuseDetected { .. }) => tenant_error(
            StatusCode::UNAUTHORIZED,
            "refresh_token_reuse_detected",
            "refresh token reuse detected",
        ),
        Err(error) => browser_error(error),
    };
    if response.status() == StatusCode::UNAUTHORIZED {
        state.config.clear(response)
    } else {
        response
    }
}
async fn logout(
    State(state): State<BrowserState>,
    headers: HeaderMap,
    Json(body): Json<SessionRequest>,
) -> Response {
    let token = match credential(&headers, &state.config.cookie_name) {
        Ok(Some(token)) => token,
        Ok(None) => return state.config.clear(StatusCode::NO_CONTENT.into_response()),
        Err(response) => return response,
    };
    match call(move || {
        state
            .service
            .browser_logout(token, body.expected_session.map(Into::into))
    })
    .await
    {
        Ok(()) => state.config.clear(StatusCode::NO_CONTENT.into_response()),
        Err(error) => browser_error(error),
    }
}

#[cfg(test)]
mod tests;

use crate::{
    http_support::{bearer_token, unix_time_secs},
    proof_http::AUTH_DEVICE_BODY_LIMIT_BYTES,
    tenant_auth::{call, map_tenant_auth_error, no_store, tenant_header_matches},
};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64ct::{Base64, Encoding};
use embedded_idp_core::{access::*, SecretString};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

/// Mount explicitly instead of the old single-domain OIDC resource routes.
/// Client credentials stay in Basic auth or POST forms, never query strings.
pub fn tenant_oidc_resource_router(service: Arc<dyn TenantOidcResourceService>) -> Router {
    Router::new()
        .route("/oidc/userinfo", get(user_info))
        .route("/oidc/introspect", post(introspect))
        .route("/oidc/revoke", post(revoke))
        .route("/auth/logout", post(logout))
        .with_state(service)
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenForm {
    token: String,
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutForm {
    refresh_token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}
fn command(headers: &HeaderMap, form: TokenForm) -> Result<TenantTokenRequest, TenantAuthError> {
    // Tokens choose their own tenant; do not accept a conflicting external context.
    if headers.contains_key("x-embedded-idp-tenant-id") {
        return Err(AccessError::InvalidInput("tenant_header").into());
    }
    let (client_id, client_secret) =
        client_credentials(headers, form.client_id, form.client_secret)?;
    Ok(TenantTokenRequest {
        token: SecretString::new(form.token),
        client_id,
        client_secret: client_secret.map(SecretString::new),
        token_type_hint: match form.token_type_hint.as_deref() {
            Some("access_token") => Some(TenantTokenType::Access),
            Some("refresh_token") => Some(TenantTokenType::Refresh),
            _ => None,
        },
    })
}
pub(super) fn client_credentials(
    headers: &HeaderMap,
    id: Option<String>,
    secret: Option<String>,
) -> Result<(String, Option<String>), TenantAuthError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok((id.ok_or(TenantAuthError::InvalidClient)?, secret));
    };
    if values.next().is_some() || id.is_some() || secret.is_some() {
        return Err(TenantAuthError::InvalidClient);
    }
    let value = value.to_str().map_err(|_| TenantAuthError::InvalidClient)?;
    let (scheme, encoded) = value
        .split_once(' ')
        .ok_or(TenantAuthError::InvalidClient)?;
    if !scheme.eq_ignore_ascii_case("Basic") || encoded.len() > 8192 {
        return Err(TenantAuthError::InvalidClient);
    }
    let bytes = Base64::decode_vec(encoded).map_err(|_| TenantAuthError::InvalidClient)?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| TenantAuthError::InvalidClient)?;
    let (id, secret) = raw.split_once(':').ok_or(TenantAuthError::InvalidClient)?;
    Ok((basic_component(id)?, Some(basic_component(secret)?)))
}
fn basic_component(encoded: &str) -> Result<String, TenantAuthError> {
    // OAuth Basic uses form-encoded components before Base64. Reuse the same
    // parser as Axum's forms; '&' cannot inject another credential field.
    if encoded.contains('&') {
        return Err(TenantAuthError::InvalidClient);
    }
    let text = format!("value={encoded}");
    let mut pairs = form_urlencoded::parse(text.as_bytes());
    let (_, value) = pairs.next().ok_or(TenantAuthError::InvalidClient)?;
    if pairs.next().is_some() {
        return Err(TenantAuthError::InvalidClient);
    }
    Ok(value.into_owned())
}
async fn user_info(
    State(service): State<Arc<dyn TenantOidcResourceService>>,
    headers: HeaderMap,
) -> Response {
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return resource_error(TenantAuthError::InvalidSession);
    }
    let Some(raw) = bearer_token(&headers)
        .filter(|s| s.len() <= 16_384)
        .map(SecretString::new)
    else {
        return resource_error(TenantAuthError::InvalidSession);
    };
    match call(move || service.user_info(raw)).await {
        Ok(info) if tenant_header_matches(&headers, &info.tenant_id) => {
            let mut body = json!({"sub":info.subject_account_id,"tenant_id":info.tenant_id,"client_id":info.client_id});
            if let Some(email) = info.email {
                body["email"] = json!(email)
            }
            if let Some(name) = info.display_name {
                body["name"] = json!(name)
            }
            Json(body).into_response()
        }
        Ok(_) => resource_error(TenantAuthError::InvalidSession),
        Err(e) => resource_error(e),
    }
}
async fn introspect(
    State(service): State<Arc<dyn TenantOidcResourceService>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let request = match command(&headers, form) {
        Ok(c) => c,
        Err(e) => return resource_error(e),
    };
    match call(move || service.introspect_token(request)).await {
        Ok(None) => Json(json!({"active":false})).into_response(),
        Ok(Some(info)) => {
            let mut body = json!({"active":true,"tenant_id":info.tenant_id,"sub":info.subject_account_id,"client_id":info.client_id,"session_id":info.session_id,"token_type":match info.token_type{TenantTokenType::Access=>"access_token",TenantTokenType::Refresh=>"refresh_token"},"iat":unix_time_secs(info.issued_at),"exp":unix_time_secs(info.expires_at)});
            if let Some(scope) = info.scope {
                body["scope"] = json!(scope)
            }
            Json(body).into_response()
        }
        Err(e) => resource_error(e),
    }
}
async fn revoke(
    State(service): State<Arc<dyn TenantOidcResourceService>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let request = match command(&headers, form) {
        Ok(c) => c,
        Err(e) => return resource_error(e),
    };
    match call(move || service.revoke_token(request)).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => resource_error(e),
    }
}
async fn logout(
    State(service): State<Arc<dyn TenantOidcResourceService>>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let request = match command(
        &headers,
        TokenForm {
            token: form.refresh_token,
            token_type_hint: Some("refresh_token".into()),
            client_id: form.client_id,
            client_secret: form.client_secret,
        },
    ) {
        Ok(c) => c,
        Err(e) => return resource_error(e),
    };
    match call(move || service.logout(request)).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => resource_error(e),
    }
}
fn resource_error(error: TenantAuthError) -> Response {
    let (status, code) = match &error {
        TenantAuthError::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client"),
        TenantAuthError::InvalidSession | TenantAuthError::DeviceProofRequired => {
            (StatusCode::UNAUTHORIZED, "invalid_token")
        }
        TenantAuthError::Access(AccessError::Forbidden) => {
            (StatusCode::FORBIDDEN, "insufficient_scope")
        }
        TenantAuthError::Access(AccessError::InvalidInput(_)) => {
            (StatusCode::BAD_REQUEST, "invalid_request")
        }
        _ => return map_tenant_auth_error(error),
    };
    let mut response = (status, Json(json!({"error":code}))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            if code == "invalid_client" {
                "Basic realm=\"idp\""
            } else {
                "Bearer error=\"invalid_token\""
            }
            .parse()
            .unwrap(),
        );
    }
    response
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_credentials_decode_oauth_components_and_reject_ambiguous_sources() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {}", Base64::encode_string(b"client%3Aid:s%2Bec+ret"))
                .parse()
                .unwrap(),
        );
        assert_eq!(
            client_credentials(&headers, None, None).unwrap(),
            ("client:id".into(), Some("s+ec ret".into()))
        );
        assert!(client_credentials(&headers, Some("client".into()), None).is_err());
        headers.append(header::AUTHORIZATION, "Basic YTpi".parse().unwrap());
        assert!(client_credentials(&headers, None, None).is_err());
        assert!(basic_component("a&secret=evil").is_err());
        assert!(basic_component("secret&").is_err());
        assert_eq!(basic_component("secret%26").unwrap(), "secret&");
        headers.clear();
        headers.insert(header::AUTHORIZATION, "Bearer token".parse().unwrap());
        assert!(client_credentials(&headers, None, None).is_err());
    }
}

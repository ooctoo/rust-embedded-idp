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
        .route("/auth/logout", post(logout))
        .with_state(service.clone())
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
        .merge(tenant_oidc_protocol_resource_router(service))
}
/// Shared issuer resource endpoints, without an entry-local logout route.
pub fn tenant_oidc_protocol_resource_router(service: Arc<dyn TenantOidcResourceService>) -> Router {
    Router::new()
        .route("/oidc/userinfo", get(user_info))
        .route("/oidc/introspect", post(introspect))
        .route("/oidc/revoke", post(revoke))
        .with_state(service)
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}
/// Ordinary logout only, retaining the existing form/Basic client contract.
pub fn tenant_logout_router(service: Arc<dyn TenantLogoutService>) -> Router {
    Router::new()
        .route("/auth/logout", post(ordinary_logout))
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
    logout_response(headers, form, move |request| service.logout(request)).await
}
async fn ordinary_logout(
    State(service): State<Arc<dyn TenantLogoutService>>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    logout_response(headers, form, move |request| {
        service.logout_session(request)
    })
    .await
}
async fn logout_response(
    headers: HeaderMap,
    form: LogoutForm,
    operation: impl FnOnce(TenantTokenRequest) -> Result<(), TenantAuthError> + Send + 'static,
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
    match call(move || operation(request)).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => resource_error(e),
    }
}

fn resource_error(error: TenantAuthError) -> Response {
    if password_work_unavailable(&error) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"server_error"})),
        )
            .into_response();
    }
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
fn password_work_unavailable(error: &TenantAuthError) -> bool {
    let is_marker = |error: &embedded_idp_core::StoreError| matches!(error, embedded_idp_core::StoreError::Backend(code) if code == "password.work_unavailable");
    match error {
        TenantAuthError::Store(error) => is_marker(error),
        TenantAuthError::Access(AccessError::Store(error)) => is_marker(error),
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[tokio::test]
    async fn resource_budget_failure_uses_oauth_server_error_without_challenge() {
        let response = resource_error(TenantAuthError::Store(
            embedded_idp_core::StoreError::Backend("password.work_unavailable".into()),
        ));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(header::WWW_AUTHENTICATE), None);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"], "server_error");

        assert_eq!(
            resource_error(TenantAuthError::Store(
                embedded_idp_core::StoreError::Backend("ordinary failure".into()),
            ))
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let invalid = resource_error(TenantAuthError::InvalidClient);
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            invalid.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"idp\""
        );
    }

    #[derive(Default)]
    struct Logout(Mutex<Vec<TenantTokenRequest>>);
    impl TenantLogoutService for Logout {
        fn logout_session(&self, command: TenantTokenRequest) -> Result<(), TenantAuthError> {
            self.0.lock().unwrap().push(command);
            Ok(())
        }
    }
    #[tokio::test]
    async fn ordinary_logout_retains_form_basic_limits_and_does_not_expose_oidc() {
        let service = Arc::new(Logout::default());
        let router = tenant_logout_router(service.clone());
        for basic in [false, true] {
            let mut request = axum::http::Request::post("/auth/logout")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            let body = if basic {
                request = request.header(
                    header::AUTHORIZATION,
                    format!("Basic {}", Base64::encode_string(b"web:synthetic")),
                );
                "refresh_token=fixture"
            } else {
                "refresh_token=fixture&client_id=desktop"
            };
            let response = router
                .clone()
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        {
            let calls = service.0.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].client_id, "desktop");
            assert!(calls[0].client_secret.is_none());
            assert_eq!(calls[1].client_id, "web");
            assert_eq!(
                calls[1].client_secret.as_ref().unwrap().expose_secret(),
                "synthetic"
            );
            assert_eq!(calls[1].token.expose_secret(), "fixture");
            assert_eq!(calls[1].token_type_hint, Some(TenantTokenType::Refresh));
        }
        for (uri, content_type, body, tenant, basic, status) in [
            (
                "/auth/logout?client_id=desktop",
                "application/x-www-form-urlencoded",
                "refresh_token=fixture".into(),
                false,
                false,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "/auth/logout",
                "application/x-www-form-urlencoded",
                "refresh_token=fixture&client_id=desktop".into(),
                true,
                false,
                StatusCode::BAD_REQUEST,
            ),
            (
                "/auth/logout",
                "application/x-www-form-urlencoded",
                "refresh_token=fixture&client_id=desktop".into(),
                false,
                true,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "/auth/logout",
                "application/json",
                "{}".into(),
                false,
                false,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "/auth/logout",
                "application/x-www-form-urlencoded",
                "x".repeat(AUTH_DEVICE_BODY_LIMIT_BYTES + 1),
                false,
                false,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let mut request =
                axum::http::Request::post(uri).header(header::CONTENT_TYPE, content_type);
            if tenant {
                request = request.header("x-embedded-idp-tenant-id", "t1");
            }
            if basic {
                request = request.header(header::AUTHORIZATION, "Basic d2ViOnNlY3JldA==");
            }
            let response = router
                .clone()
                .oneshot(request.body(Body::from(body)).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            if status == StatusCode::UNAUTHORIZED {
                assert_eq!(
                    response.headers()[header::WWW_AUTHENTICATE],
                    "Basic realm=\"idp\""
                );
            }
        }
        assert_eq!(service.0.lock().unwrap().len(), 2);
        for path in ["/oidc/userinfo", "/oidc/introspect", "/oidc/revoke"] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(axum::http::Request::post(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
    }
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

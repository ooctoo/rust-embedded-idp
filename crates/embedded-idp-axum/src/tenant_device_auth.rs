use crate::{http_support::unix_time_secs, proof_http::*, tenant_auth::*};
use axum::{
    body::to_bytes,
    extract::{OriginalUri, Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use embedded_idp_core::{
    access::*, CanonicalHttpMethod, DeviceProofProfile, DeviceProofPurpose, IssuedTokenBundle,
    SecretString,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub struct TenantDeviceAuthHttpConfig {
    login: ProtectedRouteConfig,
    selection: ProtectedRouteConfig,
    refresh: ProtectedRouteConfig,
}
impl TenantDeviceAuthHttpConfig {
    /// Literal externally visible paths, including the embedding host's prefix.
    pub fn new(
        audience: &str,
        login_path: &str,
        selection_path: &str,
        refresh_path: &str,
    ) -> Result<Self, ProofHttpError> {
        let route = |path: &str| {
            ProtectedRouteConfig::new(
                DeviceProofProfile::new(TENANT_DEVICE_AUTH_PROFILE)
                    .map_err(|_| ProofHttpError::ProofInvalid)?,
                audience,
                CanonicalHttpMethod::Post,
                path,
            )
        };
        Ok(Self {
            login: route(login_path)?,
            selection: route(selection_path)?,
            refresh: route(refresh_path)?,
        })
    }
}
#[derive(Clone)]
struct DeviceAuthState {
    service: Arc<dyn TenantDeviceAuthenticationService>,
    config: TenantDeviceAuthHttpConfig,
}
/// Replaces tenant_auth_router, retaining its read/switch routes. Merge the OIDC
/// resource router separately. Neither router changes the reference host startup.
pub fn tenant_device_auth_router(
    service: Arc<dyn TenantDeviceAuthenticationService>,
    config: TenantDeviceAuthHttpConfig,
) -> Router {
    let capabilities = service.login_capabilities();
    let base = TenantAuthState {
        service: service.clone(),
    };
    let mut routes = Router::new()
        .route("/auth/login", post(login_proven))
        .route("/auth/refresh", post(refresh))
        .route("/devices/proof/challenges", post(challenge));
    if capabilities.mode == TenancyMode::Enabled
        && capabilities.policy == LoginTenantPolicy::ChooseAfterAuthentication
    {
        routes = routes.route("/auth/tenant-selection/complete", post(select_proven));
    }
    routes
        .with_state(DeviceAuthState { service, config })
        .merge(base_routes(&base, false).with_state(base))
        .layer(axum::extract::DefaultBodyLimit::max(
            AUTH_DEVICE_BODY_LIMIT_BYTES,
        ))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshRequest {
    refresh_token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    tenant_id: String,
    device_id: String,
    purpose: String,
}
async fn challenge(
    State(state): State<DeviceAuthState>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Response {
    if !tenant_header_matches(&headers, &body.tenant_id) {
        return map_tenant_auth_error(TenantAuthError::InvalidSession);
    }
    let Ok(purpose) = DeviceProofPurpose::new(body.purpose) else {
        return bad_request();
    };
    match call(move || {
        state
            .service
            .authentication_challenge(body.tenant_id, body.device_id, purpose)
    })
    .await
    {
        Ok(result) => Json(serde_json::json!({
            "challenge": result.challenge.into_exposed(),
            "expires_at_unix_secs": unix_time_secs(result.expires_at),
        }))
        .into_response(),
        Err(e) => map_tenant_auth_error(e),
    }
}
pub(super) async fn raw_json<T: serde::de::DeserializeOwned>(
    request: Request,
) -> Result<(T, HeaderMap, Method, [u8; 32]), Response> {
    let (parts, body) = request.into_parts();
    let content_type = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or("")
        .trim();
    if content_type != "application/json"
        && !(content_type.starts_with("application/") && content_type.ends_with("+json"))
    {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
    }
    let bytes = to_bytes(body, AUTH_DEVICE_BODY_LIMIT_BYTES)
        .await
        .map_err(|_| {
            tenant_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                "request body exceeds the configured limit",
            )
        })?;
    let Json(parsed) = Json::<T>::from_bytes(&bytes).map_err(IntoResponse::into_response)?;
    Ok((
        parsed,
        parts.headers,
        parts.method,
        Sha256::digest(&bytes).into(),
    ))
}
fn has_proof(headers: &HeaderMap) -> bool {
    [
        DEVICE_ID_HEADER,
        DEVICE_KEY_ID_HEADER,
        DEVICE_CHALLENGE_HEADER,
        DEVICE_SIGNATURE_HEADER,
        DEVICE_SIGNED_AT_HEADER,
    ]
    .iter()
    .any(|h| headers.contains_key(*h))
}
fn proof(
    route: &ProtectedRouteConfig,
    tenant: &str,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    digest: [u8; 32],
) -> Result<Option<TenantAuthenticationProof>, Response> {
    let binding = route
        .binding_for_request(tenant, method, uri, digest)
        .map_err(|_| bad_request())?;
    if !has_proof(headers) {
        return Ok(None);
    }
    let presentation = parse_device_proof_headers(headers).map_err(|_| {
        tenant_error(
            StatusCode::UNAUTHORIZED,
            "device_proof_invalid",
            "device proof is invalid",
        )
    })?;
    Ok(Some(TenantAuthenticationProof {
        proof: presentation,
        binding,
    }))
}
fn bad_request() -> Response {
    tenant_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "request is invalid",
    )
}
fn authenticated(result: TenantLoginSession) -> Response {
    let (session, tokens) = session_parts(result);
    Json(LoginResponse {
        status: "authenticated",
        session: Some(session),
        tokens: Some(tokens),
        selection_ticket: None,
        expires_in: None,
    })
    .into_response()
}
async fn login_proven(
    State(state): State<DeviceAuthState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (body, headers, method, digest) = match raw_json::<LoginRequest>(request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let proof = match state.service.login_capabilities().policy {
        LoginTenantPolicy::Fixed { tenant_id } => {
            if !tenant_header_matches(&headers, &tenant_id) {
                return bad_request();
            }
            match proof(
                &state.config.login,
                &tenant_id,
                &headers,
                &method,
                &uri,
                digest,
            ) {
                Ok(p) => p,
                Err(r) => return r,
            }
        }
        LoginTenantPolicy::ChooseAfterAuthentication => {
            if headers.contains_key("x-embedded-idp-tenant-id") || has_proof(&headers) {
                return bad_request();
            }
            if state
                .config
                .login
                .binding_for_request("0", &method, &uri, digest)
                .is_err()
            {
                return bad_request();
            }
            None
        }
    };
    let command = TenantPasswordLogin {
        email: body.email,
        password: SecretString::new(body.password),
    };
    match call(move || match proof {
        Some(p) => state.service.login_proven(command, p),
        None => state.service.login(command),
    })
    .await
    {
        Ok(TenantLoginOutcome::Authenticated(session)) => authenticated(session),
        Ok(TenantLoginOutcome::SelectionRequired(ticket)) => {
            Json(ticket_response(ticket)).into_response()
        }
        Err(e) => map_tenant_auth_error(e),
    }
}
async fn select_proven(
    State(state): State<DeviceAuthState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (body, headers, method, digest) = match raw_json::<SelectTenantRequest>(request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(ticket) = selection_ticket(&headers).map(SecretString::new) else {
        return map_tenant_auth_error(TenantAuthError::InvalidSelection);
    };
    if !tenant_header_matches(&headers, &body.tenant_id) {
        return bad_request();
    }
    let proof = match proof(
        &state.config.selection,
        &body.tenant_id,
        &headers,
        &method,
        &uri,
        digest,
    ) {
        Ok(p) => p,
        Err(r) => return r,
    };
    match call(move || match proof {
        Some(p) => state.service.select_proven(ticket, body.tenant_id, p),
        None => state.service.select_tenant(ticket, body.tenant_id),
    })
    .await
    {
        Ok(result) => authenticated(result),
        Err(e) => map_tenant_auth_error(e),
    }
}
/// Tenant is an assertion only; the Core transaction resolves the credential's
/// actual tenant and checks equality before consuming its proof.
pub(super) fn credential_proof(
    route: &ProtectedRouteConfig,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    digest: [u8; 32],
) -> Result<Option<TenantAuthenticationProof>, Response> {
    if has_proof(headers) {
        let mut values = headers.get_all("x-embedded-idp-tenant-id").iter();
        let Some(tenant) = values.next().and_then(|v| v.to_str().ok()) else {
            return Err(bad_request());
        };
        if values.next().is_some() {
            return Err(bad_request());
        }
        proof(route, tenant, headers, method, uri, digest)
    } else {
        if headers.contains_key("x-embedded-idp-tenant-id") {
            return Err(bad_request());
        }
        if route.binding_for_request("0", method, uri, digest).is_err() {
            return Err(bad_request());
        }
        Ok(None)
    }
}
async fn refresh(
    State(state): State<DeviceAuthState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let (body, headers, method, digest) = match raw_json::<RefreshRequest>(request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let proof = match credential_proof(&state.config.refresh, &headers, &method, &uri, digest) {
        Ok(p) => p,
        Err(r) => return r,
    };
    match call(move || {
        state
            .service
            .refresh(SecretString::new(body.refresh_token), proof)
    })
    .await
    {
        Ok(TenantRefreshOutcome::Rotated { session, tokens }) => {
            authenticated(TenantLoginSession {
                session,
                tokens: IssuedTokenBundle {
                    access_token: tokens.access_token.token,
                    access_expires_at: tokens.access_token.expires_at,
                    refresh_token: tokens.refresh_token,
                    refresh_expires_at: tokens.refresh_expires_at,
                    refresh_token_version: tokens.refresh_token_version,
                },
            })
        }
        // The Core transaction has COMMITTED the revocation before this response.
        Ok(TenantRefreshOutcome::ReuseDetected { .. }) => tenant_error(
            StatusCode::UNAUTHORIZED,
            "refresh_token_reuse_detected",
            "refresh token reuse detected",
        ),
        Err(e) => map_tenant_auth_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    #[tokio::test]
    async fn raw_json_hashes_original_bytes_and_rejects_ambiguous_or_large_bodies() {
        let body = "{ \"refresh_token\" : \"synthetic\" }\n";
        let request = |body: String| {
            Request::builder()
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        let (value, _, _, hash) = raw_json::<RefreshRequest>(request(body.into()))
            .await
            .unwrap();
        assert_eq!(value.refresh_token, "synthetic");
        assert_eq!(hash, <[u8; 32]>::from(Sha256::digest(body.as_bytes())));
        for body in [
            r#"{"refresh_token":"a","refresh_token":"b"}"#,
            r#"{"refresh_token":"a","tenant_id":"t2"}"#,
        ] {
            assert_eq!(
                raw_json::<RefreshRequest>(request(body.into()))
                    .await
                    .err()
                    .unwrap()
                    .status(),
                StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        assert_eq!(
            raw_json::<RefreshRequest>(request("x".repeat(AUTH_DEVICE_BODY_LIMIT_BYTES + 1)))
                .await
                .err()
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
    #[test]
    fn configured_auth_routes_reject_query_and_wrong_external_prefix_even_without_proof() {
        let config = TenantDeviceAuthHttpConfig::new(
            "api",
            "/api/auth/login",
            "/api/auth/tenant-selection/complete",
            "/api/auth/refresh",
        )
        .unwrap();
        for path in ["/auth/login", "/api/auth/login?tenant=t2"] {
            assert!(proof(
                &config.login,
                "t1",
                &HeaderMap::new(),
                &Method::POST,
                &path.parse().unwrap(),
                [0; 32]
            )
            .is_err());
        }
        assert!(proof(
            &config.login,
            "t1",
            &HeaderMap::new(),
            &Method::POST,
            &"/api/auth/login".parse().unwrap(),
            [0; 32]
        )
        .unwrap()
        .is_none());
        let mut headers = HeaderMap::new();
        headers.insert(DEVICE_ID_HEADER, "device".parse().unwrap());
        assert!(proof(
            &config.login,
            "t1",
            &headers,
            &Method::POST,
            &"/api/auth/login".parse().unwrap(),
            [0; 32]
        )
        .is_err());
    }
}

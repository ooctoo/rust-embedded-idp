use crate::{
    http_support::{authorization_redirect_location, bearer_token},
    proof_http::{ProofHttpError, ProtectedRouteConfig, AUTH_DEVICE_BODY_LIMIT_BYTES},
    tenant_auth::{call, no_store, tenant_header_matches},
    tenant_device_auth::credential_proof,
    tenant_oidc_resource::client_credentials,
};
use axum::{
    body::{to_bytes, Body},
    extract::{FromRequest, OriginalUri, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use embedded_idp_core::{
    access::*, CanonicalHttpMethod, DeviceProofProfile, PkceChallengeMethod, SecretString,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub struct TenantOidcHttpConfig {
    token: ProtectedRouteConfig,
}
impl TenantOidcHttpConfig {
    /// The literal external token path, including any host mount prefix.
    pub fn new(audience: &str, token_path: &str) -> Result<Self, ProofHttpError> {
        Ok(Self {
            token: ProtectedRouteConfig::new(
                DeviceProofProfile::new(TENANT_DEVICE_AUTH_PROFILE)
                    .map_err(|_| ProofHttpError::ProofInvalid)?,
                audience,
                CanonicalHttpMethod::Post,
                token_path,
            )?,
        })
    }
}
#[derive(Clone)]
struct OidcState {
    service: Arc<dyn TenantOidcAuthorizationService>,
    config: TenantOidcHttpConfig,
}
/// Merge with tenant authentication/resource routers; replaces the old OIDC
/// authorize/token routes. No caller-supplied subject or tenant selects identity.
pub fn tenant_oidc_authorization_router(
    service: Arc<dyn TenantOidcAuthorizationService>,
    config: TenantOidcHttpConfig,
) -> Router {
    Router::new()
        .route("/oidc/authorize", get(authorize))
        .route("/oidc/token", post(token))
        .with_state(OidcState { service, config })
        .layer(axum::extract::DefaultBodyLimit::max(
            AUTH_DEVICE_BODY_LIMIT_BYTES,
        ))
        .layer(middleware::from_fn(no_store))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
}
async fn authorize(
    State(state): State<OidcState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if uri
        .query()
        .is_some_and(|q| q.len() > AUTH_DEVICE_BODY_LIMIT_BYTES)
    {
        return oauth_error(StatusCode::URI_TOO_LONG, "invalid_request");
    }
    let query = match Query::<AuthorizationQuery>::try_from_uri(&uri) {
        Ok(Query(query)) => query,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return authorization_error(TenantAuthError::InvalidSession);
    }
    let Some(access) = bearer_token(&headers)
        .filter(|s| s.len() <= 16_384)
        .map(SecretString::new)
    else {
        return authorization_error(TenantAuthError::InvalidSession);
    };
    if query.response_type != "code" {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_response_type");
    }
    let method = match query.code_challenge_method.as_deref() {
        None => None,
        Some("plain") => Some(PkceChallengeMethod::Plain),
        Some("S256") => Some(PkceChallengeMethod::S256),
        _ => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let command = TenantAuthorizationRequest {
        response_type: query.response_type,
        client_id: query.client_id,
        redirect_uri: query.redirect_uri,
        scope: query.scope.unwrap_or_default(),
        state: query.state,
        nonce: query.nonce,
        code_challenge: query.code_challenge,
        code_challenge_method: method,
    };
    match call(move || {
        let actor = state.service.authenticate(access)?;
        if !tenant_header_matches(&headers, &actor.tenant_id) {
            return Err(TenantAuthError::InvalidSession);
        }
        state.service.authorize(actor, command)
    })
    .await
    {
        Ok(result) => Redirect::temporary(&authorization_redirect_location(
            &result.redirect_uri,
            result.code.expose_secret(),
            result.state.as_deref(),
        ))
        .into_response(),
        Err(error) => authorization_error(error),
    }
}
async fn token(
    State(state): State<OidcState>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    // Retain original encoded bytes; decoding and re-encoding a form changes the
    // signed request, even when the parsed fields have the same values.
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, AUTH_DEVICE_BODY_LIMIT_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return oauth_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request"),
    };
    let digest = Sha256::digest(&bytes).into();
    let proof = match credential_proof(
        &state.config.token,
        &parts.headers,
        &parts.method,
        &uri,
        digest,
    ) {
        Ok(proof) => proof,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let headers = parts.headers.clone();
    let form =
        match Form::<CodeForm>::from_request(Request::from_parts(parts, Body::from(bytes)), &())
            .await
        {
            Ok(Form(form)) => form,
            Err(error) => {
                let status = if error.status() == StatusCode::UNPROCESSABLE_ENTITY {
                    StatusCode::BAD_REQUEST
                } else {
                    error.status()
                };
                return oauth_error(status, "invalid_request");
            }
        };
    if form.grant_type != "authorization_code" {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let (client_id, client_secret) =
        match client_credentials(&headers, form.client_id, form.client_secret) {
            Ok(credentials) => credentials,
            Err(error) => return exchange_error(error),
        };
    let command = TenantCodeExchange {
        grant_type: form.grant_type,
        client_id,
        code: SecretString::new(form.code),
        redirect_uri: form.redirect_uri,
        client_secret: client_secret.map(SecretString::new),
        code_verifier: form.code_verifier.map(SecretString::new),
    };
    match call(move || state.service.exchange(command, proof)).await {
        Ok(result) => {
            let tokens = result.login.tokens;
            let session = result.login.session;
            let mut response = json!({
                "access_token": tokens.access_token.into_exposed(),
                "refresh_token": tokens.refresh_token.into_exposed(),
                "refresh_token_version": tokens.refresh_token_version,
                "token_type": "Bearer",
                "expires_in": tokens.access_expires_at.duration_since(session.created_at).unwrap_or_default().as_secs(),
                "scope": result.scope,
                "tenant_id": session.tenant_id,
                "subject_account_id": session.account_id,
                "session_id": session.id,
            });
            if let Some(token) = result.id_token {
                response["id_token"] = json!(token.into_exposed());
            }
            Json(response).into_response()
        }
        Err(error) => exchange_error(error),
    }
}
fn authorization_error(error: TenantAuthError) -> Response {
    match error {
        TenantAuthError::Access(AccessError::Store(_) | AccessError::InvalidStoreResponse) => {
            exchange_error(error)
        }
        TenantAuthError::InvalidSession | TenantAuthError::Access(_) => {
            oauth_error(StatusCode::UNAUTHORIZED, "invalid_token")
        }
        TenantAuthError::InvalidAuthorization | TenantAuthError::InvalidClient => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request")
        }
        _ => exchange_error(error),
    }
}
fn exchange_error(error: TenantAuthError) -> Response {
    match error {
        TenantAuthError::InvalidClient => oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"),
        TenantAuthError::Configuration(_)
        | TenantAuthError::Store(_)
        | TenantAuthError::Token(_)
        | TenantAuthError::Security(_)
        | TenantAuthError::Access(AccessError::Store(_) | AccessError::InvalidStoreResponse) => {
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
        _ => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}
fn oauth_error(status: StatusCode, error: &'static str) -> Response {
    let mut response = (status, Json(json!({"error":error}))).into_response();
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            if error == "invalid_client" {
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
    use tower::ServiceExt;
    struct Unreachable;
    impl TenantOidcAuthorizationService for Unreachable {
        fn authenticate(&self, _: SecretString) -> Result<AccessActor, TenantAuthError> {
            panic!("invalid request reached service")
        }
        fn authorize(
            &self,
            _: AccessActor,
            _: TenantAuthorizationRequest,
        ) -> Result<TenantAuthorizationResult, TenantAuthError> {
            panic!("invalid request reached service")
        }
        fn exchange(
            &self,
            _: TenantCodeExchange,
            _: Option<TenantAuthenticationProof>,
        ) -> Result<TenantCodeExchangeResult, TenantAuthError> {
            panic!("invalid request reached service")
        }
    }
    #[tokio::test]
    async fn oidc_http_rejects_ambiguous_input_before_service_calls() {
        let app = Router::new().nest(
            "/api",
            tenant_oidc_authorization_router(
                Arc::new(Unreachable),
                TenantOidcHttpConfig::new("test-api", "/api/oidc/token").unwrap(),
            ),
        );
        for (method, path, content_type, body, expected) in [
            ("GET", "/api/oidc/authorize?response_type=code&response_type=code", "", "", StatusCode::BAD_REQUEST),
            ("GET", "/api/oidc/authorize?response_type=code&client_id=web&redirect_uri=testapp%3A%2F%2Fcallback", "", "", StatusCode::UNAUTHORIZED),
            ("POST", "/api/oidc/token?extra=1", "application/x-www-form-urlencoded", "", StatusCode::BAD_REQUEST),
            ("POST", "/api/oidc/token", "application/json", "{}", StatusCode::UNSUPPORTED_MEDIA_TYPE),
            ("POST", "/api/oidc/token", "application/x-www-form-urlencoded", "grant_type=authorization_code&code=a&code=b&redirect_uri=x&client_id=web", StatusCode::BAD_REQUEST),
            ("POST", "/api/oidc/token", "application/x-www-form-urlencoded", "grant_type=authorization_code&code=a&redirect_uri=x&client_id=web&tenant_id=t2", StatusCode::BAD_REQUEST),
            ("POST", "/api/oidc/token", "application/x-www-form-urlencoded", "grant_type=password&code=a&redirect_uri=x&client_id=web", StatusCode::BAD_REQUEST),
        ] {
            let response = app.clone().oneshot(Request::builder().method(method).uri(path).header(header::CONTENT_TYPE, content_type).body(Body::from(body)).unwrap()).await.unwrap();
            assert_eq!(response.status(), expected, "{path} {body}");
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body = to_bytes(response.into_body(), 65536).await.unwrap();
            assert!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"].is_string());
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/oidc/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("x".repeat(16_385)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[test]
    fn oidc_errors_preserve_infrastructure_failure_and_authentication_challenges() {
        assert_eq!(
            authorization_error(TenantAuthError::Access(AccessError::Store(
                embedded_idp_core::StoreError::Backend("synthetic".into())
            )))
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let invalid = exchange_error(TenantAuthError::InvalidClient);
        assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            invalid.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"idp\""
        );
        assert_eq!(
            exchange_error(TenantAuthError::InvalidGrant).status(),
            StatusCode::BAD_REQUEST
        );
    }
    #[test]
    fn authorization_redirect_encodes_code_and_state_as_distinct_query_values() {
        let code = "code+&=/#";
        let state = "状态 &code=evil+#";
        let result =
            authorization_redirect_location("testapp://callback?existing=1", code, Some(state));
        let pairs: Vec<_> =
            form_urlencoded::parse(result.split_once('?').unwrap().1.as_bytes()).collect();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[1], ("code".into(), code.into()));
        assert_eq!(pairs[2], ("state".into(), state.into()));
        assert!(!result.contains('#'));
    }
}

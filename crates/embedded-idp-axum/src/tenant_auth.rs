use std::sync::Arc;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Json, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use embedded_idp_core::{access::*, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    http_support::{bearer_token, unix_time_secs},
    proof_http::AUTH_DEVICE_BODY_LIMIT_BYTES,
};

#[derive(Clone)]
pub(super) struct TenantAuthState {
    pub(super) service: Arc<dyn TenantAuthenticationService>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginRequest {
    pub(super) email: String,
    pub(super) password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListTenantsRequest {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SelectTenantRequest {
    pub(super) tenant_id: String,
}

#[derive(Serialize)]
pub(super) struct LoginResponse {
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) session: Option<SessionResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) tokens: Option<TokensResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) selection_ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) expires_in: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct SessionResponse {
    tenant_id: String,
    account_id: String,
    session_id: String,
    client_id: String,
    expires_at_unix_secs: u64,
}

#[derive(Serialize)]
pub(super) struct TokensResponse {
    access_token: String,
    refresh_token: String,
    access_expires_at_unix_secs: u64,
    refresh_expires_at_unix_secs: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TenantCursor {
    version: u8,
    subject_id: String,
    after_tenant_id: String,
}

#[derive(Serialize)]
struct CapabilitiesResponse {
    tenancy_enabled: bool,
    login_tenant_policy: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_tenant_id: Option<String>,
    page_limit: u32,
    max_page_limit: u32,
}

#[derive(Serialize)]
struct TenantResponse {
    tenant_id: String,
    name: String,
    status: &'static str,
    membership_status: &'static str,
}

#[derive(Serialize)]
pub(super) struct TenantListResponse {
    tenants: Vec<TenantResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    has_more: bool,
}

#[derive(Serialize)]
struct SessionActorResponse {
    tenant_id: String,
    account_id: String,
    session_id: String,
}

pub fn tenant_auth_router(service: Arc<dyn TenantAuthenticationService>) -> Router {
    let state = TenantAuthState { service };
    base_routes(&state, true)
        .route("/auth/login", post(login))
        .with_state(state)
        .layer(DefaultBodyLimit::max(AUTH_DEVICE_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(no_store))
}

pub(super) fn base_routes(state: &TenantAuthState, selection: bool) -> Router<TenantAuthState> {
    let capabilities = state.service.login_capabilities();
    let mut router = Router::new()
        .route("/auth/access/capabilities", get(capabilities_handler))
        .route("/auth/session", get(session));
    if capabilities.mode == TenancyMode::Enabled
        && capabilities.policy == LoginTenantPolicy::ChooseAfterAuthentication
    {
        router = router
            .route("/auth/tenant-selection/tenants", get(list_tenants))
            .route("/auth/me/tenant-selection", post(switch_tenant));
        if selection {
            router = router.route("/auth/tenant-selection/complete", post(select_tenant));
        }
    }
    router
}

async fn capabilities_handler(State(state): State<TenantAuthState>) -> Response {
    capabilities_response(state.service.login_capabilities())
}

pub(super) fn capabilities_response(capabilities: TenantLoginCapabilities) -> Response {
    let (policy, fixed_tenant_id) = match capabilities.policy {
        LoginTenantPolicy::Fixed { tenant_id } => ("fixed", Some(tenant_id)),
        LoginTenantPolicy::ChooseAfterAuthentication => ("choose_after_authentication", None),
    };
    (
        StatusCode::OK,
        Json(CapabilitiesResponse {
            tenancy_enabled: capabilities.mode == TenancyMode::Enabled,
            login_tenant_policy: policy,
            fixed_tenant_id,
            page_limit: embedded_idp_core::DEFAULT_PAGE_LIMIT,
            max_page_limit: embedded_idp_core::MAX_PAGE_LIMIT,
        }),
    )
        .into_response()
}

pub(super) fn login_response(result: Result<TenantLoginOutcome, TenantAuthError>) -> Response {
    match result {
        Ok(TenantLoginOutcome::Authenticated(result)) => {
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
        Ok(TenantLoginOutcome::SelectionRequired(ticket)) => {
            Json(ticket_response(ticket)).into_response()
        }
        Err(error) => map_tenant_auth_error(error),
    }
}

async fn login(
    State(state): State<TenantAuthState>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Response {
    if headers.get("x-embedded-idp-tenant-id").is_some() {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        );
    }
    let service = state.service;
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

impl ListTenantsRequest {
    pub(super) fn into_page(self) -> Result<AccessPageRequest, Response> {
        let cursor = match self.cursor {
            None => None,
            Some(encoded) if encoded.len() <= 1024 => match decode_cursor(&encoded) {
                Ok(cursor) => Some(AccessCursor {
                    version: cursor.version,
                    scope: AccessListScope::SubjectTenants {
                        subject_id: cursor.subject_id,
                    },
                    after: vec![cursor.after_tenant_id],
                    sort_order: None,
                }),
                Err(response) => return Err(response),
            },
            Some(_) => {
                return Err(tenant_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_cursor",
                    "request is invalid",
                ))
            }
        };
        Ok(AccessPageRequest {
            limit: self.limit.unwrap_or(embedded_idp_core::DEFAULT_PAGE_LIMIT),
            cursor,
            sort_order: None,
        })
    }
}

async fn list_tenants(
    State(state): State<TenantAuthState>,
    headers: HeaderMap,
    Query(request): Query<ListTenantsRequest>,
) -> Response {
    let Some(ticket) = selection_ticket(&headers).map(str::to_owned) else {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        );
    };
    let page = match request.into_page() {
        Ok(page) => page,
        Err(response) => return response,
    };
    let service = state.service;
    match call(move || service.list_tenants(SecretString::new(ticket), page)).await {
        Ok(page) => match tenant_page_response(page) {
            Ok(body) => (StatusCode::OK, Json(body)).into_response(),
            Err(response) => response,
        },
        Err(error) => map_tenant_auth_error(error),
    }
}

async fn select_tenant(
    State(state): State<TenantAuthState>,
    headers: HeaderMap,
    Json(request): Json<SelectTenantRequest>,
) -> Response {
    let Some(ticket) = selection_ticket(&headers).map(str::to_owned) else {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        );
    };
    if !tenant_header_matches(&headers, &request.tenant_id) {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        );
    }
    let service = state.service;
    login_response(
        call(move || {
            service
                .select_tenant(SecretString::new(ticket), request.tenant_id)
                .map(TenantLoginOutcome::Authenticated)
        })
        .await,
    )
}

async fn switch_tenant(State(state): State<TenantAuthState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers).map(str::to_owned) else {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        );
    };
    let service = state.service;
    match call(move || {
        let actor = service.authenticate(SecretString::new(token.clone()))?;
        if !tenant_header_matches(&headers, &actor.tenant_id) {
            return Err(TenantAuthError::InvalidSession);
        }
        service.begin_switch(SecretString::new(token))
    })
    .await
    {
        Ok(ticket) => (StatusCode::OK, Json(ticket_response(ticket))).into_response(),
        Err(error) => map_tenant_auth_error(error),
    }
}

async fn session(State(state): State<TenantAuthState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers).map(str::to_owned) else {
        return tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        );
    };
    let service = state.service;
    match call(move || service.authenticate(SecretString::new(token))).await {
        Ok(actor) if tenant_header_matches(&headers, &actor.tenant_id) => (
            StatusCode::OK,
            Json(SessionActorResponse {
                tenant_id: actor.tenant_id,
                account_id: actor.subject_id,
                session_id: actor.session_id,
            }),
        )
            .into_response(),
        Ok(_) => tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        ),
        Err(error) => map_tenant_auth_error(error),
    }
}

pub(super) fn selection_ticket(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, ticket) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("TenantSelection")
        && !ticket.is_empty()
        && ticket
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)))
    .then_some(ticket)
}

pub(crate) fn tenant_header_matches(headers: &HeaderMap, tenant_id: &str) -> bool {
    headers
        .get_all("x-embedded-idp-tenant-id")
        .iter()
        .all(|value| value.to_str().is_ok_and(|value| value == tenant_id))
}

pub(crate) async fn call<T, E>(
    operation: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<T, E>
where
    T: Send + 'static,
    E: From<embedded_idp_core::StoreError> + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(result) => result,
        Err(error) => Err(embedded_idp_core::StoreError::Backend(error.to_string()).into()),
    }
}

pub(super) fn session_parts(result: TenantLoginSession) -> (SessionResponse, TokensResponse) {
    let session = SessionResponse {
        tenant_id: result.session.tenant_id,
        account_id: result.session.account_id,
        session_id: result.session.id,
        client_id: result.session.client_id,
        expires_at_unix_secs: unix_time_secs(result.session.expires_at),
    };
    let tokens = TokensResponse {
        access_token: result.tokens.access_token.into_exposed(),
        refresh_token: result.tokens.refresh_token.into_exposed(),
        access_expires_at_unix_secs: unix_time_secs(result.tokens.access_expires_at),
        refresh_expires_at_unix_secs: unix_time_secs(result.tokens.refresh_expires_at),
    };
    (session, tokens)
}

pub(super) fn ticket_response(ticket: TenantSelectionTicket) -> LoginResponse {
    LoginResponse {
        status: "tenant_selection_required",
        session: None,
        tokens: None,
        selection_ticket: Some(ticket.ticket.into_exposed()),
        expires_in: Some(
            ticket
                .expires_at
                .duration_since(ticket.issued_at)
                .unwrap_or_default()
                .as_secs(),
        ),
    }
}

pub(super) fn tenant_page_response(
    page: AccessPage<SubjectTenant>,
) -> Result<TenantListResponse, Response> {
    let next_cursor = match page.next_cursor {
        None => None,
        Some(cursor) => match (cursor.scope, cursor.after.as_slice()) {
            (AccessListScope::SubjectTenants { subject_id }, [after_tenant_id]) => {
                Some(encode_cursor(TenantCursor {
                    version: cursor.version,
                    subject_id,
                    after_tenant_id: after_tenant_id.clone(),
                })?)
            }
            _ => {
                return Err(tenant_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "the request could not be completed",
                ))
            }
        },
    };
    Ok(TenantListResponse {
        tenants: page
            .items
            .into_iter()
            .map(|item| TenantResponse {
                tenant_id: item.tenant.id,
                name: item.tenant.name,
                status: tenant_status(item.tenant.status),
                membership_status: membership_status(item.membership.status),
            })
            .collect(),
        next_cursor,
        has_more: page.has_more,
    })
}

fn decode_cursor(value: &str) -> Result<TenantCursor, Response> {
    let bytes = Base64UrlUnpadded::decode_vec(value).map_err(|_| {
        tenant_error(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "request is invalid",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        tenant_error(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "request is invalid",
        )
    })
}

fn encode_cursor(cursor: TenantCursor) -> Result<String, Response> {
    let bytes = serde_json::to_vec(&cursor).map_err(|_| {
        tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        )
    })?;
    let encoded = Base64UrlUnpadded::encode_string(&bytes);
    if encoded.len() > 1024 {
        return Err(tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ));
    }
    Ok(encoded)
}

fn tenant_status(status: TenantStatus) -> &'static str {
    match status {
        TenantStatus::Active => "active",
        TenantStatus::Suspended => "suspended",
        TenantStatus::Archived => "archived",
    }
}
fn membership_status(status: MembershipStatus) -> &'static str {
    match status {
        MembershipStatus::Active => "active",
        MembershipStatus::Suspended => "suspended",
        MembershipStatus::Removed => "removed",
    }
}
pub(crate) async fn no_store(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

pub(crate) fn map_tenant_auth_error(error: TenantAuthError) -> Response {
    match error {
        TenantAuthError::InvalidCredentials
        | TenantAuthError::InvalidAuthorization
        | TenantAuthError::InvalidGrant
        | TenantAuthError::InvalidClient
        | TenantAuthError::InvalidRefresh
        | TenantAuthError::InvalidSelection
        | TenantAuthError::InvalidSession => tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        ),
        TenantAuthError::DeviceProof(_) => tenant_error(
            StatusCode::UNAUTHORIZED,
            "device_proof_invalid",
            "device proof is invalid",
        ),
        TenantAuthError::DeviceProofRequired => tenant_error(
            StatusCode::FORBIDDEN,
            "device_proof_required",
            "device proof is required",
        ),
        TenantAuthError::Access(AccessError::InvalidInput(_) | AccessError::InvalidCursor) => {
            tenant_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request is invalid",
            )
        }
        TenantAuthError::Access(AccessError::InvalidStoreResponse | AccessError::Store(_)) => {
            tenant_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the request could not be completed",
            )
        }
        TenantAuthError::Access(_) => tenant_error(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "credentials are invalid",
        ),
        TenantAuthError::Configuration(_)
        | TenantAuthError::Store(_)
        | TenantAuthError::Token(_)
        | TenantAuthError::Security(_) => tenant_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the request could not be completed",
        ),
    }
}
pub(super) fn tenant_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response {
    (
        status,
        Json(crate::dto::ErrorHttpResponse {
            code,
            message: message.into(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Request};
    use embedded_idp_core::access::{
        AccessActor, AccessPage, LoginTenantPolicy, MembershipStatus, TenancyMode, Tenant,
        TenantLoginCapabilities, TenantMembership, TenantStatus,
    };
    use std::{sync::Mutex, time::UNIX_EPOCH};
    use tower::ServiceExt;

    #[derive(Clone)]
    struct Fake {
        pages: Arc<Mutex<Vec<AccessPageRequest>>>,
        malformed_cursor: bool,
    }
    impl TenantAuthenticationService for Fake {
        fn login_capabilities(&self) -> TenantLoginCapabilities {
            TenantLoginCapabilities {
                mode: TenancyMode::Enabled,
                policy: LoginTenantPolicy::ChooseAfterAuthentication,
            }
        }
        fn login(
            &self,
            command: TenantPasswordLogin,
        ) -> Result<TenantLoginOutcome, TenantAuthError> {
            assert_eq!(command.email, "user@example.com");
            assert_eq!(command.password.expose_secret(), "password1");
            Ok(TenantLoginOutcome::SelectionRequired(
                TenantSelectionTicket {
                    ticket: SecretString::new("ticket-secret"),
                    issued_at: UNIX_EPOCH,
                    expires_at: UNIX_EPOCH + std::time::Duration::from_secs(100),
                },
            ))
        }
        fn list_tenants(
            &self,
            ticket: SecretString,
            page: AccessPageRequest,
        ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
            assert_eq!(ticket.expose_secret(), "ticket-secret");
            self.pages.lock().unwrap().push(page);
            let cursor = if self.malformed_cursor {
                Some(AccessCursor {
                    version: 1,
                    scope: AccessListScope::SubjectRoles {
                        tenant_id: "t1".into(),
                        subject_id: "a1".into(),
                    },
                    after: vec!["bad".into()],
                    sort_order: None,
                })
            } else {
                Some(AccessCursor {
                    version: 1,
                    scope: AccessListScope::SubjectTenants {
                        subject_id: "a1".into(),
                    },
                    after: vec!["t1".into()],
                    sort_order: None,
                })
            };
            Ok(AccessPage {
                items: vec![SubjectTenant {
                    tenant: Tenant {
                        id: "t1".into(),
                        name: "Tenant 1".into(),
                        status: TenantStatus::Active,
                        allow_registration: true,
                    },
                    membership: TenantMembership {
                        tenant_id: "t1".into(),
                        subject_id: "a1".into(),
                        status: MembershipStatus::Active,
                        joined_at: UNIX_EPOCH,
                        version: 1,
                    },
                }],
                next_cursor: cursor,
                has_more: true,
            })
        }
        fn select_tenant(
            &self,
            _: SecretString,
            _: String,
        ) -> Result<TenantLoginSession, TenantAuthError> {
            Err(TenantAuthError::InvalidSelection)
        }
        fn authenticate(&self, _: SecretString) -> Result<AccessActor, TenantAuthError> {
            Err(TenantAuthError::InvalidSession)
        }
        fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
            Err(TenantAuthError::InvalidSelection)
        }
    }
    fn app(fake: Fake) -> Router {
        tenant_auth_router(Arc::new(fake))
    }
    async fn json(response: Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    #[test]
    fn selection_scheme_rejects_bearer_and_ambiguous_credentials() {
        let mut headers = HeaderMap::new();
        assert!(selection_ticket(&headers).is_none());
        for value in [
            "Bearer ticket",
            "TenantSelection ",
            "TenantSelection a b",
            "TenantSelection a,b",
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
            assert!(selection_ticket(&headers).is_none());
        }
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("TenantSelection ticket"),
        );
        assert_eq!(selection_ticket(&headers), Some("ticket"));
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("TenantSelection other"),
        );
        assert!(selection_ticket(&headers).is_none());
    }

    #[test]
    fn optional_tenant_header_rejects_invalid_or_conflicting_values() {
        let mut headers = HeaderMap::new();
        assert!(tenant_header_matches(&headers, "t1"));
        headers.append("x-embedded-idp-tenant-id", HeaderValue::from_static("t1"));
        assert!(tenant_header_matches(&headers, "t1"));
        assert!(!tenant_header_matches(&headers, "t2"));
        headers.append("x-embedded-idp-tenant-id", HeaderValue::from_static("t2"));
        assert!(!tenant_header_matches(&headers, "t1"));
        headers.insert(
            "x-embedded-idp-tenant-id",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert!(!tenant_header_matches(&headers, "t1"));
    }

    #[tokio::test]
    async fn login_rejects_unknown_fields_and_never_caches_credentials() {
        let response = app(Fake {
            pages: Arc::new(Mutex::new(vec![])),
            malformed_cursor: false,
        })
        .oneshot(
            Request::post("/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"user@example.com","password":"password1","client_id":"attacker"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");

        let response = app(Fake {
            pages: Arc::new(Mutex::new(vec![])),
            malformed_cursor: false,
        })
        .oneshot(
            Request::post("/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"user@example.com","password":"password1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["status"], "tenant_selection_required");
        assert_eq!(body["selection_ticket"], "ticket-secret");
    }

    #[tokio::test]
    async fn list_cursor_is_converted_and_invalid_core_cursor_is_internal_error() {
        let pages = Arc::new(Mutex::new(vec![]));
        let cursor = encode_cursor(TenantCursor {
            version: 1,
            subject_id: "a1".into(),
            after_tenant_id: "t0".into(),
        })
        .unwrap();
        let response = app(Fake {
            pages: pages.clone(),
            malformed_cursor: false,
        })
        .oneshot(
            Request::get(format!(
                "/auth/tenant-selection/tenants?limit=10&cursor={cursor}"
            ))
            .header("authorization", "TenantSelection ticket-secret")
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let request = pages.lock().unwrap().pop().unwrap();
        assert_eq!(request.limit, 10);
        assert!(
            matches!(request.cursor.unwrap().scope, AccessListScope::SubjectTenants { subject_id } if subject_id == "a1")
        );
        assert!(json(response).await["next_cursor"].as_str().is_some());

        let response = app(Fake {
            pages: Arc::new(Mutex::new(vec![])),
            malformed_cursor: true,
        })
        .oneshot(
            Request::get("/auth/tenant-selection/tenants")
                .header("authorization", "TenantSelection ticket-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn bearer_routes_separate_access_tokens_and_enforce_body_limit() {
        let response = app(Fake {
            pages: Arc::new(Mutex::new(vec![])),
            malformed_cursor: false,
        })
        .oneshot(
            Request::post("/auth/me/tenant-selection")
                .body(Body::from("ticket-secret"))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json(response).await["code"], "invalid_credentials");

        let response = app(Fake {
            pages: Arc::new(Mutex::new(vec![])),
            malformed_cursor: false,
        })
        .oneshot(
            Request::post("/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"email":"{}","password":"password1"}}"#,
                    "x".repeat(20_000)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

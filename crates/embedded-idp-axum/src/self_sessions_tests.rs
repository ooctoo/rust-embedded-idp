use super::*;
use axum::{body::Body, http::Request};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use tower::ServiceExt;

const ACCOUNT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SESSION: &str = "00000000-0000-4000-8000-000000000001";
const TOKEN: &str = "synthetic-self-session-access-secret";

#[derive(Default)]
struct Observed {
    auth_calls: usize,
    session_calls: usize,
    last_actor: Option<AccessActor>,
    last_page: Option<SelfSessionPageRequest>,
    auth_error: Option<TenantAuthError>,
}

#[derive(Clone)]
struct BusinessAuth(Arc<Mutex<Observed>>);

impl TenantAuthenticationService for BusinessAuth {
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        TenantLoginCapabilities {
            mode: TenancyMode::Enabled,
            policy: LoginTenantPolicy::ChooseAfterAuthentication,
        }
    }
    fn login(&self, _: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        Err(TenantAuthError::InvalidCredentials)
    }
    fn list_tenants(
        &self,
        _: SecretString,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn select_tenant(
        &self,
        _: SecretString,
        _: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn authenticate(&self, token: SecretString) -> Result<AccessActor, TenantAuthError> {
        let mut state = self.0.lock().unwrap();
        state.auth_calls += 1;
        assert_eq!(token.expose_secret(), TOKEN);
        if let Some(error) = state.auth_error.clone() {
            return Err(error);
        }
        Ok(actor())
    }
    fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
}

#[derive(Clone)]
struct ManagementAuth(Arc<Mutex<Observed>>);

impl ManagementAuthenticationService for ManagementAuth {
    fn login_capabilities(&self) -> TenantLoginCapabilities {
        BusinessAuth(self.0.clone()).login_capabilities()
    }
    fn login(&self, _: TenantPasswordLogin) -> Result<TenantLoginOutcome, TenantAuthError> {
        Err(TenantAuthError::InvalidCredentials)
    }
    fn list_tenants(
        &self,
        _: SecretString,
        _: AccessPageRequest,
    ) -> Result<AccessPage<SubjectTenant>, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn select_tenant(
        &self,
        _: SecretString,
        _: String,
    ) -> Result<TenantLoginSession, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn authenticate(
        &self,
        token: SecretString,
        request_id: String,
    ) -> Result<AccessAdminContext, TenantAuthError> {
        assert!(!request_id.is_empty());
        let actor = BusinessAuth(self.0.clone()).authenticate(token)?;
        Ok(AccessAdminContext {
            actor,
            authentication_source: "management_access".into(),
            request_id,
        })
    }
    fn begin_switch(&self, _: SecretString) -> Result<TenantSelectionTicket, TenantAuthError> {
        Err(TenantAuthError::InvalidSelection)
    }
    fn rotate_refresh(&self, _: SecretString) -> Result<TenantRefreshOutcome, TenantAuthError> {
        Err(TenantAuthError::InvalidRefresh)
    }
    fn logout(&self, _: SecretString) -> Result<(), TenantAuthError> {
        Err(TenantAuthError::InvalidSession)
    }
}

#[derive(Clone)]
struct Sessions(Arc<Mutex<Observed>>);

impl SelfSessionService for Sessions {
    fn list_sessions(
        &self,
        actor: AccessActor,
        page: SelfSessionPageRequest,
    ) -> Result<SelfSessionPage, AccessError> {
        let mut state = self.0.lock().unwrap();
        state.session_calls += 1;
        state.last_actor = Some(actor);
        state.last_page = Some(page);
        Ok(SelfSessionPage {
            items: vec![SelfSessionSummary {
                tenant_id: "tenant-b".into(),
                session_id: "00000000-0000-4000-8000-000000000002".into(),
                client_id: "delegated-client".into(),
                purpose: AccessTokenPurpose::Business,
                device_id: None,
                created_at: UNIX_EPOCH + Duration::from_secs(10),
                expires_at: UNIX_EPOCH + Duration::from_secs(20),
                status: SessionStatus::Active,
                current: false,
            }],
            next_cursor: None,
        })
    }
}

fn actor() -> AccessActor {
    AccessActor {
        tenant_id: "tenant-a".into(),
        subject_id: ACCOUNT.into(),
        session_id: SESSION.into(),
    }
}

fn request(path: &str) -> Request<Body> {
    Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn send(app: Router, request: Request<Body>) -> Response {
    app.oneshot(request).await.unwrap()
}

#[tokio::test]
async fn bearer_route_checks_headers_query_cursor_and_projects_no_secrets() {
    let observed = Arc::new(Mutex::new(Observed::default()));
    let app = self_session_router(
        Arc::new(BusinessAuth(observed.clone())),
        Arc::new(Sessions(observed.clone())),
    );
    let response = send(app.clone(), request("/auth/security/sessions?limit=1")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("delegated-client"));
    assert!(!text.contains(TOKEN));
    assert!(!text.contains("scope"));
    assert!(!text.contains("refresh_token"));
    assert_eq!(observed.lock().unwrap().last_actor, Some(actor()));

    let page = observed.lock().unwrap().last_page.clone().unwrap();
    assert_eq!(page.limit, 1);

    let mut duplicate = request("/auth/security/sessions");
    duplicate.headers_mut().append(
        header::AUTHORIZATION,
        format!("Bearer {TOKEN}").parse().unwrap(),
    );
    let response = send(app.clone(), duplicate).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let response = send(
        app.clone(),
        request("/auth/security/sessions?limit=1&unexpected=x"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let response = send(app.clone(), request("/auth/security/sessions?cursor=!!")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    let mut mismatch = request("/auth/security/sessions");
    mismatch
        .headers_mut()
        .insert("x-embedded-idp-tenant-id", "tenant-b".parse().unwrap());
    let response = send(app.clone(), mismatch).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let mut business_header = request("/auth/security/sessions");
    business_header
        .headers_mut()
        .insert("x-embedded-idp-business-id", "business-a".parse().unwrap());
    let response = send(app, business_header).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let state = observed.lock().unwrap();
    assert_eq!(state.auth_calls, 4);
    assert_eq!(state.session_calls, 1);
}

#[tokio::test]
async fn management_bearer_route_uses_management_authenticator() {
    let observed = Arc::new(Mutex::new(Observed::default()));
    let app = management_self_session_router(
        Arc::new(ManagementAuth(observed.clone())),
        Arc::new(Sessions(observed.clone())),
    );
    let response = send(app, request("/admin/auth/security/sessions")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(observed.lock().unwrap().session_calls, 1);
}

use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use embedded_idp_axum::{
    management_router, role_admin_router, tenant_auth_router, tenant_management_admin_router,
};
use serde_json::{json, Value};
use tower::ServiceExt;

fn app(db: &Db, policy: LoginTenantPolicy) -> Router {
    let admin = Arc::new(CoreAccessAdminService::new(
        db.mode,
        PermissionCatalog::new(vec![]).unwrap(),
        db.store(),
        TestClock,
        UuidV7IdGenerator,
    ));
    Router::new().nest(
        "/idp",
        management_router(
            Arc::new(management(db, policy)),
            role_admin_router(db.mode, admin.clone()).merge(tenant_management_admin_router(
                db.mode,
                admin,
                Arc::new(
                    CoreAccountSecurityService::new(
                        CoreAccessAdminService::new(
                            db.mode,
                            PermissionCatalog::new(vec![]).unwrap(),
                            db.store(),
                            TestClock,
                            UuidV7IdGenerator,
                        ),
                        AuthConfig {
                            allow_local_registration: false,
                            access_token_ttl_secs: 60,
                            refresh_token_ttl_secs: 600,
                            session_ttl_secs: 1200,
                            verification_code_ttl_secs: 300,
                            password_min_length: 8,
                            password_max_length: 128,
                        },
                    )
                    .unwrap(),
                ),
            )),
        ),
    )
}
fn send(
    app: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    tenant: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    send_with_business(app, method, path, credential, tenant, None, body)
}

fn send_with_business(
    app: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    tenant: Option<&str>,
    business: Option<&str>,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut request = Request::builder()
                .method(method)
                .uri(format!("/idp{path}"))
                .header("content-type", "application/json")
                .header("x-request-id", "untrusted-request-id");
            if let Some(value) = credential {
                request = request.header("authorization", value);
            }
            if let Some(value) = tenant {
                request = request.header("x-embedded-idp-tenant-id", value);
            }
            if let Some(value) = business {
                request = request.header("x-embedded-idp-business-id", value);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            let status = response.status();
            let headers = response.headers().clone();
            let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
            (
                status,
                headers,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        })
}
fn login(app: &Router) -> Value {
    let (status, _, body) = send(
        app,
        "POST",
        "/admin/auth/login",
        None,
        None,
        json!({"email":"new@example.test","password":"Test-password-123"}),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}
fn bearer(body: &Value) -> String {
    format!(
        "Bearer {}",
        body["tokens"]["access_token"].as_str().unwrap()
    )
}
fn refresh(app: &Router, body: &Value) -> (StatusCode, HeaderMap, Value) {
    send(
        app,
        "POST",
        "/admin/auth/refresh",
        None,
        None,
        json!({"refresh_token":body["tokens"]["refresh_token"]}),
    )
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn management_http_login_authorizes_admin_actions_and_refresh_logout_revoke_live_access_in_both_modes(
) {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let subject = Uuid::parse_str(&prepare(&db)).unwrap();
        let router = app(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: "0".into(),
            },
        );
        let login = login(&router);
        let credential = bearer(&login);
        assert_eq!(login["session"]["tenant_id"], "0");
        assert_eq!(
            send(
                &router,
                "GET",
                "/admin/auth/session",
                Some(&credential),
                None,
                Value::Null
            )
            .2["account_id"],
            subject.to_string()
        );
        let target = if mode == TenancyMode::Enabled {
            "t3"
        } else {
            "0"
        };
        let roles = "/admin/access/roles";
        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                None,
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                Some(&credential),
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::FORBIDDEN
        );
        let mut c = db.adapter.connect().unwrap();
        let s = db.schema();
        c.execute(&format!("insert into {s}.access_role_bindings(id,tenant_id,business_id,account_id,role_id,scope_kind,resource_type,created_at_epoch,created_by) select $1,'0','idp',$2,role_id,'type',resource_type,100,created_by from {s}.access_role_bindings where tenant_id='0' limit 1"),&[&Uuid::now_v7(),&subject]).unwrap();
        if mode == TenancyMode::Enabled {
            let (status, _, created) = send(
                &router,
                "POST",
                "/admin/tenants",
                Some(&credential),
                None,
                json!({"tenant_id":target,"name":"Managed tenant","allow_registration":false,"administrator":{"kind":"existing","subject_id":subject.to_string()}}),
            );
            assert_eq!(status, StatusCode::CREATED, "{created}");
        }

        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                Some(&credential),
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::OK
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send_with_business(
                    &router,
                    "GET",
                    roles,
                    Some(&credential),
                    None,
                    Some("f_01"),
                    Value::Null
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        let (status, headers, created) = send_with_business(
            &router,
            "POST",
            roles,
            Some(&credential),
            Some(target),
            Some("f_01"),
            json!({"key":"reports","name":"Reports"}),
        );
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let audit = Uuid::parse_str(created["audit_id"].as_str().unwrap()).unwrap();
        let request_id: String = c
            .query_one(
                &format!("select request_id from {s}.access_audit_events where id=$1"),
                &[&audit],
            )
            .unwrap()
            .get(0);
        assert_eq!(request_id, headers["x-request-id"].to_str().unwrap());
        assert_ne!(request_id, "untrusted-request-id");
        // Grant changes take effect without issuing a replacement credential.
        c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='access.manage'")).unwrap();
        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                Some(&credential),
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::FORBIDDEN
        );
        c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='access.manage'")).unwrap();
        let ordinary = auth(
            &db,
            LoginTenantPolicy::Fixed {
                tenant_id: target.into(),
            },
            "business",
            false,
            false,
        );
        let TenantLoginOutcome::Authenticated(business) = ordinary.login(password()).unwrap()
        else {
            panic!()
        };
        let business_credential =
            format!("Bearer {}", business.tokens.access_token.expose_secret());
        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                Some(&business_credential),
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/auth/refresh",
                None,
                None,
                json!({"refresh_token":business.tokens.refresh_token.expose_secret()})
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        let (status, _, rotated) = refresh(&router, &login);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                Some(&bearer(&rotated)),
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(
            refresh(&router, &login).2["code"],
            "refresh_token_reuse_detected"
        );
        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                Some(&bearer(&rotated)),
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        let fresh = self::login(&router);
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/auth/logout",
                Some(&bearer(&fresh)),
                None,
                Value::Null
            )
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            send(
                &router,
                "GET",
                "/admin/auth/session",
                Some(&bearer(&fresh)),
                None,
                Value::Null
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(refresh(&router, &fresh).0, StatusCode::UNAUTHORIZED);
        assert!(ordinary.authenticate(business.tokens.access_token).is_ok());
        let active = self::login(&router);
        c.execute(&format!("update {s}.access_memberships set status='suspended' where tenant_id='0' and account_id=$1"),&[&subject]).unwrap();
        assert_eq!(
            send_with_business(
                &router,
                "GET",
                roles,
                Some(&bearer(&active)),
                Some(target),
                Some("f_01"),
                Value::Null
            )
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn management_http_selection_paginates_separately_and_tenant_identity_cannot_cross_domains() {
    let db = Db::new(TenancyMode::Enabled);
    prepare(&db);
    let router = app(&db, LoginTenantPolicy::ChooseAfterAuthentication);
    let ordinary = auth(
        &db,
        LoginTenantPolicy::ChooseAfterAuthentication,
        "management",
        false,
        false,
    );
    let ordinary_ticket = ticket(&ordinary);
    let business = Router::new().nest("/idp", tenant_auth_router(Arc::new(ordinary)));
    let logged = login(&router);
    assert_eq!(logged["status"], "tenant_selection_required");
    let selection = format!(
        "TenantSelection {}",
        logged["selection_ticket"].as_str().unwrap()
    );
    let list = "/admin/auth/tenant-selection/tenants";
    let complete = "/admin/auth/tenant-selection/complete";
    let bad_ticket = format!("TenantSelection {}", ordinary_ticket.ticket.expose_secret());
    assert_eq!(
        send(
            &router,
            "POST",
            complete,
            Some(&bad_ticket),
            None,
            json!({"tenant_id":"t1"})
        )
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &business,
            "POST",
            "/auth/tenant-selection/complete",
            Some(&selection),
            None,
            json!({"tenant_id":"t1"})
        )
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, page) = send(
        &router,
        "GET",
        &format!("{list}?limit=1"),
        Some(&selection),
        None,
        Value::Null,
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["tenants"][0]["tenant_id"], "t1");
    let next = send(
        &router,
        "GET",
        &format!(
            "{list}?limit=1&cursor={}",
            page["next_cursor"].as_str().unwrap()
        ),
        Some(&selection),
        None,
        Value::Null,
    )
    .2;
    assert_eq!(next["tenants"][0]["tenant_id"], "t2");
    assert_eq!(next["has_more"], false);
    assert_eq!(
        send(
            &router,
            "POST",
            complete,
            Some(&selection),
            None,
            json!({"tenant_id":"0"})
        )
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, selected) = send(
        &router,
        "POST",
        complete,
        Some(&selection),
        None,
        json!({"tenant_id":"t1"}),
    );
    assert_eq!(status, StatusCode::OK);
    let credential = bearer(&selected);
    assert_eq!(
        send(
            &router,
            "GET",
            "/admin/auth/session",
            Some(&credential),
            None,
            Value::Null
        )
        .2["tenant_id"],
        "t1"
    );
    assert_eq!(
        send(
            &router,
            "GET",
            "/admin/access/roles",
            Some(&credential),
            Some("t2"),
            Value::Null
        )
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&router, "GET", list, Some(&credential), None, Value::Null).0,
        StatusCode::UNAUTHORIZED
    );
    let switch = send(
        &router,
        "POST",
        "/admin/auth/me/tenant-selection",
        Some(&credential),
        None,
        Value::Null,
    )
    .2;
    let ticket = format!(
        "TenantSelection {}",
        switch["selection_ticket"].as_str().unwrap()
    );
    let (status, _, other) = send(
        &router,
        "POST",
        complete,
        Some(&ticket),
        None,
        json!({"tenant_id":"t2"}),
    );
    assert_eq!(status, StatusCode::OK);
    assert_eq!(other["session"]["tenant_id"], "t2");
    // A switch ticket cannot outlive the authority of its source session.
    let switch = send(
        &router,
        "POST",
        "/admin/auth/me/tenant-selection",
        Some(&credential),
        None,
        Value::Null,
    )
    .2;
    assert_eq!(
        send(
            &router,
            "POST",
            "/admin/auth/logout",
            Some(&credential),
            None,
            Value::Null
        )
        .0,
        StatusCode::NO_CONTENT
    );
    let ticket = format!(
        "TenantSelection {}",
        switch["selection_ticket"].as_str().unwrap()
    );
    assert_eq!(
        send(
            &router,
            "POST",
            complete,
            Some(&ticket),
            None,
            json!({"tenant_id":"t2"})
        )
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &router,
            "GET",
            "/admin/auth/session",
            Some(&bearer(&other)),
            None,
            Value::Null
        )
        .0,
        StatusCode::OK
    );
}

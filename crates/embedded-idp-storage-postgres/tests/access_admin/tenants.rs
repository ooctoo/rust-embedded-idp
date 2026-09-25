use super::devices::{device, send};
use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Extension, Router,
};
use embedded_idp_axum::tenant_management_admin_router;
use serde_json::json;
use tower::ServiceExt;
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let r = tenant_management_admin_router(
        db.mode,
        Arc::new(db.service()),
        Arc::new(super::account_security::service(db)),
    );
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            r.layer(Extension(c))
        } else {
            r
        },
    )
}
fn create_body(db: &Db) -> String {
    json!({"tenant_id":"new","name":"New tenant","allow_registration":false,"administrator":{"kind":"existing","subject_id":db.member.to_string()}}).to_string()
}
fn update_body(status: &str, version: u64) -> String {
    json!({"name":"Updated tenant","status":status,"allow_registration":false,"expected_version":version}).to_string()
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_http_search_is_platform_only_scoped_and_rechecks_authority() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    db.adapter.connect().unwrap().batch_execute(&format!("update {s}.access_tenants set name='Alpha%_One' where id='t1'; update {s}.access_tenants set name='ALPHA Two' where id='t2'; insert into {s}.access_tenants(id,kind,name,status,allow_registration,created_at_epoch) values('Z','tenant','Other','archived',false,1000),('z','tenant','Other','suspended',false,1000)")).unwrap();
    let router = app(&db, Some(db.context(db.actor_session.to_string())));
    assert_eq!(
        send(&app(&db, None), "GET", "/admin/tenants", None, "").0,
        StatusCode::UNAUTHORIZED
    );
    let mut member = db.context(db.member_session.to_string());
    member.actor.tenant_id = "t1".into();
    member.actor.subject_id = db.member.to_string();
    assert_eq!(
        send(&app(&db, Some(member)), "GET", "/admin/tenants", None, "").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&router, "GET", "/admin/tenants", Some("t1"), "").0,
        StatusCode::BAD_REQUEST
    );
    let all = send(&router, "GET", "/admin/tenants", None, "");
    let ids: Vec<_> = all.1["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["tenant_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["Z", "t1", "t2", "z"]);
    let page = send(
        &router,
        "GET",
        "/admin/tenants?name=alpha&status=active&limit=1",
        None,
        "",
    );
    assert_eq!(page.0, StatusCode::OK);
    assert_eq!(page.1["items"][0]["tenant_id"], "t1");
    let cursor = page.1["next_cursor"].as_str().unwrap();
    let path = format!("/admin/tenants?name=alpha&status=active&cursor={cursor}");
    let next = send(&router, "GET", &path, None, "");
    assert_eq!(next.1["items"][0]["tenant_id"], "t2");
    assert_eq!(next.1["has_more"], false);
    for changed in [
        "name=alpha",
        "status=active",
        "name=alpha&status=active&tenant_id=t2",
    ] {
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/tenants?{changed}&cursor={cursor}"),
                None,
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    for (query, id) in [
        ("name=%25_", "t1"),
        ("tenant_id=t2", "t2"),
        ("status=archived", "Z"),
        ("status=suspended", "z"),
    ] {
        let result = send(&router, "GET", &format!("/admin/tenants?{query}"), None, "");
        assert_eq!(result.0, StatusCode::OK);
        assert_eq!(result.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(result.1["items"][0]["tenant_id"], id);
    }
    assert_eq!(
        send(&router, "GET", "/admin/tenants?tenant_id=missing", None, "").1["items"],
        json!([])
    );
    assert_eq!(
        send(&router, "GET", "/admin/tenants/missing", None, "").0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&router, "GET", "/admin/tenants/Z", None, "").1["status"],
        "archived"
    );
    for invalid in [
        "tenant_id=0",
        "tenant_id=bad%2Fid",
        "name=",
        "name=%20",
        "limit=0",
        "limit=201",
        "status=disabled",
        "status=active&status=archived",
        "cursor=bad",
        "unknown=1",
    ] {
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/tenants?{invalid}"),
                None,
                ""
            )
            .0,
            StatusCode::BAD_REQUEST,
            "{invalid}"
        );
    }
    assert_eq!(
        send(&router, "GET", "/admin/tenants/0", None, "").0,
        StatusCode::BAD_REQUEST
    );
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='tenants.manage'")).unwrap();
    assert_eq!(
        send(&router, "GET", &path, None, "").0,
        StatusCode::FORBIDDEN
    );
    c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action='tenants.manage'; update {s}.auth_sessions set status='revoked' where tenant_id='0'")).unwrap();
    assert_eq!(
        send(&router, "GET", &path, None, "").0,
        StatusCode::FORBIDDEN
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_http_creation_and_updates_keep_atomic_admin_cleanup_and_version_guards() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    let router = app(&db, Some(db.context(db.actor_session.to_string())));
    let body = create_body(&db);
    let mut c = db.adapter.connect().unwrap();
    for permission in ["tenants.manage", "users.bind", "access.manage"] {
        c.execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action=$1"),&[&permission]).unwrap();
        assert_eq!(
            send(&router, "POST", "/admin/tenants", None, &body).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.access_tenants where id='new'"),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        c.execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.platform' and action=$1"),&[&permission]).unwrap();
    }
    c.batch_execute(&format!("create function {s}.fail_tenant_http_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_tenant_http_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_tenant_http_audit()" )).unwrap();
    assert_eq!(
        send(&router, "POST", "/admin/tenants", None, &body).0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.access_tenants where id='new'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    c.batch_execute(&format!(
        "drop trigger fail_tenant_http_audit on {s}.access_audit_events"
    ))
    .unwrap();
    let created = send(&router, "POST", "/admin/tenants", None, &body);
    assert_eq!(created.0, StatusCode::CREATED, "{}", created.1);
    assert_eq!(created.1["tenant"]["version"], 1);
    assert!(created.1["audit_id"].is_string());
    assert_eq!(
        send(&router, "POST", "/admin/tenants", None, &body).0,
        StatusCode::CONFLICT
    );
    let row=c.query_one(&format!("select m.status,(select count(*) from {s}.access_role_bindings b join {s}.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id where b.tenant_id=m.tenant_id and b.account_id=m.account_id and r.kind='tenant_security_admin') from {s}.access_memberships m where m.tenant_id='new' and m.account_id=$1"),&[&db.member]).unwrap();
    assert_eq!(row.get::<_, String>(0), "active");
    assert_eq!(row.get::<_, i64>(1), 1);
    let original = send(&router, "GET", "/admin/tenants/t1", None, "").1;
    device(&db, "t1", Uuid::from_u128(1), db.member, 1);
    let other_session = device(&db, "t2", Uuid::from_u128(2), db.member, 2);
    c.batch_execute(&format!("create trigger fail_tenant_http_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_tenant_http_audit()" )).unwrap();
    assert_eq!(
        send(
            &router,
            "PATCH",
            "/admin/tenants/t1",
            None,
            &update_body("suspended", 1)
        )
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        send(&router, "GET", "/admin/tenants/t1", None, "").1,
        original
    );
    let active = {
        c.query_one(
            &format!(
                "select count(*) from {s}.auth_sessions where tenant_id='t1' and status='active'"
            ),
            &[],
        )
        .unwrap()
        .get::<_, i64>(0)
    };
    assert!(active > 0);
    c.batch_execute(&format!(
        "drop trigger fail_tenant_http_audit on {s}.access_audit_events"
    ))
    .unwrap();
    let suspended = send(
        &router,
        "PATCH",
        "/admin/tenants/t1",
        None,
        &update_body("suspended", 1),
    );
    assert_eq!(suspended.0, StatusCode::OK);
    assert_eq!(suspended.1["tenant"]["version"], 2);
    assert_eq!(
        c.query_one(
            &format!(
                "select count(*) from {s}.auth_sessions where tenant_id='t1' and status='active'"
            ),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            &format!("select status from {s}.auth_sessions where tenant_id='t2' and id=$1"),
            &[&other_session]
        )
        .unwrap()
        .get::<_, String>(0),
        "active"
    );
    assert_eq!(
        send(
            &router,
            "PATCH",
            "/admin/tenants/t1",
            None,
            &update_body("active", 1)
        )
        .0,
        StatusCode::CONFLICT
    );
    c.batch_execute(&format!(
        "update {s}.access_roles set status='disabled' where tenant_id='t1'"
    ))
    .unwrap();
    assert_eq!(
        send(
            &router,
            "PATCH",
            "/admin/tenants/t1",
            None,
            &update_body("active", 2)
        )
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(&router, "GET", "/admin/tenants/t1", None, "").1["version"],
        2
    );
    c.batch_execute(&format!(
        "update {s}.access_roles set status='active' where tenant_id='t1'"
    ))
    .unwrap();
    assert_eq!(
        send(
            &router,
            "PATCH",
            "/admin/tenants/t1",
            None,
            &update_body("active", 2)
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(
        c.query_one(
            &format!(
                "select count(*) from {s}.auth_sessions where tenant_id='t1' and status='active'"
            ),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        send(
            &router,
            "PATCH",
            "/admin/tenants/t1",
            None,
            &update_body("archived", 3)
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(
        send(
            &router,
            "PATCH",
            "/admin/tenants/0",
            None,
            &update_body("archived", 1)
        )
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn disabled_mode_has_no_tenant_management_routes_and_core_rejects_queries() {
    let db = Db::new(TenancyMode::Disabled);
    let router = app(&db, Some(db.context(db.actor_session.to_string())));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (method, path, body) in [
        ("GET", "/admin/tenants", String::new()),
        ("GET", "/admin/tenants/t1", String::new()),
        ("POST", "/admin/tenants", create_body(&db)),
        ("PATCH", "/admin/tenants/t1", update_body("active", 1)),
    ] {
        let response = runtime
            .block_on(
                router.clone().oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("/idp{path}"))
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                ),
            )
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    assert_eq!(
        db.service().list_tenants(
            db.context(db.actor_session.to_string()),
            AdminTenantFilter::default(),
            AccessPageRequest::default()
        ),
        Err(AccessError::FeatureDisabled)
    );
    assert_eq!(
        db.service()
            .get_tenant(db.context(db.actor_session.to_string()), "t1".into()),
        Err(AccessError::FeatureDisabled)
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_http_new_administrator_commits_identity_membership_grant_and_secret_free_audits() {
    use embedded_idp_core::{ClientSecretVerifier, PhcClientSecretCodec};
    let db = Db::new(TenancyMode::Enabled);
    let router = app(&db, Some(db.context(db.actor_session.to_string())));
    let body = json!({"tenant_id":"fresh","name":"Fresh","allow_registration":false,"administrator":{"kind":"new","email":"fresh@example.test","password":"Fixture-fresh-123"}});
    let result = send(&router, "POST", "/admin/tenants", None, &body.to_string());
    assert_eq!(result.0, StatusCode::CREATED, "{}", result.1);
    let s = db.schema();
    let mut c = db.adapter.connect().unwrap();
    let account = c.query_one(&format!("select id,password_hash,registration_tenant_id,status from {s}.accounts where email='fresh@example.test'"), &[]).unwrap();
    let id: Uuid = account.get(0);
    let hash: String = account.get(1);
    assert!(PhcClientSecretCodec
        .verify_client_secret("Fixture-fresh-123", &hash)
        .unwrap());
    assert_eq!(account.get::<_, String>(2), "fresh");
    assert_eq!(account.get::<_, String>(3), "active");
    assert_eq!(c.query_one(&format!("select count(*) from {s}.access_memberships where account_id=$1 and tenant_id='fresh' and status='active'"), &[&id]).unwrap().get::<_,i64>(0), 1);
    assert_eq!(c.query_one(&format!("select count(*) from {s}.access_role_bindings b join {s}.access_roles r on r.tenant_id=b.tenant_id and r.id=b.role_id where b.account_id=$1 and b.tenant_id='fresh' and r.kind='tenant_security_admin'"), &[&id]).unwrap().get::<_,i64>(0), 1);
    let audits = c.query(&format!("select row_to_json(a)::text from {s}.access_audit_events a where target_domain='fresh'"), &[]).unwrap();
    assert_eq!(audits.len(), 2);
    for value in audits
        .iter()
        .map(|r| r.get::<_, String>(0))
        .chain([result.1.to_string()])
    {
        assert!(!value.contains("Fixture-fresh-123"));
        assert!(!value.contains("$argon2"));
    }
    let mut duplicate = body.clone();
    duplicate["tenant_id"] = json!("duplicate");
    assert_eq!(
        send(
            &router,
            "POST",
            "/admin/tenants",
            None,
            &duplicate.to_string()
        )
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.access_tenants where id='duplicate'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            &format!("select password_hash from {s}.accounts where id=$1"),
            &[&id]
        )
        .unwrap()
        .get::<_, String>(0),
        hash
    );
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn tenant_http_new_administrator_second_audit_failure_rolls_back_all_rows() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    let router = app(&db, Some(db.context(db.actor_session.to_string())));
    let mut c = db.adapter.connect().unwrap();
    c.batch_execute(&format!("create function {s}.fail_new_tenant_audit() returns trigger language plpgsql as $$ begin if NEW.operation='tenant.create' then raise exception 'injected second audit failure'; end if; return NEW; end $$; create trigger fail_new_tenant_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_new_tenant_audit()" )).unwrap();
    let body = json!({"tenant_id":"rollback","name":"Rollback","allow_registration":false,"administrator":{"kind":"new","email":"rollback@example.test","password":"Fixture-rollback-123"}});
    assert_eq!(
        send(&router, "POST", "/admin/tenants", None, &body.to_string()).0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.accounts where email='rollback@example.test'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            &format!("select count(*) from {s}.access_tenants where id='rollback'"),
            &[]
        )
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    for table in [
        "access_memberships",
        "access_roles",
        "access_role_bindings",
        "access_audit_events",
    ] {
        let column = if table == "access_audit_events" {
            "target_domain"
        } else {
            "tenant_id"
        };
        assert_eq!(
            c.query_one(
                &format!("select count(*) from {s}.{table} where {column}='rollback'"),
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
            0
        );
    }
}

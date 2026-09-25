use super::devices::{device, send};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::account_admin_router;
use serde_json::json;
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let router = account_admin_router(db.mode, Arc::new(db.service()));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            router.layer(Extension(c))
        } else {
            router
        },
    )
}
fn account(db: &Db, email: &str, status: &str) -> Uuid {
    let id = Uuid::now_v7();
    let s = db.schema();
    let tenant = db.target();
    let mut c = db.adapter.connect().unwrap();
    let mut tx = c.transaction().unwrap();
    tx.execute(&format!("insert into {s}.accounts(id,registration_tenant_id,email,password_hash,status,created_at_epoch) values($1,$2,$3,'not-exposed-fixture',$4,1000)"),&[&id,&tenant,&email,&status]).unwrap();
    tx.execute(&format!("insert into {s}.access_memberships(tenant_id,account_id,status,joined_at_epoch) values($1,$2,'active',1000)"),&[&tenant,&id]).unwrap();
    tx.commit().unwrap();
    id
}
fn membership(db: &Db, tenant: &str, id: Uuid) -> (String, i64) {
    let r=db.adapter.connect().unwrap().query_one(&format!("select status,version from {}.access_memberships where tenant_id=$1 and account_id=$2",db.schema()),&[&tenant,&id]).unwrap();
    (r.get(0), r.get(1))
}
fn session_status(db: &Db, tenant: &str, id: Uuid) -> String {
    db.adapter
        .connect()
        .unwrap()
        .query_one(
            &format!(
                "select status from {}.auth_sessions where tenant_id=$1 and id=$2",
                db.schema()
            ),
            &[&tenant, &id],
        )
        .unwrap()
        .get(0)
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn account_admin_queries_in_both_modes_hide_secrets_and_bind_filters_and_scope() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let tenant = db.target();
        let s = db.schema();
        let closed = account(&db, "Filter_User@Example.test", "closed");
        account(&db, "FilterXUser@Example.test", "active");
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        assert_eq!(
            send(&app(&db, None), "GET", "/admin/accounts", Some(tenant), "").0,
            StatusCode::UNAUTHORIZED
        );
        let all = send(&router, "GET", "/admin/platform/accounts", None, "");
        assert_eq!(all.0, StatusCode::OK);
        assert_eq!(all.1["items"].as_array().unwrap().len(), 5);
        for item in all.1["items"].as_array().unwrap() {
            assert!(item["membership"].is_null());
            assert!(item.get("password_hash").is_none());
            assert!(item.get("registration_tenant_id").is_none());
        }
        let page = send(&router, "GET", "/admin/accounts?limit=1", Some(tenant), "");
        assert_eq!(page.0, StatusCode::OK);
        assert_eq!(page.1["has_more"], true);
        let cursor = page.1["next_cursor"].as_str().unwrap();
        let next = send(
            &router,
            "GET",
            &format!("/admin/accounts?cursor={cursor}"),
            Some(tenant),
            "",
        );
        assert_eq!(next.0, StatusCode::OK);
        assert!(next.1["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["account_id"] != page.1["items"][0]["account_id"]));
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/platform/accounts?cursor={cursor}"),
                None,
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/accounts?status=active&cursor={cursor}"),
                Some(tenant),
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        let filter=send(&router,"GET","/admin/accounts?email=FILTER_&status=closed&membership_status=active&created_after_unix_secs=1000&created_before_unix_secs=1000",Some(tenant),"");
        assert_eq!(filter.0, StatusCode::OK);
        assert_eq!(filter.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(filter.1["items"][0]["account_id"], closed.to_string());
        assert_eq!(filter.1["items"][0]["status"], "closed");
        assert_eq!(filter.1["items"][0]["membership"]["status"], "active");
        assert_eq!(
            send(
                &router,
                "GET",
                "/admin/platform/accounts?membership_status=active",
                None,
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                &router,
                "GET",
                "/admin/accounts?created_after_unix_secs=1001&created_before_unix_secs=1000",
                Some(tenant),
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                &router,
                "GET",
                "/admin/accounts?actor_id=other",
                Some(tenant),
                ""
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&router, "GET", "/admin/accounts", None, "").0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/accounts/{}", db.actor),
                    Some(tenant),
                    ""
                )
                .0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/accounts?cursor={cursor}"),
                    Some("t2"),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        } else {
            for path in [
                format!("/admin/members/{}/bind", db.member),
                format!("/admin/members/{}/status", db.member),
            ] {
                // These paths are deliberately absent, so the outer host fallback
                // handles 404 and does not run the module's no-store middleware.
                use tower::ServiceExt;
                let status = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        router
                            .clone()
                            .oneshot(
                                axum::http::Request::builder()
                                    .method("POST")
                                    .uri(format!("/idp{path}"))
                                    .body(axum::body::Body::empty())
                                    .unwrap(),
                            )
                            .await
                            .unwrap()
                            .status()
                    });
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
        }
        db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.platform' and action='users.read'"),&[]).unwrap();
        assert_eq!(
            send(&router, "GET", "/admin/accounts", Some(tenant), "").0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/platform/accounts/{}", db.member),
                None,
                ""
            )
            .0,
            StatusCode::FORBIDDEN
        );
    }
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn member_http_changes_are_tenant_scoped_atomic_and_rebinding_does_not_restore_credentials() {
    let db = Db::new(TenancyMode::Enabled);
    let s = db.schema();
    let owner_session = device(&db, "t1", Uuid::now_v7(), db.owner, 101);
    let owned_device = Uuid::now_v7();
    let member_session = device(&db, "t1", owned_device, db.member, 102);
    let other_session = device(&db, "t2", Uuid::now_v7(), db.member, 103);
    let tenant_context = AccessAdminContext {
        actor: AccessActor {
            tenant_id: "t1".into(),
            subject_id: db.owner.to_string(),
            session_id: owner_session.to_string(),
        },
        authentication_source: "test".into(),
        request_id: "member-http".into(),
    };
    let tenant = app(&db, Some(tenant_context));
    let platform = app(&db, Some(db.context(db.actor_session.to_string())));
    let path = format!("/admin/members/{}/status", db.member);
    let bind = format!("/admin/members/{}/bind", db.member);
    assert_eq!(
        send(&tenant, "GET", "/admin/accounts", None, "").0,
        StatusCode::OK
    );
    assert_eq!(
        send(&tenant, "GET", "/admin/accounts", Some("t2"), "").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&tenant, "GET", "/admin/platform/accounts", None, "").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&tenant, "POST", &bind, Some("t1"), "{}").0,
        StatusCode::FORBIDDEN
    );
    let invalid = json!({"status":"suspended","expected_version":1,"password":"override"});
    assert_eq!(
        send(&tenant, "POST", &path, None, &invalid.to_string()).0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        send(
            &tenant,
            "POST",
            &path,
            None,
            r#"{"status":"suspended","expected_version":1}"#
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(membership(&db, "t1", db.member), ("suspended".into(), 2));
    assert_eq!(session_status(&db, "t1", member_session), "revoked");
    assert_eq!(session_status(&db, "t2", other_session), "active");
    assert_eq!(
        send(&platform, "POST", &bind, Some("t1"), "{}").0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        send(
            &tenant,
            "POST",
            &path,
            None,
            r#"{"status":"active","expected_version":1}"#
        )
        .0,
        StatusCode::CONFLICT
    );
    db.adapter.connect().unwrap().batch_execute(&format!("create function {s}.member_audit_failure() returns trigger language plpgsql as $$ begin raise exception 'audit blocked'; end $$; create trigger member_audit_failure before insert on {s}.access_audit_events for each row execute function {s}.member_audit_failure()" )).unwrap();
    assert_eq!(
        send(
            &tenant,
            "POST",
            &path,
            None,
            r#"{"status":"active","expected_version":2}"#
        )
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(membership(&db, "t1", db.member), ("suspended".into(), 2));
    db.adapter
        .connect()
        .unwrap()
        .batch_execute(&format!(
            "drop trigger member_audit_failure on {s}.access_audit_events"
        ))
        .unwrap();
    assert_eq!(
        send(
            &tenant,
            "POST",
            &path,
            None,
            r#"{"status":"active","expected_version":2}"#
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(session_status(&db, "t1", member_session), "revoked");
    let owner_path = format!("/admin/members/{}/status", db.owner);
    assert_eq!(
        send(
            &tenant,
            "POST",
            &owner_path,
            None,
            r#"{"status":"suspended","expected_version":1}"#
        )
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(membership(&db, "t1", db.owner), ("active".into(), 1));
    assert_eq!(session_status(&db, "t1", owner_session), "active");
    let only = account(&db, "last-member@example.test", "active");
    assert_eq!(
        send(
            &tenant,
            "POST",
            &format!("/admin/members/{only}/status"),
            None,
            r#"{"status":"removed","expected_version":1}"#
        )
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(membership(&db, "t1", only), ("active".into(), 1));
    assert_eq!(
        send(
            &tenant,
            "POST",
            &path,
            None,
            r#"{"status":"removed","expected_version":3}"#
        )
        .0,
        StatusCode::OK
    );
    assert_eq!(membership(&db, "t1", db.member), ("removed".into(), 4));
    assert_eq!(session_status(&db, "t2", other_session), "active");
    let row=db.adapter.connect().unwrap().query_one(&format!("select a.status,a.password_hash,b.status from {s}.accounts a join {s}.account_device_bindings b on b.account_id=a.id where b.tenant_id='t1' and b.device_id=$1 and a.id=$2"),&[&owned_device,&db.member]).unwrap();
    assert_eq!(row.get::<_, String>(0), "active");
    assert_eq!(row.get::<_, String>(1), "fixture-hash");
    assert_eq!(row.get::<_, String>(2), "unbound");
    assert_eq!(
        send(
            &tenant,
            "POST",
            &path,
            None,
            r#"{"status":"active","expected_version":4}"#
        )
        .0,
        StatusCode::CONFLICT
    );
    let first = send(&platform, "POST", &bind, Some("t1"), "{}");
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(first.1["membership"]["version"], 5);
    let repeat = send(&platform, "POST", &bind, Some("t1"), "{}");
    assert_eq!(repeat.0, StatusCode::OK);
    assert_eq!(first.1["membership"], repeat.1["membership"]);
    assert_eq!(session_status(&db, "t1", member_session), "revoked");
    let count:i64=db.adapter.connect().unwrap().query_one(&format!("select count(*) from {s}.access_role_bindings where tenant_id='t1' and account_id=$1"),&[&db.member]).unwrap().get(0);
    assert_eq!(count, 0);
    db.adapter.connect().unwrap().execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='members.manage'"),&[]).unwrap();
    assert_eq!(
        send(&tenant, "GET", "/admin/accounts", None, "").0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &tenant,
            "POST",
            &path,
            None,
            r#"{"status":"suspended","expected_version":5}"#
        )
        .0,
        StatusCode::FORBIDDEN
    );
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn concurrent_http_member_removal_preserves_one_membership_and_duplicate_binding_is_idempotent() {
    let db = Db::new(TenancyMode::Enabled);
    let platform = app(&db, Some(db.context(db.actor_session.to_string())));
    let barrier = Arc::new(Barrier::new(2));
    let path = format!("/admin/members/{}/status", db.member);
    let joins: Vec<_> = ["t1", "t2"]
        .into_iter()
        .map(|t| {
            let router = platform.clone();
            let barrier = barrier.clone();
            let path = path.clone();
            thread::spawn(move || {
                barrier.wait();
                send(
                    &router,
                    "POST",
                    &path,
                    Some(t),
                    r#"{"status":"removed","expected_version":1}"#,
                )
                .0
            })
        })
        .collect();
    let codes: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(codes.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        codes.iter().filter(|s| **s == StatusCode::CONFLICT).count(),
        1
    );
    let t1 = membership(&db, "t1", db.member);
    let tenant = if t1.0 == "removed" { "t1" } else { "t2" };
    let barrier = Arc::new(Barrier::new(2));
    let path = format!("/admin/members/{}/bind", db.member);
    let joins: Vec<_> = (0..2)
        .map(|_| {
            let router = platform.clone();
            let barrier = barrier.clone();
            let path = path.clone();
            thread::spawn(move || {
                barrier.wait();
                send(&router, "POST", &path, Some(tenant), "{}")
            })
        })
        .collect();
    let results: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert!(results.iter().all(|r| r.0 == StatusCode::OK));
    assert_eq!(results[0].1["membership"], results[1].1["membership"]);
    assert_eq!(membership(&db, tenant, db.member), ("active".into(), 3));
}

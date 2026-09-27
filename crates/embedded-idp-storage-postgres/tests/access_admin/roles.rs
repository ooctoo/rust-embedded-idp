use super::devices::{device, send, send_with_business};
use super::*;
use axum::{http::StatusCode, Extension, Router};
use embedded_idp_axum::role_admin_router;
use serde_json::{json, Value};
fn app(db: &Db, context: Option<AccessAdminContext>) -> Router {
    let r = role_admin_router(db.mode, Arc::new(db.service()));
    Router::new().nest(
        "/idp",
        if let Some(c) = context {
            r.layer(Extension(c))
        } else {
            r
        },
    )
}
fn create(router: &Router, t: &str, key: &str) -> String {
    let result = send(
        router,
        "POST",
        "/admin/access/roles",
        Some(t),
        &json!({"key":key,"name":key}).to_string(),
    );
    assert_eq!(result.0, StatusCode::CREATED, "{}", result.1);
    assert_eq!(result.1["role"]["kind"], "business");
    assert_eq!(result.1["role"]["version"], 1);
    assert_eq!(result.1["role"]["permissions"], json!([]));
    result.1["role"]["role_id"].as_str().unwrap().to_owned()
}
fn permissions(keys: &[(&str, &str)], version: u64) -> String {
    json!({"permissions":keys.iter().map(|(r,a)|json!({"resource_type":r,"action":a})).collect::<Vec<_>>(),"expected_version":version}).to_string()
}
#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn role_admin_http_lifecycle_permissions_versions_and_audit_are_atomic_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let t = db.target();
        let s = db.schema();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let role = create(&router, t, "report_reader");
        let path = format!("/admin/access/roles/{role}");
        let pp = format!("{path}/permissions");
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/access/roles",
                Some(t),
                r#"{"key":"report_reader","name":"Duplicate"}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        let result = send(
            &router,
            "PUT",
            &pp,
            Some(t),
            &permissions(&[("report", "read"), ("report", "update")], 1),
        );
        assert_eq!(result.0, StatusCode::OK);
        assert_eq!(result.1["role"]["version"], 2);
        let snapshot = send(&router, "GET", &pp, Some(t), "").1;
        assert_eq!(snapshot["version"], 2);
        assert_eq!(snapshot["items"].as_array().unwrap().len(), 2);
        for (keys, status) in [
            (
                vec![("report", "read"), ("report", "read")],
                StatusCode::BAD_REQUEST,
            ),
            (vec![("missing", "read")], StatusCode::BAD_REQUEST),
            (
                vec![("idp.platform", "access.manage")],
                StatusCode::FORBIDDEN,
            ),
            (vec![("idp.tenant", "roles.manage")], StatusCode::FORBIDDEN),
        ] {
            assert_eq!(
                send(&router, "PUT", &pp, Some(t), &permissions(&keys, 2)).0,
                status
            );
        }
        assert_eq!(
            send(&router, "PUT", &pp, Some(t), &permissions(&[], 1)).0,
            StatusCode::CONFLICT
        );
        let mut c = db.adapter.connect().unwrap();
        c.batch_execute(&format!("create function {s}.fail_role_http_audit() returns trigger language plpgsql as $$ begin raise exception 'injected audit failure'; end $$; create trigger fail_role_http_audit before insert on {s}.access_audit_events for each row execute function {s}.fail_role_http_audit()" )).unwrap();
        assert_eq!(
            send(&router, "PUT", &pp, Some(t), &permissions(&[], 2)).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(send(&router, "GET", &pp, Some(t), "").1, snapshot);
        assert_eq!(
            send(
                &router,
                "DELETE",
                &path,
                Some(t),
                r#"{"expected_version":2}"#
            )
            .0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(send(&router, "GET", &pp, Some(t), "").1, snapshot);
        c.batch_execute(&format!(
            "drop trigger fail_role_http_audit on {s}.access_audit_events"
        ))
        .unwrap();
        db.service()
            .execute(
                db.context(db.actor_session.to_string()),
                db.command(AccessAdminMutation::GrantRole {
                    business_id: "f_01".into(),
                    subject_id: db.member.to_string(),
                    role_id: role.clone(),
                    scope: RoleBindingScope::Resource {
                        resource_type: "report".into(),
                        scope: ResourceScope::Instance("report-1".into()),
                    },
                }),
            )
            .unwrap();
        assert_eq!(
            send(&router, "PUT", &pp, Some(t), &permissions(&[], 2)).0,
            StatusCode::OK
        );
        assert_eq!(c.query_one(&format!("select count(*) from {s}.access_role_bindings where tenant_id=$1 and role_id=$2"),&[&t,&Uuid::parse_str(&role).unwrap()]).unwrap().get::<_,i64>(0),0);
        assert_eq!(
            send(
                &router,
                "PUT",
                &pp,
                Some(t),
                &permissions(&[("report", "read")], 3)
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(
                &router,
                "PATCH",
                &path,
                Some(t),
                r#"{"name":"Disabled reader","status":"disabled","expected_version":4}"#
            )
            .0,
            StatusCode::OK
        );
        assert_eq!(
            send(&router, "GET", &path, Some(t), "").1["status"],
            "disabled"
        );
        assert_eq!(
            send(
                &router,
                "DELETE",
                &path,
                Some(t),
                r#"{"expected_version":4}"#
            )
            .0,
            StatusCode::CONFLICT
        );
        let deleted = send(
            &router,
            "DELETE",
            &path,
            Some(t),
            r#"{"expected_version":5}"#,
        );
        assert_eq!(deleted.0, StatusCode::OK);
        assert_eq!(deleted.1["role"], Value::Null);
        assert!(deleted.1["audit_id"].is_string());
        assert_eq!(
            send(&router, "GET", &path, Some(t), "").0,
            StatusCode::NOT_FOUND
        );
        let protected: String = c
            .query_one(
                &format!("select id from {s}.access_roles where tenant_id=$1 and kind<>'business'"),
                &[&t],
            )
            .unwrap()
            .get::<_, Uuid>(0)
            .to_string();
        let protected_path = format!("/admin/access/roles/{protected}");
        let alternative = Uuid::parse_str(&protected).unwrap().simple().to_string();
        assert_eq!(
            send(
                &router,
                "GET",
                &format!("/admin/access/roles/{alternative}"),
                Some(t),
                ""
            )
            .0,
            StatusCode::NOT_FOUND
        );

        assert_eq!(
            send_with_business(&router, "GET", &protected_path, Some(t), "", Some("idp")).0,
            StatusCode::OK
        );
        for (method, path, body) in [
            (
                "PATCH",
                protected_path.clone(),
                r#"{"name":"Hijacked","status":"disabled","expected_version":1}"#.to_owned(),
            ),
            (
                "DELETE",
                protected_path.clone(),
                r#"{"expected_version":1}"#.to_owned(),
            ),
            (
                "PUT",
                format!("{protected_path}/permissions"),
                permissions(&[], 1),
            ),
        ] {
            assert_eq!(
                send_with_business(&router, method, &path, Some(t), &body, Some("idp")).0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            send(
                &router,
                "POST",
                "/admin/access/roles",
                Some(t),
                r#"{"key":"system_admin","name":"Hijacked"}"#
            )
            .0,
            StatusCode::FORBIDDEN
        );
    }
}

#[test]
#[ignore = "requires explicit EMBEDDED_IDP_TEST_PG_CONNECTION_URI"]
fn role_admin_queries_scope_cursor_and_read_write_authority_in_both_modes() {
    for mode in [TenancyMode::Disabled, TenancyMode::Enabled] {
        let db = Db::new(mode);
        let t = db.target();
        let s = db.schema();
        let router = app(&db, Some(db.context(db.actor_session.to_string())));
        let first = create(&router, t, "first");
        let second = create(&router, t, "second");
        db.adapter
            .connect()
            .unwrap()
            .execute(
                &format!(
                    "update {s}.access_roles set created_at_epoch=0 where tenant_id=$1 and kind<>'business'"
                ),
                &[&t],
            )
            .unwrap();
        assert_eq!(
            send(&app(&db, None), "GET", "/admin/access/roles", Some(t), "").0,
            StatusCode::UNAUTHORIZED
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&router, "GET", "/admin/access/roles", None, "").0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                send(&router, "GET", "/admin/access/roles", Some("0"), "").0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/access/roles/{first}"),
                    Some("t2"),
                    ""
                )
                .0,
                StatusCode::NOT_FOUND
            );
        }
        let page = send(&router, "GET", "/admin/access/roles?limit=1", Some(t), "");
        assert_eq!(page.0, StatusCode::OK);
        assert_eq!(page.1["items"][0]["role_id"], second);
        assert!(page.1["items"][0].get("permissions").is_none());
        let cursor = page.1["next_cursor"].as_str().unwrap();
        let path = format!("/admin/access/roles?cursor={cursor}&limit=1");
        assert_eq!(
            send(&router, "GET", &path, Some(t), "").1["items"][0]["role_id"],
            first
        );
        if mode == TenancyMode::Enabled {
            assert_eq!(
                send(&router, "GET", &path, Some("t2"), "").0,
                StatusCode::BAD_REQUEST
            );
            let owner_session = device(&db, t, Uuid::now_v7(), db.owner, 1);
            let mut owner = db.context(owner_session.to_string());
            owner.actor.tenant_id = t.into();
            owner.actor.subject_id = db.owner.to_string();
            let owner_app = app(&db, Some(owner));
            assert_eq!(
                send(&owner_app, "GET", "/admin/access/roles", None, "").0,
                StatusCode::OK
            );
            assert_eq!(
                send(&owner_app, "GET", "/admin/access/roles", Some("t2"), "").0,
                StatusCode::FORBIDDEN
            );
            let mut c = db.adapter.connect().unwrap();
            c.batch_execute(&format!("update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='access.read'")).unwrap();
            assert_eq!(
                send(&owner_app, "GET", "/admin/access/roles", None, "").0,
                StatusCode::FORBIDDEN
            );
            c.batch_execute(&format!("update {s}.access_permissions set enabled=true where resource_type='idp.tenant' and action='access.read'; update {s}.access_permissions set enabled=false where resource_type='idp.tenant' and action='roles.manage'")).unwrap();
            assert_eq!(
                send(&owner_app, "GET", "/admin/access/roles", None, "").0,
                StatusCode::OK
            );
            assert_eq!(
                send(
                    &owner_app,
                    "POST",
                    "/admin/access/roles",
                    None,
                    r#"{"key":"denied","name":"Denied"}"#
                )
                .0,
                StatusCode::FORBIDDEN
            );
        }
        for invalid in ["limit=0", "limit=201", "cursor=bad", "unknown=value"] {
            assert_eq!(
                send(
                    &router,
                    "GET",
                    &format!("/admin/access/roles?{invalid}"),
                    Some(t),
                    ""
                )
                .0,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            send(&router, "GET", "/admin/access/roles/missing", Some(t), "").0,
            StatusCode::NOT_FOUND
        );
        db.adapter
            .connect()
            .unwrap()
            .batch_execute(&format!(
                "update {s}.auth_sessions set status='revoked' where tenant_id='0'"
            ))
            .unwrap();
        assert_eq!(
            send(&router, "GET", &path, Some(t), "").0,
            StatusCode::FORBIDDEN
        );
    }
}
